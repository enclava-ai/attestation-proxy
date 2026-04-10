/// HTTP route handlers for the attestation proxy.
///
/// All 6 GET endpoints with Python-identical response contracts.
/// POST /unlock implements the ownership handoff protocol.
use axum::body::Body;
use axum::extract::{Path, Query, State};
use axum::http::{header, Response as HttpResponse};
use axum::response::{IntoResponse, Response};
use axum::Json;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use rand::RngCore;
use serde_json::{json, Value};
use sha2::Digest;
use std::time::Instant;
use zeroize::Zeroizing;

use crate::attestation;
use crate::escrow::{self, EscrowValueUpdate, OwnerSeedMaterial};
use crate::kbs;
use crate::ownership::utc_now;
use crate::ownership::{
    BootstrapChallenge, HandoffOutcome, OwnershipError, SIGNAL_APP_DATA_SLOT, SIGNAL_TLS_DATA_SLOT,
};
use crate::AppState;

// ---------------------------------------------------------------------------
// Query param types
// ---------------------------------------------------------------------------

#[derive(serde::Deserialize)]
pub struct AttestationQuery {
    pub nonce: Option<String>,
    pub runtime_data: Option<String>,
}

#[derive(serde::Deserialize)]
pub struct UnlockRequest {
    pub password: String,
}

#[derive(serde::Deserialize)]
pub struct ChangePasswordRequest {
    pub old_password: String,
    pub new_password: String,
}

#[derive(serde::Deserialize)]
pub struct RecoverRequest {
    pub mnemonic: String,
    pub new_password: String,
}

#[derive(serde::Deserialize)]
pub struct BootstrapClaimRequest {
    pub challenge: String,
    pub bootstrap_pubkey: String,
    pub signature: String,
    pub password: String,
}

// ---------------------------------------------------------------------------
// Response helpers
// ---------------------------------------------------------------------------

/// Build a JSON response with compact serialization, Cache-Control: no-store.
fn json_response(status: u16, body: &Value) -> Response {
    let bytes = serde_json::to_vec(body).unwrap_or_default();
    HttpResponse::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::CACHE_CONTROL, "no-store")
        .body(Body::from(bytes))
        .unwrap()
        .into_response()
}

/// Build a raw bytes response with given content type, Cache-Control: no-store.
fn bytes_response(status: u16, body: Vec<u8>, content_type: &str) -> Response {
    HttpResponse::builder()
        .status(status)
        .header(header::CONTENT_TYPE, content_type)
        .header(header::CACHE_CONTROL, "no-store")
        .body(Body::from(body))
        .unwrap()
        .into_response()
}

/// Convert empty string to null for JSON output (matches Python's `or None`).
fn or_null(s: &str) -> Value {
    if s.is_empty() {
        Value::Null
    } else {
        Value::String(s.to_string())
    }
}

/// Build policy metadata JSON (matches Python build_policy_metadata).
fn build_policy_metadata(config: &crate::config::Config) -> Value {
    json!({
        "url": or_null(&config.attestation_policy_url),
        "sha256": or_null(&config.attestation_policy_sha256),
        "signature_url": or_null(&config.attestation_policy_signature_url),
    })
}

/// Build endorsement metadata JSON (matches Python build_endorsement_metadata).
fn build_endorsement_metadata(config: &crate::config::Config) -> Value {
    json!({
        "cert_chain": {
            "url": or_null(&config.attestation_cert_chain_url),
            "fetch_by_client": true,
        },
        "tcb_info": {
            "url": or_null(&config.attestation_tcb_info_url),
            "fetch_by_client": true,
        },
    })
}

/// Build server verification object (matches Python build_server_verification).
fn build_server_verification(
    identity: &Value,
    claims: &Value,
    nonce: &Option<String>,
    policy_sha256: &str,
) -> Value {
    let attested_digest = claims
        .get("workload")
        .and_then(|w| w.get("image_digest_attested"))
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty());

    let configured_digest = identity
        .get("configured")
        .and_then(|c| c.get("image_digest"))
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty());

    let nonce_supplied = nonce.is_some();
    let attested_digest_present = attested_digest.is_some();
    let configured_digest_present = configured_digest.is_some();

    let attested_matches_configured = match (attested_digest, configured_digest) {
        (Some(a), Some(c)) => Value::Bool(a == c),
        _ => Value::Null,
    };

    let mut reasons: Vec<String> = Vec::new();
    if !nonce_supplied {
        reasons.push("nonce_supplied".to_string());
    }
    if attested_matches_configured == Value::Bool(false) {
        reasons.push("attested_matches_configured".to_string());
    }

    let mut warnings: Vec<String> = Vec::new();
    if !attested_digest_present {
        warnings.push("attested_digest_missing".to_string());
    }

    let verdict = if !reasons.is_empty() {
        "fail"
    } else if !attested_digest_present {
        "inconclusive"
    } else if attested_digest_present
        && (attested_matches_configured == Value::Bool(true)
            || attested_matches_configured == Value::Null)
    {
        "pass"
    } else {
        "inconclusive"
    };

    json!({
        "verdict": verdict,
        "policy_sha256": or_null(policy_sha256),
        "checks": {
            "nonce_supplied": nonce_supplied,
            "attested_digest_present": attested_digest_present,
            "configured_digest_present": configured_digest_present,
            "attested_matches_configured": attested_matches_configured,
        },
        "reasons": reasons,
        "warnings": warnings,
        "note": "Clients must still verify evidence signatures, cert chain, TCB, and nonce binding.",
    })
}

#[derive(Default)]
struct OwnershipIdentity {
    tenant_id: Option<String>,
    instance_id: Option<String>,
    bootstrap_owner_pubkey_hash: Option<String>,
    tenant_instance_identity_hash: Option<String>,
    claims_verified: bool,
    claims_error: Option<String>,
}

async fn fetch_ownership_identity(state: &AppState) -> OwnershipIdentity {
    let token_claims = attestation::fetch_kbs_token_claims(state).await;
    let error = token_claims
        .get("error")
        .and_then(Value::as_str)
        .map(ToString::to_string);
    let claims_verified = token_claims
        .get("verified")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let claims = token_claims
        .get("claims_root")
        .filter(|value| value.is_object())
        .cloned()
        .unwrap_or_else(|| json!({}));
    let bootstrap_owner_pubkey_hash = attestation::extract_bootstrap_owner_pubkey_hash(&claims);
    let tenant_instance_identity_hash = attestation::extract_tenant_instance_identity_hash(&claims);

    OwnershipIdentity {
        tenant_id: attestation::extract_tenant_id(&claims),
        instance_id: attestation::extract_instance_id(&claims),
        bootstrap_owner_pubkey_hash,
        tenant_instance_identity_hash,
        claims_verified,
        claims_error: error,
    }
}

fn emit_signed_owner_audit_event(
    state: &AppState,
    owner_seed: &[u8; 32],
    action: &str,
    details: Value,
) {
    match state.ownership.signed_owner_audit_event(
        owner_seed,
        &state.config.instance_id,
        &state.config.storage_ownership_mode,
        action,
        details,
    ) {
        Ok(event) => eprintln!("{event}"),
        Err(err) => eprintln!(
            "{}",
            json!({
                "kind": "owner_seed_audit_error",
                "timestamp": utc_now(),
                "instance_id": state.config.instance_id.as_str(),
                "action": action,
                "error": err.to_string(),
            })
        ),
    }
}

fn decode_binary_field(value: &str) -> Result<Vec<u8>, OwnershipError> {
    let trimmed = value.trim();
    let decode_hex = || -> Result<Vec<u8>, OwnershipError> {
        if trimmed.len() % 2 != 0 {
            return Err(OwnershipError::Envelope(
                "binary_decode_failed:hex_length_invalid".to_string(),
            ));
        }
        let mut out = Vec::with_capacity(trimmed.len() / 2);
        let bytes = trimmed.as_bytes();
        for idx in (0..bytes.len()).step_by(2) {
            let pair = std::str::from_utf8(&bytes[idx..idx + 2])
                .map_err(|err| OwnershipError::Envelope(format!("binary_decode_failed:{err}")))?;
            let value = u8::from_str_radix(pair, 16)
                .map_err(|err| OwnershipError::Envelope(format!("binary_decode_failed:{err}")))?;
            out.push(value);
        }
        Ok(out)
    };
    URL_SAFE_NO_PAD
        .decode(trimmed.as_bytes())
        .or_else(|_| base64::engine::general_purpose::STANDARD.decode(trimmed.as_bytes()))
        .map_err(|_| OwnershipError::Envelope("binary_decode_failed".to_string()))
        .or_else(|_| decode_hex())
}

fn bootstrap_pubkey_hash_matches(expected: &str, raw_pubkey: &[u8]) -> bool {
    let expected = expected.trim();
    let digest = sha2::Sha256::digest(raw_pubkey);
    let hex = digest
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let b64url = URL_SAFE_NO_PAD.encode(digest);
    expected.eq_ignore_ascii_case(&hex) || expected == b64url
}

fn is_missing_owner_seed_resource(error_json: &Value) -> bool {
    matches!(
        error_json.get("upstream_status").and_then(Value::as_u64),
        Some(404)
    )
}

fn is_optional_sealed_owner_seed_resource_missing(error_json: &Value) -> bool {
    matches!(
        error_json.get("upstream_status").and_then(Value::as_u64),
        Some(404)
    )
}

fn owner_seed_unavailable_error(error_json: &Value) -> OwnershipError {
    OwnershipError::OwnerSeedUnavailable(
        error_json
            .get("error")
            .and_then(Value::as_str)
            .unwrap_or("owner_seed_fetch_failed")
            .to_string(),
    )
}

async fn cdh_missing_owner_seed_resource(
    state: &AppState,
    resource_path: &str,
    error_json: &Value,
) -> Result<bool, OwnershipError> {
    if is_missing_owner_seed_resource(error_json) {
        return Ok(true);
    }

    if error_json.get("upstream_status").and_then(Value::as_u64) != Some(500) {
        return Ok(false);
    }

    match kbs::probe_direct_kbs_resource_status(state, resource_path).await? {
        404 => Ok(true),
        200 => Ok(false),
        status => Err(OwnershipError::OwnerSeedUnavailable(format!(
            "owner_seed_probe_unexpected_status:{status}"
        ))),
    }
}

async fn cdh_missing_optional_sealed_owner_seed_resource(
    state: &AppState,
    resource_path: &str,
    error_json: &Value,
) -> Result<bool, OwnershipError> {
    if is_optional_sealed_owner_seed_resource_missing(error_json) {
        return Ok(true);
    }

    if error_json.get("upstream_status").and_then(Value::as_u64) != Some(500) {
        return Ok(false);
    }

    match kbs::probe_direct_kbs_resource_status(state, resource_path).await? {
        404 => Ok(true),
        200 => Ok(false),
        status => Err(OwnershipError::OwnerSeedUnavailable(format!(
            "owner_seed_sealed_probe_unexpected_status:{status}"
        ))),
    }
}

#[cfg(test)]
const OWNER_SEED_STARTUP_RECHECK_ATTEMPTS: usize = 3;
#[cfg(not(test))]
const OWNER_SEED_STARTUP_RECHECK_ATTEMPTS: usize = 5;

#[cfg(test)]
const OWNER_SEED_STARTUP_RECHECK_DELAY_MS: u64 = 10;
#[cfg(not(test))]
const OWNER_SEED_STARTUP_RECHECK_DELAY_MS: u64 = 2_000;

fn validate_bootstrap_signature(
    challenge_b64: &str,
    bootstrap_pubkey: &str,
    signature: &str,
    expected_pubkey_hash: &str,
) -> Result<(), OwnershipError> {
    let challenge = decode_binary_field(challenge_b64)?;
    let public_key_bytes = decode_binary_field(bootstrap_pubkey)?;
    let signature_bytes = decode_binary_field(signature)?;

    if !bootstrap_pubkey_hash_matches(expected_pubkey_hash, &public_key_bytes) {
        return Err(OwnershipError::Envelope(
            "bootstrap_pubkey_hash_mismatch".to_string(),
        ));
    }
    let verifying_key =
        VerifyingKey::from_bytes(&public_key_bytes.as_slice().try_into().map_err(|_| {
            OwnershipError::Envelope("bootstrap_pubkey_length_invalid".to_string())
        })?)
        .map_err(|err| OwnershipError::Envelope(format!("bootstrap_pubkey_invalid:{err}")))?;
    let signature = Signature::from_slice(&signature_bytes)
        .map_err(|err| OwnershipError::Envelope(format!("bootstrap_signature_invalid:{err}")))?;
    verifying_key
        .verify(&challenge, &signature)
        .map_err(|_| OwnershipError::Envelope("bootstrap_signature_mismatch".to_string()))
}

async fn load_owner_seed_material(state: &AppState) -> Result<OwnerSeedMaterial, OwnershipError> {
    match state.config.owner_ciphertext_backend.as_str() {
        "filesystem" => escrow::load_owner_seed_material_from_files(state).await,
        "kubernetes-secret" => escrow::load_owner_seed_material(state).await,
        "kbs-resource" => {
            let encrypted = match kbs::fetch_kbs_resource(
                state,
                state.config.owner_seed_encrypted_kbs_path.trim(),
            )
            .await
            {
                Ok((body, _, _)) => Some(body),
                Err((_status, error_json)) => {
                    if cdh_missing_owner_seed_resource(
                        state,
                        state.config.owner_seed_encrypted_kbs_path.trim(),
                        &error_json,
                    )
                    .await?
                    {
                        None
                    } else {
                        return Err(owner_seed_unavailable_error(&error_json));
                    }
                }
            };
            let sealed = match kbs::fetch_kbs_resource(
                state,
                state.config.owner_seed_sealed_kbs_path.trim(),
            )
            .await
            {
                Ok((body, _, _)) => Some(body),
                Err((_status, error_json)) => {
                    if cdh_missing_optional_sealed_owner_seed_resource(
                        state,
                        state.config.owner_seed_sealed_kbs_path.trim(),
                        &error_json,
                    )
                    .await?
                    {
                        None
                    } else {
                        return Err(owner_seed_unavailable_error(&error_json));
                    }
                }
            };
            Ok(OwnerSeedMaterial { encrypted, sealed })
        }
        other => Err(OwnershipError::Store(format!(
            "unsupported_owner_ciphertext_backend:{other}"
        ))),
    }
}

async fn refresh_ownership_state(
    state: &AppState,
    force_refresh: bool,
) -> Result<(), OwnershipError> {
    if !(state.ownership.is_password_mode() || state.ownership.is_auto_unlock_mode()) {
        return Ok(());
    }

    if force_refresh && state.config.owner_ciphertext_backend == "kbs-resource" {
        kbs::evict_kbs_cache_entry(state, state.config.owner_seed_encrypted_kbs_path.trim()).await;
        kbs::evict_kbs_cache_entry(state, state.config.owner_seed_sealed_kbs_path.trim()).await;
    }

    let material = load_owner_seed_material(state).await?;
    let claimed = material.encrypted.is_some();
    state
        .ownership
        .set_auto_unlock_enabled(material.sealed.is_some());
    if claimed {
        if state.ownership.is_auto_unlock_mode() && material.sealed.is_some() {
            state.ownership.set_unlocking();
        } else {
            state.ownership.set_locked();
        }
    } else {
        state.ownership.set_unclaimed();
    }
    Ok(())
}

async fn maybe_refresh_unclaimed_state(state: &AppState) {
    if !state.ownership.is_unclaimed() {
        return;
    }
    if let Err(err) = refresh_ownership_state(state, true).await {
        state.ownership.set_error(err.to_string());
    }
}

async fn load_owner_seed_material_with_revalidation(
    state: &AppState,
) -> Result<OwnerSeedMaterial, OwnershipError> {
    let material = load_owner_seed_material(state).await?;
    if material.encrypted.is_some() || state.config.owner_ciphertext_backend != "kbs-resource" {
        return Ok(material);
    }

    refresh_ownership_state(state, true).await?;
    load_owner_seed_material(state).await
}

async fn apply_kbs_owner_seed_update(
    state: &AppState,
    resource_path: &str,
    update: EscrowValueUpdate<'_>,
) -> Result<bool, OwnershipError> {
    match update {
        EscrowValueUpdate::Keep => Ok(false),
        EscrowValueUpdate::Remove => {
            kbs::delete_kbs_workload_resource(state, resource_path).await?;
            Ok(true)
        }
        EscrowValueUpdate::Set(bytes) => {
            kbs::put_kbs_workload_resource(state, resource_path, bytes).await?;
            Ok(true)
        }
    }
}

async fn restore_kbs_owner_seed_resource(
    state: &AppState,
    resource_path: &str,
    previous: Option<&[u8]>,
) -> Result<(), OwnershipError> {
    match previous {
        Some(bytes) => kbs::put_kbs_workload_resource(state, resource_path, bytes).await,
        None => kbs::delete_kbs_workload_resource(state, resource_path).await,
    }
}

async fn update_owner_seed_material(
    state: &AppState,
    encrypted: EscrowValueUpdate<'_>,
    sealed: EscrowValueUpdate<'_>,
) -> Result<(), OwnershipError> {
    match state.config.owner_ciphertext_backend.as_str() {
        "filesystem" => {
            escrow::update_owner_seed_material_from_files(state, encrypted, sealed).await
        }
        "kubernetes-secret" => escrow::update_owner_seed_material(state, encrypted, sealed).await,
        "kbs-resource" => {
            let previous = load_owner_seed_material(state).await?;
            let encrypted_changed = apply_kbs_owner_seed_update(
                state,
                &state.config.owner_seed_encrypted_kbs_path,
                encrypted,
            )
            .await?;

            if let Err(err) =
                apply_kbs_owner_seed_update(state, &state.config.owner_seed_sealed_kbs_path, sealed)
                    .await
            {
                if encrypted_changed {
                    if let Err(rollback_err) = restore_kbs_owner_seed_resource(
                        state,
                        &state.config.owner_seed_encrypted_kbs_path,
                        previous.encrypted.as_deref(),
                    )
                    .await
                    {
                        return Err(OwnershipError::Store(format!(
                            "owner_seed_update_failed:{err}; rollback_failed:{rollback_err}"
                        )));
                    }
                }

                return Err(OwnershipError::Store(format!(
                    "owner_seed_update_failed:{err}"
                )));
            }
            Ok(())
        }
        other => Err(OwnershipError::Store(format!(
            "unsupported_owner_ciphertext_backend:{other}"
        ))),
    }
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// GET /health
pub async fn health(State(state): State<AppState>) -> Response {
    let (code, body) = state.ownership.health_status();
    json_response(code, &body)
}

/// GET /status, GET /.well-known/confidential/status
pub async fn status(State(state): State<AppState>) -> Response {
    if !state.ownership.requires_manual_unlock() {
        return json_response(404, &json!({"error": "not_found"}));
    }
    maybe_refresh_unclaimed_state(&state).await;
    let mut body = state.ownership.state_json();
    let identity = fetch_ownership_identity(&state).await;
    body["instance_id"] = json!(state.config.instance_id);
    body["ciphertext_backend"] = json!(state.config.owner_ciphertext_backend);
    body["tenant_id"] = json!(identity.tenant_id);
    body["claims_instance_id"] = json!(identity.instance_id);
    body["bootstrap_owner_pubkey_hash"] = json!(identity.bootstrap_owner_pubkey_hash);
    body["tenant_instance_identity_hash"] = json!(identity.tenant_instance_identity_hash);
    body["claims_verified"] = json!(identity.claims_verified);
    body["claims_error"] = json!(identity.claims_error);
    json_response(200, &body)
}

/// GET /v1/attestation/info
pub async fn attestation_info(State(state): State<AppState>) -> Response {
    let config = &state.config;
    let payload = json!({
        "version": "1",
        "timestamp": utc_now(),
        "attestation_type": config.attestation_profile,
        "runtime_class": config.attestation_runtime_class,
        "evidence_endpoint": "/v1/attestation?nonce=<base64-random>",
        "nonce_encoding": "base64",
        "policy": build_policy_metadata(config),
        "endorsements": build_endorsement_metadata(config),
        "trust": {
            "authoritative_identity_source": "attested_claims",
            "operational_identity_sources": [],
        },
    });
    json_response(200, &payload)
}

/// GET /v1/attestation?nonce=<b64>
pub async fn attestation(
    State(state): State<AppState>,
    Query(query): Query<AttestationQuery>,
) -> Response {
    let nonce = query.nonce.or(query.runtime_data);

    // Validate nonce presence
    let nonce = match nonce {
        Some(n) if !n.is_empty() => n,
        _ => {
            return json_response(
                400,
                &json!({
                    "error": "nonce_required",
                    "detail": "Provide nonce via query parameter '?nonce=<base64>' (or '?runtime_data=<base64>').",
                    "timestamp": utc_now(),
                }),
            );
        }
    };

    // Validate nonce is valid base64
    if !attestation::nonce_is_valid_b64(&nonce) {
        return json_response(
            400,
            &json!({
                "error": "nonce_invalid",
                "detail": "nonce must be base64/url-safe-base64 encoded and <= 4096 chars",
                "timestamp": utc_now(),
            }),
        );
    }

    // Fetch evidence from AA agent
    let encoded_nonce =
        percent_encoding::percent_encode(nonce.as_bytes(), percent_encoding::NON_ALPHANUMERIC)
            .to_string();
    let evidence_url = format!(
        "{}?runtime_data={}",
        state.config.aa_evidence_url, encoded_nonce
    );

    let evidence_result = state
        .http_client
        .get(&evidence_url)
        .header("Accept", "application/json")
        .timeout(std::time::Duration::from_secs(15))
        .send()
        .await;

    let (raw_bytes, content_type, upstream_status) = match evidence_result {
        Ok(resp) => {
            let status = resp.status().as_u16();
            let ct = resp
                .headers()
                .get("content-type")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("application/octet-stream")
                .to_string();

            if !resp.status().is_success() {
                let error_body = resp.text().await.unwrap_or_default();
                return json_response(
                    502,
                    &json!({
                        "error": "attestation-agent-http-error",
                        "upstream_status": status,
                        "upstream_body": error_body,
                        "nonce": nonce,
                        "aa_evidence_url": evidence_url,
                        "timestamp": utc_now(),
                    }),
                );
            }

            match resp.bytes().await {
                Ok(b) => (b.to_vec(), ct, status),
                Err(e) => {
                    return json_response(
                        502,
                        &json!({
                            "error": "attestation-agent-http-error",
                            "detail": e.to_string(),
                            "nonce": nonce,
                            "aa_evidence_url": evidence_url,
                            "timestamp": utc_now(),
                        }),
                    );
                }
            }
        }
        Err(e) => {
            // Check if it's a status error
            if let Some(status) = e.status() {
                return json_response(
                    502,
                    &json!({
                        "error": "attestation-agent-http-error",
                        "upstream_status": status.as_u16(),
                        "upstream_body": e.to_string(),
                        "nonce": nonce,
                        "aa_evidence_url": evidence_url,
                        "timestamp": utc_now(),
                    }),
                );
            }
            return json_response(
                502,
                &json!({
                    "error": "attestation-agent-unreachable",
                    "detail": e.to_string(),
                    "nonce": nonce,
                    "aa_evidence_url": evidence_url,
                    "timestamp": utc_now(),
                }),
            );
        }
    };

    // Parse evidence as JSON (if valid)
    let evidence_json: Option<Value> = std::str::from_utf8(&raw_bytes)
        .ok()
        .and_then(|s| serde_json::from_str(s).ok())
        .filter(|v: &Value| v.is_object());

    // Base64 encode raw evidence
    let evidence_payload_b64 =
        base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &raw_bytes);

    let mut claims = json!({});
    let mut token_claims = json!({
        "claims_root": null,
        "measurement": null,
        "error": null,
    });
    let mut token_measurement_mismatch = false;

    if let Some(ref ej) = evidence_json {
        // Fetch KBS token claims
        token_claims = attestation::fetch_kbs_token_claims(&state).await;

        // Extract claims
        let supplemental = token_claims.get("claims_root").filter(|v| v.is_object());
        claims = attestation::extract_claims(
            ej,
            supplemental,
            &state.config.attestation_profile,
            &state.config.attestation_workload_container,
        );

        // Check for measurement mismatch
        let evidence_measurement = claims.get("measurement").and_then(|v| v.as_str());
        let token_measurement = token_claims.get("measurement").and_then(|v| v.as_str());
        let source = claims.get("source").and_then(|v| v.as_str());

        if source == Some("aa_token")
            && evidence_measurement.is_some()
            && token_measurement.is_some()
            && evidence_measurement != token_measurement
        {
            token_measurement_mismatch = true;
            claims["source"] = json!("none");
            claims["workload"] = json!({
                "container_name": null,
                "image_reference_attested": null,
                "image_digest_attested": null,
                "namespace": null,
                "service_account": null,
                "init_data_hash": null,
            });
        }
    }

    // Build identity
    let workload = claims.get("workload").cloned().unwrap_or(json!({}));
    let full_identity = json!({
        "attested": {
            "image_reference": workload.get("image_reference_attested"),
            "image_digest": workload.get("image_digest_attested"),
            "namespace": workload.get("namespace"),
            "service_account": workload.get("service_account"),
            "init_data_hash": workload.get("init_data_hash"),
            "source": claims.get("source"),
        },
        "configured": {
            "image_reference": or_null(&state.config.attestation_workload_image),
            "image_digest": attestation::digest_from_image_ref(&state.config.attestation_workload_image),
        },
    });

    let identity = json!({
        "attested": full_identity.get("attested"),
    });

    let server_verification = build_server_verification(
        &full_identity,
        &claims,
        &Some(nonce.clone()),
        &state.config.attestation_policy_sha256,
    );

    // Build claims_meta matching Python exactly
    let evidence_measurement = claims.get("measurement").and_then(|v| v.as_str());
    let token_measurement_val = token_claims.get("measurement").and_then(|v| v.as_str());
    let aa_token_measurement_matches_evidence = match (evidence_measurement, token_measurement_val)
    {
        (Some(em), Some(tm)) => Value::Bool(em == tm),
        _ => Value::Null,
    };

    let payload = json!({
        "version": "1",
        "timestamp": utc_now(),
        "attestation_type": state.config.attestation_profile,
        "runtime_class": state.config.attestation_runtime_class,
        "nonce": nonce,
        "evidence": {
            "format": if evidence_json.is_some() { "coco-attestation-report" } else { "opaque" },
            "payload_b64": evidence_payload_b64,
            "json": evidence_json,
            "content_type": content_type,
            "upstream_status": upstream_status,
        },
        "endorsements": build_endorsement_metadata(&state.config),
        "claims": claims,
        "claims_meta": {
            "aa_token_error": token_claims.get("error"),
            "aa_token_measurement": token_claims.get("measurement"),
            "aa_token_measurement_matches_evidence": aa_token_measurement_matches_evidence,
            "aa_token_measurement_mismatch": token_measurement_mismatch,
        },
        "identity": identity,
        "server_verification": server_verification,
        "policy": build_policy_metadata(&state.config),
    });

    json_response(200, &payload)
}

/// GET /cdh/resource/{*path}
pub async fn cdh_resource(State(state): State<AppState>, Path(path): Path<String>) -> Response {
    let cache_key = path.trim_start_matches('/');

    match kbs::fetch_kbs_resource(&state, cache_key).await {
        Ok((body, content_type, status)) => bytes_response(status, body, &content_type),
        Err((_status, error_json)) => json_response(502, &error_json),
    }
}

pub async fn initialize_ownership_state(state: &AppState) {
    if !(state.ownership.is_password_mode() || state.ownership.is_auto_unlock_mode()) {
        return;
    }

    for attempt in 0..OWNER_SEED_STARTUP_RECHECK_ATTEMPTS {
        match refresh_ownership_state(state, attempt > 0).await {
            Ok(()) => {
                if !state.ownership.is_unclaimed() {
                    return;
                }
                if state.config.owner_ciphertext_backend != "kbs-resource"
                    || attempt + 1 == OWNER_SEED_STARTUP_RECHECK_ATTEMPTS
                {
                    return;
                }
                tokio::time::sleep(std::time::Duration::from_millis(
                    OWNER_SEED_STARTUP_RECHECK_DELAY_MS,
                ))
                .await;
            }
            Err(err) => {
                if state.config.owner_ciphertext_backend == "kbs-resource"
                    && attempt + 1 < OWNER_SEED_STARTUP_RECHECK_ATTEMPTS
                {
                    tokio::time::sleep(std::time::Duration::from_millis(
                        OWNER_SEED_STARTUP_RECHECK_DELAY_MS,
                    ))
                    .await;
                    continue;
                }
                state.ownership.set_error(err.to_string());
                return;
            }
        }
    }
}

pub fn spawn_auto_unlock_if_needed(state: AppState) {
    if !state.ownership.is_auto_unlock_mode() || !state.ownership.auto_unlock_enabled() {
        return;
    }

    tokio::spawn(async move {
        // Delay SEV ioctls until the AA token path has completed at least once.
        let _ = attestation::fetch_kbs_token_claims(&state).await;
        let material = match load_owner_seed_material(&state).await {
            Ok(material) => material,
            Err(err) => {
                state.ownership.set_error(err.to_string());
                return;
            }
        };
        let sealed = match material.sealed {
            Some(sealed) => sealed,
            None => {
                state.ownership.set_locked();
                return;
            }
        };
        let wrap_key = match state
            .ownership
            .derive_sealing_wrap_key(&state.config.instance_id)
        {
            Ok(key) => key,
            Err(_) => {
                state.ownership.set_locked();
                return;
            }
        };
        let owner_seed = match state.ownership.decrypt_owner_seed(&sealed, &wrap_key) {
            Ok(seed) => seed,
            Err(_) => {
                state.ownership.set_locked();
                return;
            }
        };

        match unlock_owner_seed_material(&state, &owner_seed).await {
            Ok(warning) => emit_signed_owner_audit_event(
                &state,
                &owner_seed,
                "auto_unlock_resumed",
                json!({
                    "auto_unlock_enabled": true,
                    "warning": warning,
                }),
            ),
            Err(err) => state.ownership.set_error(err.to_string()),
        }
    });
}

/// POST /unlock, POST /.well-known/confidential/unlock.
pub async fn unlock(State(state): State<AppState>, Json(payload): Json<UnlockRequest>) -> Response {
    let mut password = Zeroizing::new(payload.password.into_bytes());

    if !state.ownership.requires_manual_unlock() {
        return json_response(404, &json!({"error": "not_found"}));
    }
    maybe_refresh_unclaimed_state(&state).await;
    if state.ownership.is_unclaimed() {
        return json_response(409, &json!({"error": "unclaimed", "state": "unclaimed"}));
    }

    if password.is_empty() {
        return json_response(400, &json!({"error": "password_required"}));
    }

    if let Err(err) = state.ownership.begin_unlock_attempt() {
        return match err {
            OwnershipError::RateLimited => {
                json_response(429, &json!({"error": "rate_limited", "retry_after": 60}))
            }
            OwnershipError::NotLocked => {
                let current_state = state
                    .ownership
                    .state_json()
                    .get("state")
                    .and_then(Value::as_str)
                    .unwrap_or("unknown")
                    .to_string();
                json_response(409, &json!({"error": "not_locked", "state": current_state}))
            }
            _ => json_response(
                500,
                &json!({"error": "unlock_failed", "detail": err.to_string(), "state": "error"}),
            ),
        };
    }

    if state.config.instance_id.is_empty() {
        state.ownership.set_error("configuration_error");
        return json_response(
            500,
            &json!({"error": "configuration_error", "state": "error"}),
        );
    }

    if state.ownership.is_password_mode() || state.ownership.is_auto_unlock_mode() {
        unlock_password_mode(&state, &mut password).await
    } else {
        unlock_level1_mode(&state, &mut password)
    }
}

fn unlock_level1_mode(state: &AppState, password: &mut Zeroizing<Vec<u8>>) -> Response {
    let key = match state
        .ownership
        .derive_luks_key(password, &state.config.instance_id)
    {
        Ok(key) => key,
        Err(err) => {
            state.ownership.set_error(err.to_string());
            return json_response(
                500,
                &json!({"error": "unlock_failed", "detail": err.to_string(), "state": "error"}),
            );
        }
    };

    if let Err(err) = state.ownership.write_handoff_key(&key) {
        state.ownership.set_error(err.to_string());
        return json_response(
            500,
            &json!({"error": "unlock_failed", "detail": err.to_string(), "state": "error"}),
        );
    }

    let outcome = match state
        .ownership
        .poll_handoff_result(unlock_poll_timeout_seconds())
    {
        Ok(outcome) => outcome,
        Err(err) => {
            state.ownership.set_error(err.to_string());
            return json_response(
                500,
                &json!({"error": "unlock_failed", "detail": err.to_string(), "state": "error"}),
            );
        }
    };

    render_level1_handoff_outcome(state, outcome)
}

async fn unlock_password_mode(state: &AppState, password: &mut Zeroizing<Vec<u8>>) -> Response {
    let wrap_key = match state
        .ownership
        .derive_password_wrap_key(password, &state.config.instance_id)
    {
        Ok(key) => key,
        Err(err) => {
            state.ownership.set_error(err.to_string());
            return json_response(
                500,
                &json!({"error": "unlock_failed", "detail": err.to_string(), "state": "error"}),
            );
        }
    };

    let owner_seed_resource = match load_owner_seed_material_with_revalidation(state).await {
        Ok(material) => match material.encrypted {
            Some(resource) => resource,
            None => {
                state.ownership.set_unclaimed();
                return json_response(409, &json!({"error": "unclaimed", "state": "unclaimed"}));
            }
        },
        Err(err) => {
            state.ownership.set_error(err.to_string());
            return json_response(
                500,
                &json!({"error": "unlock_failed", "detail": err.to_string(), "state": "error"}),
            );
        }
    };

    let owner_seed = match state
        .ownership
        .decrypt_owner_seed(&owner_seed_resource, &wrap_key)
    {
        Ok(owner_seed) => owner_seed,
        Err(OwnershipError::WrongPassword) => {
            state.ownership.set_locked_after_retry();
            return json_response(200, &json!({"error": "wrong_password", "state": "locked"}));
        }
        Err(err) => {
            state.ownership.set_error(err.to_string());
            return json_response(
                500,
                &json!({"error": "unlock_failed", "detail": err.to_string(), "state": "error"}),
            );
        }
    };

    match unlock_owner_seed_material(state, &owner_seed).await {
        Ok(warning) => {
            emit_signed_owner_audit_event(
                state,
                &owner_seed,
                "unlock",
                json!({
                    "auto_unlock_enabled": state.ownership.auto_unlock_enabled(),
                    "warning": warning.clone(),
                }),
            );
            match warning {
                None => json_response(200, &json!({"state": "unlocked"})),
                Some(warning) => {
                    json_response(200, &json!({"state": "unlocked", "warning": warning}))
                }
            }
        }
        Err(OwnershipError::WrongPassword) => {
            state.ownership.set_locked_after_retry();
            json_response(200, &json!({"error": "wrong_password", "state": "locked"}))
        }
        Err(err) => {
            state.ownership.set_error(err.to_string());
            let detail = match &err {
                OwnershipError::Store(detail) => detail.clone(),
                _ => err.to_string(),
            };
            json_response(
                500,
                &json!({"error": "unlock_failed", "detail": detail, "state": "error"}),
            )
        }
    }
}

fn render_level1_handoff_outcome(state: &AppState, outcome: HandoffOutcome) -> Response {
    match outcome {
        HandoffOutcome::Unlocked => {
            state.ownership.set_unlocked();
            json_response(200, &json!({"state": "unlocked"}))
        }
        HandoffOutcome::WrongPassword => {
            if let Err(err) = state.ownership.clear_handoff_retry_files() {
                state.ownership.set_error(err.to_string());
                return json_response(
                    500,
                    &json!({"error": "unlock_failed", "detail": err.to_string(), "state": "error"}),
                );
            }
            state.ownership.set_locked_after_retry();
            json_response(200, &json!({"error": "wrong_password", "state": "locked"}))
        }
        HandoffOutcome::Fatal(message) => {
            state.ownership.set_error(message.clone());
            json_response(
                500,
                &json!({"error": "unlock_failed", "detail": message, "state": "error"}),
            )
        }
        HandoffOutcome::Timeout => {
            state.ownership.set_error("unlock_timeout");
            json_response(500, &json!({"error": "unlock_timeout", "state": "error"}))
        }
    }
}

async fn maybe_refresh_auto_unlock_seal(
    state: &AppState,
    owner_seed: &[u8; 32],
) -> Result<Option<String>, OwnershipError> {
    if !state.ownership.is_auto_unlock_mode() || !state.ownership.auto_unlock_enabled() {
        return Ok(None);
    }
    let wrap_key = state
        .ownership
        .derive_sealing_wrap_key(&state.config.instance_id)?;
    let sealed = state.ownership.encrypt_owner_seed(owner_seed, &wrap_key)?;
    update_owner_seed_material(
        state,
        EscrowValueUpdate::Keep,
        EscrowValueUpdate::Set(&sealed),
    )
    .await
    .map(|_| None)
    .or_else(|_| Ok(Some("auto_unlock_reseal_failed".to_string())))
}

async fn unlock_owner_seed_material(
    state: &AppState,
    owner_seed: &[u8; 32],
) -> Result<Option<String>, OwnershipError> {
    let owner_keys = Zeroizing::new(state.ownership.derive_owner_volume_keys(owner_seed)?);
    state.ownership.write_password_handoff_keys(&owner_keys)?;
    let outcome = state
        .ownership
        .poll_password_handoff_result(unlock_poll_timeout_seconds())?;
    render_password_handoff_outcome(state, outcome, owner_seed).await
}

async fn finalize_rewrapped_owner_seed(
    state: &AppState,
    owner_seed: &[u8; 32],
) -> Result<Option<String>, OwnershipError> {
    if state.ownership.is_unlocked() {
        state.ownership.clear_password_handoff_retry_files()?;
        state.ownership.set_unlocked();
        return maybe_refresh_auto_unlock_seal(state, owner_seed).await;
    }
    unlock_owner_seed_material(state, owner_seed).await
}

async fn render_password_handoff_outcome(
    state: &AppState,
    outcome: HandoffOutcome,
    owner_seed: &[u8; 32],
) -> Result<Option<String>, OwnershipError> {
    match outcome {
        HandoffOutcome::Unlocked => {
            state.ownership.set_unlocked();
            maybe_refresh_auto_unlock_seal(state, owner_seed).await
        }
        HandoffOutcome::WrongPassword => Err(OwnershipError::WrongPassword),
        HandoffOutcome::Fatal(message) => {
            let detail = match message.split_once(':') {
                Some((slot, reason))
                    if slot == SIGNAL_APP_DATA_SLOT || slot == SIGNAL_TLS_DATA_SLOT =>
                {
                    format!("{slot}_unlock_failed:{reason}")
                }
                _ => message,
            };
            Err(OwnershipError::Store(detail))
        }
        HandoffOutcome::Timeout => Err(OwnershipError::Timeout),
    }
}

#[cfg(test)]
fn unlock_poll_timeout_seconds() -> u64 {
    1
}

#[cfg(not(test))]
fn unlock_poll_timeout_seconds() -> u64 {
    crate::ownership::HANDOFF_DEFAULT_TIMEOUT_SECONDS
}

pub async fn bootstrap_challenge(State(state): State<AppState>) -> Response {
    if !state.ownership.requires_manual_unlock() {
        return json_response(404, &json!({"error": "not_found"}));
    }
    maybe_refresh_unclaimed_state(&state).await;
    if !state.ownership.is_unclaimed() {
        return json_response(
            409,
            &json!({"error": "already_claimed", "state": state.ownership.state_json()}),
        );
    }

    let identity = fetch_ownership_identity(&state).await;
    if identity.bootstrap_owner_pubkey_hash.is_none() {
        return json_response(
            409,
            &json!({"error": "bootstrap_owner_pubkey_hash_missing", "claims_error": identity.claims_error}),
        );
    }

    let mut challenge_bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut challenge_bytes);
    let challenge_b64 = URL_SAFE_NO_PAD.encode(challenge_bytes);
    let expires_at = Instant::now()
        + std::time::Duration::from_secs(state.config.ownership_challenge_ttl_seconds as u64);
    {
        let mut slot = state
            .bootstrap_challenge
            .lock()
            .expect("bootstrap challenge lock poisoned");
        *slot = Some(BootstrapChallenge {
            challenge_b64: challenge_b64.clone(),
            expires_at,
        });
    }

    json_response(
        200,
        &json!({
            "instance_id": state.config.instance_id,
            "challenge": challenge_b64,
            "nonce": challenge_b64,
            "expires_in_seconds": state.config.ownership_challenge_ttl_seconds,
        }),
    )
}

pub async fn bootstrap_claim(
    State(state): State<AppState>,
    Json(payload): Json<BootstrapClaimRequest>,
) -> Response {
    if !state.ownership.requires_manual_unlock() {
        return json_response(404, &json!({"error": "not_found"}));
    }
    maybe_refresh_unclaimed_state(&state).await;
    if !state.ownership.is_unclaimed() {
        return json_response(
            409,
            &json!({"error": "already_claimed", "state": state.ownership.state_json()}),
        );
    }
    if payload.password.trim().is_empty() {
        return json_response(400, &json!({"error": "password_required"}));
    }

    let challenge_ok = {
        let slot = state
            .bootstrap_challenge
            .lock()
            .expect("bootstrap challenge lock poisoned");
        match slot.as_ref() {
            Some(challenge)
                if challenge.challenge_b64 == payload.challenge
                    && Instant::now() < challenge.expires_at =>
            {
                true
            }
            _ => false,
        }
    };
    if !challenge_ok {
        return json_response(400, &json!({"error": "bootstrap_challenge_invalid"}));
    }

    let identity = fetch_ownership_identity(&state).await;
    let expected_hash = match identity.bootstrap_owner_pubkey_hash {
        Some(hash) => hash,
        None => {
            return json_response(
                409,
                &json!({"error": "bootstrap_owner_pubkey_hash_missing", "claims_error": identity.claims_error}),
            )
        }
    };

    if let Err(err) = validate_bootstrap_signature(
        &payload.challenge,
        &payload.bootstrap_pubkey,
        &payload.signature,
        &expected_hash,
    ) {
        return json_response(
            401,
            &json!({"error": "bootstrap_signature_invalid", "detail": err.to_string()}),
        );
    }

    let mut password = Zeroizing::new(payload.password.into_bytes());
    let wrap_key = match state
        .ownership
        .derive_password_wrap_key(&mut password, &state.config.instance_id)
    {
        Ok(key) => key,
        Err(err) => {
            return json_response(
                500,
                &json!({"error": "claim_failed", "detail": err.to_string()}),
            )
        }
    };

    let mut owner_seed = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut owner_seed);
    let owner_seed = Zeroizing::new(owner_seed);
    let encrypted = match state.ownership.encrypt_owner_seed(&owner_seed, &wrap_key) {
        Ok(encrypted) => encrypted,
        Err(err) => {
            return json_response(
                500,
                &json!({"error": "claim_failed", "detail": err.to_string()}),
            )
        }
    };

    if let Err(err) = update_owner_seed_material(
        &state,
        EscrowValueUpdate::Set(&encrypted),
        EscrowValueUpdate::Remove,
    )
    .await
    {
        return json_response(
            500,
            &json!({"error": "claim_failed", "detail": err.to_string()}),
        );
    }
    state.ownership.set_auto_unlock_enabled(false);
    state.ownership.set_locked();

    match unlock_owner_seed_material(&state, &owner_seed).await {
        Ok(warning) => {
            let mnemonic = state
                .ownership
                .owner_seed_mnemonic(&owner_seed)
                .unwrap_or_default();
            let owner_pubkey = state
                .ownership
                .owner_public_key_b64url(&owner_seed)
                .unwrap_or_default();
            emit_signed_owner_audit_event(
                &state,
                &owner_seed,
                "claim",
                json!({
                    "auto_unlock_enabled": false,
                    "owner_public_key": owner_pubkey.clone(),
                    "warning": warning.clone(),
                }),
            );
            {
                let mut slot = state
                    .bootstrap_challenge
                    .lock()
                    .expect("bootstrap challenge lock poisoned");
                *slot = None;
            }
            json_response(
                200,
                &json!({
                    "status": "CLAIM_ACCEPTED",
                    "state": "unlocked",
                    "owner_public_key": owner_pubkey,
                    "owner_seed_mnemonic": mnemonic,
                    "warning": warning,
                }),
            )
        }
        Err(err) => {
            state.ownership.set_error(err.to_string());
            json_response(
                500,
                &json!({"error": "claim_failed", "detail": err.to_string(), "state": "error"}),
            )
        }
    }
}

pub async fn change_password(
    State(state): State<AppState>,
    Json(payload): Json<ChangePasswordRequest>,
) -> Response {
    let mut old_password = Zeroizing::new(payload.old_password.into_bytes());
    let mut new_password = Zeroizing::new(payload.new_password.into_bytes());
    if old_password.is_empty() || new_password.is_empty() {
        return json_response(400, &json!({"error": "password_required"}));
    }

    let material = match load_owner_seed_material_with_revalidation(&state).await {
        Ok(material) if material.encrypted.is_some() => material,
        Ok(_) => return json_response(409, &json!({"error": "unclaimed", "state": "unclaimed"})),
        Err(err) => {
            return json_response(
                500,
                &json!({"error": "change_password_failed", "detail": err.to_string()}),
            )
        }
    };

    let old_wrap_key = match state
        .ownership
        .derive_password_wrap_key(&mut old_password, &state.config.instance_id)
    {
        Ok(key) => key,
        Err(err) => {
            return json_response(
                500,
                &json!({"error": "change_password_failed", "detail": err.to_string()}),
            )
        }
    };
    let owner_seed = match state.ownership.decrypt_owner_seed(
        material.encrypted.as_ref().expect("encrypted present"),
        &old_wrap_key,
    ) {
        Ok(seed) => seed,
        Err(OwnershipError::WrongPassword) => {
            return json_response(401, &json!({"error": "wrong_password"}))
        }
        Err(err) => {
            return json_response(
                500,
                &json!({"error": "change_password_failed", "detail": err.to_string()}),
            )
        }
    };
    let new_wrap_key = match state
        .ownership
        .derive_password_wrap_key(&mut new_password, &state.config.instance_id)
    {
        Ok(key) => key,
        Err(err) => {
            return json_response(
                500,
                &json!({"error": "change_password_failed", "detail": err.to_string()}),
            )
        }
    };
    let encrypted = match state
        .ownership
        .encrypt_owner_seed(&owner_seed, &new_wrap_key)
    {
        Ok(encrypted) => encrypted,
        Err(err) => {
            return json_response(
                500,
                &json!({"error": "change_password_failed", "detail": err.to_string()}),
            )
        }
    };

    if let Err(err) = update_owner_seed_material(
        &state,
        EscrowValueUpdate::Set(&encrypted),
        EscrowValueUpdate::Keep,
    )
    .await
    {
        return json_response(
            500,
            &json!({"error": "change_password_failed", "detail": err.to_string()}),
        );
    }

    emit_signed_owner_audit_event(
        &state,
        &owner_seed,
        "change_password",
        json!({
            "auto_unlock_enabled": state.ownership.auto_unlock_enabled(),
            "owner_public_key": state
                .ownership
                .owner_public_key_b64url(&owner_seed)
                .unwrap_or_default(),
        }),
    );
    json_response(200, &json!({"status": "password_changed"}))
}

pub async fn recover(
    State(state): State<AppState>,
    Json(payload): Json<RecoverRequest>,
) -> Response {
    if payload.new_password.trim().is_empty() || payload.mnemonic.trim().is_empty() {
        return json_response(400, &json!({"error": "mnemonic_and_password_required"}));
    }

    let owner_seed = match state.ownership.owner_seed_from_mnemonic(&payload.mnemonic) {
        Ok(seed) => seed,
        Err(err) => {
            return json_response(
                400,
                &json!({"error": "mnemonic_invalid", "detail": err.to_string()}),
            )
        }
    };
    let mut new_password = Zeroizing::new(payload.new_password.into_bytes());
    let wrap_key = match state
        .ownership
        .derive_password_wrap_key(&mut new_password, &state.config.instance_id)
    {
        Ok(key) => key,
        Err(err) => {
            return json_response(
                500,
                &json!({"error": "recover_failed", "detail": err.to_string()}),
            )
        }
    };
    let encrypted = match state.ownership.encrypt_owner_seed(&owner_seed, &wrap_key) {
        Ok(encrypted) => encrypted,
        Err(err) => {
            return json_response(
                500,
                &json!({"error": "recover_failed", "detail": err.to_string()}),
            )
        }
    };
    if let Err(err) = update_owner_seed_material(
        &state,
        EscrowValueUpdate::Set(&encrypted),
        EscrowValueUpdate::Keep,
    )
    .await
    {
        return json_response(
            500,
            &json!({"error": "recover_failed", "detail": err.to_string()}),
        );
    }

    match finalize_rewrapped_owner_seed(&state, &owner_seed).await {
        Ok(warning) => {
            let owner_pubkey = state
                .ownership
                .owner_public_key_b64url(&owner_seed)
                .unwrap_or_default();
            emit_signed_owner_audit_event(
                &state,
                &owner_seed,
                "recover",
                json!({
                    "auto_unlock_enabled": state.ownership.auto_unlock_enabled(),
                    "owner_public_key": owner_pubkey.clone(),
                    "warning": warning.clone(),
                }),
            );
            json_response(
                200,
                &json!({"status": "recovered", "state": "unlocked", "owner_public_key": owner_pubkey, "warning": warning}),
            )
        }
        Err(err) => {
            state.ownership.set_error(err.to_string());
            json_response(
                500,
                &json!({"error": "recover_failed", "detail": err.to_string(), "state": "error"}),
            )
        }
    }
}

pub async fn enable_auto_unlock(
    State(state): State<AppState>,
    Json(payload): Json<UnlockRequest>,
) -> Response {
    let mut password = Zeroizing::new(payload.password.into_bytes());
    if password.is_empty() {
        return json_response(400, &json!({"error": "password_required"}));
    }
    let material = match load_owner_seed_material_with_revalidation(&state).await {
        Ok(material) if material.encrypted.is_some() => material,
        Ok(_) => return json_response(409, &json!({"error": "unclaimed", "state": "unclaimed"})),
        Err(err) => {
            return json_response(
                500,
                &json!({"error": "enable_auto_unlock_failed", "detail": err.to_string()}),
            )
        }
    };
    let wrap_key = match state
        .ownership
        .derive_password_wrap_key(&mut password, &state.config.instance_id)
    {
        Ok(key) => key,
        Err(err) => {
            return json_response(
                500,
                &json!({"error": "enable_auto_unlock_failed", "detail": err.to_string()}),
            )
        }
    };
    let owner_seed = match state.ownership.decrypt_owner_seed(
        material.encrypted.as_ref().expect("encrypted present"),
        &wrap_key,
    ) {
        Ok(seed) => seed,
        Err(OwnershipError::WrongPassword) => {
            return json_response(401, &json!({"error": "wrong_password"}))
        }
        Err(err) => {
            return json_response(
                500,
                &json!({"error": "enable_auto_unlock_failed", "detail": err.to_string()}),
            )
        }
    };
    let seal_key = match state
        .ownership
        .derive_sealing_wrap_key(&state.config.instance_id)
    {
        Ok(key) => key,
        Err(err) => {
            return json_response(
                500,
                &json!({"error": "enable_auto_unlock_failed", "detail": err.to_string()}),
            )
        }
    };
    let sealed = match state.ownership.encrypt_owner_seed(&owner_seed, &seal_key) {
        Ok(sealed) => sealed,
        Err(err) => {
            return json_response(
                500,
                &json!({"error": "enable_auto_unlock_failed", "detail": err.to_string()}),
            )
        }
    };
    if let Err(err) = update_owner_seed_material(
        &state,
        EscrowValueUpdate::Keep,
        EscrowValueUpdate::Set(&sealed),
    )
    .await
    {
        return json_response(
            500,
            &json!({"error": "enable_auto_unlock_failed", "detail": err.to_string()}),
        );
    }
    state.ownership.set_auto_unlock_enabled(true);
    emit_signed_owner_audit_event(
        &state,
        &owner_seed,
        "enable_auto_unlock",
        json!({
            "auto_unlock_enabled": true,
            "owner_public_key": state
                .ownership
                .owner_public_key_b64url(&owner_seed)
                .unwrap_or_default(),
        }),
    );
    json_response(200, &json!({"status": "auto_unlock_enabled"}))
}

pub async fn disable_auto_unlock(
    State(state): State<AppState>,
    Json(payload): Json<UnlockRequest>,
) -> Response {
    let mut password = Zeroizing::new(payload.password.into_bytes());
    if password.is_empty() {
        return json_response(400, &json!({"error": "password_required"}));
    }
    let material = match load_owner_seed_material_with_revalidation(&state).await {
        Ok(material) if material.encrypted.is_some() => material,
        Ok(_) => return json_response(409, &json!({"error": "unclaimed", "state": "unclaimed"})),
        Err(err) => {
            return json_response(
                500,
                &json!({"error": "disable_auto_unlock_failed", "detail": err.to_string()}),
            )
        }
    };
    let wrap_key = match state
        .ownership
        .derive_password_wrap_key(&mut password, &state.config.instance_id)
    {
        Ok(key) => key,
        Err(err) => {
            return json_response(
                500,
                &json!({"error": "disable_auto_unlock_failed", "detail": err.to_string()}),
            )
        }
    };
    let owner_seed = match state.ownership.decrypt_owner_seed(
        material.encrypted.as_ref().expect("encrypted present"),
        &wrap_key,
    ) {
        Ok(seed) => seed,
        Err(err) => {
            return match err {
                OwnershipError::WrongPassword => {
                    json_response(401, &json!({"error": "wrong_password"}))
                }
                _ => json_response(
                    500,
                    &json!({"error": "disable_auto_unlock_failed", "detail": err.to_string()}),
                ),
            };
        }
    };
    if let Err(err) =
        update_owner_seed_material(&state, EscrowValueUpdate::Keep, EscrowValueUpdate::Remove).await
    {
        return json_response(
            500,
            &json!({"error": "disable_auto_unlock_failed", "detail": err.to_string()}),
        );
    }
    state.ownership.set_auto_unlock_enabled(false);
    emit_signed_owner_audit_event(
        &state,
        &owner_seed,
        "disable_auto_unlock",
        json!({
            "auto_unlock_enabled": false,
            "owner_public_key": state
                .ownership
                .owner_public_key_b64url(&owner_seed)
                .unwrap_or_default(),
        }),
    );
    json_response(200, &json!({"status": "auto_unlock_disabled"}))
}

/// Fallback handler for unmatched routes.
pub async fn not_found(req: axum::extract::Request) -> Response {
    let path = req.uri().path().to_string();
    json_response(
        404,
        &json!({
            "error": "not_found",
            "path": path,
            "supported_paths": ["/health", "/v1/attestation/info", "/v1/attestation", "/status"],
        }),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attestation::AaTokenCache;
    use crate::config::Config;
    use crate::kbs::KbsCacheEntry;
    use crate::ownership::{
        OwnershipGuard, OWNER_SEED_ENVELOPE_VERSION, SIGNAL_APP_DATA_SLOT, SIGNAL_ERROR_FILE,
        SIGNAL_KEY_FILE, SIGNAL_TLS_DATA_SLOT, SIGNAL_UNLOCKED_FILE,
    };
    use aes_gcm::aead::{Aead, KeyInit};
    use aes_gcm::{Aes256Gcm, Nonce};
    use axum::body::Bytes;
    use axum::extract::{Path as AxumPath, State as AxumState};
    use axum::http::StatusCode;
    use axum::response::IntoResponse;
    use axum::routing::{get, put};
    use axum::Router;
    use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD as BASE64_URL_SAFE_NO_PAD;
    use ed25519_dalek::{Signer, SigningKey};
    use jsonwebtoken::jwk::{
        AlgorithmParameters, CommonParameters, Jwk, KeyAlgorithm, OctetKeyParameters, OctetKeyType,
    };
    use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
    use serde_json::json;
    use std::collections::HashMap;
    use std::fs;
    use std::net::SocketAddr;
    use std::path::{Path, PathBuf};
    use std::sync::{Arc, Mutex};
    use std::time::{SystemTime, UNIX_EPOCH};
    use tokio::sync::RwLock;
    use tokio::time::{sleep, Duration};

    #[test]
    fn missing_owner_seed_resource_accepts_only_404() {
        assert!(is_missing_owner_seed_resource(
            &json!({"upstream_status": 404})
        ));
        assert!(!is_missing_owner_seed_resource(
            &json!({"upstream_status": 500})
        ));
        assert!(!is_missing_owner_seed_resource(
            &json!({"upstream_status": 401})
        ));
    }

    #[test]
    fn optional_sealed_owner_seed_resource_accepts_only_404() {
        assert!(is_optional_sealed_owner_seed_resource_missing(&json!({
            "upstream_status": 404
        })));
        assert!(!is_optional_sealed_owner_seed_resource_missing(&json!({
            "upstream_status": 500
        })));
        assert!(!is_optional_sealed_owner_seed_resource_missing(&json!({
            "upstream_status": 401
        })));
    }

    #[tokio::test]
    async fn initialize_ownership_state_retries_transient_unclaimed_reads() {
        let signal_dir = test_signal_dir("initialize-ownership-state-retries");
        let owner_seed = [0x55; 32];
        let mut resources = HashMap::new();
        resources.insert(
            "default/instance-test-01-owner/seed-encrypted".to_string(),
            owner_seed_envelope_json(owner_seed, "correct-password", "instance-test-01"),
        );
        let mut sequences = HashMap::new();
        sequences.insert(
            "default/instance-test-01-owner/seed-encrypted".to_string(),
            vec![500],
        );
        let api_server = spawn_test_api_server_with_sequences(
            owner_escrow_secret_json(None, None),
            json!({}),
            resources,
            sequences,
        )
        .await;
        let state = build_state_with_mode(
            &signal_dir.path,
            "password",
            api_server.base_url(),
            Some("default/instance-test-01-owner/seed-encrypted".to_string()),
        );

        initialize_ownership_state(&state).await;

        assert_eq!(
            state
                .ownership
                .state_json()
                .get("state")
                .and_then(Value::as_str),
            Some("locked")
        );
    }

    #[tokio::test]
    async fn initialize_ownership_state_keeps_unclaimed_when_cdh_reports_500_for_missing_seed() {
        let signal_dir = test_signal_dir("initialize-ownership-state-unclaimed-after-cdh-500");
        let mut sequences = HashMap::new();
        sequences.insert(
            "default/instance-test-01-owner/seed-encrypted".to_string(),
            vec![500],
        );
        let api_server = spawn_test_api_server_with_sequences(
            owner_escrow_secret_json(None, None),
            json!({}),
            HashMap::new(),
            sequences,
        )
        .await;
        let state = build_state_with_mode(
            &signal_dir.path,
            "password",
            api_server.base_url(),
            Some("default/instance-test-01-owner/seed-encrypted".to_string()),
        );

        initialize_ownership_state(&state).await;

        assert_eq!(
            state
                .ownership
                .state_json()
                .get("state")
                .and_then(Value::as_str),
            Some("unclaimed")
        );
    }

    #[tokio::test]
    async fn unlock_handoff_success() {
        let signal_dir = test_signal_dir("unlock-success");
        let state = build_state(&signal_dir.path);
        fs::write(
            signal_dir.path.join(SIGNAL_UNLOCKED_FILE),
            "unlocked_at=now",
        )
        .expect("write unlocked sentinel");

        let response = unlock(
            State(state.clone()),
            Json(UnlockRequest {
                password: "correct-password".to_string(),
            }),
        )
        .await;

        assert_eq!(response.status().as_u16(), 200);
        assert_eq!(read_json(response).await, json!({ "state": "unlocked" }));
        assert_eq!(
            state
                .ownership
                .state_json()
                .get("state")
                .and_then(Value::as_str),
            Some("unlocked")
        );
    }

    #[tokio::test]
    async fn unlock_error_and_rate_limit_paths() {
        let wrong_signal_dir = test_signal_dir("unlock-error-paths-wrong");
        let wrong_state = build_state(&wrong_signal_dir.path);

        fs::write(
            wrong_signal_dir.path.join(SIGNAL_ERROR_FILE),
            "wrong_password\n",
        )
        .expect("write wrong_password sentinel");
        let wrong_password = unlock(
            State(wrong_state.clone()),
            Json(UnlockRequest {
                password: "bad-password".to_string(),
            }),
        )
        .await;
        assert_eq!(wrong_password.status().as_u16(), 200);
        assert_eq!(
            read_json(wrong_password).await,
            json!({ "error": "wrong_password", "state": "locked" })
        );
        assert!(!wrong_signal_dir.path.join(SIGNAL_KEY_FILE).exists());
        assert!(!wrong_signal_dir.path.join(SIGNAL_ERROR_FILE).exists());
        assert_eq!(
            wrong_state
                .ownership
                .state_json()
                .get("state")
                .and_then(Value::as_str),
            Some("locked")
        );

        let fatal_signal_dir = test_signal_dir("unlock-error-paths-fatal");
        let fatal_state = build_state(&fatal_signal_dir.path);
        fs::write(
            fatal_signal_dir.path.join(SIGNAL_ERROR_FILE),
            "format_failed\n",
        )
        .expect("write fatal sentinel");
        let fatal = unlock(
            State(fatal_state.clone()),
            Json(UnlockRequest {
                password: "password".to_string(),
            }),
        )
        .await;
        assert_eq!(fatal.status().as_u16(), 500);
        assert_eq!(
            read_json(fatal).await,
            json!({ "error": "unlock_failed", "detail": "format_failed", "state": "error" })
        );
        assert_eq!(
            fatal_state
                .ownership
                .state_json()
                .get("state")
                .and_then(Value::as_str),
            Some("error")
        );

        let timeout_signal_dir = test_signal_dir("unlock-error-paths-timeout");
        let timeout_state = build_state(&timeout_signal_dir.path);
        let timeout = unlock(
            State(timeout_state.clone()),
            Json(UnlockRequest {
                password: "password".to_string(),
            }),
        )
        .await;
        assert_eq!(timeout.status().as_u16(), 500);
        assert_eq!(
            read_json(timeout).await,
            json!({ "error": "unlock_timeout", "state": "error" })
        );
        assert_eq!(
            timeout_state
                .ownership
                .state_json()
                .get("state")
                .and_then(Value::as_str),
            Some("error")
        );

        let rate_signal_dir = test_signal_dir("unlock-error-paths-rate-limit");
        let rate_state = build_state(&rate_signal_dir.path);
        for _ in 0..5 {
            fs::write(
                rate_signal_dir.path.join(SIGNAL_ERROR_FILE),
                "wrong_password\n",
            )
            .expect("write retry sentinel");
            let retry = unlock(
                State(rate_state.clone()),
                Json(UnlockRequest {
                    password: "password".to_string(),
                }),
            )
            .await;
            assert_eq!(retry.status().as_u16(), 200);
            assert_eq!(
                read_json(retry).await,
                json!({ "error": "wrong_password", "state": "locked" })
            );
        }

        let rate_limited = unlock(
            State(rate_state),
            Json(UnlockRequest {
                password: "password".to_string(),
            }),
        )
        .await;
        assert_eq!(rate_limited.status().as_u16(), 429);
        assert_eq!(
            read_json(rate_limited).await,
            json!({ "error": "rate_limited", "retry_after": 60 })
        );
    }

    #[tokio::test]
    async fn unlock_password_mode_success() {
        let signal_dir = test_signal_dir("unlock-password-success");
        let owner_seed = [0x21; 32];
        let kbs_server =
            spawn_owner_seed_server(owner_seed, "correct-password", "instance-test-01").await;
        let state = build_state_with_mode(
            &signal_dir.path,
            "password",
            kbs_server.base_url(),
            Some("default/instance-test-01-owner/seed-encrypted".to_string()),
        );

        fs::create_dir_all(signal_dir.path.join(SIGNAL_APP_DATA_SLOT)).expect("create app slot");
        fs::create_dir_all(signal_dir.path.join(SIGNAL_TLS_DATA_SLOT)).expect("create tls slot");
        fs::write(
            signal_dir
                .path
                .join(SIGNAL_APP_DATA_SLOT)
                .join(SIGNAL_UNLOCKED_FILE),
            "unlocked_at=now",
        )
        .expect("write app unlocked sentinel");
        fs::write(
            signal_dir
                .path
                .join(SIGNAL_TLS_DATA_SLOT)
                .join(SIGNAL_UNLOCKED_FILE),
            "unlocked_at=now",
        )
        .expect("write tls unlocked sentinel");

        let response = unlock(
            State(state.clone()),
            Json(UnlockRequest {
                password: "correct-password".to_string(),
            }),
        )
        .await;

        assert_eq!(response.status().as_u16(), 200);
        assert_eq!(read_json(response).await, json!({ "state": "unlocked" }));
        assert!(
            signal_dir
                .path
                .join(SIGNAL_APP_DATA_SLOT)
                .join(SIGNAL_KEY_FILE)
                .exists(),
            "app-data key file should be written"
        );
        assert!(
            signal_dir
                .path
                .join(SIGNAL_TLS_DATA_SLOT)
                .join(SIGNAL_KEY_FILE)
                .exists(),
            "tls-data key file should be written"
        );
    }

    #[tokio::test]
    async fn unlock_password_mode_wrong_password() {
        let signal_dir = test_signal_dir("unlock-password-wrong-password");
        let owner_seed = [0x31; 32];
        let kbs_server =
            spawn_owner_seed_server(owner_seed, "correct-password", "instance-test-01").await;
        let state = build_state_with_mode(
            &signal_dir.path,
            "password",
            kbs_server.base_url(),
            Some("default/instance-test-01-owner/seed-encrypted".to_string()),
        );

        let response = unlock(
            State(state.clone()),
            Json(UnlockRequest {
                password: "bad-password".to_string(),
            }),
        )
        .await;

        assert_eq!(response.status().as_u16(), 200);
        assert_eq!(
            read_json(response).await,
            json!({ "error": "wrong_password", "state": "locked" })
        );
        assert!(
            !signal_dir
                .path
                .join(SIGNAL_APP_DATA_SLOT)
                .join(SIGNAL_KEY_FILE)
                .exists(),
            "password failures must not write app-data key files"
        );
        assert!(
            !signal_dir
                .path
                .join(SIGNAL_TLS_DATA_SLOT)
                .join(SIGNAL_KEY_FILE)
                .exists(),
            "password failures must not write tls-data key files"
        );
    }

    #[tokio::test]
    async fn unlock_password_mode_slot_failure_surfaces_slot_name() {
        let signal_dir = test_signal_dir("unlock-password-slot-failure");
        let owner_seed = [0x41; 32];
        let kbs_server =
            spawn_owner_seed_server(owner_seed, "correct-password", "instance-test-01").await;
        let state = build_state_with_mode(
            &signal_dir.path,
            "password",
            kbs_server.base_url(),
            Some("default/instance-test-01-owner/seed-encrypted".to_string()),
        );

        fs::create_dir_all(signal_dir.path.join(SIGNAL_APP_DATA_SLOT)).expect("create app slot");
        fs::create_dir_all(signal_dir.path.join(SIGNAL_TLS_DATA_SLOT)).expect("create tls slot");
        fs::write(
            signal_dir
                .path
                .join(SIGNAL_APP_DATA_SLOT)
                .join(SIGNAL_ERROR_FILE),
            "mount_failed\n",
        )
        .expect("write slot error");

        let response = unlock(
            State(state),
            Json(UnlockRequest {
                password: "correct-password".to_string(),
            }),
        )
        .await;

        assert_eq!(response.status().as_u16(), 500);
        assert_eq!(
            read_json(response).await,
            json!({
                "error": "unlock_failed",
                "detail": "app-data_unlock_failed:mount_failed",
                "state": "error"
            })
        );
    }

    #[tokio::test]
    async fn bootstrap_claim_persists_encrypted_seed_and_returns_recovery_material() {
        let signal_dir = test_signal_dir("bootstrap-claim");
        mark_password_slots_unlocked(&signal_dir.path);

        let signing_key = SigningKey::from_bytes(&[7u8; 32]);
        let bootstrap_hash = bootstrap_owner_pubkey_hash(&signing_key);
        let api_server = spawn_test_api_server(
            owner_escrow_secret_json(None, None),
            test_identity_claims(&bootstrap_hash),
            HashMap::new(),
        )
        .await;
        let token_file = test_temp_file("bootstrap-claim-token", "test-token");
        let state = build_state_with_secret_backend(
            &signal_dir.path,
            "password",
            api_server.base_url(),
            &token_file.path,
        );
        initialize_ownership_state(&state).await;

        let body = claim_owner(&state, &signing_key, "claim-password").await;
        assert_eq!(
            body.get("status").and_then(Value::as_str),
            Some("CLAIM_ACCEPTED")
        );
        assert_eq!(body.get("state").and_then(Value::as_str), Some("unlocked"));
        assert!(
            body.get("owner_seed_mnemonic")
                .and_then(Value::as_str)
                .map(|value| !value.is_empty())
                .unwrap_or(false),
            "claim should return a non-empty mnemonic"
        );

        let secret = api_server.secret_json();
        let encrypted = decode_secret_field(&secret, "seed-encrypted").expect("seed-encrypted");
        assert!(
            decode_secret_field(&secret, "seed-sealed").is_none(),
            "claim should not create an auto-unlock seal"
        );

        let owner_seed = decrypt_owner_seed_with_password(&state, &encrypted, "claim-password");
        assert_eq!(
            state.ownership.owner_seed_mnemonic(&owner_seed).unwrap(),
            body.get("owner_seed_mnemonic")
                .and_then(Value::as_str)
                .unwrap()
        );
        assert_eq!(
            state
                .ownership
                .owner_public_key_b64url(&owner_seed)
                .unwrap(),
            body.get("owner_public_key")
                .and_then(Value::as_str)
                .unwrap()
        );
    }

    #[tokio::test]
    async fn change_password_rewraps_seed_without_rotating_owner_identity() {
        let signal_dir = test_signal_dir("change-password");
        mark_password_slots_unlocked(&signal_dir.path);

        let signing_key = SigningKey::from_bytes(&[8u8; 32]);
        let bootstrap_hash = bootstrap_owner_pubkey_hash(&signing_key);
        let api_server = spawn_test_api_server(
            owner_escrow_secret_json(None, None),
            test_identity_claims(&bootstrap_hash),
            HashMap::new(),
        )
        .await;
        let token_file = test_temp_file("change-password-token", "test-token");
        let state = build_state_with_secret_backend(
            &signal_dir.path,
            "password",
            api_server.base_url(),
            &token_file.path,
        );
        initialize_ownership_state(&state).await;

        let claim = claim_owner(&state, &signing_key, "old-password").await;
        let expected_owner_public_key = claim
            .get("owner_public_key")
            .and_then(Value::as_str)
            .unwrap()
            .to_string();

        let response = change_password(
            State(state.clone()),
            Json(ChangePasswordRequest {
                old_password: "old-password".to_string(),
                new_password: "new-password".to_string(),
            }),
        )
        .await;
        assert_eq!(response.status().as_u16(), 200);
        assert_eq!(
            read_json(response).await,
            json!({"status": "password_changed"})
        );

        let secret = api_server.secret_json();
        let encrypted = decode_secret_field(&secret, "seed-encrypted").expect("seed-encrypted");
        let owner_seed = decrypt_owner_seed_with_password(&state, &encrypted, "new-password");
        assert_eq!(
            state
                .ownership
                .owner_public_key_b64url(&owner_seed)
                .unwrap(),
            expected_owner_public_key
        );
        assert_eq!(
            decrypt_owner_seed_result(&state, &encrypted, "old-password"),
            Err(OwnershipError::WrongPassword)
        );
    }

    #[tokio::test]
    async fn recover_rewraps_seed_from_mnemonic_and_unlocks() {
        let signal_dir = test_signal_dir("recover");
        mark_password_slots_unlocked(&signal_dir.path);

        let signing_key = SigningKey::from_bytes(&[9u8; 32]);
        let bootstrap_hash = bootstrap_owner_pubkey_hash(&signing_key);
        let api_server = spawn_test_api_server(
            owner_escrow_secret_json(None, None),
            test_identity_claims(&bootstrap_hash),
            HashMap::new(),
        )
        .await;
        let token_file = test_temp_file("recover-token", "test-token");
        let state = build_state_with_secret_backend(
            &signal_dir.path,
            "password",
            api_server.base_url(),
            &token_file.path,
        );
        initialize_ownership_state(&state).await;

        let claim = claim_owner(&state, &signing_key, "initial-password").await;
        let mnemonic = claim
            .get("owner_seed_mnemonic")
            .and_then(Value::as_str)
            .unwrap()
            .to_string();
        let expected_owner_public_key = claim
            .get("owner_public_key")
            .and_then(Value::as_str)
            .unwrap()
            .to_string();

        clear_password_slot_artifacts(&signal_dir.path);
        mark_password_slots_unlocked(&signal_dir.path);

        let response = recover(
            State(state.clone()),
            Json(RecoverRequest {
                mnemonic,
                new_password: "recovered-password".to_string(),
            }),
        )
        .await;
        assert_eq!(response.status().as_u16(), 200);
        let body = read_json(response).await;
        assert_eq!(
            body.get("status").and_then(Value::as_str),
            Some("recovered")
        );
        assert_eq!(body.get("state").and_then(Value::as_str), Some("unlocked"));
        assert_eq!(
            body.get("owner_public_key").and_then(Value::as_str),
            Some(expected_owner_public_key.as_str())
        );

        let secret = api_server.secret_json();
        let encrypted = decode_secret_field(&secret, "seed-encrypted").expect("seed-encrypted");
        let owner_seed = decrypt_owner_seed_with_password(&state, &encrypted, "recovered-password");
        assert_eq!(
            state
                .ownership
                .owner_public_key_b64url(&owner_seed)
                .unwrap(),
            expected_owner_public_key
        );
        assert_eq!(
            decrypt_owner_seed_result(&state, &encrypted, "initial-password"),
            Err(OwnershipError::WrongPassword)
        );
    }

    #[tokio::test]
    async fn recover_while_unlocked_clears_stale_password_handoff_files() {
        let signal_dir = test_signal_dir("recover-already-unlocked");
        mark_password_slots_unlocked(&signal_dir.path);

        let signing_key = SigningKey::from_bytes(&[11u8; 32]);
        let bootstrap_hash = bootstrap_owner_pubkey_hash(&signing_key);
        let api_server = spawn_test_api_server(
            owner_escrow_secret_json(None, None),
            test_identity_claims(&bootstrap_hash),
            HashMap::new(),
        )
        .await;
        let token_file = test_temp_file("recover-already-unlocked-token", "test-token");
        let state = build_state_with_secret_backend(
            &signal_dir.path,
            "auto-unlock",
            api_server.base_url(),
            &token_file.path,
        );
        initialize_ownership_state(&state).await;

        let claim = claim_owner(&state, &signing_key, "initial-password").await;
        let mnemonic = claim
            .get("owner_seed_mnemonic")
            .and_then(Value::as_str)
            .unwrap()
            .to_string();

        clear_password_slot_artifacts(&signal_dir.path);
        mark_password_slots_unlocked(&signal_dir.path);
        let enable = enable_auto_unlock(
            State(state.clone()),
            Json(UnlockRequest {
                password: "initial-password".to_string(),
            }),
        )
        .await;
        assert_eq!(enable.status().as_u16(), 200);

        for slot in [SIGNAL_APP_DATA_SLOT, SIGNAL_TLS_DATA_SLOT] {
            let slot_dir = signal_dir.path.join(slot);
            fs::write(slot_dir.join(SIGNAL_KEY_FILE), "stale-key").expect("write stale key");
            fs::write(slot_dir.join(SIGNAL_ERROR_FILE), "stale-error").expect("write stale error");
        }

        let response = recover(
            State(state.clone()),
            Json(RecoverRequest {
                mnemonic,
                new_password: "recovered-password".to_string(),
            }),
        )
        .await;
        assert_eq!(response.status().as_u16(), 200);
        let body = read_json(response).await;
        assert_eq!(
            body.get("status").and_then(Value::as_str),
            Some("recovered")
        );
        assert_eq!(body.get("state").and_then(Value::as_str), Some("unlocked"));

        for slot in [SIGNAL_APP_DATA_SLOT, SIGNAL_TLS_DATA_SLOT] {
            let slot_dir = signal_dir.path.join(slot);
            assert!(
                !slot_dir.join(SIGNAL_KEY_FILE).exists(),
                "recover should clear stale key file for {slot}"
            );
            assert!(
                !slot_dir.join(SIGNAL_ERROR_FILE).exists(),
                "recover should clear stale error file for {slot}"
            );
            assert!(
                slot_dir.join(SIGNAL_UNLOCKED_FILE).exists(),
                "recover should preserve unlocked sentinel for {slot}"
            );
        }

        let secret = api_server.secret_json();
        let encrypted = decode_secret_field(&secret, "seed-encrypted").expect("seed-encrypted");
        assert!(
            decode_secret_field(&secret, "seed-sealed").is_some(),
            "recover should preserve the sealed owner-seed copy in auto-unlock mode"
        );
        assert_eq!(
            decrypt_owner_seed_result(&state, &encrypted, "initial-password"),
            Err(OwnershipError::WrongPassword)
        );
        let _ = decrypt_owner_seed_with_password(&state, &encrypted, "recovered-password");
    }

    #[tokio::test]
    async fn auto_unlock_enable_disable_and_startup_resume_round_trip() {
        let signal_dir = test_signal_dir("auto-unlock");
        mark_password_slots_unlocked(&signal_dir.path);

        let signing_key = SigningKey::from_bytes(&[10u8; 32]);
        let bootstrap_hash = bootstrap_owner_pubkey_hash(&signing_key);
        let api_server = spawn_test_api_server(
            owner_escrow_secret_json(None, None),
            test_identity_claims(&bootstrap_hash),
            HashMap::new(),
        )
        .await;
        let token_file = test_temp_file("auto-unlock-token", "test-token");
        let state = build_state_with_secret_backend(
            &signal_dir.path,
            "auto-unlock",
            api_server.base_url(),
            &token_file.path,
        );
        initialize_ownership_state(&state).await;

        let _ = claim_owner(&state, &signing_key, "claim-password").await;
        clear_password_slot_artifacts(&signal_dir.path);
        mark_password_slots_unlocked(&signal_dir.path);

        let enable = enable_auto_unlock(
            State(state.clone()),
            Json(UnlockRequest {
                password: "claim-password".to_string(),
            }),
        )
        .await;
        assert_eq!(enable.status().as_u16(), 200);
        assert_eq!(
            read_json(enable).await,
            json!({"status": "auto_unlock_enabled"})
        );
        assert!(state.ownership.auto_unlock_enabled());
        let secret = api_server.secret_json();
        assert!(
            decode_secret_field(&secret, "seed-sealed").is_some(),
            "enable-auto-unlock should persist the sealed seed copy"
        );

        let restart_signal_dir = test_signal_dir("auto-unlock-restart");
        mark_password_slots_unlocked(&restart_signal_dir.path);
        let restart_state = build_state_with_secret_backend(
            &restart_signal_dir.path,
            "auto-unlock",
            api_server.base_url(),
            &token_file.path,
        );
        initialize_ownership_state(&restart_state).await;
        spawn_auto_unlock_if_needed(restart_state.clone());
        sleep(Duration::from_millis(150)).await;
        assert_eq!(
            restart_state
                .ownership
                .state_json()
                .get("state")
                .and_then(Value::as_str),
            Some("unlocked")
        );

        let disable = disable_auto_unlock(
            State(state.clone()),
            Json(UnlockRequest {
                password: "claim-password".to_string(),
            }),
        )
        .await;
        assert_eq!(disable.status().as_u16(), 200);
        assert_eq!(
            read_json(disable).await,
            json!({"status": "auto_unlock_disabled"})
        );
        assert!(!state.ownership.auto_unlock_enabled());
        let secret = api_server.secret_json();
        assert!(
            decode_secret_field(&secret, "seed-sealed").is_none(),
            "disable-auto-unlock should remove the sealed seed copy"
        );
    }

    #[tokio::test]
    async fn kbs_resource_update_rolls_back_first_write_when_second_operation_fails() {
        let signal_dir = test_signal_dir("kbs-resource-rollback");
        let old_encrypted =
            owner_seed_envelope_json([0x61; 32], "old-password", "instance-test-01");
        let old_sealed = json!({"sealed": "old"}).to_string();
        let new_encrypted =
            owner_seed_envelope_json([0x62; 32], "new-password", "instance-test-01");

        let mut resources = HashMap::new();
        resources.insert(
            "default/instance-test-01-owner/seed-encrypted".to_string(),
            old_encrypted.clone(),
        );
        resources.insert(
            "default/instance-test-01-owner/seed-sealed".to_string(),
            old_sealed.clone(),
        );

        let mut workload_resource_status_sequences = HashMap::new();
        workload_resource_status_sequences.insert(
            "DELETE default/instance-test-01-owner/seed-sealed".to_string(),
            vec![500],
        );

        let api_server = spawn_test_api_server_with_all_sequences(
            owner_escrow_secret_json(None, None),
            json!({}),
            resources,
            HashMap::new(),
            workload_resource_status_sequences,
        )
        .await;
        let state = build_state_with_mode(
            &signal_dir.path,
            "password",
            api_server.base_url(),
            Some("default/instance-test-01-owner/seed-encrypted".to_string()),
        );

        let err = update_owner_seed_material(
            &state,
            EscrowValueUpdate::Set(new_encrypted.as_bytes()),
            EscrowValueUpdate::Remove,
        )
        .await
        .expect_err("second write should fail");

        let err_text = err.to_string();
        assert!(
            err_text.contains("owner_seed_update_failed"),
            "rollback path should add failure context: {err_text}"
        );
        assert_eq!(
            api_server.kbs_resource("default/instance-test-01-owner/seed-encrypted"),
            Some(old_encrypted),
            "encrypted resource should be restored after rollback"
        );
        assert_eq!(
            api_server.kbs_resource("default/instance-test-01-owner/seed-sealed"),
            Some(old_sealed),
            "sealed resource should remain untouched when the second operation fails"
        );
    }

    fn build_state(signal_dir: &PathBuf) -> AppState {
        build_state_with_mode(signal_dir, "level1", "http://127.0.0.1:9".to_string(), None)
    }

    fn build_state_with_mode(
        signal_dir: &PathBuf,
        mode: &str,
        base_url: String,
        owner_seed_encrypted_kbs_path: Option<String>,
    ) -> AppState {
        let mut config = Config::from_env_for_test();
        config.storage_ownership_mode = mode.to_string();
        config.instance_id = "instance-test-01".to_string();
        config.kbs_resource_url = format!("{base_url}/kbs/v0/resource");
        config.aa_token_url = format!("{base_url}/aa/token");
        config.owner_seed_encrypted_kbs_path = owner_seed_encrypted_kbs_path.unwrap_or_default();
        config.owner_ciphertext_backend = if config.owner_seed_encrypted_kbs_path.is_empty() {
            "kubernetes-secret".to_string()
        } else {
            "kbs-resource".to_string()
        };
        config.owner_seed_sealed_kbs_path =
            "default/instance-test-01-owner/seed-sealed".to_string();
        config.attestation_pod_namespace = "tenant-test".to_string();
        config.owner_escrow_secret_name = "instance-test-01-owner-escrow".to_string();
        config.k8s_api_url = base_url;

        AppState {
            config: Arc::new(config),
            http_client: reqwest::Client::new(),
            aa_token_cache: Arc::new(RwLock::new(AaTokenCache::new())),
            kbs_resource_cache: Arc::new(RwLock::new(HashMap::<String, KbsCacheEntry>::new())),
            ownership: Arc::new(OwnershipGuard::new_with_signal_dir(
                mode.to_string(),
                signal_dir.clone(),
            )),
            bootstrap_challenge: Arc::new(Mutex::new(None)),
        }
    }

    fn build_state_with_secret_backend(
        signal_dir: &PathBuf,
        mode: &str,
        base_url: String,
        token_path: &Path,
    ) -> AppState {
        let mut config = Config::from_env_for_test();
        config.storage_ownership_mode = mode.to_string();
        config.instance_id = "instance-test-01".to_string();
        config.owner_ciphertext_backend = "kubernetes-secret".to_string();
        config.owner_seed_encrypted_kbs_path =
            "default/instance-test-01-owner/seed-encrypted".to_string();
        config.owner_seed_sealed_kbs_path =
            "default/instance-test-01-owner/seed-sealed".to_string();
        config.owner_escrow_secret_name = "instance-test-01-owner-escrow".to_string();
        config.owner_escrow_encrypted_key = "seed-encrypted".to_string();
        config.owner_escrow_sealed_key = "seed-sealed".to_string();
        config.attestation_pod_namespace = "tenant-test".to_string();
        config.k8s_api_url = base_url.clone();
        config.k8s_service_account_token_path = token_path.display().to_string();
        config.aa_token_url = format!("{base_url}/aa/token");
        config.kbs_resource_url = format!("{base_url}/kbs/v0/resource");

        AppState {
            config: Arc::new(config),
            http_client: reqwest::Client::new(),
            aa_token_cache: Arc::new(RwLock::new(AaTokenCache::new())),
            kbs_resource_cache: Arc::new(RwLock::new(HashMap::<String, KbsCacheEntry>::new())),
            ownership: Arc::new(OwnershipGuard::new_with_signal_dir(
                mode.to_string(),
                signal_dir.clone(),
            )),
            bootstrap_challenge: Arc::new(Mutex::new(None)),
        }
    }

    async fn read_json(response: Response) -> Value {
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("read response body");
        serde_json::from_slice(&body).expect("response json")
    }

    struct TestSignalDir {
        path: PathBuf,
    }

    impl Drop for TestSignalDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    fn test_signal_dir(prefix: &str) -> TestSignalDir {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock before epoch")
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "attestation-proxy-handlers-{prefix}-{}-{}",
            std::process::id(),
            nanos
        ));
        fs::create_dir_all(&path).expect("create temp signal dir");
        TestSignalDir { path }
    }

    struct TestTempFile {
        path: PathBuf,
    }

    impl Drop for TestTempFile {
        fn drop(&mut self) {
            let _ = fs::remove_file(&self.path);
        }
    }

    fn test_temp_file(prefix: &str, contents: &str) -> TestTempFile {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock before epoch")
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "attestation-proxy-test-{prefix}-{}-{}",
            std::process::id(),
            nanos
        ));
        fs::write(&path, contents).expect("write temp file");
        TestTempFile { path }
    }

    #[derive(Clone)]
    struct TestApiState {
        aa_token_response: Value,
        owner_secret: Arc<Mutex<Value>>,
        kbs_resources: Arc<Mutex<HashMap<String, String>>>,
        cdh_status_sequences: Arc<Mutex<HashMap<String, Vec<u16>>>>,
        workload_resource_status_sequences: Arc<Mutex<HashMap<String, Vec<u16>>>>,
    }

    struct TestApiServer {
        addr: SocketAddr,
        task: tokio::task::JoinHandle<()>,
        owner_secret: Arc<Mutex<Value>>,
        kbs_resources: Arc<Mutex<HashMap<String, String>>>,
    }

    impl TestApiServer {
        fn base_url(&self) -> String {
            format!("http://{}", self.addr)
        }

        fn secret_json(&self) -> Value {
            self.owner_secret
                .lock()
                .expect("owner secret lock poisoned")
                .clone()
        }

        fn kbs_resource(&self, path: &str) -> Option<String> {
            self.kbs_resources
                .lock()
                .expect("kbs resource lock poisoned")
                .get(path)
                .cloned()
        }
    }

    impl Drop for TestApiServer {
        fn drop(&mut self) {
            self.task.abort();
        }
    }

    async fn get_owner_secret(AxumState(state): AxumState<TestApiState>) -> impl IntoResponse {
        Json(
            state
                .owner_secret
                .lock()
                .expect("owner secret lock poisoned")
                .clone(),
        )
    }

    async fn put_owner_secret(
        AxumState(state): AxumState<TestApiState>,
        Json(secret): Json<Value>,
    ) -> impl IntoResponse {
        *state
            .owner_secret
            .lock()
            .expect("owner secret lock poisoned") = secret.clone();
        (StatusCode::OK, Json(secret))
    }

    async fn get_cdh_kbs_resource(
        AxumState(state): AxumState<TestApiState>,
        AxumPath(path): AxumPath<String>,
    ) -> impl IntoResponse {
        if let Some(status) = state
            .cdh_status_sequences
            .lock()
            .expect("cdh status sequence lock poisoned")
            .get_mut(&path)
            .and_then(|statuses| {
                if statuses.is_empty() {
                    None
                } else {
                    Some(statuses.remove(0))
                }
            })
        {
            return (
                StatusCode::from_u16(status).expect("valid transient status"),
                Json(json!({"error": "transient"})),
            )
                .into_response();
        }

        let resources = state
            .kbs_resources
            .lock()
            .expect("kbs resource lock poisoned");
        match resources.get(&path) {
            Some(body) => (StatusCode::OK, body.clone()).into_response(),
            None => (StatusCode::NOT_FOUND, Json(json!({"error": "not_found"}))).into_response(),
        }
    }

    async fn get_direct_kbs_resource(
        AxumState(state): AxumState<TestApiState>,
        AxumPath(path): AxumPath<String>,
    ) -> impl IntoResponse {
        let resources = state
            .kbs_resources
            .lock()
            .expect("kbs resource lock poisoned");
        match resources.get(&path) {
            Some(body) => (StatusCode::OK, body.clone()).into_response(),
            None => (StatusCode::NOT_FOUND, Json(json!({"error": "not_found"}))).into_response(),
        }
    }

    async fn put_workload_kbs_resource(
        AxumState(state): AxumState<TestApiState>,
        AxumPath(path): AxumPath<String>,
        body: Bytes,
    ) -> impl IntoResponse {
        let sequence_key = format!("PUT {path}");
        if let Some(status) = state
            .workload_resource_status_sequences
            .lock()
            .expect("workload status sequence lock poisoned")
            .get_mut(&sequence_key)
            .and_then(|statuses| {
                if statuses.is_empty() {
                    None
                } else {
                    Some(statuses.remove(0))
                }
            })
        {
            return (
                StatusCode::from_u16(status).expect("valid transient status"),
                Json(json!({"error": "transient"})),
            )
                .into_response();
        }

        let body = String::from_utf8(body.to_vec()).expect("utf-8 workload body");
        state
            .kbs_resources
            .lock()
            .expect("kbs resource lock poisoned")
            .insert(path, body.clone());
        (StatusCode::OK, body).into_response()
    }

    async fn delete_workload_kbs_resource(
        AxumState(state): AxumState<TestApiState>,
        AxumPath(path): AxumPath<String>,
    ) -> impl IntoResponse {
        let sequence_key = format!("DELETE {path}");
        if let Some(status) = state
            .workload_resource_status_sequences
            .lock()
            .expect("workload status sequence lock poisoned")
            .get_mut(&sequence_key)
            .and_then(|statuses| {
                if statuses.is_empty() {
                    None
                } else {
                    Some(statuses.remove(0))
                }
            })
        {
            return (
                StatusCode::from_u16(status).expect("valid transient status"),
                Json(json!({"error": "transient"})),
            )
                .into_response();
        }

        state
            .kbs_resources
            .lock()
            .expect("kbs resource lock poisoned")
            .remove(&path);
        StatusCode::OK.into_response()
    }

    async fn test_aa_token_handler(AxumState(state): AxumState<TestApiState>) -> Json<Value> {
        Json(state.aa_token_response.clone())
    }

    async fn spawn_test_api_server(
        owner_secret: Value,
        aa_claims: Value,
        kbs_resources: HashMap<String, String>,
    ) -> TestApiServer {
        spawn_test_api_server_with_sequences(owner_secret, aa_claims, kbs_resources, HashMap::new())
            .await
    }

    async fn spawn_test_api_server_with_sequences(
        owner_secret: Value,
        aa_claims: Value,
        kbs_resources: HashMap<String, String>,
        cdh_status_sequences: HashMap<String, Vec<u16>>,
    ) -> TestApiServer {
        spawn_test_api_server_with_all_sequences(
            owner_secret,
            aa_claims,
            kbs_resources,
            cdh_status_sequences,
            HashMap::new(),
        )
        .await
    }

    async fn spawn_test_api_server_with_all_sequences(
        owner_secret: Value,
        aa_claims: Value,
        kbs_resources: HashMap<String, String>,
        cdh_status_sequences: HashMap<String, Vec<u16>>,
        workload_resource_status_sequences: HashMap<String, Vec<u16>>,
    ) -> TestApiServer {
        let owner_secret = Arc::new(Mutex::new(owner_secret));
        let kbs_resources = Arc::new(Mutex::new(kbs_resources));
        let state = TestApiState {
            aa_token_response: json!({ "token": jwt_for_claims(&aa_claims) }),
            owner_secret: owner_secret.clone(),
            kbs_resources: kbs_resources.clone(),
            cdh_status_sequences: Arc::new(Mutex::new(cdh_status_sequences)),
            workload_resource_status_sequences: Arc::new(Mutex::new(
                workload_resource_status_sequences,
            )),
        };
        let router = Router::new()
            .route(
                "/api/v1/namespaces/tenant-test/secrets/instance-test-01-owner-escrow",
                get(get_owner_secret).put(put_owner_secret),
            )
            .route("/cdh/resource/{*path}", get(get_cdh_kbs_resource))
            .route("/kbs/v0/resource/{*path}", get(get_direct_kbs_resource))
            .route(
                "/kbs/v0/workload-resource/{*path}",
                put(put_workload_kbs_resource).delete(delete_workload_kbs_resource),
            )
            .route("/aa/token", get(test_aa_token_handler))
            .with_state(state);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind test api server");
        let addr = listener.local_addr().expect("local addr");
        let task = tokio::spawn(async move {
            axum::serve(listener, router)
                .await
                .expect("serve test api server");
        });
        TestApiServer {
            addr,
            task,
            owner_secret,
            kbs_resources,
        }
    }

    async fn spawn_owner_seed_server(
        owner_seed: [u8; 32],
        password: &str,
        instance_id: &str,
    ) -> TestApiServer {
        let mut resources = HashMap::new();
        resources.insert(
            "default/instance-test-01-owner/seed-encrypted".to_string(),
            owner_seed_envelope_json(owner_seed, password, instance_id),
        );
        spawn_test_api_server(owner_escrow_secret_json(None, None), json!({}), resources).await
    }

    fn owner_seed_envelope_json(owner_seed: [u8; 32], password: &str, instance_id: &str) -> String {
        let guard = OwnershipGuard::new("password".to_string());
        let mut password = Zeroizing::new(password.as_bytes().to_vec());
        let wrap_key = guard
            .derive_password_wrap_key(&mut password, instance_id)
            .expect("derive password wrap key for test");
        let cipher = Aes256Gcm::new_from_slice(&wrap_key[..]).expect("cipher");
        let nonce_bytes = [9u8; 12];
        let ciphertext = cipher
            .encrypt(Nonce::from_slice(&nonce_bytes), owner_seed.as_slice())
            .expect("encrypt owner seed");
        json!({
            "version": OWNER_SEED_ENVELOPE_VERSION,
            "nonce": BASE64_STANDARD.encode(nonce_bytes),
            "ciphertext": BASE64_STANDARD.encode(ciphertext),
        })
        .to_string()
    }

    fn owner_escrow_secret_json(encrypted: Option<&[u8]>, sealed: Option<&[u8]>) -> Value {
        let mut data = serde_json::Map::new();
        if let Some(encrypted) = encrypted {
            data.insert(
                "seed-encrypted".to_string(),
                Value::String(BASE64_STANDARD.encode(encrypted)),
            );
        }
        if let Some(sealed) = sealed {
            data.insert(
                "seed-sealed".to_string(),
                Value::String(BASE64_STANDARD.encode(sealed)),
            );
        }
        json!({
            "apiVersion": "v1",
            "kind": "Secret",
            "metadata": {
                "name": "instance-test-01-owner-escrow",
                "namespace": "tenant-test",
                "resourceVersion": "1",
            },
            "data": Value::Object(data),
            "type": "Opaque",
        })
    }

    fn decode_secret_field(secret: &Value, key: &str) -> Option<Vec<u8>> {
        secret
            .get("data")
            .and_then(Value::as_object)
            .and_then(|data| data.get(key))
            .and_then(Value::as_str)
            .map(|value| {
                BASE64_STANDARD
                    .decode(value.as_bytes())
                    .expect("decode secret field")
            })
    }

    fn test_identity_claims(bootstrap_owner_pubkey_hash: &str) -> Value {
        json!({
            "init_data_claims": {
                "identity": {
                    "bootstrap_owner_pubkey_hash": bootstrap_owner_pubkey_hash,
                    "tenant_instance_identity_hash": "test-tenant-instance-hash",
                    "tenant_id": "tenant-test",
                    "instance_id": "instance-test-01"
                }
            }
        })
    }

    fn jwt_for_claims(claims: &Value) -> String {
        let secret = b"attestation-proxy-test-secret";
        let encoding_key = EncodingKey::from_secret(secret);
        let mut header = Header::new(Algorithm::HS256);
        header.typ = Some("JWT".to_string());
        header.jwk = Some(Jwk {
            common: CommonParameters {
                key_algorithm: Some(KeyAlgorithm::HS256),
                ..Default::default()
            },
            algorithm: AlgorithmParameters::OctetKey(OctetKeyParameters {
                key_type: OctetKeyType::Octet,
                value: URL_SAFE_NO_PAD.encode(secret),
            }),
        });
        let mut token_claims = claims.clone();
        if let Some(object) = token_claims.as_object_mut() {
            object
                .entry("exp".to_string())
                .or_insert_with(|| json!(9999999999u64));
        }
        let token = encode(&header, &token_claims, &encoding_key).expect("encode signed test jwt");
        assert!(
            crate::attestation::verify_jwt_claims(&token).is_ok(),
            "test jwt must verify"
        );
        token
    }

    fn bootstrap_owner_pubkey_hash(signing_key: &SigningKey) -> String {
        let digest = sha2::Sha256::digest(signing_key.verifying_key().as_bytes());
        digest.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    async fn claim_owner(state: &AppState, signing_key: &SigningKey, password: &str) -> Value {
        let challenge = bootstrap_challenge(State(state.clone())).await;
        let challenge_body = read_json(challenge).await;
        assert_eq!(
            challenge_body.get("error").is_none(),
            true,
            "bootstrap challenge failed: {challenge_body}"
        );
        let challenge_b64 = challenge_body
            .get("challenge")
            .and_then(Value::as_str)
            .expect("challenge");
        let challenge_bytes = BASE64_URL_SAFE_NO_PAD
            .decode(challenge_b64.as_bytes())
            .expect("decode challenge");
        let signature = signing_key.sign(&challenge_bytes);
        let response = bootstrap_claim(
            State(state.clone()),
            Json(BootstrapClaimRequest {
                challenge: challenge_b64.to_string(),
                bootstrap_pubkey: BASE64_URL_SAFE_NO_PAD
                    .encode(signing_key.verifying_key().as_bytes()),
                signature: BASE64_URL_SAFE_NO_PAD.encode(signature.to_bytes()),
                password: password.to_string(),
            }),
        )
        .await;
        let body = read_json(response).await;
        assert_eq!(
            body.get("error").is_none(),
            true,
            "bootstrap claim failed: {body}"
        );
        body
    }

    fn decrypt_owner_seed_with_password(
        state: &AppState,
        encrypted: &[u8],
        password: &str,
    ) -> Zeroizing<[u8; 32]> {
        decrypt_owner_seed_result(state, encrypted, password).expect("decrypt owner seed")
    }

    fn decrypt_owner_seed_result(
        state: &AppState,
        encrypted: &[u8],
        password: &str,
    ) -> Result<Zeroizing<[u8; 32]>, OwnershipError> {
        let mut password = Zeroizing::new(password.as_bytes().to_vec());
        let wrap_key = state
            .ownership
            .derive_password_wrap_key(&mut password, &state.config.instance_id)
            .expect("derive password wrap key");
        state.ownership.decrypt_owner_seed(encrypted, &wrap_key)
    }

    fn mark_password_slots_unlocked(signal_dir: &Path) {
        for slot in [SIGNAL_APP_DATA_SLOT, SIGNAL_TLS_DATA_SLOT] {
            let slot_dir = signal_dir.join(slot);
            fs::create_dir_all(&slot_dir).expect("create slot dir");
            fs::write(slot_dir.join(SIGNAL_UNLOCKED_FILE), "unlocked_at=now")
                .expect("write unlocked sentinel");
        }
    }

    fn clear_password_slot_artifacts(signal_dir: &Path) {
        for slot in [SIGNAL_APP_DATA_SLOT, SIGNAL_TLS_DATA_SLOT] {
            for name in [SIGNAL_KEY_FILE, SIGNAL_UNLOCKED_FILE, SIGNAL_ERROR_FILE] {
                let _ = fs::remove_file(signal_dir.join(slot).join(name));
            }
        }
    }
}
