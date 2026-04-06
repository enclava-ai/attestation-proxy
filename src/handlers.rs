/// HTTP route handlers for the attestation proxy.
///
/// All 6 GET endpoints with Python-identical response contracts.
/// POST /unlock implements the ownership handoff protocol.
use axum::body::Body;
use axum::extract::{Path, Query, State};
use axum::http::{header, Response as HttpResponse};
use axum::response::{IntoResponse, Response};
use axum::Json;

use serde_json::{json, Value};
use zeroize::Zeroizing;

use crate::attestation;
use crate::kbs;
use crate::ownership::utc_now;
use crate::ownership::{OwnershipError, HandoffOutcome};
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
    if !state.ownership.is_level1() {
        return json_response(404, &json!({"error": "not_found"}));
    }
    let body = state.ownership.state_json();
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
    let encoded_nonce = percent_encoding::percent_encode(
        nonce.as_bytes(),
        percent_encoding::NON_ALPHANUMERIC,
    )
    .to_string();
    let evidence_url = format!("{}?runtime_data={}", state.config.aa_evidence_url, encoded_nonce);

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
pub async fn cdh_resource(
    State(state): State<AppState>,
    Path(path): Path<String>,
) -> Response {
    let cache_key = path.trim_start_matches('/');

    match kbs::fetch_kbs_resource(&state, cache_key).await {
        Ok((body, content_type, status)) => bytes_response(status, body, &content_type),
        Err((_status, error_json)) => json_response(502, &error_json),
    }
}

/// POST /unlock, POST /.well-known/confidential/unlock.
pub async fn unlock(
    State(state): State<AppState>,
    Json(payload): Json<UnlockRequest>,
) -> Response {
    let mut password = Zeroizing::new(payload.password.into_bytes());

    if !state.ownership.is_level1() {
        return json_response(404, &json!({"error": "not_found"}));
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

    let key = match state
        .ownership
        .derive_luks_key(&mut password, &state.config.instance_id)
    {
        Ok(key) => Zeroizing::new(key),
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

#[cfg(test)]
fn unlock_poll_timeout_seconds() -> u64 {
    1
}

#[cfg(not(test))]
fn unlock_poll_timeout_seconds() -> u64 {
    crate::ownership::HANDOFF_DEFAULT_TIMEOUT_SECONDS
}

/// Fallback handler for unmatched routes.
pub async fn not_found(
    req: axum::extract::Request,
) -> Response {
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
    use crate::ownership::{OwnershipGuard, SIGNAL_ERROR_FILE, SIGNAL_KEY_FILE, SIGNAL_UNLOCKED_FILE};
    use serde_json::json;
    use std::collections::HashMap;
    use std::fs;
    use std::path::PathBuf;
    use std::sync::Arc;
    use std::time::{SystemTime, UNIX_EPOCH};
    use tokio::sync::RwLock;

    #[tokio::test]
    async fn unlock_handoff_success() {
        let signal_dir = test_signal_dir("unlock-success");
        let state = build_state(&signal_dir.path);
        fs::write(signal_dir.path.join(SIGNAL_UNLOCKED_FILE), "unlocked_at=now")
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
        fs::write(fatal_signal_dir.path.join(SIGNAL_ERROR_FILE), "format_failed\n")
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
            fs::write(rate_signal_dir.path.join(SIGNAL_ERROR_FILE), "wrong_password\n")
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

    fn build_state(signal_dir: &PathBuf) -> AppState {
        let mut config = Config::from_env_for_test();
        config.storage_ownership_mode = "level1".to_string();
        config.instance_id = "instance-test-01".to_string();

        AppState {
            config: Arc::new(config),
            http_client: reqwest::Client::new(),
            aa_token_cache: Arc::new(RwLock::new(AaTokenCache::new())),
            kbs_resource_cache: Arc::new(RwLock::new(HashMap::<String, KbsCacheEntry>::new())),
            ownership: Arc::new(OwnershipGuard::new_with_signal_dir(
                "level1".to_string(),
                signal_dir.clone(),
            )),
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
}
