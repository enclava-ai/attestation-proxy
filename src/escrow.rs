use std::collections::BTreeMap;
use std::fs;

use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine as _;
use reqwest::Url;
use serde::{Deserialize, Serialize};

use crate::ownership::OwnershipError;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OwnerSeedMaterial {
    pub encrypted: Option<Vec<u8>>,
    pub sealed: Option<Vec<u8>>,
}

pub enum EscrowValueUpdate<'a> {
    Keep,
    Remove,
    Set(&'a [u8]),
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct SecretMetadata {
    name: String,
    namespace: String,
    #[serde(rename = "resourceVersion", default)]
    resource_version: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct SecretObject {
    #[serde(rename = "apiVersion")]
    api_version: String,
    kind: String,
    metadata: SecretMetadata,
    #[serde(default)]
    data: BTreeMap<String, String>,
    #[serde(rename = "type", default = "default_secret_type")]
    secret_type: String,
}

fn default_secret_type() -> String {
    "Opaque".to_string()
}

fn build_kube_client(config: &crate::config::Config) -> Result<reqwest::Client, OwnershipError> {
    let mut builder = reqwest::Client::builder();
    if config.k8s_api_url.starts_with("https://") {
        let pem = fs::read(&config.k8s_ca_cert_path)
            .map_err(|err| OwnershipError::Store(format!("k8s_ca_read_failed:{err}")))?;
        let cert = reqwest::Certificate::from_pem(&pem)
            .map_err(|err| OwnershipError::Store(format!("k8s_ca_parse_failed:{err}")))?;
        builder = builder.add_root_certificate(cert);
    }
    builder
        .build()
        .map_err(|err| OwnershipError::Store(format!("k8s_client_build_failed:{err}")))
}

fn owner_secret_name(config: &crate::config::Config) -> Result<String, OwnershipError> {
    let name = if config.owner_escrow_secret_name.is_empty() {
        if config.instance_id.is_empty() {
            String::new()
        } else {
            format!("{}-owner-escrow", config.instance_id)
        }
    } else {
        config.owner_escrow_secret_name.clone()
    };
    if name.is_empty() {
        return Err(OwnershipError::Store("owner_escrow_secret_name_missing".to_string()));
    }
    Ok(name)
}

fn owner_secret_url(config: &crate::config::Config) -> Result<Url, OwnershipError> {
    if config.attestation_pod_namespace.is_empty() {
        return Err(OwnershipError::Store(
            "attestation_pod_namespace_missing".to_string(),
        ));
    }
    let name = owner_secret_name(config)?;
    let url = format!(
        "{}/api/v1/namespaces/{}/secrets/{}",
        config.k8s_api_url.trim_end_matches('/'),
        config.attestation_pod_namespace,
        name
    );
    Url::parse(&url).map_err(|err| OwnershipError::Store(format!("k8s_url_invalid:{err}")))
}

fn read_service_account_token(config: &crate::config::Config) -> Result<String, OwnershipError> {
    fs::read_to_string(&config.k8s_service_account_token_path)
        .map(|token| token.trim().to_string())
        .map_err(|err| OwnershipError::Store(format!("k8s_token_read_failed:{err}")))
}

async fn fetch_secret(
    state: &crate::AppState,
) -> Result<SecretObject, OwnershipError> {
    let client = build_kube_client(&state.config)?;
    let token = read_service_account_token(&state.config)?;
    let url = owner_secret_url(&state.config)?;
    let response = client
        .get(url)
        .bearer_auth(token)
        .header("Accept", "application/json")
        .send()
        .await
        .map_err(|err| OwnershipError::Store(format!("k8s_secret_get_failed:{err}")))?;

    if response.status().as_u16() == 404 {
        return Err(OwnershipError::Store("owner_escrow_secret_missing".to_string()));
    }
    if !response.status().is_success() {
        let status = response.status().as_u16();
        let body = response.text().await.unwrap_or_default();
        return Err(OwnershipError::Store(format!(
            "k8s_secret_get_non_200:{status}:{body}"
        )));
    }

    response
        .json::<SecretObject>()
        .await
        .map_err(|err| OwnershipError::Store(format!("k8s_secret_parse_failed:{err}")))
}

async fn put_secret(
    state: &crate::AppState,
    secret: &SecretObject,
) -> Result<(), OwnershipError> {
    let client = build_kube_client(&state.config)?;
    let token = read_service_account_token(&state.config)?;
    let url = owner_secret_url(&state.config)?;
    let response = client
        .put(url)
        .bearer_auth(token)
        .json(secret)
        .send()
        .await
        .map_err(|err| OwnershipError::Store(format!("k8s_secret_put_failed:{err}")))?;

    if !response.status().is_success() {
        let status = response.status().as_u16();
        let body = response.text().await.unwrap_or_default();
        return Err(OwnershipError::Store(format!(
            "k8s_secret_put_non_200:{status}:{body}"
        )));
    }
    Ok(())
}

fn decode_secret_value(
    map: &BTreeMap<String, String>,
    key: &str,
) -> Result<Option<Vec<u8>>, OwnershipError> {
    match map.get(key) {
        Some(encoded) => BASE64_STANDARD
            .decode(encoded.as_bytes())
            .map(Some)
            .map_err(|err| OwnershipError::Store(format!("k8s_secret_base64_decode_failed:{key}:{err}"))),
        None => Ok(None),
    }
}

pub async fn load_owner_seed_material(
    state: &crate::AppState,
) -> Result<OwnerSeedMaterial, OwnershipError> {
    let secret = fetch_secret(state).await?;
    Ok(OwnerSeedMaterial {
        encrypted: decode_secret_value(&secret.data, &state.config.owner_escrow_encrypted_key)?,
        sealed: decode_secret_value(&secret.data, &state.config.owner_escrow_sealed_key)?,
    })
}

pub async fn update_owner_seed_material(
    state: &crate::AppState,
    encrypted: EscrowValueUpdate<'_>,
    sealed: EscrowValueUpdate<'_>,
) -> Result<(), OwnershipError> {
    let mut secret = fetch_secret(state).await?;

    match encrypted {
        EscrowValueUpdate::Keep => {}
        EscrowValueUpdate::Remove => {
            secret.data.remove(&state.config.owner_escrow_encrypted_key);
        }
        EscrowValueUpdate::Set(bytes) => {
            secret.data.insert(
                state.config.owner_escrow_encrypted_key.clone(),
                BASE64_STANDARD.encode(bytes),
            );
        }
    }

    match sealed {
        EscrowValueUpdate::Keep => {}
        EscrowValueUpdate::Remove => {
            secret.data.remove(&state.config.owner_escrow_sealed_key);
        }
        EscrowValueUpdate::Set(bytes) => {
            secret.data.insert(
                state.config.owner_escrow_sealed_key.clone(),
                BASE64_STANDARD.encode(bytes),
            );
        }
    }

    put_secret(state, &secret).await
}
