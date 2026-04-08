/// KBS resource fetch and per-path caching.
///
/// Ports Python's KBS resource handling: cache read/write with per-path TTL
/// and error caching. Resource reads use the local AA/CDH passthrough so the
/// caller receives plaintext resource bytes rather than KBS-wrapped ciphertext.
use std::time::Duration;

use serde_json::{json, Value};
use tokio::time::Instant;

use crate::attestation::fetch_kbs_bearer_token;
use crate::ownership::{utc_now, OwnershipError};

pub struct KbsCacheEntry {
    pub body: Vec<u8>,
    pub content_type: String,
    pub status: u16,
    pub expires_at: Instant,
    pub error: Option<Value>,
    pub error_until: Instant,
}

impl KbsCacheEntry {
    /// Returns true if the cache entry has valid (non-expired) content.
    pub fn is_valid(&self) -> bool {
        Instant::now() < self.expires_at && !self.body.is_empty()
    }

    /// Returns true if there is a cached error that hasn't expired.
    pub fn has_valid_error(&self) -> bool {
        self.error.is_some() && Instant::now() < self.error_until
    }
}

fn cdh_resource_base(aa_token_url: &str, aa_evidence_url: &str) -> String {
    if let Some((base, _)) = aa_token_url.split_once("/aa/token") {
        return format!("{}/cdh/resource", base.trim_end_matches('/'));
    }

    if let Some((base, _)) = aa_evidence_url.split_once("/aa/evidence") {
        return format!("{}/cdh/resource", base.trim_end_matches('/'));
    }

    "http://127.0.0.1:8006/cdh/resource".to_string()
}

/// Check cache for a resource entry. Returns (entry_body_data, error_payload).
/// Both None means cache miss.
fn cached_resource_entry(
    cache: &mut std::collections::HashMap<String, KbsCacheEntry>,
    cache_key: &str,
) -> (Option<(Vec<u8>, String, u16)>, Option<Value>) {
    if let Some(entry) = cache.get(cache_key) {
        if entry.is_valid() {
            return (
                Some((entry.body.clone(), entry.content_type.clone(), entry.status)),
                None,
            );
        }
        if entry.has_valid_error() {
            return (None, entry.error.clone());
        }
        // Expired -- remove
        cache.remove(cache_key);
    }
    (None, None)
}

/// Store a successful resource fetch in the cache.
fn store_resource_success(
    cache: &mut std::collections::HashMap<String, KbsCacheEntry>,
    cache_key: &str,
    body: Vec<u8>,
    content_type: String,
    status: u16,
    cache_seconds: f64,
) {
    let ttl = cache_seconds.max(0.0);
    if ttl <= 0.0 {
        cache.remove(cache_key);
        return;
    }
    cache.insert(
        cache_key.to_string(),
        KbsCacheEntry {
            body,
            content_type,
            status,
            expires_at: Instant::now() + Duration::from_secs_f64(ttl),
            error: None,
            error_until: Instant::now(),
        },
    );
}

/// Store an error for a resource fetch in the cache.
fn store_resource_error(
    cache: &mut std::collections::HashMap<String, KbsCacheEntry>,
    cache_key: &str,
    error_payload: Value,
    failure_cache_seconds: f64,
) {
    let ttl = failure_cache_seconds.max(0.0);
    if ttl <= 0.0 {
        cache.remove(cache_key);
        return;
    }
    cache.insert(
        cache_key.to_string(),
        KbsCacheEntry {
            body: Vec::new(),
            content_type: String::new(),
            status: 0,
            expires_at: Instant::now(),
            error: Some(error_payload),
            error_until: Instant::now() + Duration::from_secs_f64(ttl),
        },
    );
}

/// Fetch a KBS resource by path.
/// Holds the write lock across the entire fetch (matching Python's RESOURCE_FETCH_LOCK).
/// Returns Ok((body, content_type, status)) or Err((http_status, error_json)).
pub async fn fetch_kbs_resource(
    state: &crate::AppState,
    cache_key: &str,
) -> Result<(Vec<u8>, String, u16), (u16, Value)> {
    let mut cache = state.kbs_resource_cache.write().await;

    // Check cache first
    let (cached_success, cached_error) = cached_resource_entry(&mut cache, cache_key);
    if let Some((body, content_type, status)) = cached_success {
        return Ok((body, content_type, status));
    }
    if let Some(error) = cached_error {
        return Err((502, error));
    }

    let resource_url = format!(
        "{}/{}",
        cdh_resource_base(&state.config.aa_token_url, &state.config.aa_evidence_url)
            .trim_end_matches('/'),
        cache_key
    );

    let result = state
        .http_client
        .get(&resource_url)
        .header("Accept", "application/octet-stream")
        .timeout(Duration::from_secs(20))
        .send()
        .await;

    match result {
        Ok(resp) => {
            let upstream_status = resp.status().as_u16();
            let content_type = resp
                .headers()
                .get("content-type")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("application/octet-stream")
                .to_string();

            if upstream_status != 200 {
                let error_body = resp.text().await.unwrap_or_default();
                let error_payload = json!({
                    "error": "kbs_resource_non_200",
                    "upstream_status": upstream_status,
                    "upstream_body": error_body,
                    "resource_url": resource_url,
                    "timestamp": utc_now(),
                });
                store_resource_error(
                    &mut cache,
                    cache_key,
                    error_payload.clone(),
                    state.config.kbs_resource_failure_cache_seconds,
                );
                return Err((502, error_payload));
            }

            match resp.bytes().await {
                Ok(body) => {
                    let body_vec = body.to_vec();
                    store_resource_success(
                        &mut cache,
                        cache_key,
                        body_vec.clone(),
                        content_type.clone(),
                        200,
                        state.config.kbs_resource_cache_seconds,
                    );
                    Ok((body_vec, content_type, 200))
                }
                Err(e) => {
                    let error_payload = json!({
                        "error": "kbs_resource_http_error",
                        "detail": e.to_string(),
                        "resource_url": resource_url,
                        "timestamp": utc_now(),
                    });
                    store_resource_error(
                        &mut cache,
                        cache_key,
                        error_payload.clone(),
                        state.config.kbs_resource_failure_cache_seconds,
                    );
                    Err((502, error_payload))
                }
            }
        }
        Err(e) => {
            // Check if it's an HTTP error (status code available) vs connection error
            let (error_type, upstream_status, upstream_body) = if e.is_status() {
                let status = e.status().map(|s| s.as_u16());
                ("kbs_resource_http_error", status, Some(e.to_string()))
            } else {
                ("kbs_resource_unreachable", None, None)
            };

            let mut error_payload = json!({
                "error": error_type,
                "detail": e.to_string(),
                "resource_url": resource_url,
                "timestamp": utc_now(),
            });
            if let Some(status) = upstream_status {
                error_payload["upstream_status"] = json!(status);
            }
            if let Some(body) = upstream_body {
                error_payload["upstream_body"] = json!(body);
            }
            store_resource_error(
                &mut cache,
                cache_key,
                error_payload.clone(),
                state.config.kbs_resource_failure_cache_seconds,
            );
            Err((502, error_payload))
        }
    }
}

/// Evict a cached KBS resource entry after a write or delete.
/// This ensures read-after-write consistency for paths that were
/// modified via the workload-resource endpoint.
pub async fn evict_kbs_cache_entry(state: &crate::AppState, cache_key: &str) {
    let mut cache = state.kbs_resource_cache.write().await;
    cache.remove(cache_key);
}

/// Derive the workload-resource base URL from kbs_resource_url.
/// Replaces the trailing `/resource` segment with `/workload-resource`.
/// E.g. "http://host:8080/kbs/v0/resource" -> "http://host:8080/kbs/v0/workload-resource"
fn workload_resource_base(kbs_resource_url: &str) -> String {
    let base = kbs_resource_url.trim_end_matches('/');
    if base.ends_with("/resource") {
        format!(
            "{}/workload-resource",
            &base[..base.len() - "/resource".len()]
        )
    } else {
        format!("{}/workload-resource", base)
    }
}

/// Write ciphertext to KBS via the workload-resource endpoint.
/// Uses PUT /kbs/v0/workload-resource/{resource_path} with Bearer token auth.
pub async fn put_kbs_workload_resource(
    state: &crate::AppState,
    resource_path: &str,
    body: &[u8],
) -> Result<(), OwnershipError> {
    let token = fetch_kbs_bearer_token(state)
        .await
        .map_err(|e| OwnershipError::Store(format!("kbs_token_unavailable:{e}")))?;

    let workload_url = format!(
        "{}/{resource_path}",
        workload_resource_base(&state.config.kbs_resource_url)
    );

    let response = state
        .http_client
        .put(&workload_url)
        .header("Authorization", format!("Bearer {token}"))
        .header("Content-Type", "application/octet-stream")
        .timeout(std::time::Duration::from_secs(20))
        .body(body.to_vec())
        .send()
        .await
        .map_err(|e| OwnershipError::Store(format!("kbs_workload_put_failed:{e}")))?;

    if !response.status().is_success() {
        let status = response.status().as_u16();
        let resp_body = response.text().await.unwrap_or_default();
        return Err(OwnershipError::Store(format!(
            "kbs_workload_put_non_200:{status}:{resp_body}"
        )));
    }
    // Evict cached entry to ensure read-after-write consistency
    evict_kbs_cache_entry(state, resource_path).await;
    Ok(())
}

/// Delete ciphertext from KBS via the workload-resource endpoint.
/// Uses DELETE /kbs/v0/workload-resource/{resource_path} with Bearer token auth.
pub async fn delete_kbs_workload_resource(
    state: &crate::AppState,
    resource_path: &str,
) -> Result<(), OwnershipError> {
    let token = fetch_kbs_bearer_token(state)
        .await
        .map_err(|e| OwnershipError::Store(format!("kbs_token_unavailable:{e}")))?;

    let workload_url = format!(
        "{}/{resource_path}",
        workload_resource_base(&state.config.kbs_resource_url)
    );

    let response = state
        .http_client
        .delete(&workload_url)
        .header("Authorization", format!("Bearer {token}"))
        .timeout(std::time::Duration::from_secs(20))
        .send()
        .await
        .map_err(|e| OwnershipError::Store(format!("kbs_workload_delete_failed:{e}")))?;

    if !response.status().is_success() {
        let status = response.status().as_u16();
        let resp_body = response.text().await.unwrap_or_default();
        return Err(OwnershipError::Store(format!(
            "kbs_workload_delete_non_200:{status}:{resp_body}"
        )));
    }
    // Evict cached entry to ensure read-after-write consistency
    evict_kbs_cache_entry(state, resource_path).await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cdh_resource_base_from_aa_token_url() {
        let base = cdh_resource_base(
            "http://127.0.0.1:8006/aa/token?token_type=kbs",
            "http://127.0.0.1:8006/aa/evidence",
        );
        assert_eq!(base, "http://127.0.0.1:8006/cdh/resource");
    }

    #[test]
    fn test_cdh_resource_base_from_aa_evidence_url() {
        let base = cdh_resource_base(
            "http://invalid-token-url",
            "http://127.0.0.1:8006/aa/evidence",
        );
        assert_eq!(base, "http://127.0.0.1:8006/cdh/resource");
    }

    #[test]
    fn test_workload_resource_url_derivation() {
        let base =
            "http://kbs-service.trustee-operator-system.svc.cluster.local:8080/kbs/v0/resource";
        let derived = format!(
            "{}/default/test-owner/seed-encrypted",
            workload_resource_base(base)
        );
        assert_eq!(
            derived,
            "http://kbs-service.trustee-operator-system.svc.cluster.local:8080/kbs/v0/workload-resource/default/test-owner/seed-encrypted"
        );
    }

    #[test]
    fn test_workload_resource_url_derivation_no_trailing_resource() {
        let base = "http://kbs:8080/kbs/v0/custom";
        let derived = format!("{}/default/owner/seed", workload_resource_base(base));
        assert_eq!(
            derived,
            "http://kbs:8080/kbs/v0/custom/workload-resource/default/owner/seed"
        );
    }

    #[test]
    fn test_workload_resource_url_derivation_trailing_slash() {
        let base =
            "http://kbs-service.trustee-operator-system.svc.cluster.local:8080/kbs/v0/resource/";
        let derived = format!(
            "{}/default/test-owner/seed-sealed",
            workload_resource_base(base)
        );
        assert_eq!(
            derived,
            "http://kbs-service.trustee-operator-system.svc.cluster.local:8080/kbs/v0/workload-resource/default/test-owner/seed-sealed"
        );
    }

    #[test]
    fn test_cache_entry_valid() {
        let entry = KbsCacheEntry {
            body: vec![1, 2, 3],
            content_type: "application/octet-stream".to_string(),
            status: 200,
            expires_at: Instant::now() + Duration::from_secs(60),
            error: None,
            error_until: Instant::now(),
        };
        assert!(entry.is_valid());
        assert!(!entry.has_valid_error());
    }

    #[test]
    fn test_cache_entry_expired() {
        let entry = KbsCacheEntry {
            body: vec![1, 2, 3],
            content_type: "application/octet-stream".to_string(),
            status: 200,
            // Already expired (in the past)
            expires_at: Instant::now() - Duration::from_secs(1),
            error: None,
            error_until: Instant::now(),
        };
        assert!(!entry.is_valid());
    }

    #[test]
    fn test_cache_entry_with_error() {
        let entry = KbsCacheEntry {
            body: Vec::new(),
            content_type: String::new(),
            status: 0,
            expires_at: Instant::now(),
            error: Some(json!({"error": "test_error"})),
            error_until: Instant::now() + Duration::from_secs(60),
        };
        assert!(!entry.is_valid());
        assert!(entry.has_valid_error());
    }

    #[tokio::test]
    async fn test_evict_kbs_cache_entry() {
        use crate::attestation::AaTokenCache;
        use crate::config::Config;
        use crate::ownership::OwnershipGuard;
        use std::sync::Arc;
        use tokio::sync::RwLock;

        let config = Config::from_env_for_test();
        let signal_dir = std::env::temp_dir().join(format!(
            "attestation-proxy-kbs-evict-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&signal_dir).unwrap();

        let cache_map = {
            let mut m = std::collections::HashMap::new();
            m.insert(
                "default/test-owner/seed-encrypted".to_string(),
                KbsCacheEntry {
                    body: vec![1, 2, 3],
                    content_type: "application/octet-stream".to_string(),
                    status: 200,
                    expires_at: Instant::now() + Duration::from_secs(300),
                    error: None,
                    error_until: Instant::now(),
                },
            );
            m
        };

        let state = crate::AppState {
            config: Arc::new(config),
            http_client: reqwest::Client::new(),
            aa_token_cache: Arc::new(RwLock::new(AaTokenCache::new())),
            kbs_resource_cache: Arc::new(RwLock::new(cache_map)),
            ownership: Arc::new(OwnershipGuard::new_with_signal_dir(
                "level1".to_string(),
                signal_dir.clone(),
            )),
            bootstrap_challenge: Arc::new(std::sync::Mutex::new(None)),
        };

        // Verify entry exists before eviction
        assert!(state
            .kbs_resource_cache
            .read()
            .await
            .contains_key("default/test-owner/seed-encrypted"));

        // Evict
        evict_kbs_cache_entry(&state, "default/test-owner/seed-encrypted").await;

        // Verify entry is gone
        assert!(!state
            .kbs_resource_cache
            .read()
            .await
            .contains_key("default/test-owner/seed-encrypted"));

        // Evicting a non-existent key should not panic
        evict_kbs_cache_entry(&state, "default/nonexistent/path").await;

        let _ = std::fs::remove_dir_all(&signal_dir);
    }

    #[test]
    fn test_cache_entry_expired_error() {
        let entry = KbsCacheEntry {
            body: Vec::new(),
            content_type: String::new(),
            status: 0,
            expires_at: Instant::now(),
            error: Some(json!({"error": "test_error"})),
            error_until: Instant::now() - Duration::from_secs(1),
        };
        assert!(!entry.is_valid());
        assert!(!entry.has_valid_error());
    }
}
