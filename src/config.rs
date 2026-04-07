/// Typed configuration parsed from environment variables at startup.
///
/// All 27 env vars match the Python server.py reference implementation
/// (lines 39-65, 83-88) with identical names and defaults.
pub struct Config {
    pub listen_host: String,
    pub listen_port: u16,
    pub aa_evidence_url: String,
    pub aa_token_url: String,
    pub aa_token_timeout_seconds: f64,
    pub aa_token_cache_seconds: f64,
    pub aa_token_failure_cache_seconds: f64,
    pub aa_token_refresh_skew_seconds: f64,
    pub aa_token_fetch_attempts: u32,
    pub aa_token_fetch_retry_sleep_seconds: f64,
    pub kbs_resource_url: String,
    pub kbs_resource_cache_seconds: f64,
    pub kbs_resource_failure_cache_seconds: f64,
    pub attestation_profile: String,
    pub attestation_runtime_class: String,
    pub attestation_workload_image: String,
    pub attestation_workload_container: String,
    pub attestation_pod_name: String,
    pub attestation_pod_namespace: String,
    pub attestation_policy_url: String,
    pub attestation_policy_sha256: String,
    pub attestation_policy_signature_url: String,
    pub attestation_cert_chain_url: String,
    pub attestation_tcb_info_url: String,
    pub attestation_enable_k8s_pod_lookup: bool,
    pub attestation_k8s_api_timeout_seconds: f64,
    pub storage_ownership_mode: String,
    pub instance_id: String,
    pub bootstrap_owner_pubkey_hash: String,
    pub tenant_instance_identity_hash: String,
    pub owner_ciphertext_backend: String,
    pub owner_seed_encrypted_kbs_path: String,
    pub owner_seed_sealed_kbs_path: String,
    pub owner_escrow_secret_name: String,
    pub owner_escrow_encrypted_key: String,
    pub owner_escrow_sealed_key: String,
    pub owner_escrow_dir: String,
    pub ownership_challenge_ttl_seconds: u64,
    pub k8s_api_url: String,
    pub k8s_service_account_token_path: String,
    pub k8s_ca_cert_path: String,
}

impl Config {
    pub fn from_env() -> Self {
        fn env_or(key: &str, default: &str) -> String {
            std::env::var(key).unwrap_or_else(|_| default.to_string())
        }

        fn env_f64(key: &str, default: f64) -> f64 {
            std::env::var(key)
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(default)
        }

        fn env_u32(key: &str, default: u32) -> u32 {
            std::env::var(key)
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(default)
        }

        fn env_u64(key: &str, default: u64) -> u64 {
            std::env::var(key)
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(default)
        }

        fn env_bool(key: &str, default: bool) -> bool {
            match std::env::var(key) {
                Ok(v) => matches!(v.trim().to_lowercase().as_str(), "1" | "true" | "yes"),
                Err(_) => default,
            }
        }

        let instance_id = env_or("INSTANCE_ID", "");
        let storage_ownership_mode = env_or("STORAGE_OWNERSHIP_MODE", "legacy");
        let owner_ciphertext_backend = std::env::var("OWNER_CIPHERTEXT_BACKEND").unwrap_or_else(
            |_| {
                if matches!(storage_ownership_mode.as_str(), "password" | "auto-unlock") {
                    "kubernetes-secret".to_string()
                } else {
                    "kbs-resource".to_string()
                }
            },
        );
        let owner_seed_encrypted_kbs_path = std::env::var("OWNER_SEED_ENCRYPTED_KBS_PATH")
            .unwrap_or_else(|_| {
                if instance_id.is_empty() {
                    String::new()
                } else {
                    format!("default/{instance_id}-owner/seed-encrypted")
                }
            });
        let owner_seed_sealed_kbs_path = std::env::var("OWNER_SEED_SEALED_KBS_PATH")
            .unwrap_or_else(|_| {
                if instance_id.is_empty() {
                    String::new()
                } else {
                    format!("default/{instance_id}-owner/seed-sealed")
                }
            });
        let owner_escrow_secret_name = std::env::var("OWNER_ESCROW_SECRET_NAME")
            .unwrap_or_else(|_| {
                if instance_id.is_empty() {
                    String::new()
                } else {
                    format!("{instance_id}-owner-escrow")
                }
            });

        Self {
            listen_host: env_or("ATTESTATION_BIND", "0.0.0.0"),
            listen_port: env_or("ATTESTATION_PORT", "8081").parse().unwrap_or(8081),
            aa_evidence_url: env_or("AA_EVIDENCE_URL", "http://127.0.0.1:8006/aa/evidence"),
            aa_token_url: env_or(
                "AA_TOKEN_URL",
                "http://127.0.0.1:8006/aa/token?token_type=kbs",
            ),
            aa_token_timeout_seconds: env_f64("AA_TOKEN_TIMEOUT_SECONDS", 10.0),
            aa_token_cache_seconds: env_f64("AA_TOKEN_CACHE_SECONDS", 30.0),
            aa_token_failure_cache_seconds: env_f64("AA_TOKEN_FAILURE_CACHE_SECONDS", 2.0),
            aa_token_refresh_skew_seconds: env_f64("AA_TOKEN_REFRESH_SKEW_SECONDS", 5.0),
            aa_token_fetch_attempts: env_u32("AA_TOKEN_FETCH_ATTEMPTS", 3),
            aa_token_fetch_retry_sleep_seconds: env_f64("AA_TOKEN_FETCH_RETRY_SLEEP_SECONDS", 1.0),
            kbs_resource_url: env_or(
                "KBS_RESOURCE_URL",
                "http://kbs-service.trustee-operator-system.svc.cluster.local:8080/kbs/v0/resource",
            ),
            kbs_resource_cache_seconds: env_f64("KBS_RESOURCE_CACHE_SECONDS", 300.0),
            kbs_resource_failure_cache_seconds: env_f64("KBS_RESOURCE_FAILURE_CACHE_SECONDS", 30.0),
            attestation_profile: env_or("ATTESTATION_PROFILE", "coco-sev-snp"),
            attestation_runtime_class: env_or("ATTESTATION_RUNTIME_CLASS", "kata-qemu-snp"),
            attestation_workload_image: env_or("ATTESTATION_WORKLOAD_IMAGE", ""),
            attestation_workload_container: env_or("ATTESTATION_WORKLOAD_CONTAINER", "enclava"),
            attestation_pod_name: std::env::var("ATTESTATION_POD_NAME")
                .unwrap_or_else(|_| std::env::var("HOSTNAME").unwrap_or_default()),
            attestation_pod_namespace: env_or("ATTESTATION_POD_NAMESPACE", ""),
            attestation_policy_url: env_or("ATTESTATION_POLICY_URL", ""),
            attestation_policy_sha256: env_or("ATTESTATION_POLICY_SHA256", ""),
            attestation_policy_signature_url: env_or("ATTESTATION_POLICY_SIGNATURE_URL", ""),
            attestation_cert_chain_url: env_or("ATTESTATION_CERT_CHAIN_URL", ""),
            attestation_tcb_info_url: env_or("ATTESTATION_TCB_INFO_URL", ""),
            attestation_enable_k8s_pod_lookup: env_bool("ATTESTATION_ENABLE_K8S_POD_LOOKUP", false),
            attestation_k8s_api_timeout_seconds: env_f64(
                "ATTESTATION_K8S_API_TIMEOUT_SECONDS",
                6.0,
            ),
            storage_ownership_mode,
            instance_id,
            bootstrap_owner_pubkey_hash: env_or("BOOTSTRAP_OWNER_PUBKEY_HASH", ""),
            tenant_instance_identity_hash: env_or("TENANT_INSTANCE_IDENTITY_HASH", ""),
            owner_ciphertext_backend,
            owner_seed_encrypted_kbs_path,
            owner_seed_sealed_kbs_path,
            owner_escrow_secret_name,
            owner_escrow_encrypted_key: env_or("OWNER_ESCROW_ENCRYPTED_KEY", "seed-encrypted"),
            owner_escrow_sealed_key: env_or("OWNER_ESCROW_SEALED_KEY", "seed-sealed"),
            owner_escrow_dir: env_or("OWNER_ESCROW_DIR", "/owner-escrow"),
            ownership_challenge_ttl_seconds: env_u64("OWNERSHIP_CHALLENGE_TTL_SECONDS", 300),
            k8s_api_url: env_or("K8S_API_URL", "https://kubernetes.default.svc"),
            k8s_service_account_token_path: env_or(
                "K8S_SERVICE_ACCOUNT_TOKEN_PATH",
                "/var/run/secrets/kubernetes.io/serviceaccount/token",
            ),
            k8s_ca_cert_path: env_or(
                "K8S_CA_CERT_PATH",
                "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt",
            ),
        }
    }
}

impl Config {
    /// Create a Config with default values for testing (no env vars read).
    #[cfg(test)]
    pub fn from_env_for_test() -> Self {
        Self {
            listen_host: "0.0.0.0".into(),
            listen_port: 8081,
            aa_evidence_url: "http://127.0.0.1:8006/aa/evidence".into(),
            aa_token_url: "http://127.0.0.1:8006/aa/token?token_type=kbs".into(),
            aa_token_timeout_seconds: 10.0,
            aa_token_cache_seconds: 30.0,
            aa_token_failure_cache_seconds: 2.0,
            aa_token_refresh_skew_seconds: 5.0,
            aa_token_fetch_attempts: 3,
            aa_token_fetch_retry_sleep_seconds: 1.0,
            kbs_resource_url: "http://kbs-service.trustee-operator-system.svc.cluster.local:8080/kbs/v0/resource".into(),
            kbs_resource_cache_seconds: 300.0,
            kbs_resource_failure_cache_seconds: 30.0,
            attestation_profile: "coco-sev-snp".into(),
            attestation_runtime_class: "kata-qemu-snp".into(),
            attestation_workload_image: "".into(),
            attestation_workload_container: "enclava".into(),
            attestation_pod_name: "".into(),
            attestation_pod_namespace: "".into(),
            attestation_policy_url: "".into(),
            attestation_policy_sha256: "".into(),
            attestation_policy_signature_url: "".into(),
            attestation_cert_chain_url: "".into(),
            attestation_tcb_info_url: "".into(),
            attestation_enable_k8s_pod_lookup: false,
            attestation_k8s_api_timeout_seconds: 6.0,
            storage_ownership_mode: "legacy".into(),
            instance_id: "".into(),
            bootstrap_owner_pubkey_hash: "".into(),
            tenant_instance_identity_hash: "".into(),
            owner_ciphertext_backend: "kbs-resource".into(),
            owner_seed_encrypted_kbs_path: "".into(),
            owner_seed_sealed_kbs_path: "".into(),
            owner_escrow_secret_name: "".into(),
            owner_escrow_encrypted_key: "seed-encrypted".into(),
            owner_escrow_sealed_key: "seed-sealed".into(),
            owner_escrow_dir: "/owner-escrow".into(),
            ownership_challenge_ttl_seconds: 300,
            k8s_api_url: "https://kubernetes.default.svc".into(),
            k8s_service_account_token_path:
                "/var/run/secrets/kubernetes.io/serviceaccount/token".into(),
            k8s_ca_cert_path: "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt".into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    // Tests must run serially since they modify process-wide env vars.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    /// All env var names that Config reads, for cleanup between tests.
    const ALL_ENV_VARS: &[&str] = &[
        "ATTESTATION_BIND",
        "ATTESTATION_PORT",
        "AA_EVIDENCE_URL",
        "AA_TOKEN_URL",
        "AA_TOKEN_TIMEOUT_SECONDS",
        "AA_TOKEN_CACHE_SECONDS",
        "AA_TOKEN_FAILURE_CACHE_SECONDS",
        "AA_TOKEN_REFRESH_SKEW_SECONDS",
        "AA_TOKEN_FETCH_ATTEMPTS",
        "AA_TOKEN_FETCH_RETRY_SLEEP_SECONDS",
        "KBS_RESOURCE_URL",
        "KBS_RESOURCE_CACHE_SECONDS",
        "KBS_RESOURCE_FAILURE_CACHE_SECONDS",
        "ATTESTATION_PROFILE",
        "ATTESTATION_RUNTIME_CLASS",
        "ATTESTATION_WORKLOAD_IMAGE",
        "ATTESTATION_WORKLOAD_CONTAINER",
        "ATTESTATION_POD_NAME",
        "ATTESTATION_POD_NAMESPACE",
        "ATTESTATION_POLICY_URL",
        "ATTESTATION_POLICY_SHA256",
        "ATTESTATION_POLICY_SIGNATURE_URL",
        "ATTESTATION_CERT_CHAIN_URL",
        "ATTESTATION_TCB_INFO_URL",
        "ATTESTATION_ENABLE_K8S_POD_LOOKUP",
        "ATTESTATION_K8S_API_TIMEOUT_SECONDS",
        "STORAGE_OWNERSHIP_MODE",
        "INSTANCE_ID",
        "BOOTSTRAP_OWNER_PUBKEY_HASH",
        "TENANT_INSTANCE_IDENTITY_HASH",
        "OWNER_CIPHERTEXT_BACKEND",
        "OWNER_SEED_ENCRYPTED_KBS_PATH",
        "OWNER_SEED_SEALED_KBS_PATH",
        "OWNER_ESCROW_SECRET_NAME",
        "OWNER_ESCROW_ENCRYPTED_KEY",
        "OWNER_ESCROW_SEALED_KEY",
        "OWNER_ESCROW_DIR",
        "OWNERSHIP_CHALLENGE_TTL_SECONDS",
        "K8S_API_URL",
        "K8S_SERVICE_ACCOUNT_TOKEN_PATH",
        "K8S_CA_CERT_PATH",
        "HOSTNAME",
    ];

    fn clear_env() {
        for var in ALL_ENV_VARS {
            std::env::remove_var(var);
        }
    }

    #[test]
    fn test_defaults() {
        let _lock = ENV_LOCK.lock().unwrap();
        clear_env();

        let config = Config::from_env();

        assert_eq!(config.listen_host, "0.0.0.0");
        assert_eq!(config.listen_port, 8081);
        assert_eq!(
            config.aa_evidence_url,
            "http://127.0.0.1:8006/aa/evidence"
        );
        assert_eq!(
            config.aa_token_url,
            "http://127.0.0.1:8006/aa/token?token_type=kbs"
        );
        assert_eq!(config.aa_token_timeout_seconds, 10.0);
        assert_eq!(config.aa_token_cache_seconds, 30.0);
        assert_eq!(config.aa_token_failure_cache_seconds, 2.0);
        assert_eq!(config.aa_token_refresh_skew_seconds, 5.0);
        assert_eq!(config.aa_token_fetch_attempts, 3);
        assert_eq!(config.aa_token_fetch_retry_sleep_seconds, 1.0);
        assert_eq!(
            config.kbs_resource_url,
            "http://kbs-service.trustee-operator-system.svc.cluster.local:8080/kbs/v0/resource"
        );
        assert_eq!(config.kbs_resource_cache_seconds, 300.0);
        assert_eq!(config.kbs_resource_failure_cache_seconds, 30.0);
        assert_eq!(config.attestation_profile, "coco-sev-snp");
        assert_eq!(config.attestation_runtime_class, "kata-qemu-snp");
        assert_eq!(config.attestation_workload_image, "");
        assert_eq!(config.attestation_workload_container, "enclava");
        assert_eq!(config.attestation_pod_name, "");
        assert_eq!(config.attestation_pod_namespace, "");
        assert_eq!(config.attestation_policy_url, "");
        assert_eq!(config.attestation_policy_sha256, "");
        assert_eq!(config.attestation_policy_signature_url, "");
        assert_eq!(config.attestation_cert_chain_url, "");
        assert_eq!(config.attestation_tcb_info_url, "");
        assert!(!config.attestation_enable_k8s_pod_lookup);
        assert_eq!(config.attestation_k8s_api_timeout_seconds, 6.0);
        assert_eq!(config.storage_ownership_mode, "legacy");
        assert_eq!(config.instance_id, "");
        assert_eq!(config.bootstrap_owner_pubkey_hash, "");
        assert_eq!(config.tenant_instance_identity_hash, "");
        assert_eq!(config.owner_ciphertext_backend, "kbs-resource");
        assert_eq!(config.owner_seed_encrypted_kbs_path, "");
        assert_eq!(config.owner_seed_sealed_kbs_path, "");
        assert_eq!(config.owner_escrow_secret_name, "");
        assert_eq!(config.owner_escrow_encrypted_key, "seed-encrypted");
        assert_eq!(config.owner_escrow_sealed_key, "seed-sealed");
        assert_eq!(config.owner_escrow_dir, "/owner-escrow");
        assert_eq!(config.ownership_challenge_ttl_seconds, 300);
        assert_eq!(config.k8s_api_url, "https://kubernetes.default.svc");
    }

    #[test]
    fn test_pod_name_fallback_to_hostname() {
        let _lock = ENV_LOCK.lock().unwrap();
        clear_env();

        std::env::set_var("HOSTNAME", "my-pod-abc");
        let config = Config::from_env();
        assert_eq!(config.attestation_pod_name, "my-pod-abc");
    }

    #[test]
    fn test_pod_name_explicit_overrides_hostname() {
        let _lock = ENV_LOCK.lock().unwrap();
        clear_env();

        std::env::set_var("HOSTNAME", "should-not-use");
        std::env::set_var("ATTESTATION_POD_NAME", "explicit-name");
        let config = Config::from_env();
        assert_eq!(config.attestation_pod_name, "explicit-name");
    }

    #[test]
    fn test_owner_seed_path_defaults_from_instance_id() {
        let _lock = ENV_LOCK.lock().unwrap();
        clear_env();

        std::env::set_var("INSTANCE_ID", "flowforge-1-ot-1");
        let config = Config::from_env();
        assert_eq!(
            config.owner_seed_encrypted_kbs_path,
            "default/flowforge-1-ot-1-owner/seed-encrypted"
        );
        assert_eq!(
            config.owner_seed_sealed_kbs_path,
            "default/flowforge-1-ot-1-owner/seed-sealed"
        );
        assert_eq!(
            config.owner_escrow_secret_name,
            "flowforge-1-ot-1-owner-escrow"
        );
    }

    #[test]
    fn test_owner_seed_path_explicit_override() {
        let _lock = ENV_LOCK.lock().unwrap();
        clear_env();

        std::env::set_var("INSTANCE_ID", "flowforge-1-ot-1");
        std::env::set_var(
            "OWNER_SEED_ENCRYPTED_KBS_PATH",
            "default/custom-owner/seed-encrypted",
        );
        let config = Config::from_env();
        assert_eq!(
            config.owner_seed_encrypted_kbs_path,
            "default/custom-owner/seed-encrypted"
        );
    }

    #[test]
    fn test_password_mode_defaults_to_kubernetes_secret_backend() {
        let _lock = ENV_LOCK.lock().unwrap();
        clear_env();

        std::env::set_var("STORAGE_OWNERSHIP_MODE", "password");
        std::env::set_var("INSTANCE_ID", "flowforge-1-ot-1");
        let config = Config::from_env();
        assert_eq!(config.owner_ciphertext_backend, "kubernetes-secret");
    }

    #[test]
    fn test_bool_parsing_truthy() {
        let _lock = ENV_LOCK.lock().unwrap();

        for value in &["1", "true", "yes", "True", "YES", " true ", " YES "] {
            clear_env();
            std::env::set_var("ATTESTATION_ENABLE_K8S_POD_LOOKUP", value);
            let config = Config::from_env();
            assert!(
                config.attestation_enable_k8s_pod_lookup,
                "expected true for {:?}",
                value
            );
        }
    }

    #[test]
    fn test_bool_parsing_falsy() {
        let _lock = ENV_LOCK.lock().unwrap();

        for value in &["false", "", "0", "no", "False", "NO", "random"] {
            clear_env();
            std::env::set_var("ATTESTATION_ENABLE_K8S_POD_LOOKUP", value);
            let config = Config::from_env();
            assert!(
                !config.attestation_enable_k8s_pod_lookup,
                "expected false for {:?}",
                value
            );
        }
    }
}
