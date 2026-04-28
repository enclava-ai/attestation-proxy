use attestation_proxy::attestation::AaTokenCache;
use attestation_proxy::config::Config;
use attestation_proxy::handlers;
use attestation_proxy::ownership::OwnershipGuard;
use attestation_proxy::receipts::ReceiptSigner;
use attestation_proxy::AppState;
use axum::body::Body;
use axum::extract::State;
use axum::http::{header, Request};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post, put};
use axum::Router;
use axum_server::tls_rustls::RustlsConfig;
use rcgen::generate_simple_self_signed;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use tokio::sync::RwLock;
use x509_cert::der::{Decode, Encode};

/// Ownership gate middleware: blocks non-allowed paths with 423 in level1 mode.
async fn ownership_gate(State(state): State<AppState>, req: Request<Body>, next: Next) -> Response {
    let path = req.uri().path().to_string();
    if state.ownership.should_gate(&path) {
        let body = serde_json::json!({
            "error": "locked",
            "state": "locked",
            "message": "Pod is locked. POST /unlock with password to proceed.",
        });
        let bytes = serde_json::to_vec(&body).unwrap_or_default();
        return axum::http::Response::builder()
            .status(423)
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::CACHE_CONTROL, "no-store")
            .body(Body::from(bytes))
            .unwrap()
            .into_response();
    }
    next.run(req).await
}

#[tokio::main]
async fn main() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let config = Config::from_env();
    let http_addr = format!("{}:{}", config.listen_host, config.listen_port);
    let tls_addr = format!("{}:{}", config.listen_host, config.listen_tls_port);
    let tls_domain = config.tee_domain.clone();
    let tls_material =
        generate_tls_material(&tls_domain).expect("failed to generate attestation TLS cert");

    let state = AppState {
        ownership: Arc::new(OwnershipGuard::new(config.storage_ownership_mode.clone())),
        config: Arc::new(config),
        http_client: reqwest::Client::new(),
        aa_token_cache: Arc::new(RwLock::new(AaTokenCache::new())),
        kbs_resource_cache: Arc::new(RwLock::new(HashMap::new())),
        bootstrap_challenges: Arc::new(Mutex::new(VecDeque::new())),
        receipt_signer: Arc::new(ReceiptSigner::ephemeral()),
        tls_leaf_spki_sha256: tls_material.spki_sha256,
    };

    handlers::initialize_ownership_state(&state).await;
    handlers::spawn_auto_unlock_if_needed(state.clone());

    // If CAP config management is not configured (no signing pubkey), write .ready sentinel
    // immediately so bootstrap.sh does not block waiting for config that will never arrive (D-07).
    if state.config.cap_api_signing_pubkey.is_empty() {
        let config_dir = std::path::Path::new(&state.config.cap_config_dir);
        if let Err(e) = attestation_proxy::config_store::write_ready_sentinel(config_dir) {
            eprintln!("{{\"event\":\"config_ready_sentinel_startup_failed\",\"error\":\"{e}\"}}");
        }
    }

    let http_app = app_router(state.clone());
    let tls_app = app_router(state);
    let http_listener = tokio::net::TcpListener::bind(&http_addr)
        .await
        .expect("failed to bind attestation HTTP listener");
    let tls_config = RustlsConfig::from_der(vec![tls_material.cert_der], tls_material.key_der)
        .await
        .expect("failed to build attestation TLS config");

    println!("attestation-proxy HTTP listening on {http_addr}");
    println!("attestation-proxy TLS listening on {tls_addr}");

    let tls_socket_addr: std::net::SocketAddr = tls_addr.parse().unwrap();
    tokio::select! {
        result = axum::serve(http_listener, http_app.into_make_service()) => {
            result.expect("attestation HTTP server failed");
        }
        result = axum_server::bind_rustls(tls_socket_addr, tls_config)
            .serve(tls_app.into_make_service()) => {
            result.expect("attestation TLS server failed");
        }
    }
}

fn app_router(state: AppState) -> Router {
    Router::new()
        .route("/health", get(handlers::health))
        .route("/status", get(handlers::status))
        .route("/.well-known/confidential/status", get(handlers::status))
        .route("/v1/attestation/info", get(handlers::attestation_info))
        .route("/v1/attestation", get(handlers::attestation))
        .route(
            "/.well-known/confidential/attestation",
            get(handlers::attestation),
        )
        .route("/cdh/resource/{*path}", get(handlers::cdh_resource))
        .route("/unlock", post(handlers::unlock))
        .route("/.well-known/confidential/unlock", post(handlers::unlock))
        .route("/change-password", post(handlers::change_password))
        .route(
            "/.well-known/confidential/change-password",
            post(handlers::change_password),
        )
        .route("/recover", post(handlers::recover))
        .route("/.well-known/confidential/recover", post(handlers::recover))
        .route("/enable-auto-unlock", post(handlers::enable_auto_unlock))
        .route(
            "/.well-known/confidential/enable-auto-unlock",
            post(handlers::enable_auto_unlock),
        )
        .route("/disable-auto-unlock", post(handlers::disable_auto_unlock))
        .route(
            "/.well-known/confidential/disable-auto-unlock",
            post(handlers::disable_auto_unlock),
        )
        .route(
            "/.well-known/confidential/bootstrap/challenge",
            post(handlers::bootstrap_challenge),
        )
        .route(
            "/.well-known/confidential/bootstrap/claim",
            post(handlers::bootstrap_claim),
        )
        // CAP config routes (JWT-authenticated, ownership-gated)
        .route(
            "/.well-known/confidential/config/{key}",
            put(handlers::config_put).delete(handlers::config_delete),
        )
        .route(
            "/config/{key}",
            put(handlers::config_put).delete(handlers::config_delete),
        )
        .route(
            "/.well-known/confidential/config",
            get(handlers::config_list),
        )
        .route("/config", get(handlers::config_list))
        // CAP teardown route (JWT-authenticated, ownership-gated)
        .route(
            "/.well-known/confidential/teardown",
            post(handlers::teardown),
        )
        .route("/teardown", post(handlers::teardown))
        .route("/receipts/sign", post(handlers::sign_receipt))
        .route(
            "/.well-known/confidential/receipts/sign",
            post(handlers::sign_receipt),
        )
        .fallback(handlers::not_found)
        .layer(middleware::from_fn_with_state(
            state.clone(),
            ownership_gate,
        ))
        .with_state(state)
}

struct TlsMaterial {
    cert_der: Vec<u8>,
    key_der: Vec<u8>,
    spki_sha256: [u8; 32],
}

fn generate_tls_material(domain: &str) -> Result<TlsMaterial, Box<dyn std::error::Error>> {
    let subject_alt_names = vec![domain.to_string(), "localhost".to_string()];
    let certified = generate_simple_self_signed(subject_alt_names)?;
    let cert_der = certified.cert.der().to_vec();
    let cert = x509_cert::Certificate::from_der(&cert_der)?;
    let spki_der = cert.tbs_certificate.subject_public_key_info.to_der()?;
    let spki_sha256 = Sha256::digest(spki_der).into();
    Ok(TlsMaterial {
        cert_der,
        key_der: certified.signing_key.serialize_der(),
        spki_sha256,
    })
}

#[cfg(test)]
mod main {
    mod tests {
        use attestation_proxy::ownership::OwnershipGuard;

        #[test]
        fn ownership_gate_blocks_config_and_teardown_when_locked() {
            let guard = OwnershipGuard::new("level1".to_string());
            // Config and teardown are gated (blocked when locked)
            assert!(guard.should_gate("/.well-known/confidential/config/MY_KEY"));
            assert!(guard.should_gate("/.well-known/confidential/config"));
            assert!(guard.should_gate("/.well-known/confidential/teardown"));
            assert!(guard.should_gate("/config/MY_KEY"));
            assert!(guard.should_gate("/config"));
            assert!(guard.should_gate("/teardown"));

            guard.set_unlocked();
            assert!(!guard.should_gate("/.well-known/confidential/config/MY_KEY"));
            assert!(!guard.should_gate("/.well-known/confidential/config"));
            assert!(!guard.should_gate("/.well-known/confidential/teardown"));
            assert!(!guard.should_gate("/config/MY_KEY"));
            assert!(!guard.should_gate("/config"));
            assert!(!guard.should_gate("/teardown"));
        }

        #[test]
        fn ownership_gate_state_behavior() {
            let guard = OwnershipGuard::new("level1".to_string());

            assert!(!guard.should_gate("/unlock"));
            assert!(!guard.should_gate("/status"));
            assert!(!guard.should_gate("/health"));
            assert!(!guard.should_gate("/v1/attestation"));
            assert!(guard.should_gate("/cdh/resource/default/key/1"));

            assert!(guard.begin_unlock_attempt().is_ok());
            assert!(guard.should_gate("/cdh/resource/default/key/1"));

            guard.set_unlocked();
            assert!(!guard.should_gate("/cdh/resource/default/key/1"));

            guard.set_error("fatal");
            assert!(guard.should_gate("/cdh/resource/default/key/1"));
        }
    }
}
