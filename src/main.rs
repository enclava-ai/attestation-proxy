use axum::body::Body;
use axum::extract::State;
use axum::http::{header, Request};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::Router;
use attestation_proxy::attestation::AaTokenCache;
use attestation_proxy::config::Config;
use attestation_proxy::handlers;
use attestation_proxy::ownership::OwnershipGuard;
use attestation_proxy::AppState;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tokio::sync::RwLock;

/// Ownership gate middleware: blocks non-allowed paths with 423 in level1 mode.
async fn ownership_gate(
    State(state): State<AppState>,
    req: Request<Body>,
    next: Next,
) -> Response {
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
    let config = Config::from_env();
    let addr = format!("{}:{}", config.listen_host, config.listen_port);

    let state = AppState {
        ownership: Arc::new(OwnershipGuard::new(config.storage_ownership_mode.clone())),
        config: Arc::new(config),
        http_client: reqwest::Client::new(),
        aa_token_cache: Arc::new(RwLock::new(AaTokenCache::new())),
        kbs_resource_cache: Arc::new(RwLock::new(HashMap::new())),
        bootstrap_challenge: Arc::new(Mutex::new(None)),
    };

    handlers::initialize_ownership_state(&state).await;
    handlers::spawn_auto_unlock_if_needed(state.clone());

    let app = Router::new()
        .route("/health", get(handlers::health))
        .route("/status", get(handlers::status))
        .route("/.well-known/confidential/status", get(handlers::status))
        .route("/v1/attestation/info", get(handlers::attestation_info))
        .route("/v1/attestation", get(handlers::attestation))
        .route("/.well-known/confidential/attestation", get(handlers::attestation))
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
        .fallback(handlers::not_found)
        .layer(middleware::from_fn_with_state(state.clone(), ownership_gate))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();
    println!("attestation-proxy listening on {addr}");
    axum::serve(listener, app).await.unwrap();
}

#[cfg(test)]
mod main {
    mod tests {
        use attestation_proxy::ownership::OwnershipGuard;

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
