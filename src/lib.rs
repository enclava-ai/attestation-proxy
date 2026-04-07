pub mod attestation;
pub mod config;
pub mod escrow;
pub mod handlers;
pub mod kbs;
pub mod ownership;
pub mod sev;

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use tokio::sync::RwLock;

use attestation::AaTokenCache;
use config::Config;
use kbs::KbsCacheEntry;
use ownership::{BootstrapChallenge, OwnershipGuard};

#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Config>,
    pub http_client: reqwest::Client,
    pub aa_token_cache: Arc<RwLock<AaTokenCache>>,
    pub kbs_resource_cache: Arc<RwLock<HashMap<String, KbsCacheEntry>>>,
    pub ownership: Arc<OwnershipGuard>,
    pub bootstrap_challenge: Arc<Mutex<Option<BootstrapChallenge>>>,
}
