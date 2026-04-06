use serde_json::{json, Value};
use std::collections::VecDeque;
use std::fs::{self, OpenOptions};
use std::io::ErrorKind;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::{Duration, Instant};
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

use argon2::{Algorithm, Argon2, Params, Version};
use hkdf::Hkdf;
use sha2::Sha256;

pub const UNLOCK_MAX_ATTEMPTS: usize = 5;
pub const UNLOCK_WINDOW_SECONDS: u64 = 60;
pub const SIGNAL_KEY_FILE: &str = "key";
pub const SIGNAL_UNLOCKED_FILE: &str = "unlocked";
pub const SIGNAL_ERROR_FILE: &str = "error";
pub const HANDOFF_DEFAULT_TIMEOUT_SECONDS: u64 = 60;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OwnershipState {
    Locked,
    Unlocking,
    Unlocked,
    Error,
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum OwnershipError {
    #[error("rate_limited")]
    RateLimited,
    #[error("not_locked")]
    NotLocked,
    #[error("password_required")]
    PasswordRequired,
    #[error("instance_id_missing")]
    InstanceIdMissing,
    #[error("timeout")]
    Timeout,
    #[error("filesystem_error: {0}")]
    Filesystem(String),
    #[error("kdf_error: {0}")]
    Kdf(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HandoffOutcome {
    Unlocked,
    WrongPassword,
    Fatal(String),
    Timeout,
}

const ALLOWED_PATHS: &[&str] = &[
    "/health",
    "/v1/attestation",
    "/unlock",
    "/.well-known/confidential/unlock",
    "/status",
    "/.well-known/confidential/status",
];

struct OwnershipMachine {
    state: OwnershipState,
    error: Option<String>,
    attempts: VecDeque<Instant>,
}

pub struct OwnershipGuard {
    mode: String,
    signal_dir: PathBuf,
    machine: Mutex<OwnershipMachine>,
}

impl OwnershipGuard {
    pub fn new(mode: String) -> Self {
        Self::new_with_signal_dir(mode, PathBuf::from("/run/ownership-signal"))
    }

    pub(crate) fn new_with_signal_dir(mode: String, signal_dir: PathBuf) -> Self {
        let initial_state = if mode == "level1" {
            OwnershipState::Locked
        } else {
            OwnershipState::Unlocked
        };
        Self {
            mode,
            signal_dir,
            machine: Mutex::new(OwnershipMachine {
                state: initial_state,
                error: None,
                attempts: VecDeque::new(),
            }),
        }
    }

    pub fn begin_unlock_attempt(&self) -> Result<(), OwnershipError> {
        if self.mode != "level1" {
            return Ok(());
        }

        let mut machine = self.machine.lock().expect("ownership lock poisoned");
        let window = Duration::from_secs(UNLOCK_WINDOW_SECONDS);
        let now = Self::now();
        while let Some(front) = machine.attempts.front() {
            if now.duration_since(*front) >= window {
                machine.attempts.pop_front();
            } else {
                break;
            }
        }

        if machine.attempts.len() >= UNLOCK_MAX_ATTEMPTS {
            return Err(OwnershipError::RateLimited);
        }
        if !matches!(machine.state, OwnershipState::Locked) {
            return Err(OwnershipError::NotLocked);
        }

        machine.attempts.push_back(now);
        machine.state = OwnershipState::Unlocking;
        machine.error = None;
        Ok(())
    }

    pub fn set_locked_after_retry(&self) {
        if let Ok(mut machine) = self.machine.lock() {
            machine.state = OwnershipState::Locked;
            machine.error = None;
        }
    }

    pub fn set_unlocked(&self) {
        if let Ok(mut machine) = self.machine.lock() {
            machine.state = OwnershipState::Unlocked;
            machine.error = None;
        }
    }

    pub fn set_error(&self, error: impl Into<String>) {
        if let Ok(mut machine) = self.machine.lock() {
            machine.state = OwnershipState::Error;
            machine.error = Some(error.into());
        }
    }

    pub fn derive_luks_key(
        &self,
        password: &mut Zeroizing<Vec<u8>>,
        instance_id: &str,
    ) -> Result<[u8; 32], OwnershipError> {
        if password.is_empty() {
            password.zeroize();
            return Err(OwnershipError::PasswordRequired);
        }
        if instance_id.is_empty() {
            password.zeroize();
            return Err(OwnershipError::InstanceIdMissing);
        }

        let salt = Zeroizing::new(instance_id.as_bytes().to_vec());
        let result = (|| {
            let params = Params::new(65536, 3, 1, Some(32))
                .map_err(|err| OwnershipError::Kdf(err.to_string()))?;
            let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

            let mut stretched = Zeroizing::new([0u8; 32]);
            argon2
                .hash_password_into(password.as_slice(), salt.as_slice(), stretched.as_mut_slice())
                .map_err(|err| OwnershipError::Kdf(err.to_string()))?;

            let hkdf = Hkdf::<Sha256>::new(Some(salt.as_slice()), stretched.as_slice());
            let mut derived = [0u8; 32];
            if let Err(err) = hkdf.expand(b"enclava-storage-v1", &mut derived) {
                derived.zeroize();
                return Err(OwnershipError::Kdf(err.to_string()));
            }

            Ok(derived)
        })();

        password.zeroize();
        result
    }

    pub fn write_handoff_key(&self, key: &[u8; 32]) -> Result<(), OwnershipError> {
        fs::create_dir_all(&self.signal_dir).map_err(|err| OwnershipError::Filesystem(err.to_string()))?;
        let key_path = self.signal_dir.join(SIGNAL_KEY_FILE);
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(&key_path)
            .map_err(|err| OwnershipError::Filesystem(err.to_string()))?;
        file.write_all(key)
            .map_err(|err| OwnershipError::Filesystem(err.to_string()))?;
        file.sync_all()
            .map_err(|err| OwnershipError::Filesystem(err.to_string()))?;
        Ok(())
    }

    pub fn poll_handoff_result(&self, timeout_secs: u64) -> Result<HandoffOutcome, OwnershipError> {
        let timeout = if timeout_secs == 0 {
            Duration::from_secs(HANDOFF_DEFAULT_TIMEOUT_SECONDS)
        } else {
            Duration::from_secs(timeout_secs)
        };
        let deadline = Self::now() + timeout;
        let unlocked_path = self.signal_dir.join(SIGNAL_UNLOCKED_FILE);
        let error_path = self.signal_dir.join(SIGNAL_ERROR_FILE);

        loop {
            if unlocked_path.exists() {
                return Ok(HandoffOutcome::Unlocked);
            }
            if error_path.exists() {
                let message = fs::read_to_string(&error_path)
                    .map_err(|err| OwnershipError::Filesystem(err.to_string()))?;
                let trimmed = message.trim();
                if trimmed.eq("wrong_password") {
                    return Ok(HandoffOutcome::WrongPassword);
                }
                let fatal = if trimmed.is_empty() {
                    "unknown_error".to_string()
                } else {
                    trimmed.to_string()
                };
                return Ok(HandoffOutcome::Fatal(fatal));
            }
            if Self::now() >= deadline {
                return Ok(HandoffOutcome::Timeout);
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    pub fn clear_handoff_retry_files(&self) -> Result<(), OwnershipError> {
        for name in [SIGNAL_KEY_FILE, SIGNAL_ERROR_FILE] {
            let path = self.signal_dir.join(name);
            match fs::remove_file(path) {
                Ok(()) => {}
                Err(err) if err.kind() == ErrorKind::NotFound => {}
                Err(err) => return Err(OwnershipError::Filesystem(err.to_string())),
            }
        }
        Ok(())
    }

    /// Returns true if the request should be blocked (gated).
    pub fn should_gate(&self, path: &str) -> bool {
        if self.mode != "level1" {
            return false;
        }
        let state = self.current_state();
        if matches!(state, OwnershipState::Unlocked) {
            return false;
        }
        !ALLOWED_PATHS.contains(&path)
    }

    /// Returns JSON describing the ownership state.
    pub fn state_json(&self) -> Value {
        if self.mode != "level1" {
            return json!({ "error": "not_found" });
        }
        let machine = self.machine.lock().expect("ownership lock poisoned");
        json!({
            "state": state_name(machine.state),
            "mode": "level1",
            "error": machine.error,
        })
    }

    pub fn is_level1(&self) -> bool {
        self.mode == "level1"
    }

    pub fn health_status(&self) -> (u16, Value) {
        let timestamp = chrono_timestamp();
        if self.mode != "level1" {
            return (
                200,
                json!({
                    "status": "ok",
                    "service": "attestation-proxy",
                    "timestamp": timestamp,
                }),
            );
        }

        let machine = self.machine.lock().expect("ownership lock poisoned");
        let state = state_name(machine.state);
        let status = if matches!(machine.state, OwnershipState::Unlocked) {
            "ok"
        } else {
            "locked"
        };
        let code = if matches!(machine.state, OwnershipState::Unlocked) {
            200
        } else {
            423
        };

        (
            code,
            json!({
                "status": status,
                "state": state,
                "service": "attestation-proxy",
                "timestamp": timestamp,
            }),
        )
    }

    fn current_state(&self) -> OwnershipState {
        self.machine
            .lock()
            .expect("ownership lock poisoned")
            .state
    }

    fn now() -> Instant {
        Instant::now()
    }

    #[allow(dead_code)]
    fn unlock_window() -> Duration {
        Duration::from_secs(UNLOCK_WINDOW_SECONDS)
    }
}

fn state_name(state: OwnershipState) -> &'static str {
    match state {
        OwnershipState::Locked => "locked",
        OwnershipState::Unlocking => "unlocking",
        OwnershipState::Unlocked => "unlocked",
        OwnershipState::Error => "error",
    }
}

/// UTC timestamp in ISO 8601 format, matching Python's datetime.now(timezone.utc).isoformat().
fn chrono_timestamp() -> String {
    use std::time::SystemTime;
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default();
    let secs = now.as_secs();

    let days = secs / 86400;
    let time_of_day = secs % 86400;
    let hours = time_of_day / 3600;
    let minutes = (time_of_day % 3600) / 60;
    let seconds = time_of_day % 60;
    let micros = now.subsec_micros();

    let (year, month, day) = days_to_ymd(days);

    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:06}+00:00",
        year, month, day, hours, minutes, seconds, micros
    )
}

fn days_to_ymd(mut days: u64) -> (u64, u64, u64) {
    days += 719468;
    let era = days / 146097;
    let doe = days - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}

pub fn utc_now() -> String {
    chrono_timestamp()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn state_machine_transitions() {
        let signal_dir = test_signal_dir("state-machine-transition");
        let guard =
            OwnershipGuard::new_with_signal_dir("level1".to_string(), signal_dir.path.clone());

        assert!(guard.begin_unlock_attempt().is_ok());
        assert_eq!(
            guard.begin_unlock_attempt(),
            Err(OwnershipError::NotLocked)
        );

        guard.set_locked_after_retry();
        assert!(guard.begin_unlock_attempt().is_ok());

        let signal_dir = test_signal_dir("state-machine-rate-limit");
        let guard = OwnershipGuard::new_with_signal_dir("level1".to_string(), signal_dir.path.clone());
        for _ in 0..UNLOCK_MAX_ATTEMPTS {
            assert!(guard.begin_unlock_attempt().is_ok());
            guard.set_locked_after_retry();
        }
        assert_eq!(
            guard.begin_unlock_attempt(),
            Err(OwnershipError::RateLimited)
        );
    }

    #[test]
    fn kdf_parity_and_zeroize() {
        let signal_dir = test_signal_dir("kdf");
        let guard = OwnershipGuard::new_with_signal_dir("level1".to_string(), signal_dir.path.clone());

        let mut password = Zeroizing::new(b"password123".to_vec());
        let key = guard
            .derive_luks_key(&mut password, "instance-abc")
            .expect("kdf should succeed");
        assert_eq!(to_hex(&key), "53713008dae51be0b32cb3815404c355483bc629703f80f26095ede6144c1182");
        assert_eq!(key.len(), 32);
    }

    #[test]
    fn derive_luks_key_zeroizes_source_password_buffer() {
        let signal_dir = test_signal_dir("kdf-source-zeroize");
        let guard = OwnershipGuard::new_with_signal_dir("level1".to_string(), signal_dir.path.clone());

        let mut password = Zeroizing::new(b"password123".to_vec());

        let key = guard
            .derive_luks_key(&mut password, "instance-abc")
            .expect("kdf should succeed");

        assert_eq!(key.len(), 32);
        assert!(
            password.iter().all(|byte| *byte == 0),
            "caller-owned password buffer must be zeroized by derive_luks_key"
        );
    }

    #[test]
    fn handoff_poll_paths() {
        let signal_dir = test_signal_dir("handoff");
        let guard = OwnershipGuard::new_with_signal_dir("level1".to_string(), signal_dir.path.clone());

        let key = [0xAB; 32];
        guard.write_handoff_key(&key).expect("key write should succeed");

        let key_path = signal_dir.path.join(SIGNAL_KEY_FILE);
        assert_eq!(fs::read(&key_path).expect("read key file"), key.to_vec());
        let mode = fs::metadata(&key_path)
            .expect("metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);

        fs::write(signal_dir.path.join(SIGNAL_UNLOCKED_FILE), "unlocked_at=now")
            .expect("write unlocked");
        assert_eq!(
            guard.poll_handoff_result(1).expect("unlocked result"),
            HandoffOutcome::Unlocked
        );

        fs::remove_file(signal_dir.path.join(SIGNAL_UNLOCKED_FILE)).expect("remove unlocked");
        fs::write(signal_dir.path.join(SIGNAL_ERROR_FILE), "wrong_password\n").expect("write error");
        assert_eq!(
            guard.poll_handoff_result(1).expect("wrong_password result"),
            HandoffOutcome::WrongPassword
        );

        fs::write(signal_dir.path.join(SIGNAL_ERROR_FILE), "format_failed\n").expect("write fatal");
        assert_eq!(
            guard.poll_handoff_result(1).expect("fatal result"),
            HandoffOutcome::Fatal("format_failed".to_string())
        );

        fs::remove_file(signal_dir.path.join(SIGNAL_ERROR_FILE)).expect("remove error");
        assert_eq!(
            guard.poll_handoff_result(1).expect("timeout result"),
            HandoffOutcome::Timeout
        );
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
            "attestation-proxy-ownership-{prefix}-{}-{}",
            std::process::id(),
            nanos
        ));
        fs::create_dir_all(&path).expect("create temp signal dir");
        TestSignalDir { path }
    }

    fn to_hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect::<String>()
    }
}
