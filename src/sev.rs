use std::ffi::CString;
use std::fs::{self, OpenOptions};
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::FileTypeExt;
use std::os::unix::io::AsRawFd;
use std::path::Path;
use std::sync::{Mutex, OnceLock};

const SEV_GUEST_DEVICE: &str = "/dev/sev-guest";
const SNP_GET_DERIVED_KEY: libc::c_ulong = 0xC0205301;
const GUEST_FIELD_SELECT_POLICY: u64 = 1 << 0;
const GUEST_FIELD_SELECT_MEASUREMENT: u64 = 1 << 3;
const GUEST_FIELD_SELECT_MEASUREMENT_AND_POLICY: u64 =
    GUEST_FIELD_SELECT_POLICY | GUEST_FIELD_SELECT_MEASUREMENT;

#[repr(C)]
struct SnpDerivedKeyReq {
    root_key_select: u32,
    rsvd: u32,
    guest_field_select: u64,
    vmpl: u32,
    guest_svn: u32,
    tcb_version: u64,
}

#[repr(C)]
struct SnpDerivedKeyResp {
    data: [u8; 64],
}

#[repr(C)]
struct SnpGuestRequestIoctl {
    msg_version: u8,
    _pad: [u8; 7],
    req_data: u64,
    resp_data: u64,
    exitinfo2: u64,
}

fn ioctl_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

fn parse_proc_misc_minor(name: &str) -> Result<Option<u32>, String> {
    let contents = fs::read_to_string("/proc/misc")
        .map_err(|err| format!("proc_misc_read_failed:{err}"))?;
    for line in contents.lines() {
        let mut parts = line.split_whitespace();
        let minor = parts.next();
        let dev_name = parts.next();
        if dev_name == Some(name) {
            let parsed = minor
                .ok_or_else(|| "proc_misc_minor_missing".to_string())?
                .parse::<u32>()
                .map_err(|err| format!("proc_misc_minor_parse_failed:{err}"))?;
            return Ok(Some(parsed));
        }
    }
    Ok(None)
}

fn ensure_sev_guest_device(path: &Path) -> Result<(), String> {
    if path.exists() {
        let metadata = fs::metadata(path).map_err(|err| format!("sev_guest_stat_failed:{err}"))?;
        if !metadata.file_type().is_char_device() {
            return Err("sev_guest_not_char_device".to_string());
        }
        return Ok(());
    }

    let minor = parse_proc_misc_minor("sev-guest")?
        .ok_or_else(|| "sev_guest_missing_from_proc_misc".to_string())?;
    let path_cstr = CString::new(path.as_os_str().as_bytes())
        .map_err(|_| "sev_guest_path_contains_nul".to_string())?;
    let mode = libc::S_IFCHR | 0o600;
    let dev = libc::makedev(10, minor.into());
    let rc = unsafe { libc::mknod(path_cstr.as_ptr(), mode, dev) };
    if rc != 0 {
        let err = io::Error::last_os_error();
        if err.kind() == io::ErrorKind::AlreadyExists {
            return Ok(());
        }
        return Err(format!("sev_guest_mknod_failed:{err}"));
    }
    Ok(())
}

fn extract_fw_error(exitinfo2: u64) -> u32 {
    (exitinfo2 & 0xffff_ffff) as u32
}

fn extract_vmm_error(exitinfo2: u64) -> u32 {
    (exitinfo2 >> 32) as u32
}

pub fn derive_measurement_policy_key() -> Result<[u8; 32], String> {
    let _guard = ioctl_lock()
        .lock()
        .map_err(|_| "sev_guest_lock_poisoned".to_string())?;

    let path = Path::new(SEV_GUEST_DEVICE);
    ensure_sev_guest_device(path)?;

    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .map_err(|err| format!("sev_guest_open_failed:{err}"))?;

    let mut req = SnpDerivedKeyReq {
        // Use the VCEK root and bind the derived bytes to guest policy + measurement.
        root_key_select: 0,
        rsvd: 0,
        guest_field_select: GUEST_FIELD_SELECT_MEASUREMENT_AND_POLICY,
        vmpl: 0,
        guest_svn: 0,
        tcb_version: 0,
    };
    let mut resp = SnpDerivedKeyResp { data: [0u8; 64] };
    let mut guest_req = SnpGuestRequestIoctl {
        msg_version: 1,
        _pad: [0u8; 7],
        req_data: (&mut req as *mut SnpDerivedKeyReq) as u64,
        resp_data: (&mut resp as *mut SnpDerivedKeyResp) as u64,
        exitinfo2: 0,
    };

    let rc = unsafe { libc::ioctl(file.as_raw_fd(), SNP_GET_DERIVED_KEY as _, &mut guest_req) };
    if rc != 0 {
        return Err(format!("sev_guest_ioctl_failed:{}", io::Error::last_os_error()));
    }

    let fw_error = extract_fw_error(guest_req.exitinfo2);
    let vmm_error = extract_vmm_error(guest_req.exitinfo2);
    if fw_error != 0 || vmm_error != 0 {
        return Err(format!("sev_guest_derived_key_error:fw={fw_error}:vmm={vmm_error}"));
    }

    let mut first = [0u8; 32];
    first.copy_from_slice(&resp.data[..32]);
    if first.iter().any(|byte| *byte != 0) {
        return Ok(first);
    }

    let mut second = [0u8; 32];
    second.copy_from_slice(&resp.data[32..64]);
    if second.iter().any(|byte| *byte != 0) {
        return Ok(second);
    }

    Err("sev_guest_derived_key_zero".to_string())
}
