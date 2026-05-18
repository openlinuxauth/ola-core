// SPDX-License-Identifier: Apache-2.0

use libc::{c_char, c_int, c_void};
use serde_json::json;
use std::ffi::CStr;
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::ptr;
use std::time::Duration;

mod unix_connect;
use unix_connect::connect_with_timeout;

const PAM_SUCCESS: c_int = 0;
const PAM_PERM_DENIED: c_int = 7;
const PAM_AUTH_ERR: c_int = 9;
const PAM_USER_UNKNOWN: c_int = 10;
const PAM_IGNORE: c_int = 25;
const PROTOCOL_VERSION: u8 = 1;
const DEFAULT_SOCKET_PATH: &str = "/run/ola/ola.sock";
const DEFAULT_METHOD: &str = "fido2";
const DEFAULT_TIMEOUT_MS: u64 = 8_000;

type PamHandle = c_void;

#[cfg(not(test))]
extern "C" {
    fn pam_get_user(pamh: *mut PamHandle, user: *mut *const c_char, prompt: *const c_char)
        -> c_int;
}

#[cfg(test)]
unsafe extern "C" fn pam_get_user(
    _pamh: *mut PamHandle,
    _user: *mut *const c_char,
    _prompt: *const c_char,
) -> c_int {
    PAM_USER_UNKNOWN
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PamOlaConfig {
    pub socket_path: String,
    pub method: String,
    pub timeout_ms: u64,
}

impl Default for PamOlaConfig {
    fn default() -> Self {
        Self {
            socket_path: DEFAULT_SOCKET_PATH.to_string(),
            method: DEFAULT_METHOD.to_string(),
            timeout_ms: DEFAULT_TIMEOUT_MS,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthOutcome {
    Allow,
    Deny(String),
    Error(String),
}

#[no_mangle]
pub extern "C" fn pam_sm_authenticate(
    pamh: *mut PamHandle,
    flags: c_int,
    argc: c_int,
    argv: *const *const c_char,
) -> c_int {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        pam_sm_authenticate_inner(pamh, flags, argc, argv)
    })) {
        Ok(code) => code,
        Err(_) => PAM_AUTH_ERR,
    }
}

fn pam_sm_authenticate_inner(
    pamh: *mut PamHandle,
    _flags: c_int,
    argc: c_int,
    argv: *const *const c_char,
) -> c_int {
    let config = parse_argv(argc, argv);
    let Some(name) = pam_user(pamh) else {
        return PAM_USER_UNKNOWN;
    };
    let Some(uid) = uid_for_user(&name) else {
        return PAM_USER_UNKNOWN;
    };

    pam_return_for_outcome(authenticate(&config, Some(uid)))
}

fn pam_return_for_outcome(outcome: AuthOutcome) -> c_int {
    match outcome {
        AuthOutcome::Allow => PAM_SUCCESS,
        AuthOutcome::Deny(_) => PAM_PERM_DENIED,
        AuthOutcome::Error(_) => PAM_AUTH_ERR,
    }
}

#[no_mangle]
pub extern "C" fn pam_sm_setcred(
    _pamh: *mut PamHandle,
    _flags: c_int,
    _argc: c_int,
    _argv: *const *const c_char,
) -> c_int {
    PAM_IGNORE
}

#[no_mangle]
pub extern "C" fn pam_sm_acct_mgmt(
    _pamh: *mut PamHandle,
    _flags: c_int,
    _argc: c_int,
    _argv: *const *const c_char,
) -> c_int {
    PAM_IGNORE
}

#[no_mangle]
pub extern "C" fn pam_sm_open_session(
    _pamh: *mut PamHandle,
    _flags: c_int,
    _argc: c_int,
    _argv: *const *const c_char,
) -> c_int {
    PAM_IGNORE
}

#[no_mangle]
pub extern "C" fn pam_sm_close_session(
    _pamh: *mut PamHandle,
    _flags: c_int,
    _argc: c_int,
    _argv: *const *const c_char,
) -> c_int {
    PAM_IGNORE
}

#[no_mangle]
pub extern "C" fn pam_sm_chauthtok(
    _pamh: *mut PamHandle,
    _flags: c_int,
    _argc: c_int,
    _argv: *const *const c_char,
) -> c_int {
    PAM_IGNORE
}

pub fn authenticate(config: &PamOlaConfig, uid: Option<u32>) -> AuthOutcome {
    let timeout = Duration::from_millis(config.timeout_ms);
    let mut stream = match connect_with_timeout(&config.socket_path, timeout) {
        Ok(stream) => stream,
        Err(e) => return AuthOutcome::Error(format!("connect failed: {e}")),
    };

    if let Err(e) = stream.set_read_timeout(Some(timeout)) {
        return AuthOutcome::Error(format!("set read timeout failed: {e}"));
    }
    if let Err(e) = stream.set_write_timeout(Some(timeout)) {
        return AuthOutcome::Error(format!("set write timeout failed: {e}"));
    }

    let params = match uid {
        Some(uid) => json!({ "method": config.method, "uid": uid }),
        None => json!({ "method": config.method }),
    };
    let request_id = match request_id() {
        Ok(id) => id,
        Err(e) => return AuthOutcome::Error(e),
    };
    let request = json!({
        "version": PROTOCOL_VERSION,
        "id": request_id,
        "method": "verify_once",
        "params": params,
    });
    let line = format!("{}\n", request);

    if let Err(e) = stream.write_all(line.as_bytes()) {
        return AuthOutcome::Error(format!("write failed: {e}"));
    }

    let response_line = match read_line(&mut stream) {
        Ok(line) => line,
        Err(e) => return AuthOutcome::Error(e),
    };

    interpret_response(&response_line, &request_id)
}

fn interpret_response(response_line: &str, expected_id: &str) -> AuthOutcome {
    let response: serde_json::Value = match serde_json::from_str(response_line.trim()) {
        Ok(response) => response,
        Err(e) => return AuthOutcome::Error(format!("invalid response json: {e}")),
    };

    if response.get("version").and_then(|v| v.as_u64()) != Some(PROTOCOL_VERSION as u64) {
        return AuthOutcome::Error("protocol version mismatch".to_string());
    }
    if response.get("id").and_then(|v| v.as_str()) != Some(expected_id) {
        return AuthOutcome::Error("response id mismatch".to_string());
    }

    if let Some(error) = response.get("error").and_then(|v| v.as_str()) {
        return AuthOutcome::Error(error.to_string());
    }

    match response
        .get("result")
        .and_then(|v| v.get("decision"))
        .and_then(|v| v.as_str())
    {
        Some("allow") => AuthOutcome::Allow,
        Some("deny") => {
            let reason = response
                .get("result")
                .and_then(|v| v.get("deny_reason"))
                .and_then(|v| v.as_str())
                .unwrap_or("denied");
            AuthOutcome::Deny(reason.to_string())
        }
        _ => AuthOutcome::Error("missing auth decision".to_string()),
    }
}

fn read_line(stream: &mut UnixStream) -> Result<String, String> {
    let mut buf = Vec::with_capacity(512);
    let mut byte = [0u8; 1];

    loop {
        match stream.read(&mut byte) {
            Ok(0) => break,
            Ok(_) if byte[0] == b'\n' => break,
            Ok(_) => buf.push(byte[0]),
            Err(e) => return Err(format!("read failed: {e}")),
        }

        if buf.len() > 64 * 1024 {
            return Err("response too large".to_string());
        }
    }

    String::from_utf8(buf).map_err(|e| format!("response was not utf-8: {e}"))
}

fn request_id() -> Result<String, String> {
    let mut bytes = [0u8; 16];
    getrandom::fill(&mut bytes).map_err(|_| "request id randomness unavailable".to_string())?;
    let mut id = String::with_capacity(36);
    id.push_str("pam-");
    for byte in bytes {
        use std::fmt::Write as _;
        write!(&mut id, "{byte:02x}").expect("write to string");
    }
    Ok(id)
}

fn parse_argv(argc: c_int, argv: *const *const c_char) -> PamOlaConfig {
    let mut config = PamOlaConfig::default();

    if argc <= 0 || argv.is_null() {
        return config;
    }

    for i in 0..argc {
        // SAFETY: PAM provides argv with argc entries. Null entries are
        // skipped before CStr conversion.
        let ptr = unsafe { *argv.add(i as usize) };
        if ptr.is_null() {
            continue;
        }
        // SAFETY: ptr is non-null and PAM owns a NUL-terminated argument
        // string for the duration of this call.
        let Ok(arg) = (unsafe { CStr::from_ptr(ptr) }).to_str() else {
            continue;
        };

        if let Some(value) = arg.strip_prefix("socket=") {
            config.socket_path = value.to_string();
        } else if let Some(value) = arg.strip_prefix("method=") {
            config.method = value.to_string();
        } else if let Some(value) = arg.strip_prefix("timeout_ms=") {
            if let Ok(timeout_ms) = value.parse::<u64>() {
                config.timeout_ms = timeout_ms;
            }
        }
    }

    config
}

fn pam_user(pamh: *mut PamHandle) -> Option<String> {
    if pamh.is_null() {
        return None;
    }

    let mut user_ptr: *const c_char = ptr::null();
    // SAFETY: pamh is non-null and user_ptr points to writable storage for
    // PAM's returned user pointer.
    let rc = unsafe { pam_get_user(pamh, &mut user_ptr, ptr::null()) };
    if rc != PAM_SUCCESS || user_ptr.is_null() {
        return None;
    }

    // SAFETY: pam_get_user returned success and a non-null NUL-terminated
    // user string owned by PAM.
    unsafe { CStr::from_ptr(user_ptr) }
        .to_str()
        .ok()
        .map(str::to_string)
}

fn uid_for_user(user: &str) -> Option<u32> {
    let c_user = std::ffi::CString::new(user).ok()?;
    let mut buf_len = 16 * 1024;
    const MAX_PASSWD_BUF: usize = 1024 * 1024;

    loop {
        // SAFETY: passwd is a plain C output struct. Zeroed storage is valid
        // before getpwnam_r fills it.
        let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
        let mut result: *mut libc::passwd = ptr::null_mut();
        let mut buf = vec![0u8; buf_len];
        // SAFETY: c_user is NUL-terminated, pwd/result are valid outputs,
        // buf is writable for buf.len() bytes.
        let rc = unsafe {
            libc::getpwnam_r(
                c_user.as_ptr(),
                &mut pwd,
                buf.as_mut_ptr().cast::<c_char>(),
                buf.len(),
                &mut result,
            )
        };

        if rc == 0 {
            return (!result.is_null()).then_some(pwd.pw_uid);
        }
        if rc != libc::ERANGE || buf_len >= MAX_PASSWD_BUF {
            return None;
        }
        buf_len = (buf_len * 2).min(MAX_PASSWD_BUF);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;
    use std::os::unix::net::UnixListener;
    use std::thread;

    #[test]
    fn argv_overrides_defaults() {
        let args = [
            CString::new("socket=/tmp/ola-test.sock").unwrap(),
            CString::new("method=pin").unwrap(),
            CString::new("timeout_ms=123").unwrap(),
        ];
        let raw: Vec<*const c_char> = args.iter().map(|arg| arg.as_ptr()).collect();
        let config = parse_argv(raw.len() as c_int, raw.as_ptr());

        assert_eq!(config.socket_path, "/tmp/ola-test.sock");
        assert_eq!(config.method, "pin");
        assert_eq!(config.timeout_ms, 123);
    }

    #[test]
    fn request_ids_are_random_hex() {
        let first = request_id().expect("first request id");
        let second = request_id().expect("second request id");

        assert!(first.starts_with("pam-"));
        assert_eq!(first.len(), 36);
        assert!(first[4..].bytes().all(|b| b.is_ascii_hexdigit()));
        assert_ne!(first, second);
    }

    #[test]
    fn response_allow_maps_to_allow() {
        let response = r#"{"version":1,"id":"x","result":{"decision":"allow"},"error":null}"#;
        assert_eq!(interpret_response(response, "x"), AuthOutcome::Allow);
    }

    #[test]
    fn response_deny_maps_to_deny() {
        let response = r#"{"version":1,"id":"x","result":{"decision":"deny","deny_reason":"low"},"error":null}"#;
        assert_eq!(
            interpret_response(response, "x"),
            AuthOutcome::Deny("low".to_string())
        );
    }

    #[test]
    fn response_rejects_version_mismatch() {
        let response = r#"{"version":2,"id":"x","result":{"decision":"allow"},"error":null}"#;
        assert_eq!(
            interpret_response(response, "x"),
            AuthOutcome::Error("protocol version mismatch".to_string())
        );
    }

    #[test]
    fn response_rejects_id_mismatch() {
        let response = r#"{"version":1,"id":"other","result":{"decision":"allow"},"error":null}"#;
        assert_eq!(
            interpret_response(response, "x"),
            AuthOutcome::Error("response id mismatch".to_string())
        );
    }

    #[test]
    fn pam_return_codes_keep_deny_and_error_distinct() {
        assert_eq!(pam_return_for_outcome(AuthOutcome::Allow), PAM_SUCCESS);
        assert_eq!(
            pam_return_for_outcome(AuthOutcome::Deny("low".to_string())),
            PAM_PERM_DENIED
        );
        assert_eq!(
            pam_return_for_outcome(AuthOutcome::Error("socket".to_string())),
            PAM_AUTH_ERR
        );
    }

    #[test]
    fn pam_authenticate_fails_closed_without_user() {
        assert_eq!(
            pam_sm_authenticate(ptr::null_mut(), 0, 0, ptr::null()),
            PAM_USER_UNKNOWN
        );
    }

    #[test]
    fn authenticate_sends_verify_once() {
        let dir = tempfile::tempdir_in(std::env::current_dir().unwrap()).unwrap();
        let socket_path = dir.path().join("core.sock");
        let listener = match UnixListener::bind(&socket_path) {
            Ok(listener) => listener,
            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => return,
            Err(e) => panic!("bind test socket failed: {e}"),
        };

        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let line = read_line(&mut stream).unwrap();
            let req: serde_json::Value = serde_json::from_str(&line).unwrap();
            assert_eq!(req["method"], "verify_once");
            assert_eq!(req["params"]["method"], "fido2");
            assert_eq!(req["params"]["uid"], 1000);

            let response = format!(
                "{{\"version\":1,\"id\":{},\"result\":{{\"decision\":\"allow\",\"method\":\"fido2\"}},\"error\":null}}\n",
                req["id"]
            );
            stream.write_all(response.as_bytes()).unwrap();
        });

        let config = PamOlaConfig {
            socket_path: socket_path.display().to_string(),
            method: "fido2".to_string(),
            timeout_ms: 1_000,
        };

        assert_eq!(authenticate(&config, Some(1000)), AuthOutcome::Allow);
        server.join().unwrap();
    }
}
