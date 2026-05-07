// SPDX-License-Identifier: Apache-2.0

use anyhow::Context;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::fs::{self, OpenOptions};
use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::fs::{FileTypeExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

const PROTOCOL_VERSION: u8 = 1;
const MAX_REQUEST_BYTES: usize = 64 * 1024;

#[derive(Debug, Clone)]
struct Config {
    socket_path: PathBuf,
    key_path: PathBuf,
    method: String,
    confidence: f32,
}

impl Config {
    fn from_env_and_args() -> anyhow::Result<Self> {
        let mut config = Self {
            socket_path: std::env::var("OLA_DEMO_FIDO2_SOCKET")
                .unwrap_or_else(|_| "/tmp/ola-demo-fido2.sock".to_string())
                .into(),
            key_path: std::env::var("OLA_DEMO_FIDO2_KEY")
                .unwrap_or_else(|_| "/tmp/ola-demo-fido2.key".to_string())
                .into(),
            method: std::env::var("OLA_DEMO_FIDO2_METHOD").unwrap_or_else(|_| "fido2".to_string()),
            confidence: std::env::var("OLA_DEMO_FIDO2_CONFIDENCE")
                .ok()
                .and_then(|value| value.parse().ok())
                .unwrap_or(1.0),
        };

        let mut args = std::env::args().skip(1);
        while let Some(arg) = args.next() {
            match arg.as_str() {
                "--socket" => {
                    config.socket_path = args.next().context("--socket requires a path")?.into();
                }
                "--key" => {
                    config.key_path = args.next().context("--key requires a path")?.into();
                }
                "--method" => {
                    config.method = args.next().context("--method requires a value")?;
                }
                "--confidence" => {
                    config.confidence = args
                        .next()
                        .context("--confidence requires a value")?
                        .parse()
                        .context("--confidence must be a float")?;
                }
                "--help" | "-h" => {
                    print_help();
                    std::process::exit(0);
                }
                other => anyhow::bail!("unknown argument: {other}"),
            }
        }

        if !(0.0..=1.0).contains(&config.confidence) {
            anyhow::bail!("confidence must be between 0.0 and 1.0");
        }

        Ok(config)
    }
}

#[derive(Debug, Deserialize)]
struct VerificationRequest {
    version: u8,
    id: [u8; 16],
    uid: u32,
    nonce: [u8; 32],
    deadline_ms: u64,
}

#[derive(Debug, Serialize)]
struct VerificationResult {
    version: u8,
    id: [u8; 16],
    confidence: f32,
    method: String,
    timestamp_ms: u64,
    uid: u32,
    nonce: [u8; 32],
    evidence_hash: [u8; 32],
}

fn main() -> anyhow::Result<()> {
    let config = Config::from_env_and_args()?;
    let key = load_key(&config.key_path)?;

    if let Some(parent) = config.socket_path.parent() {
        fs::create_dir_all(parent)?;
    }
    remove_stale_socket(&config.socket_path)?;

    let listener = UnixListener::bind(&config.socket_path)
        .with_context(|| format!("binding adapter socket {}", config.socket_path.display()))?;
    fs::set_permissions(&config.socket_path, fs::Permissions::from_mode(0o600))?;

    eprintln!(
        "ola-adapter-demo-fido2 listening on {} as method {}",
        config.socket_path.display(),
        config.method
    );

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                if let Err(e) = handle_client(stream, &config, &key) {
                    eprintln!("adapter request failed: {e:#}");
                }
            }
            Err(e) => eprintln!("adapter accept failed: {e}"),
        }
    }

    Ok(())
}

fn handle_client(stream: UnixStream, config: &Config, key: &[u8; 32]) -> anyhow::Result<()> {
    let mut reader = BufReader::new(stream.try_clone()?);
    let Some(line) = read_capped_line(&mut reader)? else {
        return Ok(());
    };
    if line.trim().is_empty() {
        return Ok(());
    }

    let value: serde_json::Value = serde_json::from_str(line.trim()).context("parse request")?;
    if value["method"] == "ping" {
        let mut stream = reader.into_inner();
        writeln!(
            stream,
            "{}",
            json!({"version": PROTOCOL_VERSION, "ok": true})
        )?;
        return Ok(());
    }

    let request: VerificationRequest =
        serde_json::from_value(value).context("parse verification request")?;
    if request.version != PROTOCOL_VERSION {
        anyhow::bail!("unsupported protocol version {}", request.version);
    }
    if now_ms() > request.deadline_ms {
        anyhow::bail!("request deadline expired");
    }

    let timestamp_ms = now_ms();
    let evidence_hash = evidence_hash(
        key,
        &request.nonce,
        request.uid,
        &config.method,
        config.confidence,
        timestamp_ms,
    );
    let result = VerificationResult {
        version: PROTOCOL_VERSION,
        id: request.id,
        confidence: config.confidence,
        method: config.method.clone(),
        timestamp_ms,
        uid: request.uid,
        nonce: request.nonce,
        evidence_hash,
    };

    let mut stream = reader.into_inner();
    writeln!(stream, "{}", serde_json::to_string(&result)?)?;
    Ok(())
}

fn read_capped_line(reader: &mut BufReader<UnixStream>) -> anyhow::Result<Option<String>> {
    let mut buf = Vec::new();
    let n = reader
        .by_ref()
        .take((MAX_REQUEST_BYTES + 1) as u64)
        .read_until(b'\n', &mut buf)?;
    if n == 0 {
        return Ok(None);
    }
    if buf.len() > MAX_REQUEST_BYTES {
        anyhow::bail!("request too large");
    }
    Ok(Some(
        String::from_utf8(buf).context("request was not utf-8")?,
    ))
}

fn evidence_hash(
    key: &[u8; 32],
    nonce: &[u8; 32],
    uid: u32,
    method: &str,
    confidence: f32,
    timestamp_ms: u64,
) -> [u8; 32] {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("hmac accepts any key size");
    mac.update(nonce);
    mac.update(&uid.to_le_bytes());
    mac.update(&method_commitment(method));
    mac.update(&confidence.to_bits().to_le_bytes());
    mac.update(&timestamp_ms.to_le_bytes());

    let bytes = mac.finalize().into_bytes();
    let mut out = [0u8; 32];
    out.copy_from_slice(bytes.as_slice());
    out
}

fn method_commitment(method: &str) -> [u8; 32] {
    Sha256::digest(method.as_bytes()).into()
}

fn load_key(path: &PathBuf) -> anyhow::Result<[u8; 32]> {
    let link_metadata = fs::symlink_metadata(path)
        .with_context(|| format!("reading key metadata {}", path.display()))?;
    if link_metadata.file_type().is_symlink() {
        anyhow::bail!("key {} must not be a symlink", path.display());
    }
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .with_context(|| format!("opening key {}", path.display()))?;
    let metadata = file
        .metadata()
        .with_context(|| format!("reading key metadata {}", path.display()))?;
    if !metadata.file_type().is_file() {
        anyhow::bail!("key {} must be a regular file", path.display());
    }
    if metadata.permissions().mode() & 0o077 != 0 {
        anyhow::bail!("key {} must not be group/world accessible", path.display());
    }
    let mut data = Vec::new();
    std::io::Read::by_ref(&mut file)
        .take(33)
        .read_to_end(&mut data)
        .with_context(|| format!("reading key {}", path.display()))?;
    if data.len() != 32 {
        anyhow::bail!("key {} must be exactly 32 bytes", path.display());
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&data);
    Ok(key)
}

fn remove_stale_socket(path: &PathBuf) -> anyhow::Result<()> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e).with_context(|| format!("checking {}", path.display())),
    };
    let file_type = metadata.file_type();
    if file_type.is_symlink() {
        anyhow::bail!("socket path {} is a symlink", path.display());
    }
    if !file_type.is_socket() {
        anyhow::bail!(
            "socket path {} exists but is not a Unix socket",
            path.display()
        );
    }

    match UnixStream::connect(path) {
        Ok(_) => anyhow::bail!("socket path {} is already in use", path.display()),
        Err(e) if e.kind() == std::io::ErrorKind::ConnectionRefused => {}
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
            anyhow::bail!("socket path {} is not accessible: {}", path.display(), e);
        }
        Err(_) => {}
    }
    fs::remove_file(path).with_context(|| format!("removing stale socket {}", path.display()))
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time before unix epoch")
        .as_millis() as u64
}

fn print_help() {
    println!(
        "Usage: ola-adapter-demo-fido2 [--socket PATH] [--key PATH] [--method fido2] [--confidence 1.0]"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn method_commitments_match_core_contract() {
        let expected: [u8; 32] = Sha256::digest("fido2".as_bytes()).into();
        assert_eq!(method_commitment("fido2"), expected);
        assert_ne!(method_commitment("custom_a"), method_commitment("custom_b"));
    }

    #[test]
    fn evidence_hash_changes_when_uid_changes() {
        let key = [7u8; 32];
        let nonce = [9u8; 32];
        let a = evidence_hash(&key, &nonce, 1000, "fido2", 1.0, 1234);
        let b = evidence_hash(&key, &nonce, 1001, "fido2", 1.0, 1234);
        assert_ne!(a, b);
    }

    #[test]
    fn load_key_rejects_symlink() {
        let dir = tempfile::tempdir().expect("tempdir");
        let key = dir.path().join("key");
        let link = dir.path().join("link");
        fs::write(&key, [1u8; 32]).expect("write key");
        fs::set_permissions(&key, fs::Permissions::from_mode(0o600)).expect("set key mode");
        std::os::unix::fs::symlink(&key, &link).expect("symlink");

        let err = load_key(&link).expect_err("symlink key must fail");
        assert!(err.to_string().contains("symlink"));
    }

    #[test]
    fn remove_stale_socket_refuses_active_listener() {
        let dir = tempfile::tempdir().expect("tempdir");
        let socket = dir.path().join("adapter.sock");
        let _listener = UnixListener::bind(&socket).expect("bind socket");

        let err = remove_stale_socket(&socket).expect_err("active socket must fail");
        assert!(err.to_string().contains("already in use"));
        assert!(socket.exists());
    }
}
