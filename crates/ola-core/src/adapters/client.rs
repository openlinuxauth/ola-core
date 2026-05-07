// SPDX-License-Identifier: Apache-2.0

use crate::core::types::request::VerificationRequest;
use crate::core::types::result::VerificationResult;
use futures::sink::SinkExt;
use futures::stream::StreamExt;
use nix::sys::socket::{getsockopt, sockopt::PeerCredentials};
use serde_json::json;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UnixStream;
use tokio::sync::Semaphore;
use tokio::time::timeout;
use tokio_util::codec::{Framed, LinesCodec, LinesCodecError};

const MAX_RESPONSE_BYTES: usize = 65536; // 64KB
const PROTOCOL_VERSION: u8 = 1;

#[derive(Clone)]
pub struct AdapterClient {
    pub name: String,
    pub socket_path: PathBuf,
    pub expected_uid: u32,
    pub timeout: Duration,
    pub concurrency: Arc<Semaphore>,
}

impl AdapterClient {
    pub async fn verify(
        &self,
        request: VerificationRequest,
    ) -> Result<VerificationResult, AdapterError> {
        // One connection per request, no pool. Unix socket setup is sub-ms;
        // the hardware step (fingerprint, FIDO2 assertion) dominates. A pool
        // adds reconnection and adapter-restart complexity with no measurable
        // gain.
        let stream = timeout(self.timeout, UnixStream::connect(&self.socket_path))
            .await
            .map_err(|_| AdapterError::Timeout)?
            .map_err(AdapterError::Connect)?;

        // SO_PEERCRED before any send. Kernel-set at connect time, the adapter
        // cannot lie about its UID. If the UID does not match the config, the
        // client refuses to send the nonce — closes the case where a compromised
        // process squats on the adapter socket and intercepts auth requests.
        let creds = getsockopt(&stream, PeerCredentials)?;
        if creds.uid() != self.expected_uid {
            return Err(AdapterError::UidMismatch {
                expected: self.expected_uid,
                got: creds.uid(),
            });
        }

        let mut framed = Framed::new(stream, LinesCodec::new_with_max_length(MAX_RESPONSE_BYTES));

        let req_json = serde_json::to_string(&request)?;
        timeout(self.timeout, framed.send(req_json))
            .await
            .map_err(|_| AdapterError::Timeout)?
            .map_err(AdapterError::Codec)?;

        let response_line = timeout(self.timeout, framed.next())
            .await
            .map_err(|_| AdapterError::Timeout)?
            .ok_or(AdapterError::Disconnected)?
            .map_err(AdapterError::Codec)?;

        let result: VerificationResult = serde_json::from_str(&response_line)?;

        // Version mismatch means the client reached the wrong adapter binary —
        // a stale build or a botched deployment. Fail loudly, do not proceed.
        if result.version != PROTOCOL_VERSION {
            return Err(AdapterError::VersionMismatch(result.version));
        }

        // Response ID must equal request ID. Without this check, a slow adapter
        // can return a stale response that gets matched to the current nonce.
        // The ID is a per-request UUID — exactly to prevent that.
        if result.id != request.id {
            return Err(AdapterError::IdMismatch);
        }

        Ok(result)
    }

    pub async fn ping(&self) -> bool {
        timeout(self.timeout, self.ping_once())
            .await
            .ok()
            .and_then(Result::ok)
            .unwrap_or(false)
    }

    async fn ping_once(&self) -> Result<bool, AdapterError> {
        let stream = UnixStream::connect(&self.socket_path)
            .await
            .map_err(AdapterError::Connect)?;

        let creds = getsockopt(&stream, PeerCredentials)?;
        if creds.uid() != self.expected_uid {
            return Ok(false);
        }

        let mut framed = Framed::new(stream, LinesCodec::new_with_max_length(MAX_RESPONSE_BYTES));
        framed
            .send(json!({"version": PROTOCOL_VERSION, "method": "ping"}).to_string())
            .await?;

        let response_line = framed
            .next()
            .await
            .ok_or(AdapterError::Disconnected)?
            .map_err(AdapterError::Codec)?;
        let response: serde_json::Value = serde_json::from_str(&response_line)?;

        Ok(response["version"] == PROTOCOL_VERSION && response["ok"] == true)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum AdapterError {
    #[error("adapter socket not found or timed out")]
    Timeout,
    #[error("connect failed: {0}")]
    Connect(std::io::Error),
    #[error("uid mismatch: expected {expected}, got {got}")]
    UidMismatch { expected: u32, got: u32 },
    #[error("adapter disconnected")]
    Disconnected,
    #[error("protocol version mismatch: {0}")]
    VersionMismatch(u8),
    #[error("response id does not match request id")]
    IdMismatch,
    #[error("serialization error: {0}")]
    Serde(#[from] serde_json::Error),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("codec error: {0}")]
    Codec(#[from] LinesCodecError),
    #[error("nix error: {0}")]
    Nix(#[from] nix::errno::Errno),
    #[error("method not found: {0}")]
    MethodNotFound(String),
    #[error("adapter down: {0}")]
    AdapterDown(String),
    #[error("adapter busy: {0}")]
    AdapterBusy(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::types::request::VerificationRequest;
    use crate::core::types::result::{AuthMethod, VerificationResult};
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::UnixListener;

    fn request() -> VerificationRequest {
        VerificationRequest {
            version: PROTOCOL_VERSION,
            id: [1u8; 16],
            uid: 1000,
            nonce: [2u8; 32],
            deadline_ms: 9999,
        }
    }

    fn result_with(id: [u8; 16], version: u8) -> VerificationResult {
        VerificationResult {
            version,
            id,
            confidence: 1.0,
            method: AuthMethod::Fido2,
            timestamp_ms: 1234,
            uid: 1000,
            nonce: [2u8; 32],
            evidence_hash: [3u8; 32],
        }
    }

    fn client(path: PathBuf, expected_uid: u32) -> AdapterClient {
        AdapterClient {
            name: "adapter_a".to_string(),
            socket_path: path,
            expected_uid,
            timeout: Duration::from_secs(1),
            concurrency: Arc::new(Semaphore::new(1)),
        }
    }

    fn tempdir() -> tempfile::TempDir {
        tempfile::tempdir_in(std::env::current_dir().expect("current dir")).expect("tempdir")
    }

    async fn serve_response(listener: UnixListener, result: VerificationResult) {
        let (stream, _) = listener.accept().await.expect("accept adapter client");
        let mut reader = BufReader::new(stream);
        let mut line = String::new();
        reader
            .read_line(&mut line)
            .await
            .expect("read adapter request");
        let mut stream = reader.into_inner();
        let response = serde_json::to_string(&result).expect("serialize result");
        stream
            .write_all(format!("{response}\n").as_bytes())
            .await
            .expect("write adapter response");
    }

    #[tokio::test]
    async fn test_verify_rejects_version_mismatch() {
        let dir = tempdir();
        let path = dir.path().join("adapter.sock");
        let listener = UnixListener::bind(&path).expect("bind adapter");
        let server = tokio::spawn(serve_response(listener, result_with([1u8; 16], 2)));

        let err = client(path, nix::unistd::getuid().as_raw())
            .verify(request())
            .await
            .expect_err("version mismatch must fail");
        assert!(matches!(err, AdapterError::VersionMismatch(2)));
        server.await.expect("server task");
    }

    #[tokio::test]
    async fn test_verify_rejects_response_id_mismatch() {
        let dir = tempdir();
        let path = dir.path().join("adapter.sock");
        let listener = UnixListener::bind(&path).expect("bind adapter");
        let server = tokio::spawn(serve_response(listener, result_with([9u8; 16], 1)));

        let err = client(path, nix::unistd::getuid().as_raw())
            .verify(request())
            .await
            .expect_err("id mismatch must fail");
        assert!(matches!(err, AdapterError::IdMismatch));
        server.await.expect("server task");
    }

    #[tokio::test]
    async fn test_verify_rejects_wrong_adapter_uid_before_sending_nonce() {
        let dir = tempdir();
        let path = dir.path().join("adapter.sock");
        let listener = UnixListener::bind(&path).expect("bind adapter");
        let server = tokio::spawn(async move {
            let _ = listener.accept().await.expect("accept adapter client");
        });
        let actual_uid = nix::unistd::getuid().as_raw();
        let wrong_uid = actual_uid.saturating_add(1);

        let err = client(path, wrong_uid)
            .verify(request())
            .await
            .expect_err("uid mismatch must fail");
        assert!(matches!(
            err,
            AdapterError::UidMismatch {
                expected,
                got
            } if expected == wrong_uid && got == actual_uid
        ));
        server.await.expect("server task");
    }
}
