// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::zombie_processes, clippy::redundant_pattern_matching)]
use std::process::Command;
use std::time::{Duration, Instant};
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

async fn start_server(socket_path: &str, temp_dir: &TempDir) -> std::process::Child {
    if std::path::Path::new(socket_path).exists() {
        let _ = std::fs::remove_file(socket_path);
    }

    let audit_log = temp_dir.path().join("audit.log");
    let policy_path = temp_dir.path().join("policy.toml");
    let adapters_dir = temp_dir.path().join("adapters.d");
    std::fs::create_dir_all(&adapters_dir).expect("create adapters dir");
    std::fs::write(
        &policy_path,
        "[[rules]]\nmin_confidence = 0.0\nmax_age_secs = 30\nrequire_uid_match = true\n",
    )
    .expect("write policy");
    let mut policy_perms = std::fs::metadata(&policy_path)
        .expect("policy metadata")
        .permissions();
    std::os::unix::fs::PermissionsExt::set_mode(&mut policy_perms, 0o600);
    std::fs::set_permissions(&policy_path, policy_perms).expect("set policy perms");

    let child = Command::new(env!("CARGO_BIN_EXE_ola-core"))
        .env("OLA_RUNMODE", "dev")
        .env("OLA_SOCKET_PATH", socket_path)
        .env("OLA_AUDIT_LOG_PATH", &audit_log)
        .env("OLA_POLICY_PATH", &policy_path)
        .env("OLA_ADAPTERS_DIR", &adapters_dir)
        .spawn()
        .expect("Failed to start server");

    // Existence is not enough; connect once so the test waits for accept().
    for _ in 0..50 {
        if std::path::Path::new(socket_path).exists()
            && std::os::unix::net::UnixStream::connect(socket_path).is_ok()
        {
            tokio::time::sleep(Duration::from_millis(50)).await;
            return child;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("Server failed to start");
}

#[tokio::test]
#[ignore] // Run with: cargo test --test performance_test -- --ignored
async fn test_concurrent_connections() {
    let temp_dir = tempfile::tempdir_in(std::env::current_dir().unwrap()).unwrap();
    let uuid = uuid::Uuid::new_v4();
    let socket_path = format!("/tmp/ola_pc_{}.sock", &uuid.to_string()[..8]);
    let mut server = start_server(&socket_path, &temp_dir).await;

    let mut handles = vec![];

    for i in 0..20 {
        // Keep total requests under the per-UID rate limit. This test measures
        // concurrent connection overhead; rate-limit behavior has separate
        // coverage.
        let socket_path = socket_path.clone();
        let handle = tokio::spawn(async move {
            let mut stream = UnixStream::connect(&socket_path).await.unwrap();

            for j in 0..4 {
                let req = format!(
                    "{{\"version\":1,\"id\":{},\"method\":\"ping\",\"params\":{{}}}}\n",
                    i * 4 + j
                );
                stream.write_all(req.as_bytes()).await.unwrap();

                let mut buf = vec![0u8; 1024];
                let _ = stream.read(&mut buf).await.unwrap();
            }
        });
        handles.push(handle);
    }

    let start = Instant::now();
    for handle in handles {
        handle.await.unwrap();
    }
    let duration = start.elapsed();

    server.kill().unwrap();
    let _ = std::fs::remove_file(socket_path);

    println!("80 requests across 20 connections: {:?}", duration);
    // Performance tests catch stalls, not normal CI jitter.
    assert!(duration.as_secs() < 10, "Performance regression detected");
}

#[tokio::test]
#[ignore]
async fn test_request_latency() {
    let temp_dir = tempfile::tempdir_in(std::env::current_dir().unwrap()).unwrap();
    let uuid = uuid::Uuid::new_v4();
    let socket_path = format!("/tmp/ola_pl_{}.sock", &uuid.to_string()[..8]);
    let mut server = start_server(&socket_path, &temp_dir).await;

    let mut stream = UnixStream::connect(&socket_path).await.unwrap();

    let mut latencies = vec![];

    for i in 0..50 {
        let start = Instant::now();

        let req = format!(
            "{{\"version\":1,\"id\":{},\"method\":\"ping\",\"params\":{{}}}}\n",
            i
        );
        stream.write_all(req.as_bytes()).await.unwrap();

        let mut buf = vec![0u8; 1024];
        let _ = stream.read(&mut buf).await.unwrap();

        latencies.push(start.elapsed());
    }

    let avg = latencies.iter().sum::<Duration>() / latencies.len() as u32;
    let mut sorted = latencies.clone();
    sorted.sort();
    let p99 = sorted[(sorted.len() as f64 * 0.99) as usize];

    server.kill().unwrap();
    let _ = std::fs::remove_file(socket_path);

    println!("Avg latency: {:?}, P99: {:?}", avg, p99);
    // Thresholds are loose by design. This catches hangs and obvious regressions.
    assert!(avg.as_millis() < 50, "Average latency too high");
    assert!(p99.as_millis() < 200, "P99 latency too high");
}
