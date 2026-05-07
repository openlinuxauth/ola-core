// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::task::JoinHandle;

const NONCE_TTL: Duration = Duration::from_secs(30);
const MAX_PENDING_NONCES: usize = 1024;
const MAX_PENDING_NONCES_PER_UID: usize = 32;

/// Single-use challenge store. Core generates a nonce per auth attempt, sends
/// it to the adapter in the VerificationRequest, the adapter echoes it back,
/// core consumes it before policy evaluation.
///
/// Single-use is the whole mechanism. The second consume call for the same
/// bytes always fails, even if the first succeeded. Replay attacks against
/// captured VerificationResults stop being possible — the nonce is gone the
/// moment it is honoured once.
pub struct NonceStore {
    state: Arc<Mutex<NonceState>>,
    cleanup_task: Option<JoinHandle<()>>,
}

struct NonceState {
    pending: HashMap<[u8; 32], (Instant, u32)>,
    pending_per_uid: HashMap<u32, usize>,
}

impl NonceStore {
    pub fn new() -> Self {
        let state = Arc::new(Mutex::new(NonceState {
            pending: HashMap::new(),
            pending_per_uid: HashMap::new(),
        }));
        let cleanup_state = state.clone();

        // Expired cannot become valid again. Snapshot outside the lock, remove
        // under it.
        let cleanup_task = tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(10));
            loop {
                interval.tick().await;
                let now = Instant::now();
                if let Ok(mut state) = cleanup_state.lock() {
                    let expired: Vec<[u8; 32]> = state
                        .pending
                        .iter()
                        .filter_map(|(nonce, (issued_at, _))| {
                            (now.duration_since(*issued_at) >= NONCE_TTL).then_some(*nonce)
                        })
                        .collect();
                    for nonce in expired {
                        if let Some((_, uid)) = state.pending.remove(&nonce) {
                            decrement_uid_count(&mut state.pending_per_uid, uid);
                        }
                    }
                }
            }
        });

        Self {
            state,
            cleanup_task: Some(cleanup_task),
        }
    }

    pub fn generate(&self, uid: u32) -> Result<[u8; 32], NonceError> {
        let mut state = self.state.lock().map_err(|_| NonceError::StatePoisoned)?;

        // TableFull is backpressure, not a bug. 1024 in-flight nonces is a load
        // event or a DoS attempt, not normal operation. Refuse new ones rather
        // than let the damage compound.
        if state.pending.len() >= MAX_PENDING_NONCES {
            return Err(NonceError::TableFull);
        }

        if state.pending_per_uid.get(&uid).copied().unwrap_or(0) >= MAX_PENDING_NONCES_PER_UID {
            return Err(NonceError::TooManyForUid);
        }

        for _ in 0..16 {
            let mut nonce = [0u8; 32];
            getrandom::fill(&mut nonce).map_err(|_| NonceError::RandomUnavailable)?;
            if state.pending.contains_key(&nonce) {
                continue;
            }
            state.pending.insert(nonce, (Instant::now(), uid));
            *state.pending_per_uid.entry(uid).or_insert(0) += 1;
            return Ok(nonce);
        }

        Err(NonceError::TableFull)
    }

    pub fn consume(&self, nonce: &[u8; 32], uid: u32) -> Result<(), NonceError> {
        // remove() is what makes this single-use — atomic, no check-then-delete
        // window for a second thread to slip through. A missing nonce is either
        // a replay (already consumed) or fabricated (never issued); both return
        // NotFound. The caller treats either as a replay.
        let mut state = self.state.lock().map_err(|_| NonceError::StatePoisoned)?;
        match state.pending.remove(nonce) {
            None => Err(NonceError::NotFound),
            Some((issued_at, stored_uid)) => {
                decrement_uid_count(&mut state.pending_per_uid, stored_uid);
                // Remove before checking expiry. Check-then-remove leaves a race
                // window where two threads can both observe "not expired" and
                // both consume. Remove first; the nonce is gone either way.
                if Instant::now().duration_since(issued_at) > NONCE_TTL {
                    return Err(NonceError::Expired);
                }
                if stored_uid != uid {
                    return Err(NonceError::UidMismatch);
                }
                Ok(())
            }
        }
    }
}

impl Drop for NonceStore {
    fn drop(&mut self) {
        if let Some(task) = self.cleanup_task.take() {
            task.abort();
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum NonceError {
    #[error("nonce not found — possible replay attack")]
    NotFound,
    #[error("nonce expired after {}s", NONCE_TTL.as_secs())]
    Expired,
    #[error("nonce uid mismatch; nonce consumed")]
    UidMismatch,
    #[error("nonce table full — server under load")]
    TableFull,
    #[error("too many pending nonces for uid")]
    TooManyForUid,
    #[error("nonce store state lock poisoned")]
    StatePoisoned,
    #[error("system random source unavailable")]
    RandomUnavailable,
}

fn decrement_uid_count(counts: &mut HashMap<u32, usize>, uid: u32) {
    if let Some(count) = counts.get_mut(&uid) {
        *count = count.saturating_sub(1);
        if *count > 0 {
            return;
        }
    }
    counts.remove(&uid);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_generate_and_consume_once() {
        let store = NonceStore::new();
        let nonce = store.generate(1000).expect("generate nonce");
        assert!(store.consume(&nonce, 1000).is_ok());
        assert!(matches!(
            store.consume(&nonce, 1000),
            Err(NonceError::NotFound)
        ));
    }

    #[tokio::test]
    async fn test_consume_uid_mismatch() {
        let store = NonceStore::new();
        let nonce = store.generate(1000).expect("generate nonce");
        assert!(matches!(
            store.consume(&nonce, 1001),
            Err(NonceError::UidMismatch)
        ));
    }

    #[tokio::test]
    async fn test_per_uid_pending_limit() {
        let store = NonceStore::new();
        for _ in 0..MAX_PENDING_NONCES_PER_UID {
            store.generate(1000).expect("generate nonce");
        }
        assert!(matches!(
            store.generate(1000),
            Err(NonceError::TooManyForUid)
        ));
        assert!(store.generate(1001).is_ok());
    }

    #[tokio::test]
    async fn test_expired_nonce_is_removed_and_rejected() {
        let store = NonceStore::new();
        let nonce = [4u8; 32];
        let uid = 1000;
        {
            let mut state = store.state.lock().expect("nonce state");
            state.pending.insert(
                nonce,
                (Instant::now() - NONCE_TTL - Duration::from_secs(1), uid),
            );
            state.pending_per_uid.insert(uid, 1);
        }

        assert!(matches!(
            store.consume(&nonce, uid),
            Err(NonceError::Expired)
        ));
        let state = store.state.lock().expect("nonce state");
        assert!(!state.pending.contains_key(&nonce));
        assert!(!state.pending_per_uid.contains_key(&uid));
    }

    #[tokio::test]
    async fn test_global_pending_limit_returns_table_full() {
        let store = NonceStore::new();
        for i in 0..MAX_PENDING_NONCES {
            let mut nonce = [0u8; 32];
            nonce[0..8].copy_from_slice(&(i as u64).to_le_bytes());
            store
                .state
                .lock()
                .expect("nonce state")
                .pending
                .insert(nonce, (Instant::now(), i as u32));
        }

        assert!(matches!(store.generate(42), Err(NonceError::TableFull)));
    }
}
