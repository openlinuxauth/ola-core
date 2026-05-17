// SPDX-License-Identifier: Apache-2.0

use crate::adapters::registry::AdapterRegistry;
use crate::config::Config;
use crate::core::policy::evaluator::PolicyEngine;
use crate::core::types::context::AuthContext;
use crate::core::types::decision::PolicyDecision;
use crate::core::types::method::validate_method_name;
use crate::core::types::request::VerificationRequest;
use crate::infrastructure::audit::{metrics, AuditEntry, AuditLogger};
use crate::infrastructure::ipc::protocol::{Request, Response, PROTOCOL_VERSION};
use crate::infrastructure::ipc::socket_setup::setup_listener;
use crate::infrastructure::ipc::systemd;
use crate::security::allowlist::Allowlist;
use crate::security::attestation::verifier::{AttestationError, AttestationVerifier};
use crate::security::fs::OwnerPolicy;
use crate::security::nonce::{NonceError, NonceStore};
use crate::security::privilege;
use crate::security::rate_limit::RateLimiter;
use anyhow::Context;
use arc_swap::ArcSwap;
use futures::sink::SinkExt;
use futures::stream::StreamExt;
use log::{error, info, warn};
use nix::sys::socket::{getsockopt, sockopt::PeerCredentials};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::net::UnixStream;
use tokio::sync::Semaphore;
use tokio::task::JoinSet;
use tokio::time::{timeout, Duration};
use tokio_util::codec::{Framed, LinesCodec};
use uzers::get_user_by_name;

const MAX_LINE_BYTES: usize = 512 * 1024;
const MAX_CONNECTIONS: usize = 16;
const RATE_LIMIT_PER_UID: u32 = 100;

#[derive(Clone)]
struct ServerState {
    adapter_registry: Arc<AdapterRegistry>,
    reloadable: Arc<ArcSwap<ReloadableState>>,
    attester: Arc<AttestationVerifier>,
    nonce_store: Arc<NonceStore>,
    audit_logger: Arc<AuditLogger>,
    rate_limiter: Arc<RateLimiter>,
    config: Arc<Config>,
    owner_policy: OwnerPolicy,
}

struct ReloadableState {
    allowlist: Allowlist,
    policy_engine: PolicyEngine,
}

impl ReloadableState {
    fn load(config: &Config, owner_policy: OwnerPolicy) -> anyhow::Result<Self> {
        // Bad trust material must fail startup. Per-request denial hides operator
        // mistakes behind auth noise.
        let mut allowlist = Allowlist::new();
        if config.is_prod_mode() {
            allowlist
                .load_from_file_with_options(&config.allowlist_path, true, owner_policy)
                .with_context(|| {
                    format!(
                        "Failed to load allowlist from {} in production mode",
                        config.allowlist_path.display()
                    )
                })?;
        } else {
            let _ =
                allowlist.load_from_file_with_options(&config.allowlist_path, false, owner_policy);
        }

        let policy_engine = PolicyEngine::from_config_with_owner(
            &config.policy_path,
            config.max_result_age_secs,
            owner_policy,
        )?;

        Ok(Self {
            allowlist,
            policy_engine,
        })
    }

    fn reload(config: &Config, owner_policy: OwnerPolicy) -> anyhow::Result<Self> {
        let mut allowlist = Allowlist::new();
        allowlist.load_from_file_with_options(
            &config.allowlist_path,
            config.is_prod_mode(),
            owner_policy,
        )?;
        let policy_engine = PolicyEngine::from_config_with_owner(
            &config.policy_path,
            config.max_result_age_secs,
            owner_policy,
        )?;

        Ok(Self {
            allowlist,
            policy_engine,
        })
    }
}

pub async fn run_server(config: Arc<Config>) -> anyhow::Result<()> {
    let owner_policy = secure_owner_policy(&config)?;

    let rate_limiter = Arc::new(RateLimiter::new());

    let adapter_registry = Arc::new(AdapterRegistry::load_from_dir_with_owner(
        &config.adapters_dir,
        config.is_prod_mode(),
        owner_policy,
    )?);
    let reloadable = Arc::new(ArcSwap::from(Arc::new(ReloadableState::load(
        &config,
        owner_policy,
    )?)));
    if config.is_prod_mode() && !config.require_attestation {
        anyhow::bail!("OLA_REQUIRE_ATTESTATION cannot be disabled in prod mode");
    }
    let attester = Arc::new(AttestationVerifier::load_from_dir_with_owner(
        &config.adapter_keys_dir,
        owner_policy,
    )?);
    if config.require_attestation {
        attester.require_keys_for_adapters(adapter_registry.adapter_names())?;
    }
    let nonce_store = Arc::new(NonceStore::new());
    let audit_logger = Arc::new(AuditLogger::open(&config.audit_log_path, owner_policy)?);

    let state = ServerState {
        adapter_registry,
        reloadable,
        attester,
        nonce_store,
        audit_logger,
        rate_limiter,
        config: config.clone(),
        owner_policy,
    };

    let listener = setup_listener(&config)?;
    info!("Listening on {}", config.socket_path.display());

    systemd::notify_ready();
    systemd::spawn_watchdog();

    // Backpressure beats task explosion. Auth load should not saturate 16
    // concurrent sockets.
    let max_conns = Arc::new(Semaphore::new(MAX_CONNECTIONS));

    let mut sigint = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())
        .context("installing SIGINT handler")?;
    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .context("installing SIGTERM handler")?;
    let mut sighup = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())
        .context("installing SIGHUP handler")?;
    let mut tasks = JoinSet::new();

    loop {
        tokio::select! {
            _ = sigint.recv() => {
                info!("SIGINT received");
                break;
            }
            _ = sigterm.recv() => {
                info!("SIGTERM received");
                break;
            }
            _ = sighup.recv() => {
                info!("SIGHUP received, reloading config...");
                reload_state(&state);
            }
            accepted = listener.accept() => {
                let (stream, _addr) = match accepted {
                    Ok(s) => s,
                    Err(e) => {
                        error!("accept failed: {}", e);
                        metrics::inc_failures();
                        continue;
                    }
                };

                let permit = match max_conns.clone().acquire_owned().await {
                    Ok(p) => p,
                    Err(_) => break,
                };

                let state = state.clone();
                tasks.spawn(async move {
                    let _permit = permit;
                    metrics::inc_active_connections();
                    let result = handle_client(stream, state).await;
                    metrics::dec_active_connections();
                    if let Err(e) = result {
                        error!("client handling error: {:?}", e);
                        metrics::inc_failures();
                    }
                });
            }
            joined = tasks.join_next(), if !tasks.is_empty() => {
                if let Some(Err(e)) = joined {
                    error!("client task failed: {}", e);
                    metrics::inc_failures();
                }
            }
        }
    }

    info!("Shutting down listener...");
    let drain_secs = config.drain_secs;
    let drain = async {
        while let Some(joined) = tasks.join_next().await {
            if let Err(e) = joined {
                error!("client task failed during drain: {}", e);
                metrics::inc_failures();
            }
        }
    };
    if timeout(Duration::from_secs(drain_secs), drain)
        .await
        .is_err()
    {
        warn!(
            "drain timeout elapsed after {}s; aborting remaining client tasks",
            drain_secs
        );
        tasks.abort_all();
        while tasks.join_next().await.is_some() {}
    }

    metrics::log_metrics();
    Ok(())
}

fn reload_state(state: &ServerState) {
    // Build both first. If either file is bad, keep the old state.
    match ReloadableState::reload(&state.config, state.owner_policy) {
        Ok(new_state) => state.reloadable.store(Arc::new(new_state)),
        Err(e) => warn!("reload failed: {}", e),
    }

    if let Err(e) = state.audit_logger.reopen() {
        error!("audit log reopen failed: {:#}", e);
        metrics::inc_failures();
    }
}

fn secure_owner_policy(config: &Config) -> anyhow::Result<OwnerPolicy> {
    if nix::unistd::geteuid().is_root() || config.is_prod_mode() {
        let service_user = privilege::service_user_name();
        let Some(ola_user) = get_user_by_name(&service_user) else {
            if config.is_prod_mode() || nix::unistd::geteuid().is_root() {
                anyhow::bail!("service user {} not found", service_user);
            }
            return Ok(OwnerPolicy::RootOrCurrent);
        };
        return Ok(OwnerPolicy::RootOrUid(ola_user.uid()));
    }

    Ok(OwnerPolicy::RootOrCurrent)
}

fn new_line_codec() -> LinesCodec {
    LinesCodec::new_with_max_length(MAX_LINE_BYTES)
}

async fn handle_client(stream: UnixStream, state: ServerState) -> anyhow::Result<()> {
    // SO_PEERCRED before any read. An unauthenticated peer never reaches JSON.
    let creds = getsockopt(&stream, PeerCredentials)?;

    // Silent close leaks no allowlist shape.
    if !state.reloadable.load().allowlist.is_allowed(creds.uid()) {
        metrics::inc_failures();
        return Ok(());
    }

    let mut framed = Framed::new(stream, new_line_codec());
    let idle_timeout = Duration::from_secs(state.config.client_idle_timeout_secs);

    loop {
        let line_result = match timeout(idle_timeout, framed.next()).await {
            Ok(Some(line_result)) => line_result,
            Ok(None) => break,
            Err(_) => {
                warn!(
                    "closing idle client connection after {}s",
                    state.config.client_idle_timeout_secs
                );
                metrics::inc_idle_closes();
                break;
            }
        };
        metrics::inc_requests();
        let line = line_result?;

        // Use one loaded state for this request. The allowlist check and policy
        // decision must not come from different reloads.
        let reloadable = state.reloadable.load_full();
        if !reloadable.allowlist.is_allowed(creds.uid()) {
            metrics::inc_failures();
            return Ok(());
        }

        // Per-request rate limit. Persistent sockets must not bypass budget.
        if !state.rate_limiter.check(creds.uid(), RATE_LIMIT_PER_UID) {
            metrics::inc_failures();
            let resp = Response::error(None, "Rate limit exceeded");
            framed.send(serde_json::to_string(&resp)?).await?;
            return Ok(());
        }

        let req: Request = match serde_json::from_str(&line) {
            Ok(r) => r,
            Err(e) => {
                metrics::inc_failures();
                let resp = Response::error(None, format!("Invalid JSON: {e}"));
                framed.send(serde_json::to_string(&resp)?).await?;
                continue;
            }
        };

        if req.version != PROTOCOL_VERSION {
            metrics::inc_failures();
            let resp = Response::error(
                req.id,
                format!("Unsupported protocol version {}", req.version),
            );
            framed.send(serde_json::to_string(&resp)?).await?;
            continue;
        }

        let response = match req.method.as_str() {
            "ping" => Response::ok(
                req.id,
                serde_json::json!({ "ok": true, "version": env!("CARGO_PKG_VERSION") }),
            ),
            "status" => {
                let methods = state.adapter_registry.available_methods();
                Response::ok(
                    req.id,
                    serde_json::json!({
                        "status": "running",
                        "version": env!("CARGO_PKG_VERSION"),
                        "methods": methods,
                    }),
                )
            }
            "list_methods" => Response::ok(
                req.id,
                serde_json::json!(state.adapter_registry.available_methods()),
            ),
            "verify_once" => {
                let req_id = req.id;
                let caller_uid = creds.uid();
                let uid_result = request_uid(caller_uid, req.params.as_ref());
                let uid = match uid_result {
                    Ok(uid) => uid,
                    Err(msg) => {
                        metrics::inc_failures();
                        return Ok(framed
                            .send(serde_json::to_string(&Response::error(req_id, msg))?)
                            .await?);
                    }
                };

                let method = match request_method(req.params.as_ref()) {
                    Ok(method) => method,
                    Err(msg) => {
                        metrics::inc_failures();
                        return Ok(framed
                            .send(serde_json::to_string(&Response::error(req_id, msg))?)
                            .await?);
                    }
                };

                handle_verify_once(&state, &reloadable, caller_uid, uid, method, req_id).await
            }
            _ => {
                metrics::inc_failures();
                Response::error(req.id, "Unknown method")
            }
        };

        framed.send(serde_json::to_string(&response)?).await?;
    }
    Ok(())
}

fn request_uid(caller_uid: u32, params: Option<&serde_json::Value>) -> Result<u32, &'static str> {
    if caller_uid != 0 {
        return Ok(caller_uid);
    }

    let Some(value) = params.and_then(|p| p.get("uid")) else {
        return Err("root caller must supply params.uid");
    };
    let Some(uid) = value.as_u64() else {
        return Err("uid must be an unsigned integer");
    };
    if uid > u32::MAX as u64 {
        return Err("uid out of range");
    }

    Ok(uid as u32)
}

fn request_method(params: Option<&serde_json::Value>) -> Result<&str, &'static str> {
    let Some(params) = params else {
        return Ok("any");
    };
    let Some(object) = params.as_object() else {
        return Err("params must be an object");
    };
    let Some(value) = object.get("method") else {
        return Ok("any");
    };
    let Some(method) = value.as_str() else {
        return Err("params.method must be a string");
    };
    validate_method_name(method, true).map_err(|_| "params.method is invalid")?;
    Ok(method)
}

fn new_uuid() -> [u8; 16] {
    *uuid::Uuid::new_v4().as_bytes()
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

async fn write_audit_or_error(
    state: &ServerState,
    entry: AuditEntry,
    response_id: Option<String>,
) -> Result<(), Response> {
    if let Err(e) = state.audit_logger.log(entry).await {
        error!("audit failed: {:#}", e);
        metrics::inc_failures();
        return Err(Response::error(response_id, "audit failed"));
    }

    Ok(())
}

async fn audit_deny(
    state: &ServerState,
    entry: AuditEntry,
    response_id: Option<String>,
    client_reason: &str,
) -> Response {
    match write_audit_or_error(state, entry, response_id.clone()).await {
        Ok(()) => Response::deny(response_id, client_reason),
        Err(response) => response,
    }
}

// Critical path. Every Allow or Deny has a durable audit entry.
async fn handle_verify_once(
    state: &ServerState,
    reloadable: &ReloadableState,
    caller_uid: u32,
    uid: u32,
    method: &str,
    req_id: Option<String>,
) -> Response {
    let resolved = match state.adapter_registry.resolve(method) {
        Ok(resolved) => resolved,
        Err(e) => {
            let reason = e.to_string();
            return audit_deny(
                state,
                AuditEntry::deny(caller_uid, uid, method, &reason, None, req_id.clone(), None),
                req_id.clone(),
                &reason,
            )
            .await;
        }
    };
    let adapter_name = resolved.adapter_name.clone();
    let resolved_method = resolved.method.clone();

    // No nonce, no replay defense.
    let nonce = match state.nonce_store.generate(uid) {
        Ok(n) => n,
        Err(e) => {
            let reason = nonce_reason(&e);
            return audit_deny(
                state,
                AuditEntry::deny(
                    caller_uid,
                    uid,
                    &resolved_method,
                    reason,
                    Some(adapter_name.clone()),
                    req_id.clone(),
                    None,
                ),
                req_id.clone(),
                reason,
            )
            .await;
        }
    };

    let request = VerificationRequest {
        version: PROTOCOL_VERSION,
        id: new_uuid(),
        uid,
        nonce,
        deadline_ms: now_ms().saturating_add(resolved.timeout_ms),
    };

    // Adapter work sits outside the trust boundary. Core verifies the result.
    let result = match state
        .adapter_registry
        .dispatch_resolved(&resolved, request.clone())
        .await
    {
        Ok(r) => r,
        Err(e) => {
            state.nonce_store.consume(&nonce, uid).ok();
            let reason = e.to_string();
            return audit_deny(
                state,
                AuditEntry::deny(
                    caller_uid,
                    uid,
                    &resolved_method,
                    &reason,
                    Some(adapter_name.clone()),
                    req_id.clone(),
                    None,
                ),
                req_id.clone(),
                &reason,
            )
            .await;
        }
    };

    if result.nonce != nonce {
        state.nonce_store.consume(&nonce, uid).ok();
        return audit_deny(
            state,
            AuditEntry::deny(
                caller_uid,
                uid,
                &resolved_method,
                "nonce_mismatch",
                Some(adapter_name.clone()),
                req_id.clone(),
                Some(&result),
            ),
            req_id.clone(),
            "nonce mismatch detected",
        )
        .await;
    }

    // Late adapter work spends the nonce, denies.
    if now_ms() > request.deadline_ms {
        state.nonce_store.consume(&nonce, uid).ok();
        return audit_deny(
            state,
            AuditEntry::deny(
                caller_uid,
                uid,
                &resolved_method,
                "request_deadline_expired",
                Some(adapter_name.clone()),
                req_id.clone(),
                Some(&result),
            ),
            req_id.clone(),
            "request deadline expired",
        )
        .await;
    }

    // Spend nonce before HMAC. Replay must not become an attestation oracle.
    if let Err(e) = state.nonce_store.consume(&nonce, uid) {
        let reason = nonce_reason(&e);
        return audit_deny(
            state,
            AuditEntry::deny(
                caller_uid,
                uid,
                &resolved_method,
                reason,
                Some(adapter_name.clone()),
                req_id.clone(),
                Some(&result),
            ),
            req_id.clone(),
            "nonce replay detected",
        )
        .await;
    }

    // Dev mode can skip HMAC. Production rejects that at startup.
    if state.config.require_attestation {
        if let Err(e) = state.attester.verify(&adapter_name, &result) {
            let reason = attestation_reason(&e);
            return audit_deny(
                state,
                AuditEntry::deny(
                    caller_uid,
                    uid,
                    &resolved_method,
                    reason,
                    Some(adapter_name.clone()),
                    req_id.clone(),
                    Some(&result),
                ),
                req_id.clone(),
                "invalid evidence hash",
            )
            .await;
        }
    }

    if result.method.as_str() != resolved_method {
        return audit_deny(
            state,
            AuditEntry::deny(
                caller_uid,
                uid,
                &resolved_method,
                "method_mismatch",
                Some(adapter_name.clone()),
                req_id.clone(),
                Some(&result),
            ),
            req_id.clone(),
            "method mismatch",
        )
        .await;
    }

    // Policy is pure. Audit owns the side effect.
    let mut context = AuthContext {
        uid,
        method: resolved_method,
        request,
        result,
        decision: None,
    };
    let decision = reloadable.policy_engine.evaluate(&context);
    context.decision = Some(decision.clone());

    // No durable audit entry, no decision.
    if let Err(response) = write_audit_or_error(
        state,
        AuditEntry::from_decision(
            &context,
            &decision,
            caller_uid,
            Some(adapter_name),
            req_id.clone(),
        ),
        req_id.clone(),
    )
    .await
    {
        return response;
    }

    match decision {
        PolicyDecision::Allow => Response::allow(req_id, context.result.method.as_str()),
        PolicyDecision::Deny(reason) => Response::deny(req_id, &format!("{reason:?}")),
    }
}

fn nonce_reason(error: &NonceError) -> &'static str {
    match error {
        NonceError::NotFound => "nonce_not_found",
        NonceError::Expired => "nonce_expired",
        NonceError::UidMismatch => "nonce_uid_mismatch",
        NonceError::TableFull => "nonce_table_full",
        NonceError::TooManyForUid => "nonce_uid_limit",
        NonceError::StatePoisoned => "nonce_store_unavailable",
        NonceError::RandomUnavailable => "nonce_random_unavailable",
    }
}

fn attestation_reason(error: &AttestationError) -> &'static str {
    match error {
        AttestationError::UnknownAdapter => "attestation_unknown_adapter",
        AttestationError::HashMismatch => "attestation_hash_mismatch",
    }
}

#[cfg(test)]
#[path = "unix_socket_tests.rs"]
mod tests;
