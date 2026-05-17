# Architecture

OLA (Open Linux Authentication) is built around one rule: PAM modules, desktop components, and
hardware drivers should not each get to decide authentication on their own.

Requests and evidence go to one local daemon. That daemon makes the decision, writes the record,
and can be tested in one place.

Evidence crosses the boundary. Authority does not.

## We cannot ignore PAM

PAM is everywhere. OLA is not trying to replace it.

Replacing PAM breaks deployment before the project earns trust. OLA keeps PAM as the
integration point and keeps the PAM bridge thin. PAM asks; `ola-core` decides.

## Relationship to polkit

polkit owns many privileged D-Bus service action checks. OLA's boundary is narrower: local
authentication evidence, policy, decision, and audit. A future polkit integration can ask `ola-core`
for stronger local authentication evidence.

## What runs where

Implemented:

- `ola-core` is the local decision daemon.
- Clients connect over a Unix stream socket.
- The daemon reads caller identity with `SO_PEERCRED`; clients cannot provide their own UID.
- Adapters run out of process and speak the adapter protocol over Unix sockets.
- Adapter ownership is checked with `SO_PEERCRED` before the daemon sends a nonce.
- Adapter health is checked with pings.
- Adapter results require valid HMAC attestation. Dev mode can explicitly disable this for local
mock adapters.

Experimental:

- `pam_ola.so` is a thin PAM bridge. It has no policy engine, no hardware logic, and no crypto.
It sends `verify_once` to `ola-core` and maps the answer to a PAM return code.

Planned, in priority order:

- Real FIDO2 adapter using `libfido2`
- Audit verifier and hash export
- Direct non-PAM client such as `ola-verify` or sudo/sudo-rs integration
- Action-aware protocol and policy
- PAM hardening and real sudo/login/screen-lock test matrix
- Distro packaging

## Secrets and conversation channel

Version 1 does not carry PINs, passphrases, recovery secrets, or PAM conversation payloads through
`ola-core`.

Current `verify_once` requests carry method and target UID. Adapter results carry evidence metadata,
confidence, timestamp, UID, nonce, and HMAC digest.

Future authenticators that need prompts or secrets need an explicit design before they are added. The
design must say who sees the secret, who consumes it, and what is cleared from memory.

## Request path

The `verify_once` path is where an auth request becomes a decision:

1. Accept a socket connection.
2. Read `SO_PEERCRED`.
3. Check the UID allowlist.
4. Close unauthorized clients before JSON parsing. These are not auth decisions and do not create
auth-decision audit entries.
5. Enforce line-size and per-UID rate limits.
6. Parse the line-delimited JSON request.
7. Check protocol version.
8. Resolve the request UID. Root callers must supply `params.uid`; there is no silent UID 0
fallback.
9. Resolve the requested method. `any` resolves to one available method.
10. Reject down adapters before sending a nonce.
11. Generate a single-use nonce.
12. Dispatch to an adapter by method.
13. Require the adapter result version to be `1`.
14. Require the adapter result ID to equal the request ID.
15. Match and consume the nonce.
16. Verify adapter HMAC attestation.
17. Require the result method to equal the registry-selected method.
18. Evaluate policy.
19. Write and sync an audit entry.
20. Return allow or deny. If audit fails, return an internal error instead of an auth decision.

Each step is ordered for a reason. Parse happens after kernel identity and allowlist checks.
The nonce is consumed before attestation and policy so the same challenge cannot be reused after a
failed attempt. Audit happens after policy because the log must record the decision that will be
returned. If the record cannot be written and synced, no auth decision is returned.

Socket permissions are the first gate. The daemon allowlist is the second gate. A UID in the
allowlist still cannot connect if Unix socket permissions block the process.

## Policy shape

Policy is a TOML rule table.

Rules can apply to one method or to all methods. The evaluator checks freshness, confidence, and whether
the adapter-reported UID must match the request UID.

Today policy answers a narrow question: is this method's evidence acceptable for this UID?

Future protocol versions should add action context so policy can separate login, `sudo`, unlock,
enrollment, recovery, and admin changes.

## Privilege and sandboxing

Under the systemd unit, the daemon starts as the `ola` user and receives its socket through socket
activation. Startup validates policy, adapter config, adapter keys, and audit-log access before the
listener accepts clients.

After listener setup, `ola-core` still runs its own privilege and sandbox path, including `NO_NEW_PRIVS`
and seccomp.

If run manually as root, the daemon prepares the socket directory as `0750` with the service group,
binds the socket, sets socket permissions, drops to the service user, clears capabilities, sets
`NO_NEW_PRIVS`, and applies seccomp before accepting clients.

The seccomp filter is allowlist-based. This document does not list syscall counts.
The source of truth is
[`crates/ola-core/src/security/seccomp.rs`](../crates/ola-core/src/security/seccomp.rs).

Counts change. Source does not.

## Sensitive file loading

Sensitive files are opened and checked through file descriptors, not by trusting the path after open.

Implemented checks include:

- `O_NOFOLLOW`
- `O_CLOEXEC`
- `fstat(fd)`
- regular-file check using `S_IFMT`
- strict mode checks
- root or service-user ownership checks where relevant

This applies to allowlist, policy, adapter configs, and adapter HMAC keys.

## Adapter lifecycle

`ola-core` does not spawn adapters today.

Adapters are separate processes with their own Unix sockets. Config tells `ola-core` the adapter name,
socket path, expected UID, methods, and timeout.

Each adapter has a 32-byte HMAC key by adapter name. Startup fails when attestation is required and a
configured adapter has no key.

If an adapter is down, has the wrong UID, misses the deadline, returns the wrong version or ID, returns
a nonce mismatch, or fails HMAC verification, `ola-core` rejects that result instead of trusting it.

## Audit

Every returned auth decision writes structured JSON to the audit log first. The log records who asked,
which UID was targeted, which adapter and method were used, the decision, the reason, and the audit
hash-chain fields.

Some requests fail before adapter evidence exists. Those entries still keep the same audit shape.

The log has a local hash chain. A verifier can detect line edits, but OLA does not yet make the log
safe from root.

The next audit step is an external verifier and a way to ship or checkpoint hashes outside the host.

If the write or sync fails, the daemon returns an internal error instead of returning allow or deny.

`SIGHUP` reloads policy and allowlist together and reopens the audit log for rotation. If either
file is invalid, the old policy and allowlist stay live.

## Future

`verify_once` is UID-and-method based today. That keeps version 1 small, but it cannot distinguish
login, `sudo`, unlock, enrollment, recovery, or admin changes.

The next architecture step is real evidence, a verifiable audit path, and a non-PAM client.

Until that client exists, OLA's wider role is still mostly proven through PAM compatibility and
protocol tests.
