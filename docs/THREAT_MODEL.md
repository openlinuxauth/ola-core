# Threat Model

Status: this document describes the implemented daemon unless marked experimental or planned.

## Assets

- Authentication decisions.
- Adapter HMAC keys.
- Nonces.
- Policy file.
- UID allowlist.
- Audit log integrity.
- The daemon socket.

Secret-bearing conversation data is planned, not implemented.

## Trust boundaries

Client -> `ola-core`: local Unix socket. The client is not trusted to report its identity. The kernel
supplies UID through `SO_PEERCRED`.

`ola-core` -> adapter: local Unix socket. A socket path is not proof of adapter identity. The daemon
checks adapter UID and verifies an HMAC over the result.

Config files -> `ola-core`: local filesystem. Paths are not trusted. Sensitive loads use
`O_NOFOLLOW` and fd metadata checks to stop symlink swaps and wrong file types.

Policy -> decision: operator-managed TOML. A missing or malformed policy is a startup or reload error.
An unconfigured method fails closed.

Conversation data -> OLA: not implemented in v1. Current client requests do not carry PINs,
passphrases, or PAM conversation payloads. Any future secret-bearing path must define who sees the
secret, who consumes it, and how memory is cleared.

## Considerations

Local unprivileged process:

- Connects to the daemon socket without permission.
- Spoofs another UID in request JSON.
- Sends malformed JSON or oversized frames.
- Replays an old adapter result.
- Floods requests over one persistent connection.

Compromised or fake adapter process:

- Squats on an adapter socket path.
- Returns a result for the wrong UID.
- Replays a captured result.
- Substitutes confidence, method, UID, timestamp, or nonce after signing.

Filesystem attacker with partial write access:

- Replaces policy or allowlist with a symlink.
- Changes file modes.
- Points config at the wrong file type.

Operator error:

- Configures a method with no policy rule.
- Leaves attestation disabled in prod.
- Installs a key with the wrong owner or mode.

## Defenses

Kernel identity: `SO_PEERCRED` decides caller UID. Request JSON does not.

Allowlist first: unauthorized clients are closed before request parsing.

Bounded parsing: line framing has a max length. Oversized payloads fail at the codec layer.

Per-UID rate limit: rate limiting is per request, not per connection alone. Persistent clients cannot
bypass it. The UID table is capped so UID-rotation floods cannot grow it without bound.

Nonce replay defense: every adapter request gets a fresh nonce. The nonce must come back unchanged in
the signed result and is single-use.

Adapter attestation: each adapter has a key under `/etc/ola/adapter-keys`. The HMAC commits to nonce,
UID, method hash, confidence bits, and timestamp.

Method binding: the adapter result method must match the method selected by the registry. A valid
adapter key is not permission to substitute one configured method for another.

Policy fail-closed: no matching rule means deny. Duplicate rules fail policy load.

Hardened file loads: sensitive files reject symlinks, non-regular files, wrong modes, and wrong owners.

Audit path: allow and deny decisions are logged before return. Entries include `prev_hash` and
`entry_hash`. If write or sync fails, the daemon returns an internal error. Log rotation uses rename
plus `SIGHUP`, not `copytruncate`.

Seccomp after setup: the daemon applies the syscall filter after setup syscalls are done.

## Out of scope

Kernel compromise.

Root compromise before the daemon starts.

Physical attacks on authenticators.

Malicious firmware in a hardware authenticator.

Side-channel analysis of the local machine.

Root-resistant audit storage is not implemented. Local hash chaining detects line edits after the
fact, but remote shipping or protected checkpoints are still planned.

Remote fleet policy distribution is planned only.

## Known gaps

The PAM bridge is experimental. Do not put it in a real login stack yet.

The demo FIDO2-shaped adapter is not a real authenticator. It proves the adapter protocol only.

No secret-bearing conversation protocol exists yet. FIDO2 PINs, recovery passphrases, and similar data
need a new design before they enter the request shape.

No direct non-PAM client exists yet. Until then, OLA's wider role is still mostly proven through PAM
compatibility and protocol tests.

There is no external security audit yet.

Release signing and provenance are planned, not implemented.

No distro package exists yet.
