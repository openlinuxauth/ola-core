# Install

Install support is experimental.

Rust builds use the toolchain pinned in `rust-toolchain.toml`.

This install path sets up `ola-core` and the systemd socket. It is still a prototype. Real FIDO2 support,
production PAM hardening, recovery, adapter service management, and external audit history are separate work.

## Development demo

Use the demo first. It makes no permanent system changes.

```bash
./demos/run_pam_fido2_demo.sh
```

The demo builds `ola-core`, the demo FIDO2-shaped adapter, and the PAM bridge. It runs from a
temporary directory, sends a `verify_once` request, prints the audit log, and removes the temporary
files when it exits.

## System install prototype

The installer writes to system paths and enables systemd socket activation.

Read it before running it.

```bash
sudo ./scripts/install_production.sh
```

The script name means production-style system paths. It does not mean OLA is production-ready.

It sets up:

- `ola` system user and group.
- `/usr/local/bin/ola-core`.
- `/etc/ola/allowlist`.
- `/etc/ola/policy.toml`.
- `/etc/ola/adapters.d`.
- `/etc/ola/adapter-keys`.
- `/var/log/ola`.
- `/etc/logrotate.d/ola`.
- `ola.service` and `ola.socket`.

Important: the installer does not install a real adapter or adapter config.

With production settings, `ola.service` is expected to fail until at least one adapter config and
matching HMAC key exist.

The installer builds the release binary with:

```bash
cargo build --release --locked -p ola-core
```

## Adapter configs

Adapter configs tell `ola-core` which adapter processes it can use.

`ola-core` will not start if the adapter config directory is missing, empty, invalid, or if a configured
adapter is missing its HMAC key.

Adapter configs live in:

```text
/etc/ola/adapters.d
```

Example:

```toml
name = "fido2"
socket_path = "/run/ola/adapters/fido2.sock"
expected_uid = 1001
methods = ["fido2"]
timeout_ms = 30000
```

Fields:

- `name`: adapter identity. The HMAC key must use this name.
- `socket_path`: Unix socket path for the adapter.
- `expected_uid`: UID that must own the adapter process.
- `methods`: method names handled by this adapter.
- `timeout_ms`: total budget for one adapter request in milliseconds. Valid range is `100` to
  `30000`.

Adapter names and method names may use ASCII letters, digits, `_`, `-`, or `.`. They must be at most
64 bytes.

`any` is reserved. Do not use it as an adapter name or method name.

One adapter can handle multiple methods. Two adapters cannot handle the same method.

Configured adapters must answer health pings. If an adapter is down, `ola-core` hides its methods from
`list_methods` and rejects requests before sending a nonce.

## Adapter keys

Adapter key filenames use the adapter name.

For the example above, the key path is:

```text
/etc/ola/adapter-keys/fido2.key
```

Generate one like this:

```bash
sudo ./scripts/generate_key.sh /etc/ola/adapter-keys/fido2.key
```

The generated key is 32 bytes, mode `0600`, and owned by the `ola` user and
group by default.

The secure loader accepts key files owned by root or by the service user.

## File modes

Trust files are checked at startup.

Expected modes:

- `/etc/ola/allowlist`: `0600` or `0640`
- `/etc/ola/policy.toml`: `0600` or `0640`
- adapter config files: not group-writable or world-writable
- adapter HMAC keys: `0600`

Files must be owned by root or by the service user, depending on the file.

## Audit log

The default audit log path is:

```text
/var/log/ola/audit.log
```

`ola-core` writes each returned auth decision to the audit log before returning allow or deny.

If the write or sync fails, it returns an internal error.

Audit entries are JSON lines. Full field details are in `PROTOCOL.md`.

Log rotation renames the audit log and sends `SIGHUP` to `ola.service`. The daemon reopens the audit
log on `SIGHUP`. It does not use `copytruncate`.

Keep log rotation enabled. Startup recovery reads only a bounded tail of the audit log.

The audit log has a local hash chain, but it is not safe from root by itself.

If audit history must survive local root access, ship the logs elsewhere or save checkpoints outside the
machine.

## Allowlist

Add one UID per line:

```text
1000
1001
```

Root and the service user are allowed by code. Normal users must be listed.

Installed allowlist path:

```text
/etc/ola/allowlist
```

## Socket access

The systemd socket is `/run/ola/ola.sock`, mode `0660`, owned by `ola:ola`.

The current install path is meant for PAM or another privileged or service-mediated caller. The
allowlist is checked after a process connects; it does not grant Unix socket access by itself.

## Policy

Installed policy lives at:

```text
/etc/ola/policy.toml
```

Rules without `method` apply to all methods. Add method-specific rules when different adapters need
different confidence or freshness requirements.

The default installed policy comes from:

```text
crates/ola-core/policies/default.toml
```

## Systemd

Validate unit files:

```bash
systemd-analyze verify dist/systemd/ola.service dist/systemd/ola.socket
```

If `/usr/local/bin/ola-core` has not been installed yet, `systemd-analyze` may
complain about the missing executable.

Start socket activation:

```bash
sudo systemctl enable --now ola.socket
```

Check service status:

```bash
sudo systemctl status ola.socket
sudo systemctl status ola.service
```

Inspect runtime logs:

```bash
sudo journalctl -u ola.service -n 100
```

Inspect the audit log:

```bash
sudo tail -f /var/log/ola/audit.log
```

## Common startup failures

Startup is strict.

`ola-core` can fail before accepting clients if:

- the allowlist cannot be loaded
- the policy cannot be loaded
- `/etc/ola/adapters.d` is missing or empty
- an adapter config is invalid
- two adapters claim the same method
- attestation is disabled with production settings
- a configured adapter is missing its HMAC key
- the audit log cannot be opened safely

Bad trust files should fail startup instead of becoming a hidden per-request problem.

On `SIGHUP`, policy and allowlist reload together. A bad edit does not partially apply.
