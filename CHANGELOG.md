# Changelog

This project follows Keep a Changelog style. GitHub Releases are the source of truth once public
releases exist.

## [Unreleased]

### Security

- Changed adapter attestation to commit to `sha256(method_string)` instead of an enum byte.
- Bound adapter HMAC keys to adapter names, not method names.
- Required HMAC keys for configured adapters when attestation is required.
- Rejected root callers that omit `params.uid`; no silent UID 0 fallback.
- Hardened policy loading with `O_NOFOLLOW`, fd metadata checks, mode checks, ownership checks, and
  size limits.
- Added systemd hardening for kernel logs, clocks, devices, runtime directory ownership, namespaces,
  memory execution, and kernel controls.
- Fixed PAM bridge return-code semantics for deny, unknown user, and transport failure.
- Made `SIGHUP` keep the old policy and allowlist if either reload fails.
- Made audit reopen wait for in-flight writes before carrying the hash forward.
- Hardened audit log recovery so startup reads the previous hash only after safe file checks.
- Made audit recovery reject malformed or hash-mismatched final audit entries.
- Made adapter `timeout_ms` apply to the whole adapter request instead of each I/O step.
- Randomized PAM bridge request IDs.
- Rejected invalid PAM bridge `method` and `timeout_ms` arguments.
- Rejected unknown PAM bridge arguments.
- Capped the rate limiter UID table.
- Required configured adapters to pass one health ping before their methods are listed or used.
- Clarified that the system installer uses production-style paths for a prototype.
- Tightened policy age-window overflow handling and Python socket-path fallback behavior.

### Changed

- Restructured the repository as a root Cargo workspace.
- Moved crates under `crates/`.
- Switched public licensing metadata to Apache-2.0.
- Removed unwired future-work code from the daemon.

### Documentation

- Replaced stale private planning docs with public architecture, protocol, threat-model, install,
  roadmap, decision, and vision docs.
