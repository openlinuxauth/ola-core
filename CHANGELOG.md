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

### Changed

- Restructured the repository as a root Cargo workspace.
- Moved crates under `crates/`.
- Switched public licensing metadata to Apache-2.0.
- Removed unwired future-work code from the daemon.

### Documentation

- Replaced stale private planning docs with public architecture, protocol, threat-model, install,
  roadmap, decision, and vision docs.
