# Roadmap

Every item is tagged. Implemented means code exists in this repo. Experimental means it exists but is
not trusted for production. Planned means it is not implemented.

## Implemented

- Implemented: hardened local daemon request path.
- Implemented: v1 client and adapter protocol.
- Implemented: demo adapter proves adapter attestation and dispatch.
- Implemented: local audit hash chain.
- Experimental: PAM bridge demo path.

## Next proof

- Planned: real FIDO2 adapter using `libfido2`.
- Planned: enrollment and credential mapping for FIDO2.
- Planned: audit verifier for the existing hash chain.
- Planned: first audit hash export or checkpoint path.
- Planned: `ola-verify` CLI as the first direct non-PAM client.
- Planned: action-aware protocol v2 design.

## Action-Aware Decisions

- Planned: action field in request, policy, and audit records.
- Planned: action-specific rules for login, `sudo`, unlock, enrollment,
  recovery, and admin changes.
- Planned: sudo or sudo-rs integration research.
- Planned: screen-lock/unlock integration research.

## Production Readiness

- Planned: PAM bridge hardening and real sudo/login/display-manager test matrix.
- Planned: distro packaging.
- Planned: release signing and provenance.
- Planned: external security review.

## Later

- Planned: second real adapter when it proves the protocol works for more than one kind of evidence.
- Planned: fingerprint/fprintd-backed adapter.
- Planned: local-agent adapter.
- Planned: polkit integration exploration.
- Planned: fleet policy distribution.
- Planned: setup UI.

No date in this file is a promise. Dates belong in release issues once the work is scoped.
