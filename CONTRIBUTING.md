# Contributing

OLA is small because the trust boundary is small.

A contribution is welcome when it makes that boundary clearer, safer, better tested, or easier to
operate. A contribution is not welcome just because it adds a feature.

If your change touches caller identity, adapter identity, policy, audit, nonces, attestation,
privilege, PAM behavior, or file loading, explain the failure mode. What could go wrong before this
change? What can no longer go wrong after it?

Keep PAM thin.
Keep adapters as evidence producers.
Keep policy in the daemon.
Keep future work out of the tree until it has behavior, tests, and docs.

## Before you change the boundary

Security-sensitive changes need a short note in the PR explaining what could go wrong and what the
change defends against.

Large refactors need an issue first. A refactor is welcome only when it makes a real invariant clearer
or removes real duplication. Moving code around for style alone is not useful here.

Protocol changes need an issue first. Version 1 is documented in [docs/PROTOCOL.md](docs/PROTOCOL.md);
adapters do not need to read Rust source to implement it.

## Run the gate

Run the same gate CI runs:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --all-features --locked -- --test-threads=1
cargo build --workspace --release --locked
```

For the full local gate:

```bash
./scripts/run_all_tests.sh
```

## Scope rules

Do not add code only to make the project look broader.

Do not put future work in the tree until it has behavior, tests, and docs.

Do not move policy into clients.

Do not make adapters authorities.

Do not make PAM carry more decision logic than it needs.

## Security-sensitive changes

If a change touches identity, evidence, policy, audit, replay defense, adapter trust, privilege
dropping, seccomp, file loading, key material, or PAM behavior, the PR must name the invariant.

Use plain language:

```text
Before this change, X could go wrong.
After this change, X fails closed because Y.
```

## Adapters

New adapters need a conformance plan: socket behavior, UID ownership, timeout behavior, attestation key
handling, method ownership, failure behavior, and test strategy.

One real adapter proves one adapter. A second real adapter is useful when it validates the protocol.
Adapter sprawl is not useful.

## Docs

Docs changes must preserve status labels: implemented, experimental, planned, or directional.

Do not turn future work into current behavior.

Do not add revenue projections, market-size claims, or pitch-deck language to technical docs.

If a doc names an adjacent project, be direct and non-defensive. OLA does not replace PAM, polkit,
SSSD, fprintd, or systemd-homed.

## License

By contributing, you agree that your contribution is licensed under
Apache-2.0.
