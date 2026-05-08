## Summary

<!-- What changed, and why? Keep it tight. -->

## Type

- [ ] Bug fix
- [ ] Feature
- [ ] Breaking change
- [ ] Docs
- [ ] Refactor
- [ ] Tests
- [ ] Security hardening
- [ ] Maintenance

## Checklist

<!-- Check only what is true for this PR. Do not check a command unless it was run. -->

- [ ] `cargo fmt --all -- --check`
- [ ] Focused tests for the touched area
- [ ] `cargo clippy --workspace --all-targets --all-features --locked -- -D warnings`
- [ ] `cargo test --workspace --all-features --locked -- --test-threads=1`
- [ ] `cargo audit` and
      `cargo deny --manifest-path Cargo.toml --all-features --locked check --config deny.toml`
- [ ] `systemd-analyze verify dist/systemd/ola.service dist/systemd/ola.socket` when units changed
- [ ] Docs updated when behavior or public statements changed
- [ ] No secrets, keys, private notes, generated caches, or local-only files

## Testing

<!-- Commands run and result. Be exact. -->

## Boundary / Failure Mode

<!--
If this touches identity, evidence, policy, audit, nonces, attestation, privilege, adapter trust, PAM
behavior, file loading, install behavior, or public protocol/docs:

What could go wrong before this change?
What can no longer go wrong after it?
Which invariant is clearer?

If it does not touch a security boundary, say that directly.
-->

## Related Issues

<!-- Fixes #123, or None. -->
