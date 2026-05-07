## Summary

<!-- What changed, and why? Keep it tight. -->

## Type

- [ ] Bug fix
- [ ] Feature
- [ ] Breaking change
- [ ] Docs
- [ ] Refactor
- [ ] Tests

## Checklist

- [ ] `cargo fmt --all -- --check`
- [ ] `cargo clippy --workspace --all-targets --all-features --locked -- -D warnings`
- [ ] `cargo test --workspace --all-features --locked -- --test-threads=1`
- [ ] `cargo audit` and
      `cargo deny --manifest-path Cargo.toml --all-features --locked check --config deny.toml`
- [ ] `systemd-analyze verify dist/systemd/ola.service dist/systemd/ola.socket` when units changed
- [ ] Docs updated when behavior or public statements changed
- [ ] No secrets, keys, or private notes

## Testing

<!-- Commands run and result. -->

## Boundary / Failure Mode

<!--
If this touches identity, evidence, policy, audit, nonces, attestation, privilege, adapter trust, PAM
behavior, or file loading:

What could go wrong before this change?
What can no longer go wrong after it?
Which invariant is clearer?
-->

## Related Issues

<!-- Fixes #123 -->
