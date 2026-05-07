# ola-adapter-demo-fido2

Status: demo only. Not a real authenticator.

A hardware-free adapter that speaks the OLA adapter protocol and returns FIDO2-shaped verification
results. It is for demos and tests. It does not talk to a real authenticator.

The adapter reads a 32-byte HMAC key, listens on a Unix socket, receives a `VerificationRequest`, and
returns a signed `VerificationResult` with method `fido2` and confidence `1.0` by default.

Build:

```bash
cargo build
```

Run:

```bash
ola-adapter-demo-fido2 --socket /tmp/ola-demo-fido2.sock --key /tmp/fido2.key
```

The real hardware adapter keeps the adapter protocol and replaces only the demo response path with
`libfido2` assertion verification.
