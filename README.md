# OLA

Linux authentication trusts too many places.

OLA starts from one question: where should the authentication decision live on a local machine?

PAM is everywhere, and that is why OLA does not try to replace it. PAM stays as the compatibility
layer. The mistake is asking every PAM module, authenticator, desktop component, and local agent to
become its own decision point.

OLA draws one smaller boundary.

- Clients ask.
- Adapters bring evidence.
- `ola-core` decides.
- The decision is audited.

Evidence crosses the boundary. Authority does not.

The current repository proves the core path: Unix-socket IPC, kernel-set caller identity, adapter
dispatch, single-use nonces, HMAC-bound evidence, policy evaluation, audit logging, rate limits,
seccomp hardening, an experimental PAM bridge, and a demo FIDO2-shaped adapter.

It is not production-ready.

The core trust path exists. Real hardware authentication does not. The PAM bridge is experimental.
Packaging is planned. The project is public now so the boundary can be read, tested, broken, and
improved before the project says more than the code proves.

![License](https://img.shields.io/badge/license-Apache--2.0-green.svg)
![Rust](https://img.shields.io/badge/rust-1.95.0-orange.svg)

## The boundary

OLA is a local authentication decision daemon for Linux.

Its boundary is narrow: clients ask, adapters bring evidence, `ola-core` applies local policy,
writes the audit record, and returns allow or deny.

It can later grow toward action-aware authentication decisions for privileged flows. That does not
make it a PAM or polkit replacement.

Adjacent Linux projects are covered in [Related Work](docs/RELATED_WORK.md).

## What exists today

This repository is an experimental public-release candidate.

| Component | Status | Notes |
| --- | --- | --- |
| `ola-core` daemon | Implemented | Hardened prototype with IPC, policy, attestation, audit, rate limits, nonce replay defense, and seccomp. |
| Adapter protocol | Implemented | Version 1 exists and is documented. Treat it as stable for this repo's demo slice, not as a standards-track spec yet. |
| Demo FIDO2-shaped adapter | Demo only | Hardware-free adapter for tests and demos. It is not a real authenticator. |
| PAM bridge | Experimental | Thin `pam_ola.so` bridge. Useful for the demo path; not ready for host login stacks. |
| Real FIDO2 adapter | Planned | Planned around the adapter protocol and `libfido2`. |
| `ola-verify` CLI | Planned | First direct non-PAM client. |
| Action-aware protocol | Planned | Needed for login, sudo, unlock, enrollment, recovery, and admin changes. |
| Audit export/checkpoints | Planned | Needed before local hash chains can support root-resistant audit use. |
| Fingerprint adapter | Planned | Not implemented. |
| Agent adapter | Planned | Not implemented. |
| Setup UI | Planned | Not implemented. |
| Distro packaging | Planned | Not implemented. |

The demo builds the PAM bridge and exercises the v1 path through `ola-core`, the demo adapter, policy, and audit.

It does not prove real hardware authentication, action context, root-resistant audit, or a direct
non-PAM client.

## What does not exist yet

Missing pieces include production FIDO2, enrollment, a secret-bearing conversation protocol, a direct
non-PAM client, sudo/sudo-rs or polkit integration, root-resistant audit checkpointing, and distro
packaging.

Do not put OLA in a real login stack yet.

## How to judge the project

Do not judge this repository by the number of authenticators it supports today.

Judge the boundary: evidence enters, policy decides, audit records the answer, and future claims stay
marked as future work.

## Read next

- [Vision](docs/VISION.md) - why OLA exists
- [Architecture](docs/ARCHITECTURE.md)
- [Threat Model](docs/THREAT_MODEL.md)
- [Protocol](docs/PROTOCOL.md)
- [Audit](docs/AUDIT.md)
- [Related Work](docs/RELATED_WORK.md)
- [Install](docs/INSTALL.md)
- [Roadmap](docs/ROADMAP.md)
- [Decisions](docs/DECISIONS.md)
- [Contributing](CONTRIBUTING.md)
- [Security](SECURITY.md)

## Run the demo

The demo makes no permanent system changes. It builds the workspace, starts a short-lived core daemon
and demo adapter, sends one `verify_once`, and prints the audit log.

```bash
./demos/run_pam_fido2_demo.sh
```

## Build the gate

Rust is pinned to `1.95.0` in `rust-toolchain.toml`. Use that toolchain for development, CI, and
release builds.

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --all-features --locked -- --test-threads=1
cargo build --workspace --release --locked
```

The project also ships a local harness:

```bash
./scripts/run_all_tests.sh
```

Full local verification, including doctests, ignored performance tests, systemd checks, the PAM/FIDO2
demo, and duplicate dependency reporting:

```bash
./scripts/verify_everything.sh
```

## Repository shape

```text
crates/ola-core/                 local decision daemon
crates/pam-ola/                  experimental PAM bridge
crates/ola-adapter-demo-fido2/   demo adapter, not real hardware
clients/python/
demos/
dist/
docs/
scripts/
```

## License and marks

Code is licensed under Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).

OLA and Open Linux Authentication are project marks. Code is open source; the name is not. See
[TRADEMARK.md](TRADEMARK.md).
