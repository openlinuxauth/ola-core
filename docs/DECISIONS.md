# Decisions

These are the decisions the project is currently built on.

These decisions came from the code and from removing parts that made the project less clear. They should change
only when the code gives a good reason.

## Apache-2.0 for public release

The project touches security, authentication, and code that uses cryptographic checks.

Apache-2.0 gives an explicit patent grant. That matters more here than having the shortest possible license.

MIT would be simpler. Apache-2.0 is clearer for distros, grant reviewers, and future commercial contributors.

## One repository for now

The ecosystem does not exist yet.

The core, PAM bridge, and demo adapter stay in one workspace until there are real external adapters and
real reasons to split them.

Splitting early would make the project harder to understand and harder to test.

## PAM compatibility

PAM is the deployment hook.

OLA keeps PAM in the path, but moves the risky decision work out of PAM modules.

Replacing PAM is not the goal.

## Do not replace polkit

polkit keeps owning those checks.

OLA may later give it stronger local authentication evidence.

## Adapter keys bind to adapter names

Keys bind to adapter identity, not method name.

One adapter can expose multiple methods. Method ownership is checked separately by the registry.

## HMAC commits to the exact method string

The HMAC includes `sha256(method_string)`, not an enum byte.

Custom methods must not collapse into one shared `other` value.

## No audit, no decision

`ola-core` returns allow or deny only after the audit entry is written and synced.

If audit fails, it returns an internal error. A missing record is a failed decision path, not a deny.

## Sensitive files use one loader

Security-sensitive checks should live in one loader where possible.

Open the file first, check the opened descriptor, and do not trust the path after open.

## Hardware stays outside the core

`ola-core` should not link `libfido2` or other hardware authenticator libraries.

Hardware code belongs in adapters.

Adapters produce evidence. `ola-core` decides.

## Root must name the target UID

Root callers must supply `params.uid`.

There is no silent UID 0 fallback. A privileged caller has to say who the decision is for.

## Production requires attestation

Unsigned adapter results are for dev mode only.

Production startup fails if attestation is disabled. Mock adapters should not teach the production path to
accept unsigned evidence.

## Down adapters do not receive nonces

Adapter health matters before authentication starts.

If an adapter is down, `ola-core` hides its methods and rejects requests for it before sending a nonce.

Configured adapters start unavailable. One successful health ping is required before their methods are
listed or used.

## `any` resolves once

`any` means the first available method after the registry has filtered out down adapters.

The method is resolved before the nonce is created. It should not change halfway through a decision.

## Action context is future protocol work

`verify_once` is enough for the first boundary, but not for the final shape.

OLA should decide authentication evidence for local privileged actions, not only whether a UID can use a
method. Login, `sudo`, unlock, enrollment, recovery, and admin changes need different policy and audit
records.

Action context belongs in the protocol, not hidden inside adapter-specific fields.

## A non-PAM client is required

PAM proves compatibility, not the whole architecture.

Before OLA is described as more than a PAM path, it needs `ola-verify`, sudo/sudo-rs integration, or a
future polkit bridge.

## Real evidence before production PAM

The next step should be a `libfido2` adapter, enrollment, credential mapping, CLI verification, and audit
records.

Debug that authenticator path outside PAM first.

Production PAM still needs hardening, a test matrix, and recovery work.

## Prove the evidence path before adapter sprawl

New adapters should not distract from proving evidence, policy, and audit with one real authenticator
and at least one non-PAM client.

A second real adapter is justified when it proves the protocol works for more than one kind of evidence.

## Do not write counts

Counts change.

Docs should not say how many syscalls, tests, or source files exist unless the number is generated during a
release.

Long-lived docs should point to the source, not freeze a number that will lie later.

## Don't ship dead work

Future work belongs in ROADMAP until it works.

No placeholder adapters. No fake implementations. No code that only exists to make the project look bigger.

The protocol can leave room for future methods. That is different from shipping features that do not exist.
