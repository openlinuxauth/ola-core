# Vision

Status: this document describes the project direction. Current behavior is tracked in the README,
architecture, threat model, protocol, and roadmap.

Every new authenticator should not become another privileged island.

A FIDO2 key, a fingerprint reader, a local approval agent, and a fleet policy service should not each
invent a different answer to the same questions: who is asking, what evidence is fresh, what policy
applies, what gets logged, and what happens when the network is gone.

OLA exists to put those questions in one small local place.

PAM remains the deployment surface because PAM is already there. But PAM should not own modern
authentication logic. It should ask a local decision daemon and map the answer.

Adapters should not decide. They should produce bounded evidence.

`ola-core` should decide, deny by default, and leave a record.

Evidence crosses the boundary. Authority does not.

OLA is built for Linux machines where local privileged authentication decisions need clear policy and
records that can be checked later.

## What OLA is not

OLA is not a passwordless login project.

It is not a nicer PAM module.

It is not a hardware-authenticator wrapper.

Those can be pieces of the work. They are not the center.

The center is the boundary where evidence becomes a decision.

## The problem

Linux has a mature login stack. The extension model puts too much trust in too many places.

PAM modules can mix policy, hardware access, user interaction, network calls, and privileged decisions
inside code loaded by sensitive host processes. Each module becomes its own security boundary. Each
module has to solve caller identity, replay defense, audit shape, error handling, and local fallback
in its own way.

New authentication methods become hard to review, combine, and deploy across distributions. FIDO2,
fingerprints, face unlock, local agents, and fleet policy all need a common place to present evidence
and get a decision. Today, that place is missing.

## The split

OLA separates authentication evidence from authentication decisions.

Adapters produce bounded evidence. They do not own the final host decision.

`ola-core` checks the request, applies policy, and writes the decision record.

OLA does not replace PAM, polkit, SSSD, fprintd, or systemd-homed. Those boundaries are documented in
[Related Work](RELATED_WORK.md).

## Why PAM stays

PAM stays because it is already the deployment path.

OLA uses PAM as a bridge. It does not let PAM own the decision.

The first test is not whether OLA can call one authenticator. It is whether evidence, policy, and
audit stay in one narrow decision path.

## Why adapters do not decide

Authenticators can prove facts: possession of a credential, a biometric match, device presence, or a
local agent signal.

Those are evidence. They are not the host decision.

If each authenticator owns policy, replay handling, identity checks, fallback, and audit, each one
becomes a small authority. OLA rejects that shape.

## Why local still matters

Linux machines do not need cloud identity for every trust decision.

Offline access, recovery flows, privacy, research labs, developer machines, public-sector systems, and
constrained environments all need a local path.

Local-first does not mean isolated forever. It means the machine can make a bounded decision with
local evidence, local policy, and local audit. A fleet system can report or sync that state later.

## Why now

Authentication is changing faster than the Linux local auth stack.

Passkeys and FIDO2 made hardware-backed assertions normal. Biometric devices are common on laptops.
Local agents are becoming part of developer and admin workflows. Fleet policy is moving onto the
machine.

Without a shared local trust boundary, each authenticator has to become a privileged integration. OLA
gives authenticators a smaller target: produce evidence, bind it to a nonce and method, let the daemon
decide.

## What OLA can become

OLA can become a standard Linux layer for local authentication decisions.

The direction is a stable adapter protocol, a local decision daemon, direct clients, more evidence
adapters, audit checkpoints, distro packaging with conservative defaults, and fleet policy support.

The current repository starts smaller: a hardened local decision daemon, a documented adapter protocol,
a demo adapter, and an experimental PAM bridge.

## Why it matters

OLA is worth building because local authentication is a shared dependency.

The value is a smaller trusted surface: fewer privileged modules, one local decision path, explicit
policy, structured audit, and offline fallback.

## What support unlocks

Support should turn the prototype into reviewed, usable infrastructure.

The important milestones are real FIDO2, enrollment, audit verification and checkpoints, a non-PAM
client, action-aware policy, conformance tests, PAM hardening, packaging, release signing, and external
review.

The vision is large. Each public release stays narrow, documented, and verifiable.

## Principles

OLA keeps privileged code small.

Trust is explicit: caller identity comes from the kernel, adapter identity comes from socket
credentials and configured keys, and decisions come from policy.

Compatibility is not authority. PAM stays useful because it is deployed everywhere, but it does not
own the decision.

Audit is part of the product, not a debug stream.

Public statements are marked as implemented, experimental, planned, or directional.
