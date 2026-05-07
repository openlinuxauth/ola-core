# Security Policy

OLA is security-sensitive code. Do not put exploitable details in public issues.

## Reporting

Use GitHub private vulnerability reporting for the upstream repository.

If that is not available, email openlinuxauth@gmail.com with the subject prefix `[SECURITY]`.

Encrypted mail is welcome. Ask for a PGP key first. Do not send vulnerability details until the
private channel is ready.

If neither path works, open a public issue that says only "private security report needed".

A maintainer will provide a private channel.

## What to include

Include:

- what component is affected
- what can go wrong
- how to reproduce it, if safe to share privately
- whether you believe the issue is already public

Do not include exploit code in public issues.

## Scope

In scope:

- `ola-core`
- The local client protocol
- The adapter protocol
- The demo adapter when the bug affects the protocol contract
- The experimental PAM bridge
- Installer, systemd, and permission mistakes that weaken the daemon

Out of scope:

- Third-party adapters not maintained here
- General Linux hardening questions
- Dependency advisories with no OLA-specific exploit path
- Social engineering, spam, or denial of service against GitHub itself

## Disclosure

The default disclosure window is 90 days from confirmed receipt.

That can move if a fix is ready earlier or coordination needs more time.

Credit is given unless the reporter asks otherwise.
