# Related Work

Status: this document explains boundaries. It is not a feature comparison.

Today OLA is a local authentication decision daemon with an experimental PAM client.

It should be judged by that boundary.

## PAM

PAM is the authentication integration framework.

OLA uses PAM through `pam_ola.so`, but it does not replace PAM. PAM remains the compatibility layer
for login stacks that already depend on it.

## polkit

polkit is the authorization framework for many privileged D-Bus service actions.

OLA does not replace it. OLA focuses on authentication evidence, local policy, decision records, and
audit for local privileged authentication flows.

A future polkit integration would make polkit a client or integration point.

## pam-u2f

`pam-u2f` handles FIDO2/U2F inside PAM.

If OLA becomes only a FIDO2 PAM module, it is too small. OLA's FIDO2 adapter should prove something
different: real authenticator evidence entering the same core decision and audit path used by other
clients.

FIDO2 is evidence for OLA. It is not the product by itself.

## fprintd

`fprintd` is Linux fingerprint infrastructure and may be a future evidence source.

A future fingerprint adapter can use existing fingerprint support while keeping the final decision and
audit record in `ola-core`.

## SSSD

SSSD owns identity and directory-backed authentication in many enterprise deployments.

OLA should not become SSSD. It should not become an identity system, a directory cache, or an
enterprise login broker.

In environments that depend on SSSD, OLA's useful boundary is narrower: local evidence policy and
records auditors can check for privileged authentication decisions.

## systemd-homed

systemd-homed manages user records and home directories.

OLA does not own the user account. OLA owns the local authentication decision record.

Login and unlock flows can overlap with systemd-homed. That does not mean OLA should become user or
home management.

## sudo and sudo-rs

sudo is a high-value privileged-action path.

sudo/sudo-rs integration would prove a direct-client path outside PAM. It should be explored as an
integration or plugin path, not as a sudo replacement.
