# Maintainers

OLA is maintained by Junaid Swati. Project contact: `openlinuxauth@gmail.com`.

The project is small on purpose. Scope is part of the security model.

The maintainer has final say on scope, security tradeoffs, release timing, and protocol compatibility
until a real multi-maintainer process exists.

Large refactors, new adapter classes, protocol changes, and security-sensitive changes start as an
issue before a PR.

Maintainers may reject useful work when it widens the trust boundary without a clear security reason.

The project should stay direct:

```text
clients ask
adapters bring evidence
ola-core decides
the decision is audited
```
