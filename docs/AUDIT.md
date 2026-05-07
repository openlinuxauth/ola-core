# Audit

Status: local hash chaining is implemented. Root-resistant audit is planned.

Audit is part of the decision path.

If OLA cannot write the record, it should not return allow or deny.

## Current behavior

Every returned auth decision is written and synced before the daemon returns allow or deny.

Entries are JSON lines. Each entry has `prev_hash` and `entry_hash`.

The chain starts with a zero previous hash. Each new entry commits to the previous entry hash and the
current entry payload.

## What the chain proves

A verifier can detect line edits after a trusted checkpoint.

The local chain helps answer:

```text
Was this entry changed?
Was a line inserted?
Was a line removed after the checkpoint?
```

## What the chain does not prove

Local hash chaining does not stop root from deleting the log or rewriting the whole chain before
anyone checks it.

It gives local tamper evidence, not root-resistant storage.

## Next step

The next audit step is an external verifier and one checkpoint or export path: remote checkpointing,
remote signing, TPM anchoring, or log forwarding.

Do this before treating a second client as strong proof. A second client matters more when its records
can be checked outside the host.

## Rule

No audit, no decision.
