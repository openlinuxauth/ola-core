# Protocol

Status: version 1 is implemented for this repository. It is stable enough for the demo adapter and
tests. It is not a standards-track specification.

## Encoding conventions

Transport is line-delimited JSON over Unix sockets. Each request or response is one JSON object
followed by `\n`.

Client request lines are capped at 512 KiB.

Adapter response lines are capped at 64 KiB.

Byte arrays are represented as JSON arrays of `u8` values. This document shows one full request and
one full result. Later examples use `[...]` where the shape is already clear.

Timestamps are Unix epoch milliseconds. Endian rules apply only to HMAC input, not to JSON fields.

## Names

Method names and adapter names are protocol identifiers. Use ASCII letters, digits, `_`, `-`, or `.`.

They must be at most 64 bytes.

`any` is only a client wildcard selector. It is not an adapter name or adapter method.

## Client protocol

Every client request includes `"version": 1`. The daemon rejects other versions.

`id` is optional. When present and the request is parsed, the daemon echoes it in the response.

Request shape:

```json
{"version":1,"id":"request-id","method":"method-name","params":{}}
```

Response shape:

```json
{"version":1,"id":"request-id","result":{},"error":null}
```

Errors use `error`. Authentication denies are not transport errors; they return
`result.decision = "deny"`.

## Client methods

| Method | Purpose |
| --- | --- |
| `ping` | Check that the daemon is reachable. |
| `status` | Return daemon status, package version, and available methods. |
| `list_methods` | Return methods owned by adapters that are not down. |
| `verify_once` | Ask the daemon for one authentication decision. |

`ping`:

```json
{"version":1,"id":"1","method":"ping","params":{}}
```

Returns:

```json
{"version":1,"id":"1","result":{"ok":true,"version":"0.2.0"},"error":null}
```

`status`:

```json
{"version":1,"id":"1","method":"status","params":{}}
```

Returns:

```json
{"version":1,"id":"1","result":{"status":"running","version":"0.2.0","methods":["fido2"]},"error":null}
```

`methods` only includes methods whose adapters are not down.

`list_methods`:

```json
{"version":1,"id":"1","method":"list_methods","params":{}}
```

Returns:

```json
{"version":1,"id":"1","result":["fido2"],"error":null}
```

`verify_once` parameters:

- `method`: optional string. Defaults to `any`.
- `uid`: required only when caller UID is 0. Non-root callers cannot use this
  field to impersonate another user; the daemon uses `SO_PEERCRED`.

If `params` is present, it must be an object.

Root callers must supply `params.uid`. There is no silent UID 0 fallback.

Allow response:

```json
{"version":1,"id":"2","result":{"decision":"allow","method":"fido2"},"error":null}
```

Deny response:

```json
{"version":1,"id":"2","result":{"decision":"deny","deny_reason":"NoMatchingRule"},"error":null}
```

If audit logging fails, the daemon returns an error instead of returning allow or deny.

Version 1 `verify_once` has no action context. It answers only whether this UID can authenticate with
this method selector.

## Adapter protocol

Adapters use the same line-delimited JSON transport.

Adapters have two duties:
- answer health pings
- answer verification requests

Health ping:

```json
{"version":1,"method":"ping"}
```

Healthy response:

```json
{"version":1,"ok":true}
```

A successful ping marks the adapter up, including after earlier failures.

A failed ping first marks the adapter degraded. After three consecutive failed pings, the adapter
is marked down.

Down adapters are not listed and do not receive verification requests.

Core sends a `VerificationRequest`:

```json
{
  "version": 1,
  "id": [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],
  "uid": 1000,
  "nonce": [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],
  "deadline_ms": 1710000000000
}
```

Adapter returns a `VerificationResult`:

```json
{
  "version": 1,
  "id": [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],
  "confidence": 1.0,
  "method": "fido2",
  "timestamp_ms": 1710000000000,
  "uid": 1000,
  "nonce": [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],
  "evidence_hash": [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]
}
```

The result version must be `1`.

The result ID must equal the request ID.

The result nonce must equal the request nonce.

The result method must equal the method selected by the daemon's adapter
registry.

## Adapter keys

Each configured adapter has one 32-byte HMAC key:

```text
/etc/ola/adapter-keys/<adapter-name>.key
```

The daemon indexes keys by adapter name, not by method. One adapter can expose more than one method.

## HMAC input

The HMAC is HMAC-SHA256 over this exact byte sequence:

```text
nonce || uid_le || sha256(method_string_utf8) || confidence_f32_bits_le || timestamp_ms_le
```

`nonce` binds the result to one request and prevents replay.

`uid_le` binds the signed result to the adapter-reported UID. Policy can then require that UID to
match the request UID.

`sha256(method_string_utf8)` binds the exact method string. Custom methods do not collapse into one
shared `other` value.

`confidence_f32_bits_le` binds the score the policy engine evaluates.

`timestamp_ms_le` binds the timestamp field that policy evaluates; it prevents unsigned timestamp
mutation after signing. The HMAC proves key possession and field binding. It does not prove the
adapter told the truth.

The adapter writes the digest into `evidence_hash`. The daemon recomputes it and compares it in
constant time.

## Audit entries

Audit entries are JSON objects written one per line.

Each entry includes:

- `ts_ms`
- `request_id`
- `caller_uid`
- `uid`
- `adapter_name`
- `method`
- `decision`
- `deny_reason`
- `confidence`
- `evidence_hash`
- `nonce_prefix`
- `prev_hash`
- `entry_hash`

Entries without adapter evidence still include `confidence`, `evidence_hash`, and `nonce_prefix`.

For those entries, `confidence` is `0.0`, and the evidence hash and nonce prefix are empty strings.

## Audit hash chain

The daemon hashes each audit entry before writing it.

To avoid hashing the hash itself, `entry_hash` is empty when the hash is made.

The fields are hashed in the same order they appear in `AuditEntry`:

```text
ts_ms
request_id
caller_uid
uid
adapter_name
method
decision
deny_reason
confidence
evidence_hash
nonce_prefix
prev_hash
```

`prev_hash` is the previous line's `entry_hash`.

The first entry uses 64 zeroes.

On startup or log reopen, the daemon reads the last non-empty audit line. If it has a valid
`entry_hash`, the next entry uses that as `prev_hash`. If not, the daemon hashes the last line and
uses that hash.

This is a local hash chain. A verifier can detect line edits, but this does not make the log safe
from root.

If audit history must survive local root access, send the logs somewhere else or save checkpoints
outside the machine.

## Planned v2 direction

Version 2 should add action context without breaking version 1 clients.

The action should name why authentication is requested, for example `login`, `sudo`, `unlock`, `enroll`,
`recover`, or `admin-change`.

It belongs in the client request and audit record, not inside adapter fields.

Version 1 remains UID-and-method based.

## Versioning

Version 1 is the only implemented version.

Planned versioning rule:

- v2 is additive.
- Breaking changes need v3.
- Future daemons advertise supported versions in `status` before an external
  adapter ecosystem depends on multiple versions.
