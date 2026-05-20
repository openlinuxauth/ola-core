# pam_ola

Status: experimental.

`pam_ola.so` is the thin Linux-PAM bridge for OLA. It contains no policy, no hardware logic, and no
crypto. It sends one `verify_once` request to `ola-core` over a Unix socket and maps the core decision
to PAM:

- `allow` -> `PAM_SUCCESS`
- `deny` -> `PAM_PERM_DENIED`
- user lookup failure -> `PAM_USER_UNKNOWN`
- transport failure -> `PAM_AUTH_ERR`

Build:

```bash
cargo build --release
```

From the workspace root, the Cargo artifact is `target/release/libpam_ola.so`. Install it under your
system PAM module directory as `pam_ola.so`, then configure a PAM service with:

```text
auth required pam_ola.so socket=/run/ola/ola.sock method=fido2 timeout_ms=8000
```

`socket`, `method`, and `timeout_ms` are the only accepted module arguments. Unknown arguments make
the PAM call return an error. `method` uses OLA method-name rules. `timeout_ms` must be between `100`
and `30000`.

`auth required` is an example, not production guidance. `required` vs `sufficient` is a site policy
decision.

For a local non-installed demo, run:

```bash
../../demos/run_pam_fido2_demo.sh
```
