#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

REPO_ROOT="$(cd "$(dirname "$(realpath "$0")")/.." && pwd)"
TMP_DIR="$(mktemp -d -t ola-pam-demo-XXXXXX)"
TARGET_DIR="$REPO_ROOT/target"
CORE_PID=""
ADAPTER_PID=""

cleanup() {
  if [ -n "$CORE_PID" ]; then kill "$CORE_PID" 2>/dev/null || true; fi
  if [ -n "$ADAPTER_PID" ]; then kill "$ADAPTER_PID" 2>/dev/null || true; fi
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT

SOCKET_PATH="$TMP_DIR/ola.sock"
ADAPTER_SOCKET="$TMP_DIR/fido2.sock"
POLICY_PATH="$TMP_DIR/policy.toml"
ADAPTERS_DIR="$TMP_DIR/adapters.d"
ADAPTER_KEYS_DIR="$TMP_DIR/adapter-keys"
AUDIT_LOG="$TMP_DIR/audit.log"
ADAPTER_KEY="$ADAPTER_KEYS_DIR/fido2.key"
PAM_MODULE="$TMP_DIR/pam_ola.so"

mkdir -p "$ADAPTERS_DIR" "$ADAPTER_KEYS_DIR"

if command -v openssl >/dev/null 2>&1; then
  openssl rand -out "$ADAPTER_KEY" 32
else
  head -c 32 /dev/urandom > "$ADAPTER_KEY"
fi
chmod 600 "$ADAPTER_KEY"

cat > "$POLICY_PATH" <<'POLICY'
[[rules]]
method = "fido2"
min_confidence = 1.0
max_age_secs = 30
require_uid_match = true
POLICY
chmod 600 "$POLICY_PATH"

cat > "$ADAPTERS_DIR/fido2.toml" <<ADAPTER
name = "fido2"
socket_path = "$ADAPTER_SOCKET"
expected_uid = $(id -u)
methods = ["fido2"]
timeout_ms = 2000
ADAPTER
chmod 600 "$ADAPTERS_DIR/fido2.toml"

printf '== Building ola-core ==\n'
(cd "$REPO_ROOT" && cargo build --locked -p ola-core)

printf '== Building demo FIDO2 adapter ==\n'
(cd "$REPO_ROOT" && cargo build --locked -p ola-adapter-demo-fido2)

printf '== Building pam_ola.so ==\n'
(cd "$REPO_ROOT" && cargo build --locked --release -p pam-ola)
cp "$TARGET_DIR/release/libpam_ola.so" "$PAM_MODULE"

printf '== Starting demo adapter ==\n'
"$TARGET_DIR/debug/ola-adapter-demo-fido2" \
  --socket "$ADAPTER_SOCKET" \
  --key "$ADAPTER_KEY" \
  --method fido2 \
  --confidence 1.0 &
ADAPTER_PID=$!

for _ in $(seq 1 50); do
  [ -S "$ADAPTER_SOCKET" ] && break
  sleep 0.05
done
if [ ! -S "$ADAPTER_SOCKET" ]; then
  echo "Adapter socket was not created: $ADAPTER_SOCKET" >&2
  exit 1
fi

printf '== Starting ola-core ==\n'
OLA_RUNMODE=dev \
OLA_SOCKET_PATH="$SOCKET_PATH" \
OLA_AUDIT_LOG_PATH="$AUDIT_LOG" \
OLA_POLICY_PATH="$POLICY_PATH" \
OLA_ADAPTERS_DIR="$ADAPTERS_DIR" \
OLA_ADAPTER_KEYS_DIR="$ADAPTER_KEYS_DIR" \
RUST_LOG=info \
"$TARGET_DIR/debug/ola-core" &
CORE_PID=$!

for _ in $(seq 1 50); do
  [ -S "$SOCKET_PATH" ] && break
  sleep 0.05
done
if [ ! -S "$SOCKET_PATH" ]; then
  echo "Core socket was not created: $SOCKET_PATH" >&2
  exit 1
fi

printf '== Core status ==\n'
OLA_SOCKET="$SOCKET_PATH" python3 "$REPO_ROOT/clients/python/ola_client.py" status

printf '== verify_once through core -> adapter ==\n'
OLA_SOCKET="$SOCKET_PATH" python3 "$REPO_ROOT/clients/python/ola_client.py" verify_once fido2

printf '== PAM module artifact ==\n'
printf '%s\n' "$PAM_MODULE"
printf 'Example PAM line after installing as pam_ola.so:\n'
printf 'auth required pam_ola.so socket=%s method=fido2 timeout_ms=8000\n' "$SOCKET_PATH"

printf '== Audit log ==\n'
cat "$AUDIT_LOG"
