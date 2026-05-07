#!/usr/bin/env bash
set -euo pipefail

if [ "${1:-}" = "" ]; then
    echo "Usage: $0 /etc/ola/adapter-keys/<adapter>.key" >&2
    exit 2
fi

KEY_PATH="$1"
OLA_USER="${OLA_USER:-ola}"
OLA_GROUP="${OLA_GROUP:-ola}"

echo "Generating 32-byte OLA adapter key at $KEY_PATH..."

DIR=$(dirname "$KEY_PATH")
if [ ! -d "$DIR" ]; then
    mkdir -p "$DIR"
    chown "root:$OLA_GROUP" "$DIR"
    chmod 750 "$DIR"
fi

TMP_KEY="$(mktemp "${DIR}/.ola-key.XXXXXX")"
cleanup() {
    rm -f "$TMP_KEY"
}
trap cleanup EXIT

umask 077
chmod 600 "$TMP_KEY"
dd if=/dev/urandom of="$TMP_KEY" bs=32 count=1 status=none

chown "$OLA_USER:$OLA_GROUP" "$TMP_KEY"
mv "$TMP_KEY" "$KEY_PATH"
trap - EXIT

echo "Key generated at $KEY_PATH (owner: $OLA_USER:$OLA_GROUP, mode: 0600)"
