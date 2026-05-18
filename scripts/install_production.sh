#!/usr/bin/env bash
set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
  echo "Please run as root (sudo)." >&2
  exit 1
fi

echo ">>> Prototype install. This writes production-style system paths, but OLA is not production-ready."
echo ">>> It does not install a real adapter or make a safe login stack."

REPO_ROOT="$(cd "$(dirname "$(realpath "$0")")/.." && pwd)"
CORE_DIR="$REPO_ROOT/crates/ola-core"
BINARY_PATH="/usr/local/bin/ola-core"

echo ">>> Creating system group and user 'ola' if missing..."
if ! getent group ola >/dev/null; then
    groupadd --system ola
    echo "Created group 'ola'"
fi
if ! id -u ola >/dev/null 2>&1; then
    useradd --system --gid ola --no-create-home --shell /usr/sbin/nologin ola
    echo "Created user 'ola'"
fi

echo ">>> Preparing /etc/ola..."
mkdir -p /etc/ola
chown root:ola /etc/ola
chmod 750 /etc/ola

echo ">>> Preparing /etc/ola/policy.toml..."
if [ ! -f /etc/ola/policy.toml ]; then
    install -o root -g ola -m 0640 "$CORE_DIR/policies/default.toml" /etc/ola/policy.toml
    echo "Default policy installed."
else
    chown root:ola /etc/ola/policy.toml
    chmod 0640 /etc/ola/policy.toml
fi

echo ">>> Preparing /etc/ola/allowlist..."
if [ ! -f /etc/ola/allowlist ]; then
    touch /etc/ola/allowlist
    echo "# Add allowed UIDs here, one per line" > /etc/ola/allowlist
    chown root:ola /etc/ola/allowlist
    chmod 0640 /etc/ola/allowlist
    echo "Allowlist created."
else
    chown root:ola /etc/ola/allowlist
    chmod 0640 /etc/ola/allowlist
fi

echo ">>> Preparing /var/log/ola..."
mkdir -p /var/log/ola
chown ola:ola /var/log/ola
chmod 750 /var/log/ola

echo ">>> Preparing adapter directories..."
mkdir -p /etc/ola/adapters.d
mkdir -p /etc/ola/adapter-keys
chown root:root /etc/ola/adapters.d
chmod 755 /etc/ola/adapters.d
chown root:ola /etc/ola/adapter-keys
chmod 750 /etc/ola/adapter-keys

echo ">>> Building release binary..."
if [ ! -d "$CORE_DIR" ]; then
    echo "Core directory not found: $CORE_DIR" >&2
    exit 1
fi

cd "$REPO_ROOT"
echo "Building workspace package ola-core..."
cargo build --release --locked -p ola-core

echo ">>> Installing binary to $BINARY_PATH"
install -m 0755 "$REPO_ROOT/target/release/ola-core" "$BINARY_PATH"

echo ">>> Installing systemd units into /etc/systemd/system..."
cp "$REPO_ROOT/dist/systemd/ola.service" /etc/systemd/system/ola.service
cp "$REPO_ROOT/dist/systemd/ola.socket"  /etc/systemd/system/ola.socket

echo ">>> Installing logrotate config into /etc/logrotate.d/ola..."
install -o root -g root -m 0644 "$REPO_ROOT/dist/logrotate/ola" /etc/logrotate.d/ola

echo ">>> Reloading systemd and enabling socket..."
if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload
    systemctl enable --now ola.socket
    echo ">>> Restarting service (if active)..."
    systemctl restart ola.service || true

    echo ">>> Done. Check status with:"
    echo "  systemctl status ola.socket"
    echo "  systemctl status ola.service"
else
    echo ">>> Systemd not found. Manual start required."
    echo "  Run: OLA_RUNMODE=prod /usr/local/bin/ola-core"
fi
