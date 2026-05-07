#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

RUN_PERF=0
RUN_AUDIT=1

while [[ "${1:-}" != "" ]]; do
  case "$1" in
    --perf) RUN_PERF=1 ;;
    --no-audit) RUN_AUDIT=0 ;;
    --help|-h)
      echo "Usage: $0 [--perf] [--no-audit]"
      exit 0
      ;;
    *) echo "Unknown arg: $1"; exit 2;;
  esac
  shift
done

REPO_ROOT="$(cd "$(dirname "$(realpath "$0")")/.." && pwd)"

echo "== OLA test harness starting at $(date) =="
echo "Repo root: $REPO_ROOT"
cd "$REPO_ROOT"

# Tests use unique sockets, but stale sockets from interrupted local runs are
# noise. Remove only the patterns this harness creates.
rm -f \
  /tmp/ola_test_*.sock \
  /tmp/ola_perf_test_*.sock \
  /tmp/ola_it_*.sock \
  /tmp/ola_pc_*.sock \
  /tmp/ola_pl_*.sock || true

TMP_DIR="$(mktemp -d -t ola-tests-XXXXXX)"
cleanup() {
  echo "== Cleaning up =="
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT

TMP_ALLOWLIST="$TMP_DIR/allowlist"

printf "100000\n100001\n" > "$TMP_ALLOWLIST"
chmod 600 "$TMP_ALLOWLIST"

export OLA_ALLOWLIST_PATH="$TMP_ALLOWLIST"
export OLA_RUNMODE="dev"

echo "Using OLA_ALLOWLIST_PATH=$OLA_ALLOWLIST_PATH"
echo "OLA_RUNMODE=$OLA_RUNMODE"

# Install the pinned toolchain when rustup is available. Non-fatal: CI installs
# the toolchain explicitly, and local users can manage it another way.
if command -v rustup >/dev/null 2>&1 && [ -f "$REPO_ROOT/rust-toolchain.toml" ]; then
  CHANNEL="$(sed -n 's/^[[:space:]]*channel[[:space:]]*=[[:space:]]*\"\([^"]*\)\".*$/\1/p' "$REPO_ROOT/rust-toolchain.toml" || echo "stable")"
  echo "rustup detected: installing toolchain $CHANNEL if needed"
  rustup toolchain install "$CHANNEL" || true
fi

echo "--> 1) cargo fmt --check"
if ! command -v cargo >/dev/null 2>&1; then
  echo "Error: cargo not found on PATH"; exit 2
fi
if ! cargo fmt --all -- --check; then
  echo "Run 'cargo fmt --all' to format the code."
  exit 1
fi

echo "--> 2) cargo clippy"
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings

echo "--> 3) cargo build"
cargo build --workspace --all-features --locked

echo "--> 4) cargo test"
# Tests mutate env vars and temp files; keep them single-threaded.
cargo test --workspace --all-features --locked -- --nocapture --test-threads=1

if [ "$RUN_PERF" -eq 1 ]; then
  echo "--> 5) ignored performance tests (release profile)"
  cargo test -p ola-core --test performance_test --release --locked -- --ignored --nocapture --test-threads=1
fi

echo "--> 6) cargo build --release"
cargo build --workspace --all-features --release --locked

CARGO_DENY_VERSION="${CARGO_DENY_VERSION:-0.18.9}"  # overrideable env var
if command -v cargo >/dev/null 2>&1; then
  INSTALLED_VERSION=""
  if command -v cargo-deny >/dev/null 2>&1; then
    INSTALLED_VERSION=$(cargo-deny --version | awk '{print $2}')
  fi

  if [ "$INSTALLED_VERSION" != "$CARGO_DENY_VERSION" ]; then
    echo "--> Installing cargo-deny v${CARGO_DENY_VERSION} (current: ${INSTALLED_VERSION:-none})"
    cargo install cargo-deny --version "$CARGO_DENY_VERSION" --force || true
  else
    echo "--> cargo-deny v$CARGO_DENY_VERSION is already installed"
  fi
fi

if [ "$RUN_AUDIT" -eq 1 ]; then
  if command -v cargo-deny >/dev/null 2>&1; then
    echo "--> 7) cargo-deny"
    cargo deny --manifest-path "$REPO_ROOT/Cargo.toml" --all-features --locked check --config "$REPO_ROOT/deny.toml" || {
      echo "cargo-deny check failed. See output above."
      if [ "${SKIP_CARGO_DENY:-0}" -eq 1 ]; then
        echo "SKIP_CARGO_DENY set; continuing despite cargo-deny failure."
      else
        exit 1
      fi
    }
  else
    echo "--> cargo-deny not available after install; skipping (set SKIP_CARGO_DENY=1 to ignore)"
  fi

  if command -v cargo-audit >/dev/null 2>&1; then
    echo "--> 8) cargo-audit"
    cargo audit
  else
    echo "--> Installing cargo-audit"
    cargo install cargo-audit
    echo "--> 8) cargo-audit"
    cargo audit
  fi
fi

echo "== All tests passed! =="
