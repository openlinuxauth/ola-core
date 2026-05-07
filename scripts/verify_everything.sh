#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

echo "== OLA full verification =="
echo

need_file() {
  if [[ ! -e "$1" ]]; then
    echo "missing required path: $1" >&2
    exit 1
  fi
}

need_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "missing required command: $1" >&2
    exit 1
  fi
}

echo "-- required tools"
need_cmd bash
need_cmd cargo
need_cmd python3
need_cmd systemd-analyze
echo

echo "-- required files"
need_file scripts/generate_key.sh
need_file scripts/install_production.sh
need_file scripts/run_all_tests.sh
need_file scripts/verify_everything.sh
need_file demos/run_pam_fido2_demo.sh
need_file clients/python/ola_client.py
need_file dist/systemd/ola.service
need_file dist/systemd/ola.socket
echo

echo "-- shell syntax"
bash -n \
  scripts/generate_key.sh \
  scripts/install_production.sh \
  scripts/run_all_tests.sh \
  scripts/verify_everything.sh \
  demos/run_pam_fido2_demo.sh
echo

echo "-- main harness"
./scripts/run_all_tests.sh
echo

echo "-- doc tests"
cargo test --doc --workspace --all-features --locked
echo

echo "-- ignored performance tests (release profile)"
cargo test -p ola-core --test performance_test --release --locked -- --ignored --nocapture --test-threads=1
echo

echo "-- python client syntax"
tmp_pyc="$(mktemp /tmp/ola-client-pycompile.XXXXXX.pyc)"
trap 'rm -f "$tmp_pyc"' EXIT

python3 - <<PY
import py_compile
py_compile.compile("clients/python/ola_client.py", cfile="$tmp_pyc", doraise=True)
PY

rm -f "$tmp_pyc"
trap - EXIT
echo

echo "-- systemd unit verification"
systemd-analyze verify dist/systemd/ola.service dist/systemd/ola.socket
echo

echo "-- systemd hardening score"
systemd-analyze security --offline=yes dist/systemd/ola.service
echo

echo "-- PAM/FIDO2 demo"
./demos/run_pam_fido2_demo.sh
echo

echo "-- duplicate dependency report"
cargo tree --workspace --all-features --locked -d
echo

echo "== OLA full verification passed =="
