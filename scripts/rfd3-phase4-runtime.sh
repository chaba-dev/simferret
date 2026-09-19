#!/usr/bin/env bash
# RFD 3 phase 4 guest-visible conformance tests.
#
# The conformance check assembles a real OCI layout, extracts its encoded guest
# template, and runs a workload that changes root and drops to nonzero
# credentials to observe the metadata it sees. That needs root (chroot, setuid,
# mknod for the runtime overlay), and the guest-wide cleanup barrier needs a
# private PID namespace. This script therefore runs the phase 4 test binary as
# PID 1 in a fresh PID namespace.
#
# Build the test binary as the invoking user first, then run this script as
# root. When cargo is available on root's PATH the script builds it itself.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if [[ "$(uname -s)" != "Linux" || "$(uname -m)" != "x86_64" ]]; then
  echo "The RFD 3 Phase 4 conformance tests support x86-64 Linux only." >&2
  exit 1
fi
if [[ "$(id -u)" -ne 0 ]]; then
  echo "The RFD 3 Phase 4 conformance tests require root (chroot, setuid, mknod)." >&2
  echo "Run: sudo env \"PATH=\$PATH\" SIMFERRET_BUSYBOX=\"\$SIMFERRET_BUSYBOX\" $0" >&2
  exit 1
fi
if [[ -z "${SIMFERRET_BUSYBOX:-}" ]]; then
  echo "SIMFERRET_BUSYBOX must name the pinned static busybox workload fixture." >&2
  exit 1
fi
if ! command -v unshare >/dev/null 2>&1; then
  echo "unshare is required for the guest-wide cleanup barrier." >&2
  exit 1
fi

binary="${SIMFERRET_PHASE4_TEST_BINARY:-}"
if [[ -z "$binary" ]]; then
  if ! command -v cargo >/dev/null 2>&1; then
    echo "cargo is not on PATH; set SIMFERRET_PHASE4_TEST_BINARY to the built test binary." >&2
    exit 1
  fi
  # Cargo writes the machine-readable messages to stdout and every diagnostic to
  # stderr, so the build's own output stays visible and a failure is reported
  # instead of silently leaving no binary behind.
  if ! binary="$(
    cargo test --manifest-path "$repo_root/Cargo.toml" --locked \
      --test rfd3_phase4 --no-run --message-format=json |
      python3 -c '
import json
import sys

for line in sys.stdin:
    try:
        message = json.loads(line)
    except ValueError:
        continue
    target = message.get("target", {})
    if (message.get("reason") == "compiler-artifact"
            and target.get("name") == "rfd3_phase4"
            and message.get("executable")):
        print(message["executable"])
' | tail -1
  )"; then
    echo "cargo could not build the RFD 3 Phase 4 test binary." >&2
    exit 1
  fi
fi
if [[ -z "$binary" || ! -x "$binary" ]]; then
  echo "Cannot locate the RFD 3 Phase 4 test binary." >&2
  exit 1
fi

umask 022
# A PID namespace gives the barrier a private process table and makes the test
# binary PID 1, which is the condition the guest-wide scope requires.
exec unshare --pid --fork --mount-proc "$binary" --test-threads=1
