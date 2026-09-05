#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
smoke="$repo_root/scripts/qemu-replay-smoke.sh"
test_root="$(mktemp -d "${TMPDIR:-/tmp}/simferret-qemu-smoke.XXXXXXXX")"
fake_qemu="$test_root/qemu-system-x86_64"
kernel="$test_root/bzImage"
trap 'rm -rf "$test_root"' EXIT

printf 'fake kernel\n' > "$kernel"
cat > "$fake_qemu" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

if [[ "${1:-}" == "--version" ]]; then
  echo "QEMU emulator version test"
  exit 0
fi

if [[ -n "${FAKE_QEMU_STARTED_FILE:-}" ]]; then
  touch "$FAKE_QEMU_STARTED_FILE"
fi

mode=""
replay_log=""
for argument in "$@"; do
  if [[ "$argument" == shift=auto,rr=*,rrfile=* ]]; then
    mode="${argument#*rr=}"
    mode="${mode%%,*}"
    replay_log="${argument#*rrfile=}"
  fi
done

if [[ "$mode" == "record" ]]; then
  printf 'fake replay log\n' > "$replay_log"
fi

case "${FAKE_QEMU_BEHAVIOR:-success}" in
  success) printf 'SIMFERRET_PHASE0_OK version=1\r\n' ;;
  mismatch)
    if [[ "$mode" == "record" ]]; then
      printf 'SIMFERRET_PHASE0_OK version=1\r\n'
    else
      printf 'SIMFERRET_PHASE0_DIFFERENT version=1\r\n'
    fi
    ;;
  missing-marker) printf 'SIMFERRET_PHASE0_MISSING version=1\r\n' ;;
  hang)
    trap '' TERM
    while true; do sleep 1; done
    ;;
  *) echo "unknown fake QEMU behavior" >&2; exit 2 ;;
esac
EOF
chmod +x "$fake_qemu"

run_smoke() {
  local output_root="$1"
  shift
  env \
    SIMFERRET_KERNEL="$kernel" \
    SIMFERRET_POC_OUTPUT="$output_root" \
    QEMU_SYSTEM_X86_64="$fake_qemu" \
    "$@" \
    "$smoke" >/dev/null 2>&1
}

preserved="$test_root/preserved"
mkdir -p "$preserved"
printf 'keep me\n' > "$preserved/sentinel"
run_smoke "$preserved"
test "$(cat "$preserved/sentinel")" = "keep me"
test "$(find "$preserved" -mindepth 1 -maxdepth 1 -type d -name 'run.*' | wc -l)" -eq 1

umask_root="$test_root/umask"
(umask 022; run_smoke "$umask_root")
(umask 077; run_smoke "$umask_root")
mapfile -t initramfs_images < <(
  find "$umask_root" -mindepth 2 -maxdepth 2 -name initramfs.cpio.gz | sort
)
test "${#initramfs_images[@]}" -eq 2
test "$(sha256sum "${initramfs_images[0]}" | cut -d' ' -f1)" = \
  "$(sha256sum "${initramfs_images[1]}" | cut -d' ' -f1)"

if run_smoke "$test_root/mismatch" FAKE_QEMU_BEHAVIOR=mismatch; then
  echo "mismatched replay output unexpectedly passed" >&2
  exit 1
fi

if run_smoke "$test_root/missing-marker" FAKE_QEMU_BEHAVIOR=missing-marker; then
  echo "missing guest marker unexpectedly passed" >&2
  exit 1
fi

for zero_duration in \
  SIMFERRET_QEMU_TIMEOUT=0 \
  SIMFERRET_QEMU_KILL_AFTER=0; do
  started_file="$test_root/${zero_duration%%=*}.started"
  if run_smoke "$test_root/zero-duration" \
    FAKE_QEMU_STARTED_FILE="$started_file" "$zero_duration"; then
    echo "$zero_duration unexpectedly passed" >&2
    exit 1
  fi
  if [[ -e "$started_file" ]]; then
    echo "$zero_duration started QEMU before validation" >&2
    exit 1
  fi
done

timeout_status_file="$test_root/timeout.status"
set +e
# The child shell expands the exported command and status-file paths.
# shellcheck disable=SC2016
SMOKE="$smoke" \
STATUS_FILE="$timeout_status_file" \
  SIMFERRET_KERNEL="$kernel" \
  SIMFERRET_POC_OUTPUT="$test_root/timeout" \
  SIMFERRET_QEMU_TIMEOUT=0.1s \
  SIMFERRET_QEMU_KILL_AFTER=0.1s \
  FAKE_QEMU_BEHAVIOR=hang \
  QEMU_SYSTEM_X86_64="$fake_qemu" \
  timeout --kill-after=1s 3s bash -c '
    set +e
    "$SMOKE" >/dev/null 2>&1
    printf "%s\n" "$?" > "$STATUS_FILE"
    exit 0
  '
watchdog_status=$?
set -e
if [[ "$watchdog_status" -ne 0 ]]; then
  echo "outer watchdog had to terminate the smoke test" >&2
  exit 1
fi
if [[ ! -f "$timeout_status_file" ]] || \
  [[ "$(cat "$timeout_status_file")" -ne 137 ]]; then
  echo "smoke test did not report QEMU's forced termination status" >&2
  exit 1
fi

printf 'QEMU replay smoke regression tests passed.\n'
