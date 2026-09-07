#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
smoke="$repo_root/scripts/qemu-network-replay-smoke.sh"
test_root="$(mktemp -d "${TMPDIR:-/tmp}/simferret-network-smoke.XXXXXXXX")"
fake_qemu="$test_root/qemu-system-x86_64"
fake_busybox="$test_root/busybox"
kernel="$test_root/bzImage"
modules="$test_root/modules/lib/modules/test/kernel/drivers/net"
trap 'rm -rf "$test_root"' EXIT

mkdir -p "$modules"
printf 'fake kernel\n' >"$kernel"
printf 'fake mii module\n' | xz >"$modules/mii.ko.xz"
mkdir -p "$modules/ethernet/realtek"
printf 'fake rtl8139cp module\n' | xz >"$modules/ethernet/realtek/8139cp.ko.xz"

cat >"$fake_busybox" <<'EOF'
#!/usr/bin/env bash
if [[ "${1:-}" == "--list" ]]; then
  printf '%s\n' cat cmp insmod ip mount poweroff readlink rm tftp
  exit 0
fi
exit 2
EOF

cat >"$fake_qemu" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

if [[ "${1:-}" == "--version" ]]; then
  echo "QEMU emulator version test"
  exit 0
fi
if [[ -n "${FAKE_QEMU_STARTED_FILE:-}" ]]; then
  touch "$FAKE_QEMU_STARTED_FILE"
fi
{
  echo '--- invocation'
  printf '%s\n' "$@"
} >>"$FAKE_QEMU_ARGUMENTS"

mode=""
replay_log=""
for argument in "$@"; do
  if [[ "$argument" == shift=auto,rr=*,rrfile=* ]]; then
    mode="${argument#*rr=}"
    mode="${mode%%,*}"
    replay_log="${argument#*rrfile=}"
  fi
done
if [[ "$mode" == record ]]; then
  printf 'fake replay log\n' >"$replay_log"
fi

emit_success() {
  printf 'SIMFERRET_NETWORK_DRIVER_OK driver=8139cp\r\n'
  printf 'SIMFERRET_NETWORK_REQUEST_OK request_id=request-000001 phase=before_outage\r\n'
  printf 'SIMFERRET_NETWORK_OUTAGE_OK errno=13\r\n'
  printf 'SIMFERRET_NETWORK_REQUEST_OK request_id=request-000001 phase=after_restoration\r\n'
  printf 'SIMFERRET_NETWORK_PHASE0_OK version=1 requests=1\r\n'
}

if [[ "${SIMFERRET_EXPECT_PROPERTY_FAILURE:-}" == true ]]; then
  printf 'SIMFERRET_NETWORK_PROPERTY_FAILURE kind=response_mismatch request_id=request-000001\r\n'
  exit 0
fi

case "${FAKE_QEMU_BEHAVIOR:-success}" in
  success) emit_success ;;
  mismatch)
    if [[ "$mode" == record ]]; then
      emit_success
    else
      printf 'SIMFERRET_NETWORK_REPLAY_DIVERGED\r\n'
    fi
    ;;
  missing-marker)
    printf 'SIMFERRET_NETWORK_OUTAGE_OK errno=13\r\n'
    ;;
  infrastructure-failure)
    printf 'SIMFERRET_NETWORK_INFRA_FAILURE kind=load_8139cp\r\n'
    ;;
  *) exit 2 ;;
esac
EOF
chmod +x "$fake_busybox" "$fake_qemu"

run_smoke() {
  local output_root="$1"
  shift
  env \
    SIMFERRET_BUSYBOX="$fake_busybox" \
    SIMFERRET_KERNEL="$kernel" \
    SIMFERRET_KERNEL_MODULES="$test_root/modules" \
    SIMFERRET_NETWORK_OUTPUT="$output_root" \
    FAKE_QEMU_ARGUMENTS="$test_root/qemu.arguments" \
    QEMU_SYSTEM_X86_64="$fake_qemu" \
    "$@" \
    "$smoke" >/dev/null 2>&1
}

preserved="$test_root/preserved"
mkdir -p "$preserved"
printf 'keep me\n' >"$preserved/sentinel"
: >"$test_root/qemu.arguments"
run_smoke "$preserved"
test "$(cat "$preserved/sentinel")" = "keep me"
run_dir="$(find "$preserved" -mindepth 1 -maxdepth 1 -type d -name 'run.*')"
test -n "$run_dir"
test -z "$(find "$run_dir/fixture" -type f -print -quit)"
test "$(grep -c '^--- invocation$' "$test_root/qemu.arguments")" -eq 4
test "$(grep -Fxc 'user,id=simnet,restrict=on,tftp='"$run_dir"'/fixture' \
  "$test_root/qemu.arguments")" -eq 4
test "$(grep -Fxc 'rtl8139,netdev=simnet,mac=52:54:00:12:34:56,bus=pci.0,addr=0x3,romfile=' \
  "$test_root/qemu.arguments")" -eq 4
test "$(grep -Fxc 'filter-replay,id=simnet-replay,netdev=simnet,queue=all' \
  "$test_root/qemu.arguments")" -eq 4
if awk '$0 == "-net" { getline; if ($0 == "none") found = 1 } END { exit !found }' \
  "$test_root/qemu.arguments"; then
  echo "network spike unexpectedly disabled networking" >&2
  exit 1
fi

umask_root="$test_root/umask"
: >"$test_root/qemu.arguments"
(umask 022; run_smoke "$umask_root")
(umask 077; run_smoke "$umask_root")
mapfile -t initramfs_images < <(
  find "$umask_root" -mindepth 2 -maxdepth 2 -name initramfs.cpio.gz | sort
)
test "${#initramfs_images[@]}" -eq 2
test "$(sha256sum "${initramfs_images[0]}" | cut -d' ' -f1)" = \
  "$(sha256sum "${initramfs_images[1]}" | cut -d' ' -f1)"

for behavior in mismatch missing-marker infrastructure-failure; do
  if run_smoke "$test_root/$behavior" "FAKE_QEMU_BEHAVIOR=$behavior"; then
    echo "$behavior unexpectedly passed" >&2
    exit 1
  fi
done

for request_count in 0 1001 invalid; do
  started_file="$test_root/request-$request_count.started"
  if run_smoke "$test_root/invalid-request" \
    "SIMFERRET_NETWORK_REQUESTS=$request_count" \
    "FAKE_QEMU_STARTED_FILE=$started_file"; then
    echo "invalid request count $request_count unexpectedly passed" >&2
    exit 1
  fi
  if [[ -e "$started_file" ]]; then
    echo "invalid request count $request_count started QEMU" >&2
    exit 1
  fi
done

started_file="$test_root/comma.started"
if run_smoke "$test_root/with,comma" "FAKE_QEMU_STARTED_FILE=$started_file"; then
  echo "comma-containing output path unexpectedly passed" >&2
  exit 1
fi
if [[ -e "$started_file" ]]; then
  echo "comma-containing output path started QEMU" >&2
  exit 1
fi

printf 'QEMU network replay smoke regression tests passed.\n'
