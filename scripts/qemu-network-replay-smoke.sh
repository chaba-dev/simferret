#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
output_root="${SIMFERRET_NETWORK_OUTPUT:-$repo_root/.poc/qemu-network-replay-smoke}"
kernel="${SIMFERRET_KERNEL:-}"
kernel_modules="${SIMFERRET_KERNEL_MODULES:-}"
busybox="${SIMFERRET_BUSYBOX:-}"
qemu="${QEMU_SYSTEM_X86_64:-qemu-system-x86_64}"
cc="${CC:-cc}"
request_count="${SIMFERRET_NETWORK_REQUESTS:-1}"
qemu_timeout="${SIMFERRET_QEMU_TIMEOUT:-120s}"
qemu_kill_after="${SIMFERRET_QEMU_KILL_AFTER:-5s}"
output_dir=""
complete=false

report_incomplete() {
  if [[ "$complete" != true && -n "$output_dir" ]]; then
    echo "Network replay spike failed; diagnostics: $output_dir" >&2
  fi
}

trap report_incomplete EXIT

validate_positive_duration() {
  local name="$1"
  local value="$2"
  local pattern='^(([0-9]*[1-9][0-9]*)(\.[0-9]+)?|0*\.[0-9]*[1-9][0-9]*)[smhd]?$'

  if [[ ! "$value" =~ $pattern ]]; then
    echo "$name must be a finite, positive duration (for example, 5s or 0.1s)." >&2
    exit 1
  fi
}

require_file() {
  local name="$1"
  local path="$2"

  if [[ -z "$path" || ! -f "$path" ]]; then
    echo "$name must name a pinned regular file; run this script through .agents/dev." >&2
    exit 1
  fi
}

find_module() {
  local name="$1"
  local -a matches=()

  mapfile -t matches < <(find "$kernel_modules/lib/modules" -type f -name "$name.ko.xz" -print)
  if [[ "${#matches[@]}" -ne 1 ]]; then
    echo "Expected exactly one $name.ko.xz under SIMFERRET_KERNEL_MODULES." >&2
    exit 1
  fi
  printf '%s\n' "${matches[0]}"
}

if [[ "$(uname -s)" != "Linux" || "$(uname -m)" != "x86_64" ]]; then
  echo "The network replay spike supports x86-64 Linux only." >&2
  exit 1
fi
if [[ ! "$request_count" =~ ^[1-9][0-9]*$ ]] || ((request_count > 1000)); then
  echo "SIMFERRET_NETWORK_REQUESTS must be an integer from 1 through 1000." >&2
  exit 1
fi
validate_positive_duration SIMFERRET_QEMU_TIMEOUT "$qemu_timeout"
validate_positive_duration SIMFERRET_QEMU_KILL_AFTER "$qemu_kill_after"
require_file SIMFERRET_KERNEL "$kernel"
require_file SIMFERRET_BUSYBOX "$busybox"
if [[ -z "$kernel_modules" || ! -d "$kernel_modules/lib/modules" ]]; then
  echo "SIMFERRET_KERNEL_MODULES must name the pinned guest-kernel module output." >&2
  exit 1
fi
if [[ "$output_root" == *,* ]]; then
  echo "SIMFERRET_NETWORK_OUTPUT may not contain a comma because it enters a QEMU option." >&2
  exit 1
fi

for command in "$qemu" "$cc" cpio find gzip mktemp sha256sum timeout xz; do
  if ! command -v "$command" >/dev/null 2>&1; then
    echo "Required command not found: $command" >&2
    exit 1
  fi
done
for applet in cat cmp insmod ip mount poweroff readlink rm tftp; do
  if ! "$busybox" --list | grep -Fx "$applet" >/dev/null; then
    echo "Pinned BusyBox is missing required applet: $applet" >&2
    exit 1
  fi
done

mii_module="$(find_module mii)"
rtl8139cp_module="$(find_module 8139cp)"

umask 022
mkdir -p "$output_root"
output_dir="$(mktemp -d "$output_root/run.XXXXXXXX")"
rootfs="$output_dir/rootfs"
fixture="$output_dir/fixture"
replay_log="$output_dir/replay.bin"
initramfs="$output_dir/initramfs.cpio.gz"
mkdir -p "$rootfs/bin" "$rootfs/dev" "$rootfs/etc" "$rootfs/modules" \
  "$rootfs/proc" "$rootfs/sys" "$rootfs/tmp" "$fixture"

cp "$busybox" "$rootfs/bin/busybox"
cp "$repo_root/poc/phase0-network/init.sh" "$rootfs/init"
"$cc" -static -Os -Wall -Wextra -Werror \
  "$repo_root/poc/phase0-network/outage-probe.c" -o "$rootfs/bin/outage-probe"
xz --decompress --stdout "$mii_module" >"$rootfs/modules/mii.ko"
xz --decompress --stdout "$rtl8139cp_module" >"$rootfs/modules/8139cp.ko"
printf '%s\n' "$request_count" >"$rootfs/etc/simferret-request-count"
chmod 0755 "$rootfs/init" "$rootfs/bin/busybox" "$rootfs/bin/outage-probe"

for ((request_number = 1; request_number <= request_count; request_number++)); do
  printf -v request_id 'request-%06d' "$request_number"
  printf 'request_id=%s\npayload=payload-%06d\n' \
    "$request_id" "$request_number" >"$fixture/$request_id"
done

find "$rootfs" -exec touch -h -d @0 {} +
(
  cd "$rootfs"
  find . -print0 | LC_ALL=C sort -z | cpio --null --create --format=newc \
    --owner=0:0 --reproducible --quiet
) | gzip -n >"$initramfs"

common_args=(
  -machine "pc-i440fx-9.2,accel=tcg"
  -cpu qemu64
  -smp 1
  -m 256M
  -nodefaults
  -no-user-config
  -display none
  -monitor none
  -serial stdio
  -no-reboot
  -rtc "base=2000-01-01T00:00:00,clock=vm"
  -kernel "$kernel"
  -initrd "$initramfs"
  -append "console=ttyS0 quiet loglevel=0 panic=-1 nokaslr random.trust_cpu=off init=/init"
  -netdev "user,id=simnet,restrict=on,tftp=$fixture"
  -device "rtl8139,netdev=simnet,mac=52:54:00:12:34:56,bus=pci.0,addr=0x3,romfile="
  -object "filter-replay,id=simnet-replay,netdev=simnet,queue=all"
)

run_qemu() {
  local mode="$1"
  local serial_log="$2"
  local diagnostic_log="$3"
  local mode_replay_log="${4:-$replay_log}"
  local started finished

  started="$(date +%s%N)"
  timeout --kill-after="$qemu_kill_after" "$qemu_timeout" \
    "$qemu" "${common_args[@]}" \
    -icount "shift=auto,rr=$mode,rrfile=$mode_replay_log" \
    >"$serial_log" 2>"$diagnostic_log"
  finished="$(date +%s%N)"
  printf '%s\n' "$((finished - started))" >"$serial_log.duration-ns"
}

run_qemu record "$output_dir/record.serial" "$output_dir/record.qemu.log"
grep -Fx $'SIMFERRET_NETWORK_OUTAGE_OK errno=13\r' "$output_dir/record.serial" >/dev/null
grep -Fx "SIMFERRET_NETWORK_PHASE0_OK version=1 requests=$request_count"$'\r' \
  "$output_dir/record.serial" >/dev/null
if grep -E 'SIMFERRET_NETWORK_(INFRA|PROPERTY)_FAILURE' \
  "$output_dir/record.serial" >/dev/null; then
  echo "Network spike emitted a failure event." >&2
  exit 1
fi

rm -f "$fixture"/*
run_qemu replay "$output_dir/replay-1.serial" "$output_dir/replay-1.qemu.log"
run_qemu replay "$output_dir/replay-2.serial" "$output_dir/replay-2.qemu.log"

cmp "$output_dir/record.serial" "$output_dir/replay-1.serial"
cmp "$output_dir/record.serial" "$output_dir/replay-2.serial"

printf 'request_id=request-000001\npayload=corrupted\n' >"$fixture/request-000001"
SIMFERRET_EXPECT_PROPERTY_FAILURE=true run_qemu record \
  "$output_dir/corrupt.serial" "$output_dir/corrupt.qemu.log" \
  "$output_dir/corrupt-replay.bin"
grep -Fx \
  $'SIMFERRET_NETWORK_PROPERTY_FAILURE kind=response_mismatch request_id=request-000001\r' \
  "$output_dir/corrupt.serial" >/dev/null
if grep -F 'SIMFERRET_NETWORK_PHASE0_OK' "$output_dir/corrupt.serial" >/dev/null; then
  echo "Intentionally corrupted fixture unexpectedly passed." >&2
  exit 1
fi
rm -f "$fixture"/*

{
  printf 'qemu_version=%s\n' "$("$qemu" --version | head -n 1)"
  printf 'machine=pc-i440fx-9.2\n'
  printf 'cpu=qemu64\n'
  printf 'memory_mib=256\n'
  printf 'nic=rtl8139\n'
  printf 'nic_mac=52:54:00:12:34:56\n'
  printf 'nic_pci_address=0x3\n'
  printf 'nic_option_rom=disabled\n'
  printf 'record_backend=user,restrict=on,tftp=<run>/fixture\n'
  printf 'replay_backend=user,restrict=on,tftp=<run>/fixture-without-files\n'
  printf 'replay_filter=filter-replay,queue=all\n'
  printf 'request_count=%s\n' "$request_count"
  printf 'fixture_absent_during_replay=true\n'
  printf 'intentional_corruption_detected=true\n'
  printf 'kernel=%s\n' "$kernel"
  printf 'kernel_modules=%s\n' "$kernel_modules"
  printf 'busybox=%s\n' "$busybox"
  sha256sum "$kernel" "$busybox" "$mii_module" "$rtl8139cp_module" \
    "$rootfs/modules/mii.ko" "$rootfs/modules/8139cp.ko" \
    "$initramfs" "$replay_log" "$output_dir/corrupt-replay.bin" \
    "$output_dir/record.serial" "$output_dir/replay-1.serial" \
    "$output_dir/replay-2.serial" "$output_dir/corrupt.serial"
  printf 'record_duration_ns=%s\n' "$(cat "$output_dir/record.serial.duration-ns")"
  printf 'replay_1_duration_ns=%s\n' "$(cat "$output_dir/replay-1.serial.duration-ns")"
  printf 'replay_2_duration_ns=%s\n' "$(cat "$output_dir/replay-2.serial.duration-ns")"
  printf 'corrupt_record_duration_ns=%s\n' "$(cat "$output_dir/corrupt.serial.duration-ns")"
  printf 'initramfs_bytes=%s\n' "$(wc -c <"$initramfs")"
  printf 'replay_log_bytes=%s\n' "$(wc -c <"$replay_log")"
} >"$output_dir/evidence.txt"

cat "$output_dir/evidence.txt"
printf '\nNetwork record/replay spike passed; artifacts: %s\n' "$output_dir"
complete=true
