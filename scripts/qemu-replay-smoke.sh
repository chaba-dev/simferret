#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
output_root="${SIMFERRET_POC_OUTPUT:-$repo_root/.poc/qemu-replay-smoke}"
kernel="${SIMFERRET_KERNEL:-}"
qemu="${QEMU_SYSTEM_X86_64:-qemu-system-x86_64}"
cc="${CC:-cc}"
qemu_timeout="${SIMFERRET_QEMU_TIMEOUT:-60s}"
qemu_kill_after="${SIMFERRET_QEMU_KILL_AFTER:-5s}"

if [[ "$(uname -s)" != "Linux" || "$(uname -m)" != "x86_64" ]]; then
  echo "The phase 0 replay spike supports x86-64 Linux only." >&2
  exit 1
fi

if [[ -z "$kernel" || ! -f "$kernel" ]]; then
  echo "SIMFERRET_KERNEL must name the pinned x86-64 Linux bzImage." >&2
  echo "Run this script through .agents/dev." >&2
  exit 1
fi

for command in "$qemu" "$cc" cpio gzip mktemp sha256sum timeout; do
  if ! command -v "$command" >/dev/null 2>&1; then
    echo "Required command not found: $command" >&2
    exit 1
  fi
done

umask 022
mkdir -p "$output_root"
output_dir="$(mktemp -d "$output_root/run.XXXXXXXX")"
replay_log="$output_dir/replay.bin"
initramfs="$output_dir/initramfs.cpio.gz"
mkdir -p "$output_dir/rootfs/dev"

"$cc" -static -Os -Wall -Wextra -Werror \
  "$repo_root/poc/phase0/init.c" -o "$output_dir/rootfs/init"
find "$output_dir/rootfs" -exec touch -h -d @0 {} +

(
  cd "$output_dir/rootfs"
  find . -print0 | LC_ALL=C sort -z | cpio --null --create --format=newc \
    --owner=0:0 --reproducible --quiet
) | gzip -n > "$initramfs"

common_args=(
  -machine "pc-i440fx-9.2,accel=tcg"
  -cpu qemu64
  -smp 1
  -m 128M
  -nodefaults
  -no-user-config
  -display none
  -monitor none
  -serial stdio
  -no-reboot
  -net none
  -rtc "base=2000-01-01T00:00:00,clock=vm"
  -kernel "$kernel"
  -initrd "$initramfs"
  -append "console=ttyS0 quiet loglevel=0 panic=-1 nokaslr random.trust_cpu=off init=/init"
)

run_qemu() {
  local mode="$1"
  local serial_log="$2"
  local diagnostic_log="$3"
  local started finished

  started="$(date +%s%N)"
  timeout --kill-after="$qemu_kill_after" "$qemu_timeout" \
    "$qemu" "${common_args[@]}" \
    -icount "shift=auto,rr=$mode,rrfile=$replay_log" \
    >"$serial_log" 2>"$diagnostic_log"
  finished="$(date +%s%N)"
  printf '%s\n' "$((finished - started))" > "$serial_log.duration-ns"
}

run_qemu record "$output_dir/record.serial" "$output_dir/record.qemu.log"
run_qemu replay "$output_dir/replay-1.serial" "$output_dir/replay-1.qemu.log"
run_qemu replay "$output_dir/replay-2.serial" "$output_dir/replay-2.qemu.log"

cmp "$output_dir/record.serial" "$output_dir/replay-1.serial"
cmp "$output_dir/record.serial" "$output_dir/replay-2.serial"
grep -Fx $'SIMFERRET_PHASE0_OK version=1\r' "$output_dir/record.serial" >/dev/null

{
  printf 'qemu_version=%s\n' "$("$qemu" --version | head -n 1)"
  printf 'machine=pc-i440fx-9.2\n'
  printf 'kernel=%s\n' "$kernel"
  sha256sum "$kernel" "$initramfs" "$replay_log" \
    "$output_dir/record.serial" "$output_dir/replay-1.serial" \
    "$output_dir/replay-2.serial"
  printf 'record_duration_ns=%s\n' "$(cat "$output_dir/record.serial.duration-ns")"
  printf 'replay_1_duration_ns=%s\n' "$(cat "$output_dir/replay-1.serial.duration-ns")"
  printf 'replay_2_duration_ns=%s\n' "$(cat "$output_dir/replay-2.serial.duration-ns")"
} > "$output_dir/evidence.txt"

cat "$output_dir/evidence.txt"
printf '\nPhase 0 record/replay passed; artifacts: %s\n' "$output_dir"
