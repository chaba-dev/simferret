#!/usr/bin/env bash
set -euo pipefail

# SimFerret host-input probe (RFD 4 Phase 0).
#
# The time-model probe establishes that guest time is reproducible. This probe
# establishes the complementary fact the product needs: whether the host can
# still drive the guest under a given model. It boots `poc/time-model/input-probe.c`
# as the guest init and reports whether the guest received the line the host
# wrote.
#
# The order of operations is the measurement, and the emulator's monitor is what
# makes it causal rather than timing-dependent. The guest has no poll limit, so a
# bounded guest window cannot close before the write. The probe stops the guest
# through the monitor, drains the output the guest produced before it stopped,
# writes the line, and resumes the guest: a stopped guest cannot poll and cannot
# produce output, so the polling it does after the resume is polling after the
# write, and no report read after the resume can be one the guest produced
# earlier. The probe then reads to the end of the emulator's output before it
# closes the pipe, so a delivery report that arrives during shutdown is
# classified rather than lost.
#
# `input=not-delivered` therefore means: the guest reported `READY`, produced a
# poll report after the resumed write, the write succeeded, the guest had not
# stopped polling for longer than the stall bound, and the emulator was still
# running when the wait expired and was stopped by this probe, with no delivery
# report seen before or during shutdown. The stall bound is a liveness heuristic
# rather than a proof, because a host stalled while consuming output cannot tell
# old progress from new; the ordering does not rest on it, because the monitor
# does.
#
# The pinned emulator carries the patch that makes this probe deliver: with
# `rr=record` and `sleep=off` alone, QEMU queues live serial input as a replay
# asynchronous event and delivers it only from `icount_account_warp_timer()`,
# which returns before `replay_async_events()`; the patch moves the flush ahead
# of the sleep check. The assertion the continuous-integration job runs expects
# delivery, and the probe is retained so the behaviour can be re-checked whenever
# the pinned QEMU or guest kernel changes.
#
# usage: time-model-input-probe.sh [--live] [--expect delivered|not-delivered] [icount-options]
#   --live            do not enable record/replay (the control that isolates
#                     replay from the model itself)
#   --expect RESULT   assert RESULT instead of reporting what was measured, so a
#                     change in QEMU's behaviour fails rather than passing
#                     unnoticed; the qemu-replay job asserts the known result
#   icount-options    defaults to the pinned model in
#                     poc/time-model/reference-host-values.txt
#
# SIMFERRET_INPUT_PROBE_WAIT is how long the guest is given to receive the line,
# in seconds. SIMFERRET_INPUT_PROBE_STALL is how long the guest may go without
# reporting a poll before the experiment is inconclusive rather than a
# non-delivery measurement, which keeps a guest that hung during the wait from
# being reported as one that kept polling. SIMFERRET_INPUT_PROBE_DRAIN bounds
# each of the two drains, in seconds. SIMFERRET_INPUT_PROBE_TIMEOUT is the
# emulator's own deadline and defaults to the wait plus a minute.
#
# The probe reports `input=delivered`, `input=not-delivered`, or
# `input=inconclusive`. Receiving the line is reported whatever else the
# experiment did, while `not-delivered` needs the whole ordering above: a guest
# that never reported `READY`, a host that could not write the line, a guest
# that produced no poll report after the write, a guest that stopped polling, an
# emulator that exited on its own, or a deadline that expired is inconclusive,
# and an inconclusive run satisfies no expectation. Configuration failures exit
# 2 before any run starts, and a failed measurement or assertion exits 1.

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
probe_source="$repo_root/poc/time-model/input-probe.c"
reference_file="${SIMFERRET_TIME_MODEL_REFERENCE:-$repo_root/poc/time-model/reference-host-values.txt}"
kernel="${SIMFERRET_KERNEL:-}"
qemu="${QEMU_SYSTEM_X86_64:-qemu-system-x86_64}"
static_cc="${SIMFERRET_STATIC_CC:-${CC:-cc}}"
output_root="${SIMFERRET_INPUT_PROBE_OUTPUT:-$repo_root/.poc/time-model-input-probe}"
qemu_kill_after_seconds="${SIMFERRET_QEMU_KILL_AFTER_SECONDS:-5}"
wait_seconds="${SIMFERRET_INPUT_PROBE_WAIT:-90}"
stall_seconds="${SIMFERRET_INPUT_PROBE_STALL:-20}"
drain_seconds="${SIMFERRET_INPUT_PROBE_DRAIN:-1}"
record=true
icount_options=""
expectation=""
guest_timeout=""

while (($# > 0)); do
  case "$1" in
    --live)
      record=false
      shift
      ;;
    --expect)
      if (($# < 2)); then
        echo "--expect needs a result: delivered or not-delivered." >&2
        exit 2
      fi
      if [[ "$2" != "delivered" && "$2" != "not-delivered" ]]; then
        echo "--expect must be delivered or not-delivered, not $2." >&2
        exit 2
      fi
      expectation="$2"
      shift 2
      ;;
    -*)
      echo "Unknown option: $1" >&2
      exit 2
      ;;
    *)
      if [[ -n "$icount_options" ]]; then
        echo "Only one icount-options argument is accepted, not $icount_options and $1." >&2
        exit 2
      fi
      icount_options="$1"
      shift
      ;;
  esac
done

if [[ -z "$icount_options" ]]; then
  if [[ ! -f "$reference_file" ]]; then
    echo "Time-model reference values not found: $reference_file" >&2
    exit 2
  fi
  if [[ "$(grep -c '^icount_options=' "$reference_file" || true)" -ne 1 ]]; then
    echo "$reference_file must record exactly one icount_options" >&2
    exit 2
  fi
  icount_options="$(sed -n 's/^icount_options=//p' "$reference_file")"
  if [[ -z "$icount_options" ]]; then
    echo "$reference_file records an empty icount_options" >&2
    exit 2
  fi
fi

if [[ "$(uname -s)" != "Linux" || "$(uname -m)" != "x86_64" ]]; then
  echo "The host-input probe supports x86-64 Linux only." >&2
  exit 2
fi
if [[ -z "$kernel" || ! -f "$kernel" ]]; then
  echo "SIMFERRET_KERNEL must name the pinned x86-64 Linux bzImage." >&2
  echo "Run this script through .agents/dev." >&2
  exit 2
fi
if [[ ! -f "$probe_source" ]]; then
  echo "Host-input probe source not found: $probe_source" >&2
  exit 2
fi
if [[ ! "$wait_seconds" =~ ^[1-9][0-9]*$ ]]; then
  echo "SIMFERRET_INPUT_PROBE_WAIT must be a whole number of seconds." >&2
  exit 2
fi
if [[ ! "$stall_seconds" =~ ^[1-9][0-9]*$ ]]; then
  echo "SIMFERRET_INPUT_PROBE_STALL must be a whole number of seconds." >&2
  exit 2
fi
if [[ ! "$drain_seconds" =~ ^[1-9][0-9]*$ ]]; then
  echo "SIMFERRET_INPUT_PROBE_DRAIN must be a whole number of seconds." >&2
  exit 2
fi
if [[ ! "$qemu_kill_after_seconds" =~ ^[1-9][0-9]*$ ]]; then
  echo "SIMFERRET_QEMU_KILL_AFTER_SECONDS must be a whole number of seconds." >&2
  exit 2
fi
# The emulator's own deadline is a safety net around the wait rather than a
# second opinion about it, so it is derived from the wait unless the caller sets
# one. A shorter one would end the experiment before the wait does and turn
# every not-delivered measurement into an inconclusive one.
guest_timeout_seconds="${SIMFERRET_INPUT_PROBE_TIMEOUT:-$((wait_seconds + 60))}"
if [[ ! "$guest_timeout_seconds" =~ ^[1-9][0-9]*$ ]] ||
  ((guest_timeout_seconds <= wait_seconds)); then
  echo "SIMFERRET_INPUT_PROBE_TIMEOUT must be a whole number of seconds greater" >&2
  echo "than SIMFERRET_INPUT_PROBE_WAIT, so the emulator's deadline is a safety" >&2
  echo "net around the wait rather than a second opinion about it." >&2
  exit 2
fi
for command in "$qemu" "$static_cc" cpio gzip mktemp python3; do
  if ! command -v "$command" >/dev/null 2>&1; then
    echo "Required command not found: $command" >&2
    exit 2
  fi
done

umask 022
# The guest and its initramfs are the experiment's inputs, so a failure to build
# them is a configuration error rather than a host that could not complete.
if ! mkdir -p "$output_root"; then
  echo "The host-input probe cannot create its output root: $output_root" >&2
  exit 2
fi
if ! output_dir="$(mktemp -d "$output_root/run.XXXXXXXX")"; then
  echo "The host-input probe cannot create a run directory under $output_root" >&2
  exit 2
fi
root="$output_dir/rootfs"
if ! mkdir -p "$root"; then
  echo "The host-input probe cannot create the guest root: $root" >&2
  exit 2
fi
if ! "$static_cc" -static -Os -Wall -Wextra -Werror "$probe_source" -o "$root/init"; then
  echo "The host-input guest did not compile with $static_cc; the experiment cannot start." >&2
  exit 2
fi
if ! find "$root" -exec touch -h -d @0 {} +; then
  echo "The host-input probe cannot normalize the guest root's timestamps." >&2
  exit 2
fi
if ! (
  cd "$root"
  find . -print0 | LC_ALL=C sort -z | cpio --null --create --format=newc \
    --owner=0:0 --reproducible --quiet
) | gzip -n >"$output_dir/initramfs.cpio.gz"; then
  echo "The host-input probe initramfs could not be built; the experiment cannot start." >&2
  exit 2
fi

# The monitor socket lives outside the run directory because a Unix socket path
# is length-limited and the run directory is nested under the caller's tree. Its
# location and the controller are checked here, so an unusable one is a
# configuration error before any run starts rather than an inconclusive
# experiment.
monitor_socket="${SIMFERRET_INPUT_PROBE_MONITOR:-${TMPDIR:-/tmp}/simferret-input-monitor.$$.sock}"
if (( ${#monitor_socket} > 100 )); then
  echo "SIMFERRET_INPUT_PROBE_MONITOR is too long for a Unix socket path: $monitor_socket" >&2
  exit 2
fi
monitor_directory="$(dirname "$monitor_socket")"
if [[ ! -d "$monitor_directory" || ! -w "$monitor_directory" ]]; then
  echo "The monitor socket directory is not writable: $monitor_directory" >&2
  exit 2
fi
if ! rm -f "$monitor_socket"; then
  echo "The monitor socket cannot be removed: $monitor_socket" >&2
  exit 2
fi
if ! python3 -c 'import json, socket' 2>/dev/null; then
  echo "The monitor controller (python3 with json and socket) is unavailable." >&2
  exit 2
fi

rr_options=""
if [[ "$record" == true ]]; then
  rr_options=",rr=record,rrfile=$output_dir/replay.bin"
fi

# SIGPIPE is ignored so that a write to an emulator that has already exited
# reports EPIPE instead of ending the probe; the write result is part of the
# measurement.
trap '' PIPE

coproc QEMU {
  exec "$qemu" \
    -machine "pc-i440fx-9.2,accel=tcg" \
    -cpu qemu64 \
    -smp 1 \
    -m 256M \
    -nodefaults \
    -no-user-config \
    -display none \
    -qmp "unix:$monitor_socket,server=on,wait=off" \
    -serial stdio \
    -no-reboot \
    -net none \
    -rtc "base=2000-01-01T00:00:00,clock=vm" \
    -kernel "$kernel" \
    -initrd "$output_dir/initramfs.cpio.gz" \
    -append "console=ttyS0 quiet loglevel=0 panic=-1 nokaslr random.trust_cpu=off init=/init" \
    -icount "$icount_options$rr_options" \
    2>"$output_dir/qemu.log"
}
# The coprocess variables are unset once it exits, so its pid and its
# descriptors are saved immediately: duplicating the descriptors into
# shell-owned ones keeps the pipes open under the read loop, where holding only
# the numbers would not.
qemu_pid="${QEMU_PID}"
exec {guest_output_fd}<&"${QEMU[0]}"
exec {host_input_fd}>&"${QEMU[1]}"

ready=false
delivered=false
wrote=false
write_ok=true
polls_reported=false
polls_after_write=false
output_ended=false
truncated=false
deadline_expired=false
ready_seconds=0
last_poll_seconds=$SECONDS
last_poll_iterations=0
inconclusive_reason=""
# A timed read returns the partial line it had read when it timed out, so the
# prefix is kept and prepended to the rest: a line split across two reads is one
# line, and dropping the prefix would lose the guest's report.
partial=""

# Consume one line of guest output: keep it for diagnostics and record what it
# says. Returns nonzero when the line ends the experiment (the guest received
# the line, or reported that its input ended).
consume_line() { # $1 line
  printf '%s\n' "$1" | tee -a "$output_dir/serial.log"
  case "$1" in
    *"GOT:hello-from-host"*)
      delivered=true
      return 1
      ;;
    *READY*)
      if [[ "$ready" != true ]]; then
        ready=true
        ready_seconds=$SECONDS
      fi
      ;;
    *WAITING*)
      polls_reported=true
      last_poll_seconds=$SECONDS
      last_poll_iterations="${1##*iterations=}"
      if [[ "$wrote" == true ]]; then
        polls_after_write=true
      fi
      ;;
    *EOF*|*POLL-ERROR*)
      inconclusive_reason="the guest reported $1"
      return 1
      ;;
  esac
  return 0
}

# Read one line. The status says what happened: 0 a complete line, 1 a timeout
# (the partial line is kept for the next read), 2 the emulator's output ended,
# and 3 the output ended in the middle of a report. The distinction matters,
# because only a clean end of output can support a non-delivery claim.
read_line() {
  local status=0

  line=""
  IFS= read -r -t 1 line <&"$guest_output_fd" || status=$?
  if ((status > 128)); then
    partial+="$line"
    line=""
    return 1
  fi
  line="$partial$line"
  partial=""
  if ((status != 0)); then
    if [[ -n "$line" ]]; then
      return 3
    fi
    return 2
  fi
  return 0
}

# The monitor is the out-of-band channel that makes the write's ordering causal
# rather than timing-dependent: a guest that is stopped cannot poll and cannot
# produce output, so anything it reports after it is resumed happened after the
# write. The command is acknowledged: the controller waits for the emulator's
# reply and reports success only when the emulator accepted it, so a `stop` that
# QEMU has not acted on cannot be mistaken for a stopped guest.
monitor_command() { # $1 command
  python3 - "$monitor_socket" "$1" <<'PYTHON'
import json
import socket
import sys

def read_message(connection, buffer):
    # QMP messages are newline-delimited, and one read can hold several.
    while b"\n" not in buffer:
        data = connection.recv(4096)
        if not data:
            return None, buffer
        buffer += data
    line, buffer = buffer.split(b"\n", 1)
    return json.loads(line.decode()), buffer

def read_reply(connection, buffer):
    # Commands are answered by a return or an error, but events such as STOP can
    # arrive between the command and its reply.
    while True:
        message, buffer = read_message(connection, buffer)
        if message is None or "event" not in message:
            return message, buffer

buffer = b""
connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
connection.settimeout(10)
try:
    connection.connect(sys.argv[1])
    greeting, buffer = read_message(connection, buffer)
    connection.sendall(b'{"execute": "qmp_capabilities"}\n')
    capabilities, buffer = read_reply(connection, buffer)
    connection.sendall((json.dumps({"execute": sys.argv[2]}) + "\n").encode())
    reply, buffer = read_reply(connection, buffer)
finally:
    connection.close()
if not isinstance(reply, dict) or "return" not in reply:
    print("the emulator did not accept %s: %r" % (sys.argv[2], reply), file=sys.stderr)
    sys.exit(1)
PYTHON
}

# Read the next line into `line` and keep the flags up to date. Returns 1 when
# there is nothing more to read (the output ended, in one piece or mid-report, or
# the emulator's deadline expired) and 0 when the caller should carry on. Whether
# an end of output is a finding depends on where it happened, so it is recorded
# rather than classified here: an end before the wait expired is not the same as
# the end the shutdown is supposed to produce.
next_line() {
  local status=0

  if ((SECONDS >= guest_deadline)); then
    deadline_expired=true
    inconclusive_reason="the emulator's deadline expired before the wait did"
    return 1
  fi
  read_line || status=$?
  case "$status" in
    0|1)
      return 0
      ;;
    2)
      output_ended=true
      return 1
      ;;
    *)
      truncated=true
      return 1
      ;;
  esac
}

# Write the line the guest is waiting for. The guest is stopped for the drain, the
# write, and the resume, so the write cannot land after polling stopped: the guest
# cannot poll while it is stopped, the drain leaves nothing buffered for the resume
# to confuse with post-write progress, and the polling it does after the resume is
# therefore polling after the write. Without that the ordering would rest on how the
# host happened to be scheduled.
write_line() {
  local drain_deadline=$((SECONDS + drain_seconds))

  if ! monitor_command stop; then
    inconclusive_reason="the emulator's monitor did not answer, so the write cannot be ordered"
    return 1
  fi
  # Drain until the pipe is empty at a single instant rather than for a fixed
  # time: the guest is stopped, so everything it produced is already there, and
  # an instant with nothing available is the boundary between what it produced
  # before the write and what it produces after the resume.
  while IFS= read -r -t 0 -u "$guest_output_fd"; do
    if ((SECONDS >= drain_deadline)); then
      inconclusive_reason="the guest's output did not go quiet before the line was written"
      return 1
    fi
    read_status=0
    read_line || read_status=$?
    if ((read_status == 1)) && [[ -z "$line" && -z "$partial" ]]; then
      # The availability check saw something, but no line followed: the pipe is
      # quiet, so the boundary between pre-write and post-write output is here.
      break
    fi
    if ((read_status == 2)); then
      inconclusive_reason="the emulator's output ended before the line was written"
      return 1
    fi
    if ((read_status == 3)); then
      inconclusive_reason="the emulator's output ended in the middle of a report"
      return 1
    fi
    if [[ -z "$line" ]]; then
      continue
    fi
    if ! consume_line "$line"; then
      return 1
    fi
  done
  if [[ -n "$partial" ]]; then
    # A report the guest had started before it stopped is still incomplete, so
    # the next line read would be a continuation rather than post-write output.
    inconclusive_reason="the guest's last report before the line was written is incomplete"
    return 1
  fi
  wrote=true
  if ! printf 'hello-from-host\n' >&"$host_input_fd" 2>/dev/null; then
    write_ok=false
  fi
  if ! monitor_command cont; then
    inconclusive_reason="the emulator's monitor did not answer, so the guest was not resumed"
    return 1
  fi
  return 0
}

deadline=$((SECONDS + wait_seconds))
guest_deadline=$((SECONDS + guest_timeout_seconds))
while ((SECONDS < deadline)); do
  if ! next_line; then
    # The output ending during the wait is not a result, and a report that was
    # cut off is not one either.
    if [[ "$truncated" == true ]]; then
      inconclusive_reason="the emulator's output ended in the middle of a report"
    elif [[ "$output_ended" == true && "$delivered" != true && -z "$inconclusive_reason" ]]; then
      inconclusive_reason="the emulator's output ended before the guest reported a result"
    fi
    break
  fi
  if [[ -z "$line" ]]; then
    continue
  fi
  if ! consume_line "$line"; then
    break
  fi
  if [[ "$ready" == true && "$wrote" != true && -z "$inconclusive_reason" ]]; then
    if ! write_line; then
      break
    fi
  fi
done

# Drain what is still in flight before stopping the emulator, so that a delivery
# report that arrived at the end of the wait is classified rather than lost to
# the shutdown.
drain_deadline=$((SECONDS + drain_seconds))
while ((SECONDS < drain_deadline)); do
  if ! next_line; then
    break
  fi
  if [[ -z "$line" ]]; then
    break
  fi
  if ! consume_line "$line"; then
    break
  fi
done

# Stop the emulator and keep its status. A guest that keeps polling has to be
# stopped, and only that shutdown is a completed experiment: an emulator that
# exited on its own before the wait expired did not run the whole wait.
stopped_by_probe=false
if kill -0 "$qemu_pid" 2>/dev/null; then
  stopped_by_probe=true
  kill "$qemu_pid" 2>/dev/null || true
  # The emulator's own deadline may have expired, and a stopped guest is still a
  # guest that has to be stopped; neither excuses waiting forever for a process
  # that ignores the signal.
  kill_deadline=$((SECONDS + qemu_kill_after_seconds))
  while ((SECONDS < kill_deadline)) && kill -0 "$qemu_pid" 2>/dev/null; do
    sleep 0.1
  done
  if kill -0 "$qemu_pid" 2>/dev/null; then
    kill -9 "$qemu_pid" 2>/dev/null || true
  fi
fi
qemu_status=0
wait "$qemu_pid" 2>/dev/null || qemu_status=$?

# Read the output the emulator left behind to its end before closing the
# descriptor: the pipe keeps what the guest wrote before it was stopped, and a
# delivery report still in it must be classified rather than discarded with the
# descriptor. Only a clean end of output can support a non-delivery claim, so a
# bound that expires, a report that ends mid-line, or the emulator's deadline
# firing leaves the experiment inconclusive.
terminal_deadline=$((SECONDS + drain_seconds))
while ((SECONDS < terminal_deadline)); do
  if ! next_line; then
    break
  fi
  if [[ -z "$line" ]]; then
    break
  fi
  if ! consume_line "$line"; then
    break
  fi
done
# Whether the end of output is a finding is decided by the classification below,
# which knows whether the emulator was stopped by this probe or left on its own:
# an emulator that exited by itself is the more specific reason, and a shutdown
# that never reached the end of the output is the one that leaves a non-delivery
# claim without anything to stand on.
exec {guest_output_fd}<&-
exec {host_input_fd}>&-
rm -f "$monitor_socket"

# Receiving the line is the measurement, so it is reported whatever else the
# experiment did. Non-delivery needs all of: a guest that reported READY,
# progress produced after the write (the fence above), a successful write, a
# guest that had not stopped polling for longer than the stall bound, and an
# emulator that was still running when the wait expired and was stopped by this
# probe. Anything else says nothing about whether input was delivered, and the
# assertion mode below refuses to accept it.
input="inconclusive"
if [[ "$delivered" == true ]]; then
  input="delivered"
elif [[ -n "$inconclusive_reason" ]]; then
  :
elif [[ "$ready" != true ]]; then
  inconclusive_reason="the guest never reported READY"
elif [[ "$write_ok" != true ]]; then
  inconclusive_reason="the host could not write to the guest"
elif [[ "$polls_after_write" != true ]]; then
  inconclusive_reason="the guest produced no poll report after the line was written"
elif [[ "$stopped_by_probe" != true ]]; then
  inconclusive_reason="the emulator exited before the wait expired"
elif [[ "$output_ended" != true ]]; then
  inconclusive_reason="the emulator's output did not end after it was stopped"
elif [[ "$truncated" == true ]]; then
  inconclusive_reason="the emulator's output ended in the middle of a report"
elif ((SECONDS - last_poll_seconds > stall_seconds)); then
  inconclusive_reason="the guest stopped polling $((SECONDS - last_poll_seconds))s before the wait expired"
else
  input="not-delivered"
fi

record_label="record"
if [[ "$record" == false ]]; then
  record_label="none"
fi
poll_seconds=0
if [[ "$ready" == true ]]; then
  poll_seconds=$((SECONDS - ready_seconds))
fi
{
  printf 'qemu_version=%s\n' "$("$qemu" --version | head -n 1)"
  printf 'kernel=%s\n' "$kernel"
  printf 'icount_options=%s\n' "$icount_options"
  printf 'replay=%s\n' "$record_label"
  printf 'guest_timeout_seconds=%s\n' "$guest_timeout_seconds"
  printf 'wait_seconds=%s\n' "$wait_seconds"
  printf 'stall_seconds=%s\n' "$stall_seconds"
  printf 'drain_seconds=%s\n' "$drain_seconds"
  printf 'write_ok=%s\n' "$write_ok"
  printf 'ready=%s\n' "$ready"
  printf 'poll_seconds=%s\n' "$poll_seconds"
  printf 'polls_reported=%s\n' "$polls_reported"
  printf 'polls_after_write=%s\n' "$polls_after_write"
  printf 'last_poll_iterations=%s\n' "$last_poll_iterations"
  printf 'output_ended=%s\n' "$output_ended"
  printf 'truncated=%s\n' "$truncated"
  printf 'deadline_expired=%s\n' "$deadline_expired"
  printf 'stopped_by_probe=%s\n' "$stopped_by_probe"
  printf 'qemu_status=%s\n' "$qemu_status"
  printf 'input=%s\n' "$input"
  if [[ -n "$inconclusive_reason" ]]; then
    printf 'inconclusive_reason=%s\n' "$inconclusive_reason"
  fi
  if [[ -n "$expectation" ]]; then
    printf 'expected_input=%s\n' "$expectation"
  fi
} >"$output_dir/evidence.txt"
cat "$output_dir/evidence.txt"

# Assertion mode: the caller states the result the measurement must have, so a
# QEMU change that alters it fails the caller instead of being reported quietly.
# An inconclusive experiment satisfies no expectation, because it says nothing
# about whether input was delivered.
if [[ -n "$expectation" ]]; then
  if [[ "$expectation" == "$input" ]]; then
    printf '\nHost input is %s under icount %s with replay %s, as expected; artifacts: %s\n' \
      "$input" "$icount_options" "$record_label" "$output_dir"
    exit 0
  fi
  echo "Host input is $input under icount $icount_options with replay $record_label," >&2
  echo "but this run expected $expectation." >&2
  if [[ "$input" == "inconclusive" ]]; then
    echo "The experiment is inconclusive: $inconclusive_reason." >&2
  elif [[ "$expectation" == "not-delivered" ]]; then
    echo "Input delivery under the pinned model may unblock the pin: re-measure and" >&2
    echo "re-record rfd/0004/EVIDENCE.adoc before changing the model the product launches." >&2
  fi
  echo "Artifacts: $output_dir" >&2
  exit 1
fi

case "$input" in
  delivered)
    printf '\nHost input was delivered under icount %s with replay %s; artifacts: %s\n' \
      "$icount_options" "$record_label" "$output_dir"
    exit 0
    ;;
  not-delivered)
    printf '\nHost input was NOT delivered under icount %s with replay %s: the guest\n' \
      "$icount_options" "$record_label"
    printf 'polled for the %ss after boot and never received a line submitted before the wait; artifacts: %s\n' \
      "$poll_seconds" "$output_dir"
    exit 1
    ;;
  *)
    printf '\nINCONCLUSIVE: %s; artifacts: %s\n' "$inconclusive_reason" "$output_dir" >&2
    exit 1
    ;;
esac
