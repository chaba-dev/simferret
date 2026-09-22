#!/usr/bin/env bash
set -euo pipefail

# Regression tests for the pinned time-model gate.
#
# The probe, QEMU, and the guest compiler are faked so the gate's contract is
# exercised quickly: it must accept a host only when every requested run
# completed with the verdict `reproducible` and the guest measurements equal the
# reference host's; it must classify an incomplete experiment as an unsupported
# execution, a bad record or configuration as a configuration error, and a
# disagreement with the reference as a validation failure; and it must fail a
# configuration error before any run starts. The input probe's assertion mode is
# covered here too, because the qemu-replay job runs it as the known-result
# assertion.

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
gate="$repo_root/scripts/time-model-gate.sh"
input_probe="$repo_root/scripts/time-model-input-probe.sh"
reference_source="$repo_root/poc/time-model/reference-host-values.txt"
test_root="$(mktemp -d "${TMPDIR:-/tmp}/simferret-time-model-gate.XXXXXXXX")"
fake_probe="$test_root/fake-probe.sh"
fake_qemu="$test_root/qemu-system-x86_64"
kernel="$test_root/bzImage"
other_kernel="$test_root/other-bzImage"
complete=false

# A failure keeps its diagnostics: the cases below capture their commands'
# output in the test directory, so deleting it would discard the evidence.
trap 'status=$?; if [[ "$complete" == true ]]; then rm -rf "$test_root"; else echo "Time-model gate regression tests failed; diagnostics retained: $test_root" >&2; fi; exit "$status"' EXIT

printf 'fake kernel\n' >"$kernel"
printf 'a different fake kernel\n' >"$other_kernel"

# The double stands in for QEMU in two places: the gate only checks that the
# executable exists and hashes it, while the input-probe cases below run it and
# read the guest behaviour it emulates. A guest that polls keeps reporting until
# the probe stops it, because that is what the real guest does; a guest that
# stops polling is a separate behaviour.
cat >"$fake_qemu" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

if [[ "${1:-}" == "--version" ]]; then
  echo "QEMU emulator version test"
  exit 0
fi

# The probe orders its write by stopping and resuming the guest through QMP, so
# the double has to answer that socket, apply the pause for real, and record the
# commands. FAKE_QEMU_STOP_DELAY makes the pause take effect that many seconds
# after the request, which is the case an unacknowledged request cannot see.
monitor_socket=""
arguments=("$@")
for ((index = 0; index < ${#arguments[@]}; index++)); do
  if [[ "${arguments[index]}" == "-qmp" ]]; then
    monitor_socket="${arguments[index + 1]:-}"
    monitor_socket="${monitor_socket#unix:}"
    monitor_socket="${monitor_socket%%,*}"
  fi
done
paused_flag=""
if [[ -n "$monitor_socket" ]]; then
  paused_flag="$monitor_socket.paused"
  rm -f "$paused_flag"
  python3 - "$monitor_socket" "${FAKE_QEMU_MONITOR_LOG:-/dev/null}" "$paused_flag" "$$" \
    "${FAKE_QEMU_STOP_DELAY:-0}" "${FAKE_QEMU_REJECT_CONT:-0}" >/dev/null 2>&1 <<'PY' &
import json
import os
import socket
import sys
import time

path, log, paused, parent = sys.argv[1], sys.argv[2], sys.argv[3], int(sys.argv[4])
stop_delay, reject_cont = float(sys.argv[5]), sys.argv[6] == "1"

server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
server.bind(path)
server.listen(8)
server.settimeout(0.5)


def send(connection, message):
    try:
        connection.sendall((json.dumps(message) + "\n").encode())
    except OSError:
        pass


while True:
    if os.getppid() != parent:
        break
    try:
        connection, _ = server.accept()
    except socket.timeout:
        continue
    send(connection, {"QMP": {"version": {"qemu": {"major": 11, "minor": 1, "micro": 0},
                                          "package": ""}, "capabilities": []}})
    buffer = b""
    while True:
        while b"\n" not in buffer:
            data = connection.recv(4096)
            if not data:
                break
            buffer += data
        if b"\n" not in buffer:
            break
        line, buffer = buffer.split(b"\n", 1)
        try:
            message = json.loads(line.decode())
        except ValueError:
            continue
        command = message.get("execute")
        if command is None:
            continue
        with open(log, "a") as handle:
            handle.write(command + "\n")
        if command == "stop":
            time.sleep(stop_delay)
            with open(paused, "w") as handle:
                handle.write("paused\n")
            send(connection, {"event": "STOP",
                              "timestamp": {"seconds": 0, "microseconds": 0}})
            send(connection, {"return": {}})
        elif command == "cont":
            if os.path.exists(paused):
                os.remove(paused)
            if reject_cont:
                send(connection, {"error": {"class": "GenericError", "desc": "rejected"}})
            else:
                send(connection, {"return": {}})
        else:
            send(connection, {"return": {}})
    connection.close()
PY
  # The socket file appears once the listener has bound it, so waiting for it
  # keeps the double from reporting READY before its monitor can answer.
  for ((attempt = 0; attempt < 100; attempt++)); do
    if [[ -S "$monitor_socket" ]]; then
      break
    fi
    sleep 0.05
  done
fi

wait_while_paused() {
  while [[ -n "$paused_flag" && -f "$paused_flag" ]]; do
    sleep 0.05
  done
}

poll() { # report progress until killed
  local iterations=0

  while :; do
    wait_while_paused
    iterations=$((iterations + 10))
    printf 'WAITING iterations=%s\n' "$iterations"
    sleep 0.2
  done
}

poll_briefly() { # $1 reports, $2 interval seconds
  local index=0

  while ((index < $1)); do
    wait_while_paused
    index=$((index + 1))
    printf 'WAITING iterations=%s\n' "$((index * 10))"
    sleep "$2"
  done
}

case "${FAKE_QEMU_INPUT_BEHAVIOR:-not-delivered}" in
  delivered)
    printf 'READY\n'
    IFS= read -r line || true
    printf 'GOT:%s iterations=10\n' "$line"
    ;;
  not-delivered)
    # The pinned model: the guest polls for as long as the probe waits and the
    # line the probe wrote is never delivered.
    printf 'READY\n'
    poll
    ;;
  polling-write)
    # The basic handshake: the line is written after READY, while the guest is
    # polling, and the double reports that it arrived at that point.
    printf 'READY\n'
    if IFS= read -r -t 2 line; then
      printf 'during-polling\n' >"${FAKE_QEMU_MARKER:?}"
    else
      printf 'never-written\n' >"${FAKE_QEMU_MARKER:?}"
      printf 'NO-INPUT\n'
      exit 0
    fi
    poll
    ;;
  stalled-before-write)
    # The guest stops polling before the line is written, which the probe has to
    # report as inconclusive: a successful write does not make a guest that
    # stopped looking a non-delivery measurement. The marker records that the
    # write arrived after polling stopped.
    printf 'READY\n'
    printf 'WAITING iterations=10\n'
    sleep 1.5
    if IFS= read -r -t 1 line; then
      printf 'write-arrived\n' >"${FAKE_QEMU_MARKER:?}"
    else
      printf 'no-write\n' >"${FAKE_QEMU_MARKER:?}"
    fi
    exec sleep 30
    ;;
  stalled-guest)
    # A guest that polls for a while and then stops producing output without
    # exiting, which the stall bound has to catch.
    printf 'READY\n'
    poll_briefly 40 0.05
    exec sleep 30
    ;;
  exit-after-polling)
    # A guest that polls and then exits while a child keeps the output pipe open,
    # so the probe sees no end of output and has to notice the emulator is gone.
    printf 'READY\n'
    poll_briefly 50 0.05
    ( sleep 30 ) &
    exit 0
    ;;
  got-on-termination)
    # The line is reported while the probe stops the emulator, so only reading
    # the output to its end can classify it.
    printf 'READY\n'
    trap 'printf "GOT:hello-from-host iterations=99\n"; exit 0' TERM
    poll
    ;;
  pipe-held-open)
    # A child keeps the output pipe open after the emulator is stopped, so the
    # shutdown cannot reach the end of the output and a non-delivery claim has
    # nothing to stand on.
    printf 'READY\n'
    ( sleep 60 ) &
    poll
    ;;
  flood-then-stop)
    # A guest whose output cannot be drained before the line is written, so the
    # write cannot be ordered and the run has to be inconclusive.
    printf 'READY\n'
    for ((index = 0; index < 200000; index++)); do
      printf 'WAITING iterations=%s\n' "$index"
    done
    exec sleep 30
    ;;
  split-report)
    # The terminal report is split by more than the probe's read timeout, so a
    # probe that drops the prefix of a timed-out read cannot see the line.
    printf 'READY\n'
    printf 'GOT:hello-fr'
    sleep 1.5
    printf 'om-host iterations=10\n'
    ;;
  no-ready)
    exit 0
    ;;
  silent-guest)
    # A guest that produced output but never reported READY, so the probe waits
    # out its deadline rather than seeing the emulator end.
    printf 'BANNER\n'
    exec sleep 30
    ;;
  eof-after-ready)
    printf 'READY\n'
    IFS= read -r line || true
    ;;
  closed-input)
    # The guest's own input is closed, so it reports EOF; whether the probe's
    # write landed in the pipe first cannot change that report.
    exec 0<&-
    printf 'READY\n'
    printf 'WAITING iterations=10\n'
    if IFS= read -r line; then
      printf 'GOT:%s iterations=20\n' "$line"
    else
      printf 'EOF\n'
    fi
    ;;
  *)
    echo "fake qemu: unknown input behavior" >&2
    exit 2
    ;;
esac
EOF
chmod +x "$fake_qemu"
fake_qemu_sha256="$(sha256sum "$fake_qemu" | cut -d' ' -f1)"

# The input-probe cases below do not exercise compilation, so the guest build
# only has to produce a file. The real probe compiles the real guest.
cat >"$test_root/fake-static-cc" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

output=""
while (($# > 0)); do
  if [[ "$1" == "-o" ]]; then
    output="${2:-}"
    shift 2
    continue
  fi
  shift
done
if [[ -z "$output" ]]; then
  echo "fake static cc: no -o output" >&2
  exit 2
fi
printf '#!/bin/sh\nexit 0\n' >"$output"
chmod +x "$output"
EOF
chmod +x "$test_root/fake-static-cc"

# The gate validates the model the checked-in reference values were measured
# under. That record must name the model RFD 4 pins, because the gate is the
# Phase 0 acceptance gate for that model rather than for whatever the probe
# happens to run.
pinned_time_model="$(sed -n 's/^icount_options=//p' "$reference_source")"
if [[ "$pinned_time_model" != "shift=4,sleep=off" ]]; then
  echo "the reference values no longer name the pinned model: $pinned_time_model" >&2
  exit 1
fi

# The expected measurements come from the reference record rather than a second
# copy, so this test cannot pass while the gate compares against values the
# repository does not record.
mapfile -t measurements < <(sed -n 's/^measurement=//p' "$reference_source")
if [[ "${#measurements[@]}" -ne 5 ]]; then
  echo "the reference record does not list five measurements" >&2
  exit 1
fi
fake_kernel_sha256="$(sha256sum "$kernel" | cut -d' ' -f1)"
fake_initramfs_sha256="$(printf 'fake initramfs\n' | sha256sum | cut -d' ' -f1)"
fake_qemu_version="QEMU emulator version test"

metric_of() { # $1 measurement row
  local metric="${1#probe }"

  printf '%s\n' "${metric%% *}"
}

# prepare builds the reference record and the probe output a run of the pinned
# model produces. Each case below perturbs one of them.
prepare() { # $1 case name
  local name="$1"
  local fixture="$test_root/$name.fixture"

  mkdir -p "$fixture"
  {
    printf 'icount_options=%s\n' "$pinned_time_model"
    printf 'requested_runs=5\n'
    printf 'complete_runs=5\n'
    printf 'incomplete_runs=0\n'
    printf 'verdict=reproducible\n'
    printf 'qemu_version=%s\n' "$fake_qemu_version"
    printf 'initramfs_sha256=%s\n' "$fake_initramfs_sha256"
  } >"$fixture/evidence.txt"
  for row in "${measurements[@]}"; do
    printf '%s\n' "$row" >"$fixture/values-$(metric_of "$row").txt"
  done
  {
    printf 'icount_options=%s\n' "$pinned_time_model"
    printf 'kernel_sha256=%s\n' "$fake_kernel_sha256"
    printf 'initramfs_sha256=%s\n' "$fake_initramfs_sha256"
    printf 'qemu_version=%s\n' "$fake_qemu_version"
    printf 'qemu_sha256=%s\n' "$fake_qemu_sha256"
    for row in "${measurements[@]}"; do
      printf 'measurement=%s\n' "$row"
    done
  } >"$test_root/$name.reference.txt"
}

run_gate() { # $1 case name, remaining arguments are environment assignments
  local name="$1"
  shift

  env \
    SIMFERRET_KERNEL="$kernel" \
    QEMU_SYSTEM_X86_64="$fake_qemu" \
    SIMFERRET_TIME_MODEL_PROBE="$fake_probe" \
    SIMFERRET_TIME_MODEL_REFERENCE="$test_root/$name.reference.txt" \
    SIMFERRET_TIME_MODEL_GATE_OUTPUT="$test_root/$name.out" \
    FAKE_PROBE_LOG="$test_root/$name.probe" \
    FAKE_PROBE_FIXTURE="$test_root/$name.fixture" \
    "$@" \
    "$gate" >"$test_root/$name.stdout" 2>"$test_root/$name.stderr"
}

probe_invocations() { # $1 case name
  local log="$test_root/$1.probe.invocations"

  if [[ -f "$log" ]]; then
    grep -c . "$log"
  else
    echo 0
  fi
}

result_of() { # $1 case name
  local directory

  directory="$(find "$test_root/$1.out" -mindepth 1 -maxdepth 1 -type d -name 'gate.*' 2>/dev/null | head -1)"
  if [[ -z "$directory" || ! -f "$directory/gate.txt" ]]; then
    printf 'none\n'
    return 0
  fi
  grep -F 'result=' "$directory/gate.txt" | cut -d= -f2
}

run_gate_status() { # $1 case name, remaining arguments are environment assignments
  local name="$1"
  local status=0

  shift
  run_gate "$name" "$@" || status=$?
  printf '%s\n' "$status"
}

cat >"$fake_probe" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

printf '%s\n' "$SIMFERRET_ICOUNT_OPTIONS" >>"$FAKE_PROBE_LOG.icount"
printf '%s\n' "$SIMFERRET_TIME_MODEL_RUNS" >>"$FAKE_PROBE_LOG.runs"
printf '%s\n' "$SIMFERRET_QEMU_TIMEOUT" >>"$FAKE_PROBE_LOG.timeout"
printf 'invoked\n' >>"$FAKE_PROBE_LOG.invocations"

case "${FAKE_PROBE_BEHAVIOR:-success}" in
  configuration-error)
    echo "fake probe: invalid configuration" >&2
    exit 2
    ;;
  no-completed-run)
    echo "fake probe: no run produced a complete probe measurement." >&2
    exit 3
    ;;
  invalid-experiment)
    echo "fake probe: the control checksum varied across completed runs." >&2
    exit 1
    ;;
  undocumented-status)
    echo "fake probe: unexpected failure" >&2
    exit 5
    ;;
  success|no-artifacts)
    ;;
esac

artifacts="$SIMFERRET_TIME_MODEL_OUTPUT/run.fake"
mkdir -p "$artifacts"
cp "$FAKE_PROBE_FIXTURE/evidence.txt" "$artifacts/evidence.txt"
cp "$FAKE_PROBE_FIXTURE"/values-*.txt "$artifacts/"
cat "$artifacts/evidence.txt"
printf '\nmeasurements over %s completed run(s):\n' "$SIMFERRET_TIME_MODEL_RUNS"
printf 'Artifacts: %s\n' "$artifacts"
if [[ "${FAKE_PROBE_BEHAVIOR:-success}" == "no-artifacts" ]]; then
  rm -rf "$artifacts"
fi
EOF
chmod +x "$fake_probe"

# A complete, reproducible run of the pinned model passes, and the gate passes
# the model from the reference record, the RFD's deadline, and its five-run
# minimum to the probe.
prepare success
run_gate success
grep -Fxq 'time_model_gate=passed' "$test_root/success.out"/gate.*/gate.txt
grep -Fxq "$pinned_time_model" "$test_root/success.probe.icount"
grep -Fxq '5' "$test_root/success.probe.runs"
grep -Fxq '180s' "$test_root/success.probe.timeout"
test "$(probe_invocations success)" -eq 1
test "$(result_of success)" = "passed"

# The probe reports variation rather than failing on it, so the gate is what
# turns a varying verdict into a failed validation.
prepare varying
sed -i 's/^verdict=reproducible$/verdict=varying/' "$test_root/varying.fixture/evidence.txt"
test "$(run_gate_status varying)" -eq 1
grep -Fq 'verdict is varying' "$test_root/varying.stderr"
test "$(result_of varying)" = "validation-failure"

# A sample that dropped a run is not the five complete runs the RFD requires,
# and a host that cannot complete under the pinned model is an unsupported
# execution rather than a measurement difference.
prepare incomplete
sed -i 's/^complete_runs=5$/complete_runs=4/;s/^incomplete_runs=0$/incomplete_runs=1/' \
  "$test_root/incomplete.fixture/evidence.txt"
test "$(run_gate_status incomplete)" -eq 3
grep -Fq '1 of 5 requested runs did not complete' "$test_root/incomplete.stderr"
grep -Fq 'unsupported' "$test_root/incomplete.stderr"
test "$(result_of incomplete)" = "unsupported-execution"

# A host whose guest measurements differ from the reference host fails rather
# than passing with a warning.
prepare golden-mismatch
sed -i 's/observed_ns=21950896/observed_ns=21950897/' \
  "$test_root/golden-mismatch.fixture/values-sleep.txt"
test "$(run_gate_status golden-mismatch)" -eq 1
grep -Fq 'the sleep measurement is' "$test_root/golden-mismatch.stderr"
grep -Fq 'the reference host recorded' "$test_root/golden-mismatch.stderr"
test "$(result_of golden-mismatch)" = "validation-failure"

# The run must be the model the reference values were measured under, not
# whatever the environment configured.
prepare wrong-model
sed -i 's/^icount_options=.*$/icount_options=shift=auto/' \
  "$test_root/wrong-model.fixture/evidence.txt"
if run_gate wrong-model; then
  echo "a run under another model unexpectedly passed the gate" >&2
  exit 1
fi
grep -Fq 'icount_options is shift=auto' "$test_root/wrong-model.stderr"

# Changing the model without re-measuring the values fails on the values, which
# is what makes the checked-in record a validation rather than a label: a real
# run under another model reports that model and its own measurements.
prepare stale-values
sed -i 's/^icount_options=.*$/icount_options=shift=7,sleep=off/' \
  "$test_root/stale-values.reference.txt"
sed -i 's/^icount_options=.*$/icount_options=shift=7,sleep=off/' \
  "$test_root/stale-values.fixture/evidence.txt"
sed -i 's/observed_ns=21950896/observed_ns=20948000/' \
  "$test_root/stale-values.fixture/values-sleep.txt"
if run_gate stale-values; then
  echo "a model change without re-measured values unexpectedly passed the gate" >&2
  exit 1
fi
grep -Fq 'the sleep measurement is' "$test_root/stale-values.stderr"

# Artifact identity: a different QEMU, initramfs, or kernel means the host did
# not run identical artifacts, so its measurements are not comparable. The QEMU
# check is a digest rather than the version string, so a rebuilt or patched
# binary cannot pass as the reference build.
prepare qemu-mismatch
sed -i 's/^qemu_sha256=.*$/qemu_sha256=0000000000000000000000000000000000000000000000000000000000000000/' \
  "$test_root/qemu-mismatch.reference.txt"
if run_gate qemu-mismatch; then
  echo "a different QEMU unexpectedly passed the gate" >&2
  exit 1
fi
grep -Fq 'the QEMU executable is' "$test_root/qemu-mismatch.stderr"
test "$(result_of qemu-mismatch)" = "validation-failure"

prepare initramfs-mismatch
sed -i 's/^initramfs_sha256=.*$/initramfs_sha256=0000000000000000000000000000000000000000000000000000000000000000/' \
  "$test_root/initramfs-mismatch.fixture/evidence.txt"
if run_gate initramfs-mismatch; then
  echo "a different initramfs unexpectedly passed the gate" >&2
  exit 1
fi
grep -Fq 'initramfs_sha256 is' "$test_root/initramfs-mismatch.stderr"

prepare kernel-mismatch
if run_gate kernel-mismatch SIMFERRET_KERNEL="$other_kernel"; then
  echo "a different guest kernel unexpectedly passed the gate" >&2
  exit 1
fi
grep -Fq 'the guest kernel is' "$test_root/kernel-mismatch.stderr"

# A host that cannot complete under the pinned model is an unsupported
# execution, and the gate does not retry another model.
prepare no-completed-run
test "$(run_gate_status no-completed-run FAKE_PROBE_BEHAVIOR=no-completed-run)" -eq 3
grep -Fq 'unsupported' "$test_root/no-completed-run.stderr"
grep -Fq 'no fallback model is attempted' "$test_root/no-completed-run.stderr"
test "$(probe_invocations no-completed-run)" -eq 1
test "$(result_of no-completed-run)" = "unsupported-execution"

# The probe's outcomes are mapped rather than merged, and each one has its own
# exit status as well as its own `result=`: a rejected configuration, a host that
# completed no run, and a completed experiment that does not support a claim are
# three different findings, and an undocumented status is not read as any of
# them.
prepare configuration-error
test "$(run_gate_status configuration-error FAKE_PROBE_BEHAVIOR=configuration-error)" -eq 2
grep -Fq 'cannot run as configured' "$test_root/configuration-error.stderr"
test "$(result_of configuration-error)" = "configuration-error"

prepare invalid-experiment
test "$(run_gate_status invalid-experiment FAKE_PROBE_BEHAVIOR=invalid-experiment)" -eq 1
grep -Fq 'did not support a reproducibility claim' "$test_root/invalid-experiment.stderr"
grep -Fq 'The pinned time model did not validate' "$test_root/invalid-experiment.stderr"
test "$(result_of invalid-experiment)" = "validation-failure"

prepare undocumented-status
test "$(run_gate_status undocumented-status FAKE_PROBE_BEHAVIOR=undocumented-status)" -eq 2
grep -Fq 'not a documented outcome' "$test_root/undocumented-status.stderr"
test "$(result_of undocumented-status)" = "configuration-error"

# A probe that reports success but leaves no experiment to read is a
# configuration error rather than a validation of the host.
prepare no-artifacts
test "$(run_gate_status no-artifacts FAKE_PROBE_BEHAVIOR=no-artifacts)" -eq 2
grep -Fq 'left no evidence to read' "$test_root/no-artifacts.stderr"
test "$(result_of no-artifacts)" = "configuration-error"

# A failed invocation writes its own result, so a later failure cannot leave an
# earlier success standing as the newest certificate in the same output root.
# That holds for a failure before the experiment too, which is why the
# invocation directory is created before anything is validated.
shared_root="$test_root/shared.out"
prepare certificate-pass
run_gate certificate-pass SIMFERRET_TIME_MODEL_GATE_OUTPUT="$shared_root"
prepare certificate-fail
sed -i 's/^verdict=reproducible$/verdict=varying/' "$test_root/certificate-fail.fixture/evidence.txt"
test "$(run_gate_status certificate-fail SIMFERRET_TIME_MODEL_GATE_OUTPUT="$shared_root")" -eq 1
prepare certificate-preflight
test "$(run_gate_status certificate-preflight SIMFERRET_TIME_MODEL_GATE_OUTPUT="$shared_root" \
  SIMFERRET_TIME_MODEL_RUNS=4)" -eq 2
test "$(probe_invocations certificate-preflight)" -eq 0
test "$(find "$shared_root" -mindepth 1 -maxdepth 1 -type d -name 'gate.*' | wc -l)" -eq 3
test "$(grep -rlFx 'time_model_gate=passed' "$shared_root" | wc -l)" -eq 1
test "$(grep -rlFx 'time_model_gate=failed' "$shared_root" | wc -l)" -eq 2
test "$(grep -rlFx 'result=configuration-error' "$shared_root" | wc -l)" -eq 1
test "$(grep -rlFx 'result=validation-failure' "$shared_root" | wc -l)" -eq 1

# An exit that records nothing is still recorded: an unreadable kernel aborts
# the gate after its invocation directory exists, and that directory says so
# rather than staying empty.
prepare aborted
test "$(run_gate_status aborted SIMFERRET_KERNEL=/proc/self/mem)" -eq 2
test "$(result_of aborted)" = "configuration-error"
grep -Fq 'without recording a result' "$test_root/aborted.out"/gate.*/gate.txt

# The input probe's assertion mode is what the qemu-replay job runs, so a QEMU
# change that starts delivering input under the pinned model becomes visible in
# continuous integration instead of waiting for someone to re-run it by hand.
run_input_probe() { # $1 case name, $2 expected result, remaining: environment
  local name="$1"
  local expectation="$2"
  shift 2

  env \
    SIMFERRET_KERNEL="$kernel" \
    SIMFERRET_STATIC_CC="$test_root/fake-static-cc" \
    QEMU_SYSTEM_X86_64="$fake_qemu" \
    SIMFERRET_INPUT_PROBE_OUTPUT="$test_root/$name.out" \
    "$@" \
    "$input_probe" --expect "$expectation" >"$test_root/$name.stdout" 2>"$test_root/$name.stderr"
}

input_evidence_value() { # $1 case name, $2 key
  local file

  file="$(find "$test_root/$1.out" -mindepth 2 -maxdepth 2 -name evidence.txt | head -1)"
  sed -n "s/^$2=//p" "$file"
}

# The double answers the probe's monitor with python3, so its first start is
# warmed here rather than inside a case with a short wait.
python3 -c 'pass'

# The known result: the pinned model records but never delivers host input, and
# the guest polls for the whole wait.
run_input_probe input-known-result not-delivered SIMFERRET_INPUT_PROBE_WAIT=6
test "$(input_evidence_value input-known-result input)" = "not-delivered"
test "$(input_evidence_value input-known-result polls_reported)" = "true"
test "$(input_evidence_value input-known-result polls_after_write)" = "true"
test "$(input_evidence_value input-known-result write_ok)" = "true"
test "$(input_evidence_value input-known-result stopped_by_probe)" = "true"
grep -Fq 'as expected' "$test_root/input-known-result.stdout"

# The basic handshake: the line is written after READY, while the double is
# polling. The ordering is the emulator's monitor rather than the host's
# scheduling, so the double has to have been stopped and resumed around the
# write.
marker="$test_root/input-polling-write.marker"
monitor_log="$test_root/input-polling-write.monitor"
run_input_probe input-polling-write not-delivered SIMFERRET_INPUT_PROBE_WAIT=6 \
  FAKE_QEMU_INPUT_BEHAVIOR=polling-write FAKE_QEMU_MARKER="$marker" \
  FAKE_QEMU_MONITOR_LOG="$monitor_log"
test "$(cat "$marker")" = "during-polling"
grep -Fxq 'stop' "$monitor_log"
grep -Fxq 'cont' "$monitor_log"

# The ordering the measurement rests on: the guest has to be polling when the
# line is written. A double that stops polling first, and records that the write
# arrived anyway, must be inconclusive rather than a non-delivery measurement.
marker="$test_root/input-stalled-before-write.marker"
if run_input_probe input-stalled-before-write not-delivered \
  FAKE_QEMU_INPUT_BEHAVIOR=stalled-before-write FAKE_QEMU_MARKER="$marker" \
  SIMFERRET_INPUT_PROBE_WAIT=6 SIMFERRET_INPUT_PROBE_STALL=1; then
  echo "a guest that stopped polling before the write satisfied the known-result assertion" >&2
  exit 1
fi
test "$(cat "$marker")" = "write-arrived"
test "$(input_evidence_value input-stalled-before-write input)" = "inconclusive"
grep -Fq 'no poll report after the line was written' "$test_root/input-stalled-before-write.stderr"

# A guest that polls for a while and then hangs is inconclusive under the stall
# bound, and a guest that exits while its output stays open is inconclusive
# because the emulator was not stopped by the probe.
if run_input_probe input-stalled-guest not-delivered FAKE_QEMU_INPUT_BEHAVIOR=stalled-guest \
  SIMFERRET_INPUT_PROBE_WAIT=6 SIMFERRET_INPUT_PROBE_STALL=1; then
  echo "a guest that stopped polling satisfied the known-result assertion" >&2
  exit 1
fi
test "$(input_evidence_value input-stalled-guest input)" = "inconclusive"
grep -Fq 'stopped polling' "$test_root/input-stalled-guest.stderr"

if run_input_probe input-exit-after-polling not-delivered \
  FAKE_QEMU_INPUT_BEHAVIOR=exit-after-polling SIMFERRET_INPUT_PROBE_WAIT=6 \
  SIMFERRET_INPUT_PROBE_STALL=1; then
  echo "an emulator that exited on its own satisfied the known-result assertion" >&2
  exit 1
fi
test "$(input_evidence_value input-exit-after-polling input)" = "inconclusive"
test "$(input_evidence_value input-exit-after-polling stopped_by_probe)" = "false"
grep -Fq 'exited before the wait expired' "$test_root/input-exit-after-polling.stderr"

# A delivery report emitted while the emulator is being stopped is classified
# rather than lost to the shutdown: the probe reads the output to its end before
# it closes the pipe, so a model that delivers input cannot be reported as one
# that does not.
run_input_probe input-got-on-termination delivered \
  FAKE_QEMU_INPUT_BEHAVIOR=got-on-termination SIMFERRET_INPUT_PROBE_WAIT=6
test "$(input_evidence_value input-got-on-termination input)" = "delivered"

# A shutdown whose output never ends cannot support a non-delivery claim, so the
# run is inconclusive rather than a measurement.
if run_input_probe input-pipe-held-open not-delivered \
  FAKE_QEMU_INPUT_BEHAVIOR=pipe-held-open SIMFERRET_INPUT_PROBE_WAIT=4 \
  SIMFERRET_INPUT_PROBE_STALL=30; then
  echo "a shutdown whose output never ended satisfied the known-result assertion" >&2
  exit 1
fi
test "$(input_evidence_value input-pipe-held-open input)" = "inconclusive"
test "$(input_evidence_value input-pipe-held-open output_ended)" = "false"
grep -Fq 'did not end after it was stopped' "$test_root/input-pipe-held-open.stderr"

# The emulator's own deadline expiring is not the probe's shutdown, so it cannot
# be a non-delivery measurement either.
if run_input_probe input-guest-deadline not-delivered \
  FAKE_QEMU_INPUT_BEHAVIOR=pipe-held-open SIMFERRET_INPUT_PROBE_WAIT=2 \
  SIMFERRET_INPUT_PROBE_TIMEOUT=4 SIMFERRET_INPUT_PROBE_DRAIN=5; then
  echo "an expired emulator deadline satisfied the known-result assertion" >&2
  exit 1
fi
test "$(input_evidence_value input-guest-deadline input)" = "inconclusive"
test "$(input_evidence_value input-guest-deadline deadline_expired)" = "true"
grep -Fq "the emulator's deadline expired" "$test_root/input-guest-deadline.stderr"

# A guest whose output cannot be drained before the line is written makes the
# ordering unprovable, so the run is inconclusive rather than a non-delivery
# measurement.
if run_input_probe input-flood-then-stop not-delivered \
  FAKE_QEMU_INPUT_BEHAVIOR=flood-then-stop SIMFERRET_INPUT_PROBE_WAIT=8; then
  echo "a guest whose output never went quiet satisfied the known-result assertion" >&2
  exit 1
fi
test "$(input_evidence_value input-flood-then-stop input)" = "inconclusive"
grep -Fq 'did not go quiet' "$test_root/input-flood-then-stop.stderr"

# If input starts being delivered under the pinned model, the assertion fails
# with the reading that matters: the pin may be unblocked.
if run_input_probe input-unblocked not-delivered FAKE_QEMU_INPUT_BEHAVIOR=delivered; then
  echo "delivered input did not fail the known-result assertion" >&2
  exit 1
fi
grep -Fq 'but this run expected not-delivered' "$test_root/input-unblocked.stderr"
grep -Fq 'may unblock the pin' "$test_root/input-unblocked.stderr"

# The mode accepts either expectation, so it asserts a stated result rather than
# hard-coding one.
run_input_probe input-delivered delivered FAKE_QEMU_INPUT_BEHAVIOR=delivered
test "$(input_evidence_value input-delivered input)" = "delivered"

# A report split by more than the read timeout is still one line: a timed read
# returns the partial prefix it read, and dropping it would lose the report.
run_input_probe input-split-report delivered SIMFERRET_INPUT_PROBE_WAIT=6 \
  FAKE_QEMU_INPUT_BEHAVIOR=split-report
test "$(input_evidence_value input-split-report input)" = "delivered"

# An experiment that cannot say whether input was delivered satisfies no
# expectation: a QEMU that never ran, a guest that never reported READY, a guest
# whose output ended first, a guest that stopped polling, and a guest whose own
# input is closed all fail the known result instead of confirming it.
for behavior in no-ready silent-guest eof-after-ready closed-input; do
  if run_input_probe "input-$behavior" not-delivered "FAKE_QEMU_INPUT_BEHAVIOR=$behavior" \
    SIMFERRET_INPUT_PROBE_WAIT=2; then
    echo "an inconclusive experiment ($behavior) satisfied the known-result assertion" >&2
    exit 1
  fi
  test "$(input_evidence_value "input-$behavior" input)" = "inconclusive"
  grep -Fq 'inconclusive' "$test_root/input-$behavior.stderr"
done
grep -Fq 'output ended' "$test_root/input-no-ready.stderr"
grep -Fq 'never reported READY' "$test_root/input-silent-guest.stderr"
grep -Fq 'output ended' "$test_root/input-eof-after-ready.stderr"
grep -Fq 'reported EOF' "$test_root/input-closed-input.stderr"

# An expectation the probe cannot check, an empty expectation, and a second
# positional model fail before any run starts.
if run_input_probe input-invalid sometimes; then
  echo "an invalid expectation unexpectedly passed" >&2
  exit 1
fi
grep -Fq 'must be delivered or not-delivered' "$test_root/input-invalid.stderr"
test ! -e "$test_root/input-invalid.out"
if run_input_probe input-empty-expectation ""; then
  echo "an empty expectation unexpectedly passed" >&2
  exit 1
fi
grep -Fq 'must be delivered or not-delivered' "$test_root/input-empty-expectation.stderr"
if env SIMFERRET_KERNEL="$kernel" SIMFERRET_STATIC_CC="$test_root/fake-static-cc" \
  QEMU_SYSTEM_X86_64="$fake_qemu" SIMFERRET_INPUT_PROBE_OUTPUT="$test_root/input-two-models.out" \
  "$input_probe" shift=4 shift=7 >"$test_root/input-two-models.stdout" 2>"$test_root/input-two-models.stderr"; then
  echo "two icount-options arguments unexpectedly passed" >&2
  exit 1
fi
grep -Fq 'Only one icount-options argument' "$test_root/input-two-models.stderr"

# A reference record without exactly one model is a configuration error.
prepare input-missing-model
sed -i '/^icount_options=/d' "$test_root/input-missing-model.reference.txt"
if env SIMFERRET_KERNEL="$kernel" SIMFERRET_STATIC_CC="$test_root/fake-static-cc" \
  QEMU_SYSTEM_X86_64="$fake_qemu" SIMFERRET_INPUT_PROBE_OUTPUT="$test_root/input-missing-model.out" \
  SIMFERRET_TIME_MODEL_REFERENCE="$test_root/input-missing-model.reference.txt" \
  "$input_probe" --expect not-delivered >"$test_root/input-missing-model.stdout" 2>"$test_root/input-missing-model.stderr"; then
  echo "a reference record without a model unexpectedly passed" >&2
  exit 1
fi
grep -Fq 'must record exactly one icount_options' "$test_root/input-missing-model.stderr"

# A guest that does not compile is a configuration error before any run starts,
# not a failed measurement: the probe's own setup failures carry status 2 like
# its other configuration errors.
status=0
if env SIMFERRET_KERNEL="$kernel" SIMFERRET_STATIC_CC=false \
  QEMU_SYSTEM_X86_64="$fake_qemu" SIMFERRET_INPUT_PROBE_OUTPUT="$test_root/input-unbuildable.out" \
  "$input_probe" --expect not-delivered >"$test_root/input-unbuildable.stdout" 2>"$test_root/input-unbuildable.stderr"; then
  echo "an input probe whose guest did not compile unexpectedly passed" >&2
  exit 1
else
  status=$?
fi
test "$status" -eq 2
grep -Fq 'did not compile' "$test_root/input-unbuildable.stderr"

# Configuration errors fail before any run starts, because a gate that accepted
# a smaller sample, a weaker deadline, or an unreadable record would validate
# less than the RFD requires.
printf 'no pinned model here\n' >"$test_root/no-declaration.rs"
for case_name in too-few-runs too-many-runs long-deadline invalid-timeout missing-reference empty-model duplicate-key empty-value duplicate-metric missing-metric; do
  prepare "$case_name"
  case "$case_name" in
    too-few-runs) arguments=("SIMFERRET_TIME_MODEL_RUNS=4") ;;
    too-many-runs) arguments=("SIMFERRET_TIME_MODEL_RUNS=51") ;;
    long-deadline) arguments=("SIMFERRET_QEMU_TIMEOUT=3600s") ;;
    invalid-timeout) arguments=("SIMFERRET_QEMU_TIMEOUT=0") ;;
    missing-reference) arguments=("SIMFERRET_TIME_MODEL_REFERENCE=$test_root/absent.txt") ;;
    empty-model) arguments=() ;;
    duplicate-key) arguments=() ;;
    empty-value) arguments=() ;;
    duplicate-metric) arguments=() ;;
    missing-metric) arguments=() ;;
  esac
  case "$case_name" in
    empty-model)
      sed -i 's/^icount_options=.*$/icount_options=/' "$test_root/$case_name.reference.txt"
      ;;
    duplicate-key)
      printf 'qemu_sha256=%s\n' "$fake_qemu_sha256" >>"$test_root/$case_name.reference.txt"
      ;;
    empty-value)
      sed -i 's/^initramfs_sha256=.*$/initramfs_sha256=/' "$test_root/$case_name.reference.txt"
      ;;
    duplicate-metric)
      # The second row repeats the spin metric, which must be caught even though
      # the record still holds five rows.
      printf 'measurement=%s\n' "${measurements[1]}" >>"$test_root/$case_name.reference.txt"
      ;;
    missing-metric)
      sed -i '/^measurement=probe spin /d' "$test_root/$case_name.reference.txt"
      ;;
  esac
  if run_gate "$case_name" "${arguments[@]}"; then
    echo "$case_name unexpectedly passed the gate" >&2
    exit 1
  fi
  test "$(probe_invocations "$case_name")" -eq 0
  grep -Fq 'cannot run as configured' "$test_root/$case_name.stderr"
  test "$(result_of "$case_name")" = "configuration-error" ||
    test ! -e "$test_root/$case_name.out"
done
grep -Fq 'must be an integer from 5 through' "$test_root/too-few-runs.stderr"
grep -Fq 'must be an integer from 5 through' "$test_root/too-many-runs.stderr"
grep -Fq 'acceptance deadline is fixed at 180s' "$test_root/long-deadline.stderr"
grep -Fq 'acceptance deadline is fixed at 180s' "$test_root/invalid-timeout.stderr"
grep -Fq 'records an empty icount_options' "$test_root/empty-model.stderr"
grep -Fq 'must record exactly one qemu_sha256; found 2' "$test_root/duplicate-key.stderr"
grep -Fq 'records an empty initramfs_sha256' "$test_root/empty-value.stderr"
grep -Fq 'must record exactly one spin measurement; found 2' "$test_root/duplicate-metric.stderr"
grep -Fq 'must record exactly one spin measurement; found 0' "$test_root/missing-metric.stderr"

complete=true
printf 'Time-model gate regression tests passed.\n'
