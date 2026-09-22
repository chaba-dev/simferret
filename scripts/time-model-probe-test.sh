#!/usr/bin/env bash
set -euo pipefail

# Regression tests for the guest time-model probe harness.
#
# The QEMU invocation is faked so the harness contract is exercised quickly:
# incomplete runs must be recorded and skipped rather than aborting the
# experiment, aggregation must use completed runs only, an inconclusive sample
# must not be reported as reproducible, and an invalid experiment must fail
# before or without QEMU.

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
probe_script="$repo_root/scripts/time-model-probe.sh"
probe_source="$repo_root/poc/time-model/probe.c"
dynamic_cc="${SIMFERRET_DYNAMIC_CC:-cc}"
test_root="$(mktemp -d "${TMPDIR:-/tmp}/simferret-time-model.XXXXXXXX")"
fake_qemu="$test_root/qemu-system-x86_64"
kernel="$test_root/bzImage"
trap 'rm -rf "$test_root"' EXIT

printf 'fake kernel\n' >"$kernel"

# The harness mirrors fixed values from the probe source, and a drift would make
# real runs look incomplete while these fakes stayed green. The mirror is
# therefore checked against the producer's own definitions.
{
  grep -E '^#define (NS_PER_MS|SLEEP_NS|WINDOW_NS|SPIN_CHECKS|RACE_WORK|SLEEP_LOOP) ' \
    "$probe_source"
  cat <<'EOF'
#include <stdio.h>

int main(void) {
    printf("probe_iterations=%llu\n", (unsigned long long)SLEEP_LOOP);
    printf("probe_sleep_ns=%llu\n", (unsigned long long)SLEEP_NS);
    printf("probe_spin_checks=%llu\n", (unsigned long long)SPIN_CHECKS);
    printf("probe_window_ns=%llu\n", (unsigned long long)WINDOW_NS);
    printf("probe_work=%llu\n", (unsigned long long)RACE_WORK);
    return 0;
}
EOF
} >"$test_root/probe-constants.c"
"$dynamic_cc" "$test_root/probe-constants.c" -o "$test_root/probe-constants"
producer_constants="$("$test_root/probe-constants" | sort)"
mirrored_constants="$(grep -E \
  '^probe_(iterations|sleep_ns|spin_checks|window_ns|work)=' "$probe_script" | sort)"
if [[ "$producer_constants" != "$mirrored_constants" ]]; then
  echo "the harness mirrors probe constants the probe source no longer defines:" >&2
  diff <(printf '%s\n' "$mirrored_constants") <(printf '%s\n' "$producer_constants") >&2 || true
  exit 1
fi

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

replay_log=""
icount=""
icount_count=0
arguments=("$@")
for ((index = 0; index < ${#arguments[@]}; index++)); do
  if [[ "${arguments[index]}" == "-icount" ]]; then
    icount_count=$((icount_count + 1))
    icount="${arguments[index + 1]:-}"
  fi
done
# The harness must pass the time model through the -icount option itself, so the
# double rejects a value that appears anywhere else in the command line.
if [[ "$icount_count" -ne 1 ]]; then
  printf 'fake qemu: expected exactly one -icount option, saw %s\n' "$icount_count" >&2
  exit 2
fi
case "$icount" in
  *rrfile=*) replay_log="${icount#*rrfile=}" ;;
  *)
    printf 'fake qemu: -icount value does not request a replay log: %s\n' "$icount" >&2
    exit 2
    ;;
esac
replay_log="${replay_log%%,*}"
if [[ -n "${FAKE_QEMU_EXPECT_ICOUNT:-}" && "$icount" != "${FAKE_QEMU_EXPECT_ICOUNT},rr=record,rrfile="* ]]; then
  printf 'fake qemu: unexpected icount options %s\n' "$icount" >&2
  exit 2
fi
if [[ -n "$replay_log" ]]; then
  printf 'fake replay log\n' >"$replay_log"
fi

counter=1
if [[ -n "${FAKE_QEMU_COUNT_FILE:-}" ]]; then
  counter="$(cat "$FAKE_QEMU_COUNT_FILE" 2>/dev/null || echo 0)"
  counter=$((counter + 1))
  printf '%s\n' "$counter" >"$FAKE_QEMU_COUNT_FILE"
fi

emit() { # $1 race elapsed, $2 sleep observed, $3 checksum
  printf 'probe sleep requested_ns=20000000 observed_ns=%s\r\n' "$2"
  printf 'probe spin chunks=64 window_ns=20000000 state=1\r\n'
  printf 'probe race work=2000000 elapsed_ns=%s within_deadline=no\r\n' "$1"
  printf 'probe sleep_loop iterations=100 observed_ns=100000000\r\n'
  printf 'probe checksum value=%s\r\n' "$3"
}

case "${FAKE_QEMU_BEHAVIOR:-success}" in
  success)
    emit 20000000 20000000 7
    ;;
  varying)
    emit $((20000000 + counter * 1000)) 20000000 7
    ;;
  bad-checksum)
    emit 20000000 20000000 $((7 + counter))
    ;;
  missing-metric)
    printf 'probe sleep requested_ns=20000000 observed_ns=20000000\r\n'
    printf 'probe checksum value=7\r\n'
    ;;
  timeout)
    sleep 30
    ;;
  timeout-first)
    if [[ "$counter" -eq 1 ]]; then
      sleep 30
    fi
    emit 20000000 20000000 7
    ;;
  nonzero)
    exit 3
    ;;
  nonzero-with-metrics)
    if [[ "$counter" -eq 1 ]]; then
      emit 99999999 20000000 7
      exit 3
    fi
    emit 20000000 20000000 7
    ;;
  truncated-metric)
    if [[ "$counter" -eq 1 ]]; then
      emit 20000000 20000000 7 | sed 's/probe checksum value=7/probe checksum value=/'
    else
      emit 20000000 20000000 7
    fi
    ;;
  duplicate-malformed-metric)
    emit 20000000 20000000 7
    if [[ "$counter" -eq 1 ]]; then
      printf 'probe checksum value=\r\n'
    fi
    ;;
  unterminated-metric)
    if [[ "$counter" -eq 1 ]]; then
      printf 'probe sleep requested_ns=20000000 observed_ns=20000000\r\n'
      printf 'probe spin chunks=64 window_ns=20000000 state=1\r\n'
      printf 'probe race work=2000000 elapsed_ns=20000000 within_deadline=no\r\n'
      printf 'probe sleep_loop iterations=100 observed_ns=100000000\r\n'
      printf 'probe checksum value=7'
    else
      emit 20000000 20000000 7
    fi
    ;;
  impossible-metric)
    if [[ "$counter" -eq 1 ]]; then
      printf 'probe sleep requested_ns=20000000 observed_ns=20000000\r\n'
      printf 'probe spin chunks=65 window_ns=20000000 state=1\r\n'
      printf 'probe race work=1999999 elapsed_ns=99999999 within_deadline=yes\r\n'
      printf 'probe sleep_loop iterations=99 observed_ns=100000000\r\n'
      printf 'probe checksum value=18446744073709551616\r\n'
    else
      emit 20000000 20000000 7
    fi
    ;;
  inconsistent-deadline)
    if [[ "$counter" -eq 1 ]]; then
      printf 'probe sleep requested_ns=20000000 observed_ns=20000000\r\n'
      printf 'probe spin chunks=64 window_ns=20000000 state=1\r\n'
      printf 'probe race work=2000000 elapsed_ns=99999999 within_deadline=yes\r\n'
      printf 'probe sleep_loop iterations=100 observed_ns=100000000\r\n'
      printf 'probe checksum value=7\r\n'
    else
      emit 20000000 20000000 7
    fi
    ;;
  leading-zero-metric)
    if [[ "$counter" -eq 1 ]]; then
      emit 20000000 20000000 7 | sed 's/probe checksum value=7/probe checksum value=07/'
    else
      emit 20000000 20000000 7
    fi
    ;;
  inconsistent-state)
    if [[ "$counter" -eq 1 ]]; then
      printf 'probe sleep requested_ns=20000000 observed_ns=20000000\r\n'
      printf 'probe spin chunks=64 window_ns=20000000 state=2\r\n'
      printf 'probe race work=2000000 elapsed_ns=20000000 within_deadline=no\r\n'
      printf 'probe sleep_loop iterations=100 observed_ns=100000000\r\n'
      printf 'probe checksum value=7\r\n'
    else
      emit 20000000 20000000 7
    fi
    ;;
  rounding-state)
    # These two states differ only beyond the range a numeric comparison keeps,
    # so they must be compared as text.
    if [[ "$counter" -eq 1 ]]; then
      printf 'probe sleep requested_ns=20000000 observed_ns=20000000\r\n'
      printf 'probe spin chunks=64 window_ns=20000000 state=9007199254740992\r\n'
      printf 'probe race work=2000000 elapsed_ns=20000000 within_deadline=no\r\n'
      printf 'probe sleep_loop iterations=100 observed_ns=100000000\r\n'
      printf 'probe checksum value=7\r\n'
    else
      printf 'probe sleep requested_ns=20000000 observed_ns=20000000\r\n'
      printf 'probe spin chunks=64 window_ns=20000000 state=9007199254740993\r\n'
      printf 'probe race work=2000000 elapsed_ns=20000000 within_deadline=no\r\n'
      printf 'probe sleep_loop iterations=100 observed_ns=100000000\r\n'
      printf 'probe checksum value=7\r\n'
    fi
    ;;
  duplicate-metric)
    if [[ "$counter" -eq 1 ]]; then
      printf 'probe race work=2000000 elapsed_ns=99999999 within_deadline=yes\r\n'
    fi
    emit 20000000 20000000 7
    ;;
  *)
    exit 2
    ;;
esac
EOF
chmod +x "$fake_qemu"

run_probe() {
  local name="$1"
  shift
  env \
    SIMFERRET_KERNEL="$kernel" \
    SIMFERRET_TIME_MODEL_OUTPUT="$test_root/$name.out" \
    QEMU_SYSTEM_X86_64="$fake_qemu" \
    FAKE_QEMU_COUNT_FILE="$test_root/$name.count" \
    "$@" \
    "$probe_script" >"$test_root/$name.stdout" 2>"$test_root/$name.stderr"
}

# A complete, reproducible experiment.
run_probe success
grep -Fxq 'verdict=reproducible' "$test_root/success.stdout"
grep -Fxq 'complete_runs=5' "$test_root/success.stdout"
grep -Fxq 'incomplete_runs=0' "$test_root/success.stdout"
test "$(find "$test_root/success.out" -mindepth 1 -maxdepth 1 -type d -name 'run.*' | wc -l)" -eq 1

# Variation is reported, not fatal.
run_probe varying FAKE_QEMU_BEHAVIOR=varying
grep -Fxq 'verdict=varying' "$test_root/varying.stdout"
grep -Fxq 'varying_time_metrics=1' "$test_root/varying.stdout"

# A varying control checksum means the runs did not produce the same fixed-work
# result, so the experiment is invalid.
status=0
if run_probe bad-checksum FAKE_QEMU_BEHAVIOR=bad-checksum; then
  echo "a varying control checksum unexpectedly passed" >&2
  exit 1
else
  status=$?
fi
test "$status" -eq 1
grep -Fq 'control checksum varied' "$test_root/bad-checksum.stderr"

# A timed-out run is recorded and skipped; the remaining runs still conclude.
run_probe timeout-first SIMFERRET_QEMU_TIMEOUT=1s SIMFERRET_TIME_MODEL_RUNS=3 \
  FAKE_QEMU_BEHAVIOR=timeout-first
grep -Fxq 'verdict=reproducible' "$test_root/timeout-first.stdout"
grep -Fxq 'complete_runs=2' "$test_root/timeout-first.stdout"
grep -Fxq 'incomplete_runs=1' "$test_root/timeout-first.stdout"
grep -Fxq 'run_1_status=124' "$test_root/timeout-first.stdout"
run_dir="$(find "$test_root/timeout-first.out" -mindepth 1 -maxdepth 1 -type d -name 'run.*')"
grep -Fq 'run-1 status=124' "$run_dir/incomplete.txt"

# No completed run at all is an unsupported execution: the host did not complete
# under this model, which is distinct from an invalid experiment.
status=0
if run_probe all-timeout SIMFERRET_QEMU_TIMEOUT=1s SIMFERRET_TIME_MODEL_RUNS=2 \
  FAKE_QEMU_BEHAVIOR=timeout; then
  echo "an experiment with no completed run unexpectedly passed" >&2
  exit 1
else
  status=$?
fi
# A host that completed no run is exit 3, distinct from a configuration error.
test "$status" -eq 3
grep -Fq 'No run produced a complete probe measurement' "$test_root/all-timeout.stderr"
grep -Fq 'unsupported' "$test_root/all-timeout.stderr"

# A guest that does not compile is a configuration error before any run starts,
# not a host that could not complete.
status=0
if run_probe unbuildable SIMFERRET_STATIC_CC=false \
  FAKE_QEMU_STARTED_FILE="$test_root/unbuildable.started"; then
  echo "an experiment whose guest did not compile unexpectedly passed" >&2
  exit 1
else
  status=$?
fi
test "$status" -eq 2
grep -Fq 'did not compile' "$test_root/unbuildable.stderr"
test ! -e "$test_root/unbuildable.started"

# A failure after setup is a harness failure rather than a reproducibility
# finding, so the probe reports it as a configuration error and not as an
# invalid experiment.
mkdir -p "$test_root/bin"
cat >"$test_root/bin/date" <<'EOF'
#!/bin/sh
echo "date is unavailable" >&2
exit 1
EOF
chmod +x "$test_root/bin/date"
status=0
if run_probe harness-failure "PATH=$test_root/bin:$PATH" SIMFERRET_TIME_MODEL_RUNS=1; then
  echo "a probe whose timestamping failed unexpectedly passed" >&2
  exit 1
else
  status=$?
fi
test "$status" -eq 2
grep -Fq 'failed unexpectedly' "$test_root/harness-failure.stderr"

# A nonzero QEMU exit is treated like a timeout.
if run_probe nonzero SIMFERRET_TIME_MODEL_RUNS=2 FAKE_QEMU_BEHAVIOR=nonzero; then
  echo "an experiment with only nonzero QEMU exits unexpectedly passed" >&2
  exit 1
fi

# A run that reports every measurement and then exits nonzero must be excluded
# by its status, not merely by missing output: if it were aggregated, its
# distinctive value would make the verdict `varying` instead of `reproducible`.
run_probe nonzero-metrics SIMFERRET_TIME_MODEL_RUNS=3 \
  FAKE_QEMU_BEHAVIOR=nonzero-with-metrics
grep -Fxq 'verdict=reproducible' "$test_root/nonzero-metrics.stdout"
grep -Fxq 'complete_runs=2' "$test_root/nonzero-metrics.stdout"
grep -Fxq 'incomplete_runs=1' "$test_root/nonzero-metrics.stdout"

# The configured time model is what the harness passes to QEMU.
run_probe nondefault SIMFERRET_ICOUNT_OPTIONS=shift=4,sleep=off \
  FAKE_QEMU_EXPECT_ICOUNT=shift=4,sleep=off
grep -Fxq 'verdict=reproducible' "$test_root/nondefault.stdout"
grep -Fxq 'icount_options=shift=4,sleep=off' "$test_root/nondefault.stdout"

# The double binds the time model to -icount, so an invocation that drops the
# switch is rejected rather than passing unnoticed.
if "$fake_qemu" -serial stdio 'shift=4,sleep=off,rr=record,rrfile=/dev/null' \
  >"$test_root/fake-stdout" 2>"$test_root/fake-stderr"; then
  echo "the fake QEMU accepted a time model that was not passed to -icount" >&2
  exit 1
fi
grep -Fq 'expected exactly one -icount option' "$test_root/fake-stderr"

# A truncated duplicate row is not a measurement, so the run is incomplete
# rather than aggregated from a partial line.
run_probe truncated-metric SIMFERRET_TIME_MODEL_RUNS=3 \
  FAKE_QEMU_BEHAVIOR=truncated-metric
grep -Fxq 'verdict=reproducible' "$test_root/truncated-metric.stdout"
grep -Fxq 'complete_runs=2' "$test_root/truncated-metric.stdout"
grep -Fxq 'incomplete_runs=1' "$test_root/truncated-metric.stdout"
run_dir="$(find "$test_root/truncated-metric.out" -mindepth 1 -maxdepth 1 -type d -name 'run.*')"
grep -Fq 'malformed: checksum' "$run_dir/incomplete.txt"

# Two conflicting rows for one measurement cannot be resolved by taking the
# first, so the run is incomplete rather than silently aggregated.
run_probe duplicate-metric SIMFERRET_TIME_MODEL_RUNS=3 \
  FAKE_QEMU_BEHAVIOR=duplicate-metric
grep -Fxq 'verdict=reproducible' "$test_root/duplicate-metric.stdout"
grep -Fxq 'complete_runs=2' "$test_root/duplicate-metric.stdout"
grep -Fxq 'incomplete_runs=1' "$test_root/duplicate-metric.stdout"
run_dir="$(find "$test_root/duplicate-metric.out" -mindepth 1 -maxdepth 1 -type d -name 'run.*')"
grep -Fq 'malformed: race' "$run_dir/incomplete.txt"

# A well-formed row plus a malformed duplicate is still two reports of one
# measurement, so the metric is malformed rather than silently resolved.
run_probe duplicate-malformed SIMFERRET_TIME_MODEL_RUNS=3 \
  FAKE_QEMU_BEHAVIOR=duplicate-malformed-metric
grep -Fxq 'verdict=reproducible' "$test_root/duplicate-malformed.stdout"
grep -Fxq 'complete_runs=2' "$test_root/duplicate-malformed.stdout"
grep -Fxq 'incomplete_runs=1' "$test_root/duplicate-malformed.stdout"
run_dir="$(find "$test_root/duplicate-malformed.out" -mindepth 1 -maxdepth 1 -type d -name 'run.*')"
grep -Fq 'malformed: checksum' "$run_dir/incomplete.txt"

# An unterminated final line means the output was cut off, so the last
# measurement is not trusted even though its text is well formed.
run_probe unterminated SIMFERRET_TIME_MODEL_RUNS=3 \
  FAKE_QEMU_BEHAVIOR=unterminated-metric
grep -Fxq 'verdict=reproducible' "$test_root/unterminated.stdout"
grep -Fxq 'complete_runs=2' "$test_root/unterminated.stdout"
grep -Fxq 'incomplete_runs=1' "$test_root/unterminated.stdout"
run_dir="$(find "$test_root/unterminated.out" -mindepth 1 -maxdepth 1 -type d -name 'run.*')"
grep -Fq 'unterminated:true' "$run_dir/incomplete.txt"

# Values the probe cannot produce are not measurements: wrong fixed constants,
# a spin count that is not a whole number of polling batches, and a checksum
# outside the producer's range.
run_probe impossible SIMFERRET_TIME_MODEL_RUNS=3 FAKE_QEMU_BEHAVIOR=impossible-metric
grep -Fxq 'verdict=reproducible' "$test_root/impossible.stdout"
grep -Fxq 'complete_runs=2' "$test_root/impossible.stdout"
grep -Fxq 'incomplete_runs=1' "$test_root/impossible.stdout"
run_dir="$(find "$test_root/impossible.out" -mindepth 1 -maxdepth 1 -type d -name 'run.*')"
grep -Fq 'malformed: spin race sleep_loop checksum' "$run_dir/incomplete.txt"

# A deadline decision that contradicts its own measured duration is rejected.
run_probe inconsistent SIMFERRET_TIME_MODEL_RUNS=3 \
  FAKE_QEMU_BEHAVIOR=inconsistent-deadline
grep -Fxq 'verdict=reproducible' "$test_root/inconsistent.stdout"
grep -Fxq 'complete_runs=2' "$test_root/inconsistent.stdout"
grep -Fxq 'incomplete_runs=1' "$test_root/inconsistent.stdout"
run_dir="$(find "$test_root/inconsistent.out" -mindepth 1 -maxdepth 1 -type d -name 'run.*')"
grep -Fq 'malformed: race' "$run_dir/incomplete.txt"

# A leading zero is not a value the probe's `%llu` can print, and it would be
# read as an octal literal by the arithmetic checks.
run_probe leading-zero SIMFERRET_TIME_MODEL_RUNS=3 \
  FAKE_QEMU_BEHAVIOR=leading-zero-metric
grep -Fxq 'verdict=reproducible' "$test_root/leading-zero.stdout"
grep -Fxq 'complete_runs=2' "$test_root/leading-zero.stdout"
grep -Fxq 'incomplete_runs=1' "$test_root/leading-zero.stdout"
run_dir="$(find "$test_root/leading-zero.out" -mindepth 1 -maxdepth 1 -type d -name 'run.*')"
grep -Fq 'malformed: checksum' "$run_dir/incomplete.txt"

# The spin state is a function of the chunk count, so two completed runs that
# report the same count with different states did not execute the same fixed
# work. That invalidates the experiment rather than being timing variation.
if run_probe inconsistent-state SIMFERRET_TIME_MODEL_RUNS=3 \
  FAKE_QEMU_BEHAVIOR=inconsistent-state; then
  echo "an experiment with a spin count and state disagreement unexpectedly passed" >&2
  exit 1
fi
grep -Fq 'spin count and state disagree' "$test_root/inconsistent-state.stderr"

# 64-bit states that differ only beyond the range a numeric comparison keeps
# must still be seen as a disagreement.
if run_probe rounding-state SIMFERRET_TIME_MODEL_RUNS=3 \
  FAKE_QEMU_BEHAVIOR=rounding-state; then
  echo "an experiment with rounded-together spin states unexpectedly passed" >&2
  exit 1
fi
grep -Fq 'spin count and state disagree' "$test_root/rounding-state.stderr"

# An incomplete measurement is not aggregated.
if run_probe missing-metric SIMFERRET_TIME_MODEL_RUNS=2 \
  FAKE_QEMU_BEHAVIOR=missing-metric; then
  echo "an experiment with no complete measurement unexpectedly passed" >&2
  exit 1
fi

# A single completed run cannot support a reproducibility claim.
run_probe single SIMFERRET_TIME_MODEL_RUNS=1
grep -Fxq 'verdict=inconclusive' "$test_root/single.stdout"
grep -Fxq 'complete_runs=1' "$test_root/single.stdout"

# Invalid inputs must fail before QEMU starts.
started_file="$test_root/started"
for case_name in invalid-icount invalid-runs invalid-duration unwritable-output; do
  case "$case_name" in
    invalid-icount) arguments=("SIMFERRET_ICOUNT_OPTIONS=shift=1,rr=record") ;;
    invalid-runs) arguments=("SIMFERRET_TIME_MODEL_RUNS=0") ;;
    invalid-duration) arguments=("SIMFERRET_QEMU_TIMEOUT=0") ;;
    # A setup command that cannot run is a configuration error too: the
    # experiment's own output cannot be created, so nothing is measured.
    unwritable-output) arguments=("SIMFERRET_TIME_MODEL_OUTPUT=/dev/null") ;;
  esac
  status=0
  if run_probe "$case_name" "${arguments[@]}" "FAKE_QEMU_STARTED_FILE=$started_file"; then
    echo "$case_name unexpectedly passed" >&2
    exit 1
  else
    status=$?
  fi
  # A configuration error is exit 2, distinct from an invalid experiment.
  test "$status" -eq 2
  if [[ -e "$started_file" ]]; then
    echo "$case_name started QEMU" >&2
    exit 1
  fi
done

printf 'Time-model probe regression tests passed.\n'
