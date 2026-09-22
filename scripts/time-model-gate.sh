#!/usr/bin/env bash
set -euo pipefail

# SimFerret pinned time-model gate (RFD 4 Phase 0).
#
# The time-model probe reports variation rather than failing on it, because
# variation is the finding it exists to detect. This gate is the opposite: it
# accepts a host only when the pinned model completed every requested run with
# the verdict `reproducible` and with the guest measurements equal to the
# reference host's recorded values. A host that cannot complete under the pinned
# model fails as an unsupported execution; no fallback model is attempted, so a
# run under this gate is either a validation of the pinned model or a failure.
#
# The pinned model and the values a host must reproduce are one checked-in
# record, `poc/time-model/reference-host-values.txt`, so the gate cannot
# validate a model whose values were measured under another one. The record
# names the model, the SHA-256 of the QEMU executable, the guest kernel, and the
# initramfs, and one measurement per metric. The product launches this model:
# `TIME_MODEL` in `crates/simferret/src/vm.rs` pins it, and the pinned emulator the
# flake builds carries the replay-flush patch `sleep=off` needs, so a recording can
# be driven. `rfd/0004/EVIDENCE.adoc` records the measurement, the pin, and the
# resolution.
#
# The deadline and the sample size are the RFD's acceptance rule, not the
# caller's, so both are fixed here: the probe keeps its own overridable deadline
# for diagnostics. Each invocation writes its own directory under the output
# root, created before anything is validated, holding its result file, the
# probe's output, and the probe's run directory, so a failure cannot leave a
# previous success behind and concurrent invocations cannot overwrite each
# other.
#
# Exit status and the `result=` line in the invocation's result file say which
# kind of failure it was: 2 configuration-error (the gate or its inputs are
# unusable, before or without a valid experiment), 3 unsupported-execution (this
# host did not complete the runs), 1 validation-failure (the runs completed and
# the experiment or its values did not hold). The probe's own outcomes are
# mapped rather than merged: its exit status 2 is a configuration error, 3 is a
# host that completed no run, and 1 is a completed experiment that does not
# support a claim.

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
probe_script="${SIMFERRET_TIME_MODEL_PROBE:-$repo_root/scripts/time-model-probe.sh}"
reference_file="${SIMFERRET_TIME_MODEL_REFERENCE:-$repo_root/poc/time-model/reference-host-values.txt}"
output_root="${SIMFERRET_TIME_MODEL_GATE_OUTPUT:-$repo_root/.poc/rfd4-phase0-gate}"
runs="${SIMFERRET_TIME_MODEL_RUNS:-5}"
kernel="${SIMFERRET_KERNEL:-}"
qemu="${QEMU_SYSTEM_X86_64:-qemu-system-x86_64}"
output_dir=""
result_file=""
probe_stdout=""
probe_stderr=""
pinned_time_model=""
result_recorded=false

readonly validation_deadline="180s"
readonly minimum_runs=5
readonly maximum_runs=50
readonly required_metrics=(sleep spin race sleep_loop checksum)

# The result file is written for failures as well as for success, so the
# invocation's own directory says what happened even when a later run passes.
record_result() { # $1 result, remaining lines are reason lines
  local result="$1"
  shift

  if [[ -z "$result_file" ]]; then
    return 0
  fi
  if ! {
    if [[ "$result" == "passed" ]]; then
      printf 'time_model_gate=passed\n'
    else
      printf 'time_model_gate=failed\n'
    fi
    printf 'result=%s\n' "$result"
    local line
    for line in "$@"; do
      printf 'reason=%s\n' "$line"
    done
    printf 'host=%s\n' "$(uname -n)"
    printf 'platform=%s %s\n' "$(uname -s)" "$(uname -m)"
    printf 'icount_options=%s\n' "$pinned_time_model"
    printf 'requested_runs=%s\n' "$runs"
    printf 'qemu_timeout=%s\n' "$validation_deadline"
  } >"$result_file"; then
    # A result that cannot be recorded is a harness failure, and the status says
    # so rather than leaving the recorded result and the status disagreeing.
    echo "The time-model gate could not record its result in $result_file" >&2
    exit 2
  fi
  result_recorded=true
}

diagnostics_note() {
  if [[ -n "$output_dir" ]]; then
    printf 'Diagnostics: %s\n' "$output_dir" >&2
  else
    printf 'Diagnostics: none; the gate did not start an experiment.\n' >&2
  fi
}

# A configuration error is the gate's own inputs being unusable: a malformed
# reference record, an unsupported platform, or a probe that rejects its
# arguments. It is not a statement about the host.
fail_configuration() {
  local reason="$1"

  record_result configuration-error "$reason"
  echo "The time-model gate cannot run as configured: $reason" >&2
  diagnostics_note
  exit 2
}

# A host that cannot complete under the pinned model is unsupported. The gate
# reports that as the finding rather than retrying another model, because a
# fallback would hide the incompatibility and validate a model other than the
# one the RFD pins.
fail_unsupported() {
  local reason="$1"

  record_result unsupported-execution "$reason"
  echo "The pinned time model did not complete on this host: $reason" >&2
  echo "A host that cannot complete under the pinned model is an unsupported" >&2
  echo "execution, and no fallback model is attempted." >&2
  diagnostics_note
  exit 3
}

# The runs completed and disagreed with the reference record, or the gate cannot
# read the experiment it produced.
fail_validation() {
  local reason="$1"

  record_result validation-failure "$reason"
  echo "The pinned time model did not validate: $reason" >&2
  diagnostics_note
  exit 1
}

# A key must appear exactly once and must not be empty, because a duplicated or
# absent value would let the comparison below read a different value than the
# one that was recorded.
reference_value() { # $1 key
  local matches value

  matches="$(grep -c "^$1=" "$reference_file" || true)"
  if [[ "$matches" -ne 1 ]]; then
    fail_configuration "$reference_file must record exactly one $1; found $matches"
  fi
  value="$(sed -n "s/^$1=//p" "$reference_file")"
  if [[ -z "$value" ]]; then
    fail_configuration "$reference_file records an empty $1"
  fi
  printf '%s\n' "$value"
}

evidence_value() { # $1 key
  sed -n "s/^$1=//p" <<<"$evidence"
}

require_evidence() { # $1 key, $2 expected value
  local key="$1"
  local expected="$2"
  local actual

  actual="$(evidence_value "$key")"
  if [[ "$actual" != "$expected" ]]; then
    fail_validation "$key is ${actual:-<missing>}; expected $expected"
  fi
}

# Every invocation gets its own directory before anything is validated, so a
# configuration error is recorded in the invocation that produced it instead of
# leaving an earlier success as the newest result under the output root. Only a
# root that cannot be created at all has nowhere to write and reports on stderr.
umask 022
if ! mkdir -p "$output_root"; then
  echo "The time-model gate cannot create its output root: $output_root" >&2
  exit 2
fi
if ! output_dir="$(mktemp -d "$output_root/gate.XXXXXXXX")"; then
  echo "The time-model gate cannot create an invocation directory under $output_root" >&2
  exit 2
fi
result_file="$output_dir/gate.txt"
probe_stdout="$output_dir/probe.stdout"
probe_stderr="$output_dir/probe.stderr"

# An exit that records nothing is still an invocation that failed, so it is
# recorded rather than left as an empty directory that reads like a missing run.
# The status it exits with is the one its recorded result means, so a caller
# reading either the status or the result file sees the same finding.
finish_unrecorded() {
  local status=$?

  trap - EXIT
  if [[ "$result_recorded" != true ]]; then
    record_result configuration-error "the gate exited with status $status without recording a result"
    exit 2
  fi
  exit "$status"
}
trap finish_unrecorded EXIT

if [[ "$(uname -s)" != "Linux" || "$(uname -m)" != "x86_64" ]]; then
  fail_configuration "the gate supports x86-64 Linux only"
fi
# The acceptance deadline is fixed rather than inherited: a caller that could
# raise it would accept a host the recorded deadline rejects. The probe keeps
# its own deadline for diagnostics.
if [[ -n "${SIMFERRET_QEMU_TIMEOUT:-}" && "$SIMFERRET_QEMU_TIMEOUT" != "$validation_deadline" ]]; then
  fail_configuration "the acceptance deadline is fixed at $validation_deadline, and SIMFERRET_QEMU_TIMEOUT adjusts the probe rather than the gate"
fi
if [[ ! "$runs" =~ ^[1-9][0-9]*$ ]] || ((runs < minimum_runs)) || ((runs > maximum_runs)); then
  fail_configuration "SIMFERRET_TIME_MODEL_RUNS must be an integer from $minimum_runs through $maximum_runs, because the RFD requires zero varying measurements across at least five complete runs on every host in the supported matrix"
fi
if [[ -z "$kernel" || ! -f "$kernel" ]]; then
  fail_configuration "SIMFERRET_KERNEL must name the pinned x86-64 Linux bzImage; run this script through .agents/dev"
fi
if [[ ! -f "$probe_script" ]]; then
  fail_configuration "time-model probe not found: $probe_script"
fi
if [[ ! -f "$reference_file" ]]; then
  fail_configuration "time-model reference values not found: $reference_file"
fi
for command in "$qemu" sha256sum; do
  if ! command -v "$command" >/dev/null 2>&1; then
    fail_configuration "required command not found: $command"
  fi
done

# The model the reference values were measured under is the model this gate
# validates, and the record must name one measurement for each required metric:
# five rows that repeat one metric would compare that metric five times and
# never check the others.
pinned_time_model="$(reference_value icount_options)"
reference_kernel_sha256="$(reference_value kernel_sha256)"
reference_initramfs_sha256="$(reference_value initramfs_sha256)"
reference_qemu_sha256="$(reference_value qemu_sha256)"
for metric in "${required_metrics[@]}"; do
  rows="$(grep -c "^measurement=probe $metric " "$reference_file" || true)"
  if [[ "$rows" -ne 1 ]]; then
    fail_configuration "$reference_file must record exactly one $metric measurement; found $rows"
  fi
done
mapfile -t reference_measurements < <(sed -n 's/^measurement=//p' "$reference_file")
if [[ "${#reference_measurements[@]}" -ne "${#required_metrics[@]}" ]]; then
  fail_configuration "$reference_file must record five measurements; found ${#reference_measurements[@]}"
fi

umask 022
kernel_sha256="$(sha256sum "$kernel" | cut -d' ' -f1)"
# The executable rather than its version string is the QEMU identity, so a
# rebuilt or patched binary cannot pass as the reference build.
qemu_path="$(command -v "$qemu")"
qemu_sha256="$(sha256sum "$qemu_path" | cut -d' ' -f1)"

# The probe runs once, with the pinned model and the fixed deadline, and its own
# diagnostics are kept so a failure can be read rather than guessed at.
set +e
SIMFERRET_ICOUNT_OPTIONS="$pinned_time_model" \
  SIMFERRET_TIME_MODEL_RUNS="$runs" \
  SIMFERRET_QEMU_TIMEOUT="$validation_deadline" \
  SIMFERRET_TIME_MODEL_OUTPUT="$output_dir" \
  "$probe_script" >"$probe_stdout" 2>"$probe_stderr"
probe_status=$?
set -e
cat "$probe_stdout"
if [[ -s "$probe_stderr" ]]; then
  cat "$probe_stderr" >&2
fi

if ((probe_status == 2)); then
  fail_configuration "the probe rejected its configuration (exit status 2)"
fi
if ((probe_status == 3)); then
  fail_unsupported "the probe completed no run (exit status 3), so this host did not complete under the pinned model"
fi
if ((probe_status == 1)); then
  fail_validation "the probe's completed runs did not support a reproducibility claim (exit status 1)"
fi
if ((probe_status != 0)); then
  fail_configuration "the probe exited with status $probe_status, which is not a documented outcome"
fi

artifacts="$(sed -n 's/^Artifacts: //p' "$probe_stdout" | tail -n 1)"
if [[ -z "$artifacts" || ! -f "$artifacts/evidence.txt" ]]; then
  fail_configuration "the probe reported success but left no evidence to read"
fi
evidence="$(cat "$artifacts/evidence.txt")"

# Every requested run must complete, the verdict must be an explicit
# reproducibility claim, and the run must be the pinned model rather than
# whatever the environment happened to configure. A host that dropped runs
# cannot complete under the model, which is an unsupported execution rather than
# a measurement difference.
incomplete_runs="$(evidence_value incomplete_runs)"
if [[ "$incomplete_runs" != 0 ]]; then
  fail_unsupported "$incomplete_runs of $runs requested runs did not complete"
fi
require_evidence icount_options "$pinned_time_model"
require_evidence requested_runs "$runs"
require_evidence complete_runs "$runs"
require_evidence verdict reproducible

# Identical artifacts on every host, so a measurement difference is a time-model
# difference rather than a different guest.
require_evidence initramfs_sha256 "$reference_initramfs_sha256"
if [[ "$kernel_sha256" != "$reference_kernel_sha256" ]]; then
  fail_validation "the guest kernel is $kernel_sha256; the reference host recorded $reference_kernel_sha256"
fi
if [[ "$qemu_sha256" != "$reference_qemu_sha256" ]]; then
  fail_validation "the QEMU executable is $qemu_sha256 ($qemu_path); the reference host recorded $reference_qemu_sha256"
fi

# The guest measurements themselves: equal to the reference host, exactly.
for row in "${reference_measurements[@]}"; do
  metric="${row#probe }"
  metric="${metric%% *}"
  values="$artifacts/values-$metric.txt"
  if [[ ! -f "$values" ]]; then
    fail_validation "the $metric measurement was not retained"
  fi
  distinct="$(sed '/^$/d' "$values" | sort -u)"
  if [[ "$distinct" != "$row" ]]; then
    fail_validation "the $metric measurement is ${distinct:-<missing>}; the reference host recorded $row"
  fi
done

{
  printf 'time_model_gate=passed\n'
  printf 'result=passed\n'
  printf 'host=%s\n' "$(uname -n)"
  printf 'platform=%s %s\n' "$(uname -s)" "$(uname -m)"
  printf 'icount_options=%s\n' "$pinned_time_model"
  printf 'requested_runs=%s\n' "$runs"
  printf 'qemu_timeout=%s\n' "$validation_deadline"
  printf 'qemu_version=%s\n' "$(evidence_value qemu_version)"
  printf 'qemu_sha256=%s\n' "$qemu_sha256"
  printf 'kernel_sha256=%s\n' "$kernel_sha256"
  printf 'initramfs_sha256=%s\n' "$reference_initramfs_sha256"
  printf 'guest_measurements=equal_to_reference_host\n'
  printf 'artifacts=%s\n' "$artifacts"
} | tee "$result_file"
result_recorded=true

printf '\nThe pinned time model %s validated on this host: %s of %s runs completed and every guest measurement equals the reference host.\n' \
  "$pinned_time_model" "$runs" "$runs"
