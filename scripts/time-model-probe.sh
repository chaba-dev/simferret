#!/usr/bin/env bash
set -euo pipefail

# SimFerret guest time-model probe.
#
# Runs the same fixed guest several times under one pinned QEMU time
# configuration and reports which guest time measurements are reproducible. See
# poc/time-model/probe.c for the measurements.
#
# The script reports rather than fails on variation, because variation is the
# finding it exists to detect. It fails only when the experiment itself is
# invalid: no run completed, or the control checksum varied across completed
# runs, which would mean they did not produce the same fixed-work result.
#
# A run that times out, exits nonzero, does not report exactly one well-formed
# row per measurement, or leaves its output unterminated is recorded and skipped
# rather than aborting the experiment, and fewer than two completed runs yields
# an `inconclusive` verdict rather than a reproducibility claim.
#
# The script exits 2 when its own configuration is unusable or the experiment
# could not be prepared, 3 when no run completed at all (the host did not
# complete under this model), and 1 when the runs completed but the experiment
# is invalid (the control checksum varied, or the spin count and state
# disagree). A caller can therefore tell a setup problem, a host that cannot
# complete, and a completed experiment that does not support a claim apart.

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
probe_source="$repo_root/poc/time-model/probe.c"
output_root="${SIMFERRET_TIME_MODEL_OUTPUT:-$repo_root/.poc/time-model-probe}"
kernel="${SIMFERRET_KERNEL:-}"
qemu="${QEMU_SYSTEM_X86_64:-qemu-system-x86_64}"
static_cc="${SIMFERRET_STATIC_CC:-${CC:-cc}}"
icount_options="${SIMFERRET_ICOUNT_OPTIONS:-shift=auto}"
runs="${SIMFERRET_TIME_MODEL_RUNS:-5}"
qemu_timeout="${SIMFERRET_QEMU_TIMEOUT:-180s}"
qemu_kill_after="${SIMFERRET_QEMU_KILL_AFTER:-5s}"
metrics=(sleep spin race sleep_loop checksum)
complete_runs=()
incomplete_runs=()
output_dir=""
complete=false

# An exit that is not one of the documented outcomes is a harness failure rather
# than a statement about reproducibility, so it is reported as a configuration
# error: every intentional outcome records itself before it exits, and an
# untagged status is not read as a finding about the host.
outcome=""
finish() {
  local status=$?

  trap - EXIT
  if [[ "$complete" != true && -n "$output_dir" ]]; then
    echo "Time-model probe failed; diagnostics: $output_dir" >&2
  fi
  case "$status:$outcome" in
    0:*|2:*|3:unsupported|1:invalid-experiment)
      ;;
    *)
      echo "The time-model probe failed unexpectedly, so the experiment's outcome is" >&2
      echo "not a reproducibility finding; see the diagnostics above." >&2
      exit 2
      ;;
  esac
  exit "$status"
}

trap finish EXIT

validate_positive_duration() {
  local name="$1"
  local value="$2"
  local pattern='^(([0-9]*[1-9][0-9]*)(\.[0-9]+)?|0*\.[0-9]*[1-9][0-9]*)[smhd]?$'

  if [[ ! "$value" =~ $pattern ]]; then
    echo "$name must be a finite, positive duration (for example, 5s or 0.1s)." >&2
    exit 2
  fi
}

# These mirror the fixed values in poc/time-model/probe.c. A row that does not
# report them did not come from the probe, so it cannot be a measurement.
probe_sleep_ns=20000000
probe_window_ns=20000000
probe_work=2000000
probe_iterations=100
probe_spin_checks=64

is_uint64() {
  local value="$1"

  # Canonical unsigned decimal only: the arithmetic checks below would read a
  # leading zero as an octal literal, and the probe's `%llu` never prints one.
  [[ "$value" =~ ^(0|[1-9][0-9]{0,19})$ ]] || return 1
  [[ "${#value}" -lt 20 || "$value" < "18446744073709551616" ]]
}

# A completed run reports exactly one well-formed row per metric, and the row
# must be one the probe can produce. A row that is absent, truncated,
# duplicated, or otherwise malformed leaves that measurement unmeasurable, so
# the run is incomplete rather than aggregated from a partial line.
metric_pattern() {
  case "$1" in
    sleep) printf '%s' "probe sleep requested_ns=${probe_sleep_ns} observed_ns=[0-9]{1,20}" ;;
    spin) printf '%s' "probe spin chunks=[0-9]{1,18} window_ns=${probe_window_ns} state=[0-9]{1,20}" ;;
    race) printf '%s' "probe race work=${probe_work} elapsed_ns=[0-9]{1,18} within_deadline=(yes|no)" ;;
    sleep_loop) printf '%s' "probe sleep_loop iterations=${probe_iterations} observed_ns=[0-9]{1,20}" ;;
    checksum) printf '%s' 'probe checksum value=[0-9]{1,20}' ;;
    *) return 1 ;;
  esac
}

# The spin loop completes whole polling batches and the race decision follows
# from its own measured duration, so a row that contradicts either is not a
# measurement the probe could have taken.
validated_metric_row() { # $1 metric, $2 CR-stripped serial output
  local metric="$1" serial="$2" rows row value
  rows="$(grep -E "^probe ${metric} " <<<"$serial" || true)"
  if [[ "$(grep -c . <<<"$rows" || true)" -ne 1 ]]; then
    return 1
  fi
  row="$rows"
  if [[ ! "$row" =~ ^$(metric_pattern "$metric")$ ]]; then
    return 1
  fi
  case "$metric" in
    sleep|sleep_loop)
      is_uint64 "${row##*observed_ns=}" || return 1
      ;;
    spin)
      value="${row#probe spin chunks=}"
      value="${value%% *}"
      is_uint64 "$value" || return 1
      ((value > 0 && value % probe_spin_checks == 0)) || return 1
      is_uint64 "${row##*state=}" || return 1
      ;;
    race)
      value="${row#probe race work=}"
      value="${value#*elapsed_ns=}"
      value="${value%% *}"
      is_uint64 "$value" || return 1
      if [[ "$row" == *within_deadline=yes ]]; then
        ((value < probe_window_ns)) || return 1
      else
        ((value >= probe_window_ns)) || return 1
      fi
      ;;
    checksum)
      is_uint64 "${row##*value=}" || return 1
      ;;
  esac
  printf '%s\n' "$row"
}

# The probe terminates every line, so an unterminated final line means the run's
# output was cut off and its last measurement cannot be trusted.
output_is_terminated() {
  local serial="$1"

  if [[ ! -s "$serial" ]]; then
    return 1
  fi
  [[ "$(tail -c1 "$serial" | od -An -tx1 | tr -d '[:space:]')" == "0a" ]]
}

if [[ "$(uname -s)" != "Linux" || "$(uname -m)" != "x86_64" ]]; then
  echo "The time-model probe supports x86-64 Linux only." >&2
  exit 2
fi
validate_positive_duration SIMFERRET_QEMU_TIMEOUT "$qemu_timeout"
validate_positive_duration SIMFERRET_QEMU_KILL_AFTER "$qemu_kill_after"
if [[ ! "$runs" =~ ^[1-9][0-9]*$ ]] || ((runs > 50)); then
  echo "SIMFERRET_TIME_MODEL_RUNS must be an integer from 1 through 50." >&2
  exit 2
fi
if [[ ! "$icount_options" =~ ^[a-z0-9=,]+$ ]] || [[ "$icount_options" == *rr=* ]]; then
  echo "SIMFERRET_ICOUNT_OPTIONS must be icount options such as shift=auto or" >&2
  echo "shift=7,sleep=off, and must not set rr= or rrfile=." >&2
  exit 2
fi
if [[ -z "$kernel" || ! -f "$kernel" ]]; then
  echo "SIMFERRET_KERNEL must name the pinned x86-64 Linux bzImage." >&2
  echo "Run this script through .agents/dev." >&2
  exit 2
fi
if [[ ! -f "$probe_source" ]]; then
  echo "Time-model probe source not found: $probe_source" >&2
  exit 2
fi
for command in "$qemu" "$static_cc" cpio gzip mktemp od sha256sum timeout; do
  if ! command -v "$command" >/dev/null 2>&1; then
    echo "Required command not found: $command" >&2
    exit 2
  fi
done

umask 022
if ! mkdir -p "$output_root"; then
  echo "The time-model probe cannot create its output root: $output_root" >&2
  exit 2
fi
if ! output_dir="$(mktemp -d "$output_root/run.XXXXXXXX")"; then
  echo "The time-model probe cannot create a run directory under $output_root" >&2
  exit 2
fi
root="$output_dir/rootfs"
# The guest and its initramfs are the experiment's inputs, so a failure to build
# them is a configuration error rather than a host that could not complete.
if ! mkdir -p "$root"; then
  echo "The time-model probe cannot create the guest root: $root" >&2
  exit 2
fi
if ! "$static_cc" -static -Os -Wall -Wextra -Werror "$probe_source" -o "$root/init"; then
  echo "The probe guest did not compile with $static_cc; the experiment cannot start." >&2
  exit 2
fi
if ! find "$root" -exec touch -h -d @0 {} +; then
  echo "The time-model probe cannot normalize the guest root's timestamps." >&2
  exit 2
fi
if ! (
  cd "$root"
  find . -print0 | LC_ALL=C sort -z | cpio --null --create --format=newc \
    --owner=0:0 --reproducible --quiet
) | gzip -n >"$output_dir/initramfs.cpio.gz"; then
  echo "The probe initramfs could not be built; the experiment cannot start." >&2
  exit 2
fi

for index in $(seq 1 "$runs"); do
  started="$(date +%s%N)"
  set +e
  timeout --kill-after="$qemu_kill_after" "$qemu_timeout" \
    "$qemu" \
    -machine "pc-i440fx-9.2,accel=tcg" \
    -cpu qemu64 \
    -smp 1 \
    -m 256M \
    -nodefaults \
    -no-user-config \
    -display none \
    -monitor none \
    -serial stdio \
    -no-reboot \
    -net none \
    -rtc "base=2000-01-01T00:00:00,clock=vm" \
    -kernel "$kernel" \
    -initrd "$output_dir/initramfs.cpio.gz" \
    -append "console=ttyS0 quiet loglevel=0 panic=-1 nokaslr random.trust_cpu=off init=/init" \
    -icount "$icount_options,rr=record,rrfile=$output_dir/run-$index.replay.bin" \
    >"$output_dir/run-$index.serial" 2>"$output_dir/run-$index.qemu.log"
  qemu_status=$?
  set -e
  finished="$(date +%s%N)"
  printf '%s\n' "$((finished - started))" >"$output_dir/run-$index.duration-ns"
  printf '%s\n' "$qemu_status" >"$output_dir/run-$index.status"

  serial="$(tr -d '\r' <"$output_dir/run-$index.serial")"
  missing=""
  malformed=""
  unterminated=false
  if ! output_is_terminated "$output_dir/run-$index.serial"; then
    unterminated=true
  fi
  for metric in "${metrics[@]}"; do
    if validated_metric_row "$metric" "$serial" >/dev/null; then
      continue
    fi
    if grep -Fq "probe $metric " <<<"$serial"; then
      malformed+=" $metric"
    else
      missing+=" $metric"
    fi
  done
  if [[ "$qemu_status" -ne 0 || -n "$missing" || -n "$malformed" || "$unterminated" == true ]]; then
    incomplete_runs+=("$index")
    printf 'run-%s status=%s missing:%s malformed:%s unterminated:%s\n' \
      "$index" "$qemu_status" "$missing" "$malformed" "$unterminated" \
      >>"$output_dir/incomplete.txt"
  else
    complete_runs+=("$index")
  fi
done

if [[ "${#complete_runs[@]}" -eq 0 ]]; then
  outcome="unsupported"
  echo "No run produced a complete probe measurement." >&2
  echo "This host did not complete under the pinned model, which is an unsupported" >&2
  echo "execution rather than a reproducibility result." >&2
  echo "Try SIMFERRET_ICOUNT_OPTIONS=shift=auto or a smaller fixed shift, and a" >&2
  echo "longer SIMFERRET_QEMU_TIMEOUT." >&2
  exit 3
fi

# Aggregate over completed runs only, so a partial run cannot contribute a
# measurement to the comparison.
measurements="$output_dir/measurements.txt"
: >"$measurements"
for metric in "${metrics[@]}"; do
  values="$output_dir/values-$metric.txt"
  : >"$values"
  for index in "${complete_runs[@]}"; do
    serial="$(tr -d '\r' <"$output_dir/run-$index.serial")"
    validated_metric_row "$metric" "$serial" >>"$values"
  done
  printf '%s distinct=%s\n' "$metric" "$(sed '/^$/d' "$values" | sort -u | wc -l)" \
    >>"$measurements"
  while IFS= read -r value; do
    printf '  %s\n' "$value" >>"$measurements"
  done < <(sed '/^$/d' "$values" | sort -u)
done

checksum_distinct="$(sed '/^$/d' "$output_dir/values-checksum.txt" | sort -u | wc -l)"
if [[ "$checksum_distinct" -ne 1 ]]; then
  outcome="invalid-experiment"
  echo "The control checksum varied across completed runs, so the experiment is invalid." >&2
  cat "$output_dir/values-checksum.txt" >&2
  exit 1
fi

# The spin state is a pure function of the chunk count, so two completed runs
# that report the same count must report the same state. A disagreement means
# the runs did not execute the same fixed work, which invalidates the experiment
# rather than being a timing measurement. The state is compared as text, because
# these are 64-bit values that a numeric comparison would round together.
comparison_status=0
sed '/^$/d' "$output_dir/values-spin.txt" |
  sed -E 's/^probe spin chunks=([0-9]+) .* state=([0-9]+)$/\1 \2/' |
  awk '{ state = "state:" $2; if ($1 in seen && seen[$1] != state) exit 1; seen[$1] = state }' ||
  comparison_status=$?
if ((comparison_status == 1)); then
  outcome="invalid-experiment"
  echo "The spin count and state disagree across completed runs, so the experiment is invalid." >&2
  cat "$output_dir/values-spin.txt" >&2
  exit 1
fi
if ((comparison_status != 0)); then
  echo "The spin count and state comparison could not run (status $comparison_status), so" >&2
  echo "the experiment's result is unknown." >&2
  exit 2
fi

varying=0
for metric in "${metrics[@]}"; do
  if [[ "$metric" == "checksum" ]]; then
    continue
  fi
  if [[ "$(sed '/^$/d' "$output_dir/values-$metric.txt" | sort -u | wc -l)" -ne 1 ]]; then
    varying=$((varying + 1))
  fi
done

if [[ "${#complete_runs[@]}" -lt 2 ]]; then
  verdict="inconclusive"
elif [[ "$varying" -eq 0 ]]; then
  verdict="reproducible"
else
  verdict="varying"
fi

{
  printf 'qemu_version=%s\n' "$("$qemu" --version | head -n 1)"
  printf 'machine=pc-i440fx-9.2\n'
  printf 'kernel=%s\n' "$kernel"
  printf 'icount_options=%s\n' "$icount_options"
  printf 'requested_runs=%s\n' "$runs"
  printf 'complete_runs=%s\n' "${#complete_runs[@]}"
  printf 'incomplete_runs=%s\n' "${#incomplete_runs[@]}"
  printf 'initramfs_sha256=%s\n' "$(sha256sum "$output_dir/initramfs.cpio.gz" | cut -d' ' -f1)"
  for index in $(seq 1 "$runs"); do
    printf 'run_%s_status=%s\n' "$index" "$(cat "$output_dir/run-$index.status")"
    printf 'run_%s_duration_ns=%s\n' "$index" "$(cat "$output_dir/run-$index.duration-ns")"
    printf 'run_%s_replay_log_bytes=%s\n' "$index" "$(wc -c <"$output_dir/run-$index.replay.bin")"
  done
  printf 'checksum_distinct=%s\n' "$checksum_distinct"
  printf 'varying_time_metrics=%s\n' "$varying"
  printf 'verdict=%s\n' "$verdict"
} >"$output_dir/evidence.txt"

cat "$output_dir/evidence.txt"
printf '\nmeasurements over %s completed run(s):\n' "${#complete_runs[@]}"
cat "$measurements"

case "$verdict" in
  reproducible)
    printf '\nGuest time is reproducible across %s completed run(s) under icount %s; %s incomplete run(s) were excluded.\n' \
      "${#complete_runs[@]}" "$icount_options" "${#incomplete_runs[@]}"
    ;;
  varying)
    printf '\nGuest time is NOT reproducible under icount %s; %s of %s time metrics varied.\n' \
      "$icount_options" "$varying" "$(( ${#metrics[@]} - 1 ))"
    ;;
  inconclusive)
    printf '\nINCONCLUSIVE: only %s completed run(s) under icount %s.\n' \
      "${#complete_runs[@]}" "$icount_options"
    ;;
esac
printf 'Artifacts: %s\n' "$output_dir"
complete=true
