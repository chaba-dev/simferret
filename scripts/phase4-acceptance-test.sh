#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
acceptance="$repo_root/scripts/phase4-acceptance.sh"
test_root="$(mktemp -d "${TMPDIR:-/tmp}/simferret-phase4-acceptance.XXXXXXXX")"
trap 'rm -rf "$test_root"' EXIT

mkdir -p "$test_root/bin" "$test_root/alternate-target"
printf 'fake kernel\n' >"$test_root/bzImage"
cat >"$test_root/bin/cargo" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' "$@" >"$FAKE_CARGO_ARGUMENTS"
exit 42
EOF
cat >"$test_root/bin/qemu-system-x86_64" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF
chmod +x "$test_root/bin/cargo" "$test_root/bin/qemu-system-x86_64"

set +e
PATH="$test_root/bin:$PATH" \
  CARGO_TARGET_DIR="$test_root/alternate-target" \
  FAKE_CARGO_ARGUMENTS="$test_root/cargo.arguments" \
  QEMU_SYSTEM_X86_64="$test_root/bin/qemu-system-x86_64" \
  SIMFERRET_KERNEL="$test_root/bzImage" \
  SIMFERRET_ACCEPTANCE_OUTPUT="$test_root/output" \
  "$acceptance" >/dev/null 2>&1
status=$?
set -e

if [[ "$status" -ne 42 ]]; then
  echo "acceptance harness did not reach the intercepted Cargo build" >&2
  exit 1
fi

mapfile -t arguments <"$test_root/cargo.arguments"
found_target_dir=false
for ((index = 0; index < ${#arguments[@]} - 1; index++)); do
  if [[ "${arguments[index]}" == "--target-dir" ]] &&
    [[ "${arguments[index + 1]}" == "$repo_root/target" ]]; then
    found_target_dir=true
    break
  fi
done
if [[ "$found_target_dir" != true ]]; then
  echo "acceptance build did not pin the repository-local target directory" >&2
  exit 1
fi

printf 'Phase 4 acceptance harness regression tests passed.\n'
