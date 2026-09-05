#!/usr/bin/env bash

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
checker="${repo_root}/scripts/check-rfd-status.sh"
test_root="$(mktemp -d "${TMPDIR:-/tmp}/simferret-rfd-check.XXXXXX")"
rfd_root="${test_root}/rfd"
output="${test_root}/output"
trap 'rm -rf "${test_root}"' EXIT

reset_fixtures() {
	rm -rf "${rfd_root}"; mkdir -p "${rfd_root}"
	printf '= Test RFDs\n' >"${rfd_root}/README.adoc"
}

run_success() {
	local expected="${1:-}"
	if ! NO_COLOR=1 RFD_DIR="${rfd_root}" bash "${checker}" >"${output}" 2>&1; then
		cat "${output}" >&2; printf 'expected RFD checker to pass\n' >&2; exit 1
	fi
	if [[ -n "${expected}" ]] && ! grep -Fq "${expected}" "${output}"; then
		cat "${output}" >&2; printf 'RFD checker output did not include: %s\n' "${expected}" >&2; exit 1
	fi
}

run_failure() {
	local expected="$1"
	if NO_COLOR=1 RFD_DIR="${rfd_root}" bash "${checker}" >"${output}" 2>&1; then
		cat "${output}" >&2; printf 'expected RFD checker to fail with: %s\n' "${expected}" >&2; exit 1
	fi
	if ! grep -Fq "${expected}" "${output}"; then
		cat "${output}" >&2; printf 'RFD checker failure did not include: %s\n' "${expected}" >&2; exit 1
	fi
}

run_missing_directory_failure() {
	if NO_COLOR=1 RFD_DIR="${test_root}/missing" bash "${checker}" >"${output}" 2>&1; then
		cat "${output}" >&2; printf 'expected missing RFD directory to fail\n' >&2; exit 1
	fi
	grep -Fq "RFD directory not found" "${output}" || {
		cat "${output}" >&2; printf 'missing directory diagnostic was not emitted\n' >&2; exit 1
	}
}

write_valid_rfd() {
	local state="$1" discussion="$2" implementation_format="${3:-org}" implementation_name
	case "${implementation_format}" in
	org) implementation_name="IMPLEMENTATION.org" ;;
	md) implementation_name="IMPLEMENTATION.md" ;;
	*) printf 'unsupported test implementation format: %s\n' "${implementation_format}" >&2; exit 1 ;;
	esac
	mkdir -p "${rfd_root}/0001"
	printf '\nlink:0001/README.adoc[1: Valid RFD]\n' >>"${rfd_root}/README.adoc"
	cat >"${rfd_root}/0001/README.adoc" <<EOF
:authors: Example Author <author@example.com>
:state: ${state}
:discussion: ${discussion}
:labels: software, process

= RFD 1 Valid RFD

== Implementation

See link:${implementation_name}[implementation checklist].
EOF
	case "${implementation_format}" in
	org)
		cat >"${rfd_root}/0001/${implementation_name}" <<'EOF'
#+TITLE: RFD 0001 implementation checklist

Implements [[file:README.adoc][RFD 1: Valid RFD]].

- [ ] Complete the work.
EOF
		;;
	md)
		cat >"${rfd_root}/0001/${implementation_name}" <<'EOF'
# RFD 0001 implementation checklist

Implements [RFD 1: Valid RFD](README.adoc).

- [ ] Complete the work.
EOF
		;;
	esac
}

reset_fixtures; write_valid_rfd discussion https://example.com/pull/1
cat >>"${rfd_root}/0001/IMPLEMENTATION.org" <<'EOF'
- [X] Finished task.
  - [x] Finished nested task.
- [-] Partially finished task.

#+BEGIN_SRC text
- [x] Example, not a task.
#+END_SRC
EOF
cat >>"${rfd_root}/0001/README.adoc" <<'EOF'

[source,asciidoc]
----
:state: committed
* [ ] Example, not an implementation task.
....
:labels: still-inside-the-listing
....
link:NOT-A-CHECKLIST[Example link]
----
EOF
run_success "0001  discussion       2/4"

reset_fixtures; write_valid_rfd prediscussion "" md
cat >>"${rfd_root}/0001/IMPLEMENTATION.md" <<'EOF'
- [x] Finished task.
+ [X] Another finished task.

````text
- [x] Example, not a task.
~~~
- [x] Still inside the four-backtick fence.
```
- [x] Still inside after a shorter same-marker fence.
<!-- Unclosed comment marker inside the fence.
````

    - [x] Four-space-indented code, not a task.
- [x] Visible task. <!-- inline note -->
EOF
run_success "0001  prediscussion    3/4"

reset_fixtures; write_valid_rfd prediscussion "" md
printf '\n- [x]\n- [ ]\n' >>"${rfd_root}/0001/IMPLEMENTATION.md"
run_success "0001  prediscussion    1/3"

reset_fixtures; write_valid_rfd prediscussion "" md
cat >>"${rfd_root}/0001/IMPLEMENTATION.md" <<'EOF'
<!--
    -->
- [x] Visible after an indented comment closer.
- [x] Visible before comments. <!-- closed --> <!--
- [ ] Hidden in the second comment.
EOF
run_success "0001  prediscussion    2/3"

reset_fixtures; write_valid_rfd prediscussion "" md
cat >>"${rfd_root}/0001/IMPLEMENTATION.md" <<'EOF'
    ```text
- [x] Visible because an indented fence is code.
    ```
- [ ] Render `<!--` literally.
- [x] Still visible after inline code.
EOF
run_success "0001  prediscussion    2/4"

reset_fixtures; write_valid_rfd prediscussion "" md
cat >>"${rfd_root}/0001/IMPLEMENTATION.md" <<'EOF'
```invalid`info
- [x] Visible after an invalid fence opener.
```
EOF
run_success "0001  prediscussion    1/2"

reset_fixtures; write_valid_rfd prediscussion ""
printf '\n- [x]\n- [ ]\n' >>"${rfd_root}/0001/IMPLEMENTATION.org"
run_success "0001  prediscussion    1/3"

reset_fixtures; write_valid_rfd prediscussion ""
cat >>"${rfd_root}/0001/IMPLEMENTATION.org" <<'EOF'
#+BEGIN_SRC text
#+END_EXAMPLE
- [x] Still inside the source block.
  #+END_SRC
EOF
run_success "0001  prediscussion    0/1"

reset_fixtures; write_valid_rfd prediscussion ""
cat >>"${rfd_root}/0001/README.adoc" <<'EOF'

////
:state: committed
* [-] Example, not an implementation task.
link:NOT-A-CHECKLIST[Example link]
////
EOF
run_success "0001  prediscussion    0/1"

run_missing_directory_failure

reset_fixtures; rm "${rfd_root}/README.adoc"
run_failure "RFD index not found"

reset_fixtures
run_failure "no RFDs found"

reset_fixtures; write_valid_rfd prediscussion ""
rm "${rfd_root}/0001/IMPLEMENTATION.org"
run_failure "missing implementation checklist"

reset_fixtures; write_valid_rfd prediscussion ""
rm "${rfd_root}/0001/README.adoc"
run_failure "missing canonical RFD source"

reset_fixtures; write_valid_rfd prediscussion ""
printf '= Test RFDs\n' >"${rfd_root}/README.adoc"
run_failure "RFD index must link to each RFD"

reset_fixtures; write_valid_rfd prediscussion ""
printf '= Test RFDs\n\n// link:0001/README.adoc[comment only]\n' >"${rfd_root}/README.adoc"
run_failure "RFD index must link to each RFD"

reset_fixtures; write_valid_rfd prediscussion ""
printf '= Test RFDs\n\n////\nlink:0001/README.adoc[comment only]\n////\n' >"${rfd_root}/README.adoc"
run_failure "RFD index must link to each RFD"

reset_fixtures; write_valid_rfd prediscussion ""
printf '= Test RFDs\n\nlink:0001/README.adoc[truncated\n' >"${rfd_root}/README.adoc"
run_failure "RFD index must link to each RFD"

reset_fixtures; write_valid_rfd prediscussion ""
printf '= Test RFDs\n\nnolink:0001/README.adoc[not a link]\n' >"${rfd_root}/README.adoc"
run_failure "RFD index must link to each RFD"

reset_fixtures; write_valid_rfd prediscussion ""
printf '= Test RFDs\n\nlink:0001/README.adoc[escaped close\\]\n' >"${rfd_root}/README.adoc"
run_failure "RFD index must link to each RFD"

reset_fixtures; write_valid_rfd prediscussion ""
printf '= Test RFDs\n\n``link:0001/README.adoc[code only]``\n' >"${rfd_root}/README.adoc"
run_failure "RFD index must link to each RFD"

reset_fixtures; write_valid_rfd prediscussion ""
printf '= Test RFDs\n\n`link:0001/README.adoc[code]`; link:0001/README.adoc[visible]\n' >"${rfd_root}/README.adoc"
run_success

reset_fixtures; write_valid_rfd prediscussion ""
printf '\n* [ ] This belongs in the implementation document.\n' >>"${rfd_root}/0001/README.adoc"
run_failure "implementation checkboxes belong in a separate implementation document"

reset_fixtures; write_valid_rfd prediscussion ""
printf '\n  ** [ ] This also belongs in the implementation document.\n' >>"${rfd_root}/0001/README.adoc"
run_failure "implementation checkboxes belong in a separate implementation document"

reset_fixtures; write_valid_rfd prediscussion ""
printf '\n* [*] This checked item also belongs in the implementation document.\n' >>"${rfd_root}/0001/README.adoc"
run_failure "implementation checkboxes belong in a separate implementation document"

reset_fixtures; write_valid_rfd prediscussion ""
printf '\n* [-] This partial item also belongs in the implementation document.\n' >>"${rfd_root}/0001/README.adoc"
run_failure "implementation checkboxes belong in a separate implementation document"

reset_fixtures; write_valid_rfd prediscussion ""
printf '\n* [ ]\n' >>"${rfd_root}/0001/README.adoc"
run_failure "implementation checkboxes belong in a separate implementation document"

reset_fixtures; write_valid_rfd prediscussion ""
printf '# RFD 0001 implementation checklist\n\nImplements [RFD 1](README.adoc).\n' >"${rfd_root}/0001/IMPLEMENTATION.md"
run_failure "multiple implementation checklist formats"

reset_fixtures; write_valid_rfd prediscussion ""
sed -i.bak '1s/.*/# invalid heading/' "${rfd_root}/0001/IMPLEMENTATION.org"
rm "${rfd_root}/0001/IMPLEMENTATION.org.bak"
run_failure "invalid implementation checklist heading"

reset_fixtures; write_valid_rfd prediscussion ""
sed -i.bak '/Implements/d' "${rfd_root}/0001/IMPLEMENTATION.org"
rm "${rfd_root}/0001/IMPLEMENTATION.org.bak"
run_failure "implementation checklist must link to its RFD"

reset_fixtures; write_valid_rfd prediscussion ""
sed -i.bak '/Implements/d' "${rfd_root}/0001/IMPLEMENTATION.org"
rm "${rfd_root}/0001/IMPLEMENTATION.org.bak"
cat >>"${rfd_root}/0001/IMPLEMENTATION.org" <<'EOF'
#+BEGIN_EXAMPLE
[[file:README.adoc][RFD link shown as an example]]
#+END_EXAMPLE
EOF
run_failure "implementation checklist must link to its RFD"

reset_fixtures; write_valid_rfd prediscussion ""
sed -i.bak '/Implements/d' "${rfd_root}/0001/IMPLEMENTATION.org"
rm "${rfd_root}/0001/IMPLEMENTATION.org.bak"
printf '\n# [[file:README.adoc][comment only]]\n' >>"${rfd_root}/0001/IMPLEMENTATION.org"
run_failure "implementation checklist must link to its RFD"

reset_fixtures; write_valid_rfd prediscussion ""
sed -i.bak '/Implements/d' "${rfd_root}/0001/IMPLEMENTATION.org"
rm "${rfd_root}/0001/IMPLEMENTATION.org.bak"
cat >>"${rfd_root}/0001/IMPLEMENTATION.org" <<'EOF'
#+BEGIN_COMMENT
Implements [[file:README.adoc][comment only]].
#+END_COMMENT
EOF
run_failure "implementation checklist must link to its RFD"

reset_fixtures; write_valid_rfd prediscussion "" md
sed -i.bak '1s/.*/# invalid heading/' "${rfd_root}/0001/IMPLEMENTATION.md"
rm "${rfd_root}/0001/IMPLEMENTATION.md.bak"
run_failure "invalid implementation checklist heading"

reset_fixtures; write_valid_rfd prediscussion "" md
sed -i.bak '/Implements/d' "${rfd_root}/0001/IMPLEMENTATION.md"
rm "${rfd_root}/0001/IMPLEMENTATION.md.bak"
run_failure "implementation checklist must link to its RFD"

reset_fixtures; write_valid_rfd prediscussion "" md
sed -i.bak '/Implements/d' "${rfd_root}/0001/IMPLEMENTATION.md"
rm "${rfd_root}/0001/IMPLEMENTATION.md.bak"
cat >>"${rfd_root}/0001/IMPLEMENTATION.md" <<'EOF'
~~~text
[RFD link shown as an example](README.adoc)
~~~
EOF
run_failure "implementation checklist must link to its RFD"

reset_fixtures; write_valid_rfd prediscussion "" md
sed -i.bak '/Implements/d' "${rfd_root}/0001/IMPLEMENTATION.md"
rm "${rfd_root}/0001/IMPLEMENTATION.md.bak"
cat >>"${rfd_root}/0001/IMPLEMENTATION.md" <<'EOF'
<!--
--> <!--
Implements [comment only](README.adoc).
-->
EOF
run_failure "implementation checklist must link to its RFD"

reset_fixtures; write_valid_rfd prediscussion "" md
sed -i.bak '/Implements/d' "${rfd_root}/0001/IMPLEMENTATION.md"
rm "${rfd_root}/0001/IMPLEMENTATION.md.bak"
printf '\n`[RFD link shown as code](README.adoc)`\n' >>"${rfd_root}/0001/IMPLEMENTATION.md"
run_failure "implementation checklist must link to its RFD"

reset_fixtures; write_valid_rfd prediscussion "" md
sed -i.bak '/Implements/d' "${rfd_root}/0001/IMPLEMENTATION.md"
rm "${rfd_root}/0001/IMPLEMENTATION.md.bak"
printf '\n<!-- Implements [comment only](README.adoc). -->\n' >>"${rfd_root}/0001/IMPLEMENTATION.md"
run_failure "implementation checklist must link to its RFD"

reset_fixtures; write_valid_rfd prediscussion "" md
sed -i.bak '/Implements/d' "${rfd_root}/0001/IMPLEMENTATION.md"
rm "${rfd_root}/0001/IMPLEMENTATION.md.bak"
cat >>"${rfd_root}/0001/IMPLEMENTATION.md" <<'EOF'
\` <!--
Implements [comment only](README.adoc).
-->
EOF
run_failure "implementation checklist must link to its RFD"

reset_fixtures; write_valid_rfd prediscussion "" md
sed -i.bak '/Implements/d' "${rfd_root}/0001/IMPLEMENTATION.md"
rm "${rfd_root}/0001/IMPLEMENTATION.md.bak"
cat >>"${rfd_root}/0001/IMPLEMENTATION.md" <<'EOF'
` <!--
Implements [comment only](README.adoc).
-->
EOF
run_failure "implementation checklist must link to its RFD"

reset_fixtures; write_valid_rfd prediscussion "" md
sed -i.bak '/Implements/d' "${rfd_root}/0001/IMPLEMENTATION.md"
rm "${rfd_root}/0001/IMPLEMENTATION.md.bak"
cat >>"${rfd_root}/0001/IMPLEMENTATION.md" <<'EOF'
<!--
-->Implements [comment only](README.adoc).
EOF
run_failure "implementation checklist must link to its RFD"

reset_fixtures; write_valid_rfd prediscussion "" md
sed -i.bak '/Implements/d' "${rfd_root}/0001/IMPLEMENTATION.md"
rm "${rfd_root}/0001/IMPLEMENTATION.md.bak"
cat >>"${rfd_root}/0001/IMPLEMENTATION.md" <<'EOF'
<!--
    -->
Implements [RFD 1: Valid RFD](README.adoc).
EOF
run_success

reset_fixtures; write_valid_rfd prediscussion "" md
printf '\n- [-] Invalid Markdown task state.\n' >>"${rfd_root}/0001/IMPLEMENTATION.md"
run_failure "invalid Markdown task state"

reset_fixtures; write_valid_rfd prediscussion "" md
cat >>"${rfd_root}/0001/IMPLEMENTATION.md" <<'EOF'
<!--
-->- [x] Hidden on the comment-closing line.
EOF
run_success "0001  prediscussion    0/1"

reset_fixtures; write_valid_rfd prediscussion "" md
cat >>"${rfd_root}/0001/IMPLEMENTATION.md" <<'EOF'
<!--
--> <!--
- [x] Hidden after the reopened comment.
-->
- [x] Visible after the final closer.
EOF
run_success "0001  prediscussion    1/2"

reset_fixtures; write_valid_rfd prediscussion ""
sed -i.bak '/link:IMPLEMENTATION.org/d' "${rfd_root}/0001/README.adoc"
rm "${rfd_root}/0001/README.adoc.bak"
run_failure "RFD must link to its implementation checklist"

reset_fixtures; write_valid_rfd prediscussion ""
sed -i.bak '/link:IMPLEMENTATION.org/d' "${rfd_root}/0001/README.adoc"
rm "${rfd_root}/0001/README.adoc.bak"
cat >>"${rfd_root}/0001/README.adoc" <<'EOF'

----
link:IMPLEMENTATION.org[Example link]
----
EOF
run_failure "RFD must link to its implementation checklist"

reset_fixtures; write_valid_rfd prediscussion ""
sed -i.bak '/link:IMPLEMENTATION.org/d' "${rfd_root}/0001/README.adoc"
rm "${rfd_root}/0001/README.adoc.bak"
printf '\n// link:IMPLEMENTATION.org[comment only]\n' >>"${rfd_root}/0001/README.adoc"
run_failure "RFD must link to its implementation checklist"

reset_fixtures; write_valid_rfd prediscussion ""
sed -i.bak '/link:IMPLEMENTATION.org/d' "${rfd_root}/0001/README.adoc"
rm "${rfd_root}/0001/README.adoc.bak"
printf '\nlink:IMPLEMENTATION.org[truncated\n' >>"${rfd_root}/0001/README.adoc"
run_failure "RFD must link to its implementation checklist"

reset_fixtures; write_valid_rfd prediscussion ""
sed -i.bak '/link:IMPLEMENTATION.org/d' "${rfd_root}/0001/README.adoc"
rm "${rfd_root}/0001/README.adoc.bak"
printf '\nnolink:IMPLEMENTATION.org[not a link]\n' >>"${rfd_root}/0001/README.adoc"
run_failure "RFD must link to its implementation checklist"

reset_fixtures; write_valid_rfd prediscussion ""
sed -i.bak '/link:IMPLEMENTATION.org/d' "${rfd_root}/0001/README.adoc"
rm "${rfd_root}/0001/README.adoc.bak"
printf '\nA literal backtick is \\`; link:IMPLEMENTATION.org[visible].\n' >>"${rfd_root}/0001/README.adoc"
run_success

reset_fixtures; write_valid_rfd prediscussion ""
sed -i.bak '/link:IMPLEMENTATION.org/d' "${rfd_root}/0001/README.adoc"
rm "${rfd_root}/0001/README.adoc.bak"
printf '\n``link:IMPLEMENTATION.org[code only]``\n' >>"${rfd_root}/0001/README.adoc"
run_failure "RFD must link to its implementation checklist"

reset_fixtures; write_valid_rfd prediscussion ""
sed -i.bak '/link:IMPLEMENTATION.org/d' "${rfd_root}/0001/README.adoc"
rm "${rfd_root}/0001/README.adoc.bak"
printf '\n`link:IMPLEMENTATION.org[code]`; link:IMPLEMENTATION.org[visible]\n' >>"${rfd_root}/0001/README.adoc"
run_success

reset_fixtures; write_valid_rfd prediscussion "" md
sed -i.bak '/link:IMPLEMENTATION.md/d' "${rfd_root}/0001/README.adoc"
rm "${rfd_root}/0001/README.adoc.bak"
run_failure "RFD must link to its implementation checklist"

reset_fixtures; write_valid_rfd draft ""
run_failure "invalid state: draft"

reset_fixtures; write_valid_rfd discussion ""
run_failure "state discussion requires a discussion URL"

reset_fixtures; write_valid_rfd discussion "https://"
run_failure "discussion must be empty or an HTTP(S) URL"

reset_fixtures; write_valid_rfd discussion "https://?query"
run_failure "discussion must be empty or an HTTP(S) URL"

reset_fixtures; write_valid_rfd discussion "https://#fragment"
run_failure "discussion must be empty or an HTTP(S) URL"

reset_fixtures; write_valid_rfd discussion "https://:"
run_failure "discussion must be empty or an HTTP(S) URL"

reset_fixtures; write_valid_rfd discussion "https://["
run_failure "discussion must be empty or an HTTP(S) URL"

reset_fixtures; write_valid_rfd discussion "https://host:bad"
run_failure "discussion must be empty or an HTTP(S) URL"

reset_fixtures; write_valid_rfd discussion "https://example.com/pull/1 trailing-space"
run_failure "discussion must be empty or an HTTP(S) URL"

reset_fixtures; write_valid_rfd discussion "https://[.]"
run_failure "discussion must be empty or an HTTP(S) URL"

reset_fixtures; write_valid_rfd discussion "https://[:::]"
run_failure "discussion must be empty or an HTTP(S) URL"

reset_fixtures; write_valid_rfd discussion "HTTPS://github.com/chaba-dev/simferret/pull/1"
run_success

reset_fixtures; write_valid_rfd prediscussion ""
sed -i.bak '1s/.*/:authors: Example Author <author@example.com>; Missing Address/' "${rfd_root}/0001/README.adoc"
rm "${rfd_root}/0001/README.adoc.bak"
run_failure "each author must include a name and address in angle brackets"

reset_fixtures; write_valid_rfd prediscussion ""
sed -i.bak '4s/.*/:labels: ,/' "${rfd_root}/0001/README.adoc"
rm "${rfd_root}/0001/README.adoc.bak"
run_failure "labels must be comma-separated names"

reset_fixtures; write_valid_rfd prediscussion ""
sed -i.bak '1s/.*/:state: prediscussion/; 2s/.*/:authors: Example Author <author@example.com>/' "${rfd_root}/0001/README.adoc"
rm "${rfd_root}/0001/README.adoc.bak"
run_failure "first line must be the authors attribute"

reset_fixtures; write_valid_rfd prediscussion ""
sed -i.bak '2s/.*/:authors: Another Author <another@example.com>/' "${rfd_root}/0001/README.adoc"
rm "${rfd_root}/0001/README.adoc.bak"
run_failure "second line must be the state attribute"

reset_fixtures; write_valid_rfd prediscussion ""
sed -i.bak '3s/.*/not a discussion attribute/' "${rfd_root}/0001/README.adoc"
rm "${rfd_root}/0001/README.adoc.bak"
run_failure "third line must be the discussion attribute"

reset_fixtures; write_valid_rfd prediscussion ""
sed -i.bak '4s/.*/not a labels attribute/' "${rfd_root}/0001/README.adoc"
rm "${rfd_root}/0001/README.adoc.bak"
run_failure "fourth line must be the labels attribute"

reset_fixtures; write_valid_rfd prediscussion ""
sed -i.bak '5s/.*/not blank/' "${rfd_root}/0001/README.adoc"
rm "${rfd_root}/0001/README.adoc.bak"
run_failure "canonical attributes must be followed by a blank line"

reset_fixtures; write_valid_rfd prediscussion ""
{
	head -n 5 "${rfd_root}/0001/README.adoc"
	printf 'Title moved down\n\n= RFD 1 Valid RFD\n'
	tail -n +7 "${rfd_root}/0001/README.adoc"
} >"${rfd_root}/0001/README.adoc.tmp"
mv "${rfd_root}/0001/README.adoc.tmp" "${rfd_root}/0001/README.adoc"
run_failure "sixth line must be the tab-free RFD title"

reset_fixtures; write_valid_rfd prediscussion ""
sed -i.bak $'6s/Valid RFD/Valid\tRFD/' "${rfd_root}/0001/README.adoc"
rm "${rfd_root}/0001/README.adoc.bak"
run_failure "sixth line must be the tab-free RFD title"

reset_fixtures; write_valid_rfd prediscussion ""
sed -i.bak '6s/Valid RFD/ /' "${rfd_root}/0001/README.adoc"
rm "${rfd_root}/0001/README.adoc.bak"
run_failure "sixth line must be the tab-free RFD title"

reset_fixtures; write_valid_rfd prediscussion ""
sed -i.bak 's/See link:/Use `simferret`; see link:/' "${rfd_root}/0001/README.adoc"
rm "${rfd_root}/0001/README.adoc.bak"
run_success

reset_fixtures; write_valid_rfd prediscussion ""
sed -i.bak '1a\
:authors: Another Author <another@example.com>
' "${rfd_root}/0001/README.adoc"
rm "${rfd_root}/0001/README.adoc.bak"
run_failure "exactly one non-empty authors attribute"

reset_fixtures; write_valid_rfd prediscussion ""
printf '\n:state: abandoned\n' >>"${rfd_root}/0001/README.adoc"
run_failure "exactly one non-empty state attribute"

reset_fixtures; write_valid_rfd prediscussion ""
printf '\n:discussion: https://example.com/other\n' >>"${rfd_root}/0001/README.adoc"
run_failure "exactly one discussion attribute"

reset_fixtures; write_valid_rfd prediscussion ""
printf '\n:labels: duplicate\n' >>"${rfd_root}/0001/README.adoc"
run_failure "exactly one non-empty labels attribute"

reset_fixtures; write_valid_rfd prediscussion ""
printf '\n= RFD 1 Duplicate title\n' >>"${rfd_root}/0001/README.adoc"
run_failure "exactly one RFD title"

reset_fixtures; write_valid_rfd prediscussion ""
sed -i.bak '/^:labels:/d' "${rfd_root}/0001/README.adoc"
rm "${rfd_root}/0001/README.adoc.bak"
run_failure "exactly one non-empty labels attribute"

reset_fixtures; write_valid_rfd prediscussion ""
sed -i.bak '/^:discussion:/d' "${rfd_root}/0001/README.adoc"
rm "${rfd_root}/0001/README.adoc.bak"
run_failure "exactly one discussion attribute"

reset_fixtures; write_valid_rfd prediscussion ""
sed -i.bak '/^= RFD 1 /d' "${rfd_root}/0001/README.adoc"
rm "${rfd_root}/0001/README.adoc.bak"
run_failure "exactly one RFD title"

reset_fixtures; write_valid_rfd prediscussion ""
sed -i.bak 's/= RFD 1 /= RFD 2 /' "${rfd_root}/0001/README.adoc"
rm "${rfd_root}/0001/README.adoc.bak"
run_failure "does not match directory number 1"

reset_fixtures; mkdir -p "${rfd_root}/1"
printf '= RFD 1 Invalid directory\n' >"${rfd_root}/1/README.adoc"
run_failure "invalid RFD entry"

printf 'RFD checker tests passed.\n'
