#!/usr/bin/env bash

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
rfd_root="${RFD_DIR:-${repo_root}/rfd}"

if [[ -z "${NO_COLOR:-}" && (-t 1 || -n "${FORCE_COLOR:-}") ]]; then
	color_reset=$'\033[0m'; color_bold=$'\033[1m'; color_red=$'\033[31m'
	color_green=$'\033[32m'; color_yellow=$'\033[33m'; color_blue=$'\033[34m'; color_dim=$'\033[2m'
else
	color_reset=""; color_bold=""; color_red=""; color_green=""
	color_yellow=""; color_blue=""; color_dim=""
fi

if [[ ! -d "${rfd_root}" ]]; then
	printf "%sRFD directory not found:%s %s\n" "${color_red}" "${color_reset}" "${rfd_root}" >&2
	exit 1
fi
if [[ ! -f "${rfd_root}/README.adoc" ]]; then
	printf "%sRFD index not found:%s %s/README.adoc\n" "${color_red}" "${color_reset}" "${rfd_root}" >&2
	exit 1
fi

colorize_state() {
	local state="$1" padded="$2"
	case "${state}" in
	prediscussion | ideation) printf "%s%s%s" "${color_blue}" "${padded}" "${color_reset}" ;;
	discussion) printf "%s%s%s" "${color_yellow}" "${padded}" "${color_reset}" ;;
	published | committed) printf "%s%s%s" "${color_green}" "${padded}" "${color_reset}" ;;
	abandoned) printf "%s%s%s" "${color_dim}" "${padded}" "${color_reset}" ;;
	*) printf "%s%s%s" "${color_red}" "${padded}" "${color_reset}" ;;
	esac
}

adoc_contains() {
	local source="$1" needle="$2"
	awk -v needle="${needle}" '
		$0 == "----" || $0 == "...." || $0 == "////" {
			if (!blocked) { blocked = 1; delimiter = $0 }
			else if ($0 == delimiter) { blocked = 0; delimiter = "" }
			next
		}
		!blocked && $0 !~ /^[[:space:]]*\/\// {
			in_single = 0; in_double = 0
			for (i = 1; i <= length($0); i++) {
				backslashes = 0
				for (j = i - 1; j > 0 && substr($0, j, 1) == "\\"; j--) backslashes++
				if (backslashes % 2 == 0 && substr($0, i, 2) == "``") { in_double = !in_double; i++; continue }
				if (backslashes % 2 == 0 && substr($0, i, 1) == "`" && !in_double) { in_single = !in_single; continue }
				if (!in_single && !in_double && substr($0, i, length(needle)) == needle &&
				    (i == 1 || substr($0, i - 1, 1) !~ /[[:alnum:]_\\]/)) {
					for (j = i + length(needle); j <= length($0); j++) {
						if (substr($0, j, 1) == "]" && substr($0, j - 1, 1) != "\\") { found = 1; break }
					}
				}
			}
		}
		END { exit !found }
	' "${source}"
}

adoc_has_checkbox() {
	awk '
		$0 == "----" || $0 == "...." || $0 == "////" {
			if (!blocked) { blocked = 1; delimiter = $0 }
			else if ($0 == delimiter) { blocked = 0; delimiter = "" }
			next
		}
		!blocked && $0 ~ /^[[:space:]]*[-+*]+[[:space:]]+\[[ *xX-]\]([[:space:]]|$)/ { found = 1 }
		END { exit !found }
	' "$1"
}

implementation_has_backlink() {
	local source="$1" format="$2"
	awk -v format="${format}" '
		function comment_opening(text, i, j, run, candidate, closing, slashes) {
			for (i = 1; i <= length(text); i++) {
				slashes = 0; for (j = i - 1; j > 0 && substr(text, j, 1) == "\\"; j--) slashes++
				if (substr(text, i, 1) == "`" && slashes % 2 == 0) {
					run = 0; while (substr(text, i + run, 1) == "`") run++
					closing = 0
					for (j = i + run; j <= length(text); j++) {
						if (substr(text, j, 1) != "`") continue
						candidate = 0; while (substr(text, j + candidate, 1) == "`") candidate++
						if (candidate == run) { closing = j; break }
						j += candidate - 1
					}
					if (closing) { i = closing + run - 1; continue }
					i += run - 1; continue
				}
				if (substr(text, i, 4) == "<!--") return i
			}
			return 0
		}
		function markdown_visible(text, visible, opening, closing) {
			if (html_comment) {
				closing = index(text, "-->"); if (!closing) return ""
				text = substr(text, closing + 3); html_comment = 0
				while ((opening = comment_opening(text))) {
					text = substr(text, opening + 4); closing = index(text, "-->")
					if (!closing) { html_comment = 1; return "" }
					text = substr(text, closing + 3)
				}
				return ""
			}
			visible = ""
			while (1) {
				opening = comment_opening(text)
				if (!opening) return visible text
				visible = visible substr(text, 1, opening - 1)
				text = substr(text, opening + 4); closing = index(text, "-->")
				if (!closing) { html_comment = 1; return visible }
				text = substr(text, closing + 3)
			}
		}
		{
			lower = tolower($0)
			if (format == "org" && !blocked && lower ~ /^[[:space:]]*#\+begin_(src|example|comment)([[:space:]]|$)/) {
				blocked = 1; block_kind = lower; sub(/^[[:space:]]*#\+begin_/, "", block_kind); sub(/[[:space:]].*$/, "", block_kind); next
			}
			trimmed = lower; sub(/^[[:space:]]*/, "", trimmed); sub(/[[:space:]]*$/, "", trimmed)
			if (format == "org" && blocked && trimmed == "#+end_" block_kind) { blocked = 0; block_kind = ""; next }
			if (format == "md") {
				line = $0; leading = 0
				while (substr(line, leading + 1, 1) == " " && leading < 4) leading++
				line = substr(line, leading + 1)
				marker = substr(line, 1, 1)
				if (leading <= 3 && (marker == "`" || marker == "~")) {
					marker_length = 0
					while (substr(line, marker_length + 1, 1) == marker) marker_length++
					rest = substr(line, marker_length + 1)
					if (!blocked && !html_comment && marker_length >= 3 && (marker == "~" || index(rest, "`") == 0)) {
						blocked = 1; fence_marker = marker; fence_length = marker_length; next
					}
					if (blocked && marker == fence_marker && marker_length >= fence_length && rest ~ /^[[:space:]]*$/) {
						blocked = 0; next
					}
				}
				if (blocked) next
				if (leading > 3 && !html_comment) next
				line = markdown_visible(line); sub(/[[:space:]]*$/, "", line)
			}
			if (!blocked && format == "org" && $0 ~ /^Implements \[\[file:README\.adoc\]\[[^]]+\]\]\.$/) found = 1
			if (!blocked && format == "md" && line ~ /^Implements \[[^]]+\]\(README\.adoc\)\.$/) found = 1
		}
		END { exit !found }
	' "${source}"
}

read_rfd() {
	local source="$1" source_name="$2" expected_number="$3"
	awk -v source_name="${source_name}" -v expected_number="${expected_number}" '
      function problem(message) {
        printf "  %s: %s\n", source_name, message > "/dev/stderr"
        errors++
      }
      function clean(value) {
        sub(/^:[^:]+:[[:space:]]*/, "", value)
        if (index(value, "\t") > 0) {
          problem("attribute values must not contain tabs")
          gsub(/\t/, " ", value)
        }
        return value
      }
      function trim(value) {
        sub(/^[[:space:]]+/, "", value); sub(/[[:space:]]+$/, "", value)
        return value
      }
      function valid_url(value, rest, authority, host, port, colon, scheme_end, scheme) {
        if (value ~ /[[:space:]]/) return 0
        scheme_end = index(value, "://")
        scheme = tolower(substr(value, 1, scheme_end - 1))
        if (!scheme_end || (scheme != "http" && scheme != "https")) return 0
        rest = substr(value, scheme_end + 3)
        authority = rest; sub(/[\/?#].*$/, "", authority)
        colon = index(authority, ":")
        host = authority
        if (colon) {
          host = substr(authority, 1, colon - 1); port = substr(authority, colon + 1)
          if (port !~ /^[0-9][0-9]*$/ || index(substr(authority, colon + 1), ":")) return 0
        }
        return host ~ /^[[:alnum:]]([[:alnum:].-]*[[:alnum:]])?$/
      }
      BEGIN {
        authors = ""; state = ""; discussion = ""; labels = ""
        title = ""; title_number = ""; errors = 0
      }
      NR == 1 && $0 !~ /^:authors:[[:space:]]+/ { problem("first line must be the authors attribute") }
      NR == 2 && $0 !~ /^:state:[[:space:]]+/ { problem("second line must be the state attribute") }
      NR == 3 && $0 !~ /^:discussion:([[:space:]]+.*)?$/ { problem("third line must be the discussion attribute") }
      NR == 4 && $0 !~ /^:labels:[[:space:]]+/ { problem("fourth line must be the labels attribute") }
      NR == 5 && $0 != "" { problem("canonical attributes must be followed by a blank line") }
      NR == 6 && ($0 !~ /^= RFD [0-9]+ [^[:space:]].*/ || index($0, "\t")) { problem("sixth line must be the tab-free RFD title") }
      NR > 6 && ($0 == "----" || $0 == "...." || $0 == "////") {
        if (!blocked) { blocked = 1; delimiter = $0 }
        else if ($0 == delimiter) { blocked = 0; delimiter = "" }
        next
      }
      blocked { next }
      $0 ~ /^:authors:[[:space:]]*/ {
        authors_count++; if (authors_count == 1) authors = clean($0); next
      }
      $0 ~ /^:state:[[:space:]]*/ {
        state_count++; if (state_count == 1) state = clean($0); next
      }
      $0 ~ /^:discussion:[[:space:]]*/ {
        discussion_count++; if (discussion_count == 1) discussion = clean($0); next
      }
      $0 ~ /^:labels:[[:space:]]*/ {
        labels_count++; if (labels_count == 1) labels = clean($0); next
      }
      $0 ~ /^= RFD [0-9]+ [^[:space:]].*/ {
        title_count++
        if (title_count == 1) {
          value = $0; sub(/^= RFD /, "", value)
          title_number = value; sub(/ .*/, "", title_number)
          title = value; sub(/^[0-9]+ /, "", title)
        }
      }
      END {
        if (authors_count != 1 || authors == "") {
          problem("document must contain exactly one non-empty authors attribute")
        } else {
          author_count = split(authors, author, ";")
          for (i = 1; i <= author_count; i++) {
            value = trim(author[i])
            if (value !~ /^[^<>[:space:]][^<>]*[[:space:]]+<[^<>[:space:]]+>$/) {
              problem("each author must include a name and address in angle brackets")
            }
          }
        }
        if (state_count != 1 || state == "") {
          problem("document must contain exactly one non-empty state attribute")
        } else if (state !~ /^(prediscussion|ideation|discussion|published|committed|abandoned)$/) {
          problem("invalid state: " state)
        }
        if (discussion_count != 1) {
          problem("document must contain exactly one discussion attribute")
        } else if (discussion != "" && !valid_url(discussion)) {
          problem("discussion must be empty or an HTTP(S) URL")
        } else if (state ~ /^(discussion|published|committed)$/ && discussion == "") {
          problem("state " state " requires a discussion URL")
        }
        if (labels_count != 1 || labels == "") {
          problem("document must contain exactly one non-empty labels attribute")
        } else {
          label_count = split(labels, label, ",")
          for (i = 1; i <= label_count; i++) {
            value = trim(label[i])
            if (value !~ /^[[:alnum:]][[:alnum:]_-]*$/) {
              problem("labels must be comma-separated names")
            }
          }
        }
        if (title_count != 1 || title == "") {
          problem("document must contain exactly one RFD title")
        } else if (title_number != expected_number) {
          problem("title number " title_number " does not match directory number " expected_number)
        }
        printf "%s\t%s\t%s\t%s\t%s\t%d\n", state, title, authors, labels, discussion, errors
      }
    ' "${source}"
}

printf "%s%-4s  %-13s  %5s  %-35s  %s%s\n" "${color_bold}" "RFD" "State" "Tasks" "Title" "Labels" "${color_reset}"
printf "%s%-4s  %-13s  %5s  %-35s  %s%s\n" "${color_dim}" "----" "-------------" "-----" "-----------------------------------" "--------------------" "${color_reset}"

failures=0
found=0
shopt -s nullglob
entries=("${rfd_root}"/*)
shopt -u nullglob

for entry in "${entries[@]}"; do
	entry_name="$(basename "${entry}")"
	[[ "${entry_name}" == "README.adoc" ]] && continue
	if [[ ! -d "${entry}" || ! "${entry_name}" =~ ^[0-9]{4}$ ]]; then
		printf "%sinvalid RFD entry%s: %s\n" "${color_red}" "${color_reset}" "${entry_name}" >&2
		failures=$((failures + 1)); continue
	fi

	found=1
	source="${entry}/README.adoc"
	if [[ ! -f "${source}" ]]; then
		printf "%smissing canonical RFD source%s: %s/README.adoc\n" "${color_red}" "${color_reset}" "${entry_name}" >&2
		failures=$((failures + 1)); continue
	fi
	if ! adoc_contains "${rfd_root}/README.adoc" "link:${entry_name}/README.adoc["; then
		printf "%sRFD index must link to each RFD%s: %s/README.adoc\n" "${color_red}" "${color_reset}" "${entry_name}" >&2
		failures=$((failures + 1))
	fi

	number="$(printf '%s\n' "${entry_name}" | sed 's/^0*//')"
	[[ -n "${number}" ]] || number="0"
	task_summary="-"
	implementations=()
	[[ -f "${entry}/IMPLEMENTATION.org" ]] && implementations+=("${entry}/IMPLEMENTATION.org")
	[[ -f "${entry}/IMPLEMENTATION.md" ]] && implementations+=("${entry}/IMPLEMENTATION.md")

	if [[ "${#implementations[@]}" -eq 0 ]]; then
		printf "%smissing implementation checklist%s: %s/IMPLEMENTATION.org or IMPLEMENTATION.md\n" "${color_red}" "${color_reset}" "${entry_name}" >&2
		failures=$((failures + 1))
	elif [[ "${#implementations[@]}" -gt 1 ]]; then
		printf "%smultiple implementation checklist formats%s: %s\n" "${color_red}" "${color_reset}" "${entry_name}" >&2
		failures=$((failures + 1))
	else
		implementation="${implementations[0]}"
		implementation_name="$(basename "${implementation}")"
		read -r implementation_total implementation_completed implementation_invalid < <(
			awk -v format="${implementation_name##*.}" '
			  function comment_opening(text, i, j, run, candidate, closing, slashes) {
			    for (i = 1; i <= length(text); i++) {
			      slashes = 0; for (j = i - 1; j > 0 && substr(text, j, 1) == "\\"; j--) slashes++
			      if (substr(text, i, 1) == "`" && slashes % 2 == 0) {
			        run = 0; while (substr(text, i + run, 1) == "`") run++
			        closing = 0
			        for (j = i + run; j <= length(text); j++) {
			          if (substr(text, j, 1) != "`") continue
			          candidate = 0; while (substr(text, j + candidate, 1) == "`") candidate++
			          if (candidate == run) { closing = j; break }
			          j += candidate - 1
			        }
			        if (closing) { i = closing + run - 1; continue }
			        i += run - 1; continue
			      }
			      if (substr(text, i, 4) == "<!--") return i
			    }
			    return 0
			  }
			  function markdown_visible(text, visible, opening, closing) {
			    if (html_comment) {
			      closing = index(text, "-->"); if (!closing) return ""
			      text = substr(text, closing + 3); html_comment = 0
			      while ((opening = comment_opening(text))) {
			        text = substr(text, opening + 4); closing = index(text, "-->")
			        if (!closing) { html_comment = 1; return "" }
			        text = substr(text, closing + 3)
			      }
			      return ""
			    }
			    visible = ""
			    while (1) {
			      opening = comment_opening(text)
			      if (!opening) return visible text
			      visible = visible substr(text, 1, opening - 1)
			      text = substr(text, opening + 4); closing = index(text, "-->")
			      if (!closing) { html_comment = 1; return visible }
			      text = substr(text, closing + 3)
			    }
			  }
			  {
			    lower = tolower($0)
			    if (format == "org" && !blocked && lower ~ /^[[:space:]]*#\+begin_(src|example|comment)([[:space:]]|$)/) {
			      blocked = 1; block_kind = lower; sub(/^[[:space:]]*#\+begin_/, "", block_kind); sub(/[[:space:]].*$/, "", block_kind); next
			    }
			    trimmed = lower; sub(/^[[:space:]]*/, "", trimmed); sub(/[[:space:]]*$/, "", trimmed)
			    if (format == "org" && blocked && trimmed == "#+end_" block_kind) { blocked = 0; block_kind = ""; next }
			    if (format == "md") {
			      line = $0; leading = 0
			      while (substr(line, leading + 1, 1) == " " && leading < 4) leading++
			      line = substr(line, leading + 1)
			      marker = substr(line, 1, 1)
			      if (leading <= 3 && (marker == "`" || marker == "~")) {
			        marker_length = 0
			        while (substr(line, marker_length + 1, 1) == marker) marker_length++
			        rest = substr(line, marker_length + 1)
			        if (!blocked && !html_comment && marker_length >= 3 && (marker == "~" || index(rest, "`") == 0)) {
			          blocked = 1; fence_marker = marker; fence_length = marker_length; next
			        }
			        if (blocked && marker == fence_marker && marker_length >= fence_length && rest ~ /^[[:space:]]*$/) {
			          blocked = 0; next
			        }
			      }
			      if (blocked) next
			      if (leading > 3 && !html_comment) next
			      line = markdown_visible(line); sub(/[[:space:]]*$/, "", line)
			    }
			    if (blocked) next
			    task = format == "md" ? line : $0
			    if (format == "md") {
			      if (task !~ /^[-+*][[:space:]]+\[[^]]\]([[:space:]]|$)/) next
			      if (task !~ /^[-+*][[:space:]]+\[[ xX]\]([[:space:]]|$)/) {
			        printf "  invalid Markdown task state: %s\n", task > "/dev/stderr"; invalid++; next
			      }
			    } else {
			      if (task !~ /^[[:space:]]*[-+*][[:space:]]+\[[^]]\]([[:space:]]|$)/) next
			      if (task !~ /^[[:space:]]*[-+*][[:space:]]+\[[ xX-]\]([[:space:]]|$)/) {
			        printf "  invalid Org task state: %s\n", task > "/dev/stderr"; invalid++; next
			      }
			    }
			    total++
			    if (task ~ /^[[:space:]]*[-+*][[:space:]]+\[[xX]\]([[:space:]]|$)/) completed++
			  }
			  END { printf "%d %d %d\n", total, completed, invalid }
			' "${implementation}"
		)
		failures=$((failures + implementation_invalid))
		task_summary="${implementation_completed}/${implementation_total}"
		case "${implementation_name}" in
		IMPLEMENTATION.org)
			expected_heading="#+TITLE: RFD ${entry_name} implementation checklist" ;;
		IMPLEMENTATION.md)
			expected_heading="# RFD ${entry_name} implementation checklist" ;;
		esac
		if [[ "$(head -n 1 "${implementation}")" != "${expected_heading}" ]]; then
			printf "%sinvalid implementation checklist heading%s: %s/%s\n" "${color_red}" "${color_reset}" "${entry_name}" "${implementation_name}" >&2
			failures=$((failures + 1))
		fi
		if ! implementation_has_backlink "${implementation}" "${implementation_name##*.}"; then
			printf "%simplementation checklist must link to its RFD%s: %s/%s\n" "${color_red}" "${color_reset}" "${entry_name}" "${implementation_name}" >&2
			failures=$((failures + 1))
		fi
		if ! adoc_contains "${source}" "link:${implementation_name}["; then
			printf "%sRFD must link to its implementation checklist%s: %s/README.adoc\n" "${color_red}" "${color_reset}" "${entry_name}" >&2
			failures=$((failures + 1))
		fi
	fi

	if adoc_has_checkbox "${source}"; then
		printf "%simplementation checkboxes belong in a separate implementation document%s: %s/README.adoc\n" "${color_red}" "${color_reset}" "${entry_name}" >&2
		failures=$((failures + 1))
	fi

	parsed="$(read_rfd "${source}" "${entry_name}/README.adoc" "${number}")"
	state="${parsed%%$'\t'*}"
	remainder="${parsed#*$'\t'}"; title="${remainder%%$'\t'*}"
	remainder="${remainder#*$'\t'}"; remainder="${remainder#*$'\t'}"
	labels="${remainder%%$'\t'*}"; remainder="${remainder#*$'\t'}"
	parser_errors="${remainder##*$'\t'}"
	failures=$((failures + parser_errors))
	state_field="$(printf '%-13s' "${state:-\(missing\)}")"
	state_text="$(colorize_state "${state}" "${state_field}")"
	printf "%-4s  %s  %5s  %-35s  %s\n" "${entry_name}" "${state_text}" "${task_summary}" "${title:-\(missing title\)}" "${labels:-\(missing labels\)}"
done

if [[ "${found}" -eq 0 ]]; then
	printf "%sno RFDs found%s in %s\n" "${color_red}" "${color_reset}" "${rfd_root}" >&2
	exit 1
fi
if [[ "${failures}" -gt 0 ]]; then
	echo
	printf "%sRFD status check failed%s with %s issue(s).\n" "${color_red}" "${color_reset}" "${failures}" >&2
	exit 1
fi
echo
printf "%sRFD status check passed.%s\n" "${color_green}" "${color_reset}"
