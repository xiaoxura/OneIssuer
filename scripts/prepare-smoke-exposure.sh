#!/bin/sh
set -eu

tool_name=prepare-smoke-exposure
redacted_csrf='[REDACTED]'
input_file=
output_file=
current_file=
next_file=

die() {
  printf '%s: %s\n' "$tool_name" "$1" >&2
  exit 1
}

cleanup() {
  cleanup_status=$?
  trap - 0 HUP INT TERM
  if [ -n "$next_file" ]; then
    rm -f "$next_file" 2>/dev/null || :
  fi
  if [ -n "$current_file" ]; then
    rm -f "$current_file" 2>/dev/null || :
  fi
  exit "$cleanup_status"
}
trap cleanup EXIT HUP INT TERM

[ "$#" -ge 4 ] || die 'usage: INPUT OUTPUT EXPECTED_CSRF ACTION...'
input_argument=$1
output_argument=$2
expected_csrf=$3
shift 3

[ -n "$input_argument" ] || die 'input path is empty'
[ -n "$output_argument" ] || die 'output path is empty'

if ! LC_ALL=C printf '%s\n' "$expected_csrf" | LC_ALL=C awk '
  NR == 1 && $0 ~ /^csrf_[A-Za-z0-9_-]+$/ && length($0) == 48 { valid = 1 }
  END { exit !(valid && NR == 1) }
'; then
  die 'expected CSRF token has an invalid shape'
fi

for action do
  case "$action" in
    /*) ;;
    *) die 'action is not a safe relative path' ;;
  esac
  if ! LC_ALL=C printf '%s\n' "$action" | LC_ALL=C awk '
    NR == 1 && $0 ~ /^\/[A-Za-z0-9._~\/-]*$/ { valid = 1 }
    END { exit !(valid && NR == 1) }
  '; then
    die 'action contains unsafe characters'
  fi
done

if ! input_directory=$(dirname -- "$input_argument") ||
   ! input_basename=$(basename -- "$input_argument") ||
   ! input_directory=$(CDPATH= cd -P -- "$input_directory" 2>/dev/null && pwd -P); then
  die "could not resolve input path: $input_argument"
fi
input_file=$input_directory/$input_basename
if [ -L "$input_file" ] || [ ! -f "$input_file" ]; then
  die "input is not a regular file: $input_file"
fi

case "$output_argument" in
  */) die 'output path must name a file' ;;
esac
if ! output_directory=$(dirname -- "$output_argument") ||
   ! output_basename=$(basename -- "$output_argument") ||
   ! output_directory=$(CDPATH= cd -P -- "$output_directory" 2>/dev/null && pwd -P); then
  die "could not resolve output path: $output_argument"
fi
output_file=$output_directory/$output_basename
if [ "$input_file" = "$output_file" ] ||
   { [ -e "$output_file" ] && [ "$input_file" -ef "$output_file" ]; }; then
  die "input and output paths identify the same file: $output_file"
fi
if [ -L "$output_file" ] || [ -d "$output_file" ] ||
   { [ -e "$output_file" ] && [ ! -f "$output_file" ]; }; then
  die "output path is not a safe regular file: $output_file"
fi

temporary_template=$output_directory/.$output_basename.XXXXXX
if ! current_file=$(mktemp "$temporary_template" 2>/dev/null); then
  die "could not create a temporary output beside: $output_file"
fi
if ! chmod 600 "$current_file" 2>/dev/null; then
  die "could not restrict temporary output: $output_file"
fi
if ! cat "$input_file" >"$current_file" 2>/dev/null; then
  die "could not read input file: $input_file"
fi

for action do
  fragment='<form method="post" action="'"$action"'"><input type="hidden" name="csrf_token" value="'"$expected_csrf"'">'
  replacement='<form method="post" action="'"$action"'"><input type="hidden" name="csrf_token" value="'"$redacted_csrf"'">'

  if ! fragment_count=$(LC_ALL=C awk -v needle="$fragment" '
    {
      remainder = $0
      while ((offset = index(remainder, needle)) > 0) {
        matches++
        remainder = substr(remainder, offset + length(needle))
      }
    }
    END { print matches + 0 }
  ' "$current_file" 2>/dev/null); then
    die "could not inspect action fragment for output: $output_file"
  fi
  case "$fragment_count" in
    1) ;;
    *) die 'action fragment is missing or not unique' ;;
  esac

  if ! escaped_fragment=$(printf '%s\n' "$fragment" | LC_ALL=C sed 's/[.[\*^$\\]/\\&/g'); then
    die "could not prepare action fragment for output: $output_file"
  fi
  if ! next_file=$(mktemp "$temporary_template" 2>/dev/null); then
    die "could not create a temporary output beside: $output_file"
  fi
  if ! chmod 600 "$next_file" 2>/dev/null; then
    die "could not restrict temporary output: $output_file"
  fi
  if ! LC_ALL=C sed "s|$escaped_fragment|$replacement|" "$current_file" >"$next_file" 2>/dev/null; then
    die "could not write temporary output beside: $output_file"
  fi
  if ! mv "$next_file" "$current_file" 2>/dev/null; then
    die "could not replace temporary output beside: $output_file"
  fi
  next_file=
done

if printf '%s\n' "$expected_csrf" | LC_ALL=C grep -Fq -f - "$current_file"; then
  die 'expected CSRF token remained outside the approved form'
else
  scan_status=$?
  [ "$scan_status" -eq 1 ] || die "could not scan prepared output: $output_file"
fi
if ! chmod 600 "$current_file" 2>/dev/null; then
  die "could not restrict final output: $output_file"
fi
if ! mv "$current_file" "$output_file" 2>/dev/null; then
  die "could not atomically install output: $output_file"
fi
current_file=
