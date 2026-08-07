#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
helper=$root/scripts/prepare-smoke-exposure.sh
if [ ! -f "$helper" ]; then
  printf '%s\n' 'prepare-smoke-exposure helper is missing' >&2
  exit 1
fi

temporary=$(mktemp -d "${TMPDIR:-/tmp}/oneissuer-prepare-smoke-exposure.XXXXXX")
case "$temporary" in
  ''|/|/tmp|.)
    printf '%s\n' 'mktemp returned an unsafe fixture directory' >&2
    exit 1
    ;;
esac
cleanup() {
  status=$?
  trap - 0 HUP INT TERM
  rm -rf "$temporary" || :
  exit "$status"
}
trap cleanup 0 HUP INT TERM
chmod 700 "$temporary"

fail() {
  printf 'prepare-smoke-exposure fixture failed: %s\n' "$1" >&2
  exit 1
}

repeat_char() {
  character=$1
  count=0
  value=
  while [ "$count" -lt 43 ]; do
    value=${value}${character}
    count=$((count + 1))
  done
  printf '%s' "$value"
}

csrf=csrf_$(repeat_char A)
other_token=r1_$(repeat_char B)
invalid_csrf=csrf_bad

write_forms() {
  path=$1
  value=$2
  {
    printf '%s\n' '<!doctype html><html><body>'
    printf '%s\n' "<form method=\"post\" action=\"/refresh\"><input type=\"hidden\" name=\"csrf_token\" value=\"$value\"><button>Refresh</button></form>"
    printf '%s\n' "<form method=\"post\" action=\"/logout\"><input type=\"hidden\" name=\"csrf_token\" value=\"$value\"><button>Logout</button></form>"
    printf '%s\n' '</body></html>'
  } >"$path"
}

write_refresh_only() {
  path=$1
  value=$2
  {
    printf '%s\n' '<!doctype html><html><body>'
    printf '%s\n' "<form method=\"post\" action=\"/refresh\"><input type=\"hidden\" name=\"csrf_token\" value=\"$value\"><button>Refresh</button></form>"
    printf '%s\n' '</body></html>'
  } >"$path"
}

count_occurrences() {
  needle=$1
  path=$2
  awk -v needle="$needle" '
    {
      remainder = $0
      while ((offset = index(remainder, needle)) != 0) {
        count++
        remainder = substr(remainder, offset + length(needle))
      }
    }
    END { print count + 0 }
  ' "$path"
}

run_helper() {
  case_name=$1
  input=$2
  output=$3
  expected=$4
  shift 4
  last_stdout=$temporary/$case_name.stdout
  last_stderr=$temporary/$case_name.stderr
  if sh "$helper" "$input" "$output" "$expected" "$@" >"$last_stdout" 2>"$last_stderr"; then
    last_status=0
  else
    last_status=$?
  fi
}

expect_success() {
  case_name=$1
  input=$2
  output=$3
  expected=$4
  shift 4
  run_helper "$case_name" "$input" "$output" "$expected" "$@"
  if [ "$last_status" -ne 0 ]; then
    fail "$case_name was rejected"
  fi
  if grep -Fq "$expected" "$last_stdout" || grep -Fq "$expected" "$last_stderr"; then
    fail "$case_name echoed the expected token in diagnostics"
  fi
}

expect_failure() {
  case_name=$1
  input=$2
  output=$3
  expected=$4
  shift 4
  run_helper "$case_name" "$input" "$output" "$expected" "$@"
  if [ "$last_status" -eq 0 ]; then
    fail "$case_name was accepted"
  fi
  if grep -Fq "$expected" "$last_stdout" || grep -Fq "$expected" "$last_stderr"; then
    fail "$case_name echoed the expected token in diagnostics"
  fi
}

umask 022

valid_input=$temporary/valid.html
valid_output=$temporary/valid.out
write_forms "$valid_input" "$csrf"
printf '%s\n' "<p>unrelated token: $other_token</p>" >>"$valid_input"
expect_success valid "$valid_input" "$valid_output" "$csrf" /refresh /logout

if [ ! -f "$valid_output" ]; then
  fail 'valid helper invocation did not create an output file'
fi
if grep -Fq "$csrf" "$valid_output"; then
  fail 'valid output retained the Session CSRF token'
fi
if [ "$(count_occurrences '<form method="post" action="/refresh"><input type="hidden" name="csrf_token" value="' "$valid_output")" -ne 1 ]; then
  fail 'valid output did not retain exactly one refresh form'
fi
if [ "$(count_occurrences '<form method="post" action="/logout"><input type="hidden" name="csrf_token" value="' "$valid_output")" -ne 1 ]; then
  fail 'valid output did not retain exactly one logout form'
fi
if [ "$(count_occurrences 'name="csrf_token"' "$valid_output")" -ne 2 ]; then
  fail 'valid output retained an unexpected hidden CSRF input'
fi
refresh_value=$(sed -n 's#.*<form method="post" action="/refresh"><input type="hidden" name="csrf_token" value="\([^"]*\)">.*#\1#p' "$valid_output")
logout_value=$(sed -n 's#.*<form method="post" action="/logout"><input type="hidden" name="csrf_token" value="\([^"]*\)">.*#\1#p' "$valid_output")
if [ -z "$refresh_value" ] || [ -z "$logout_value" ] || [ "$refresh_value" = "$csrf" ] || [ "$logout_value" = "$csrf" ]; then
  fail 'valid output did not replace both CSRF values with non-empty placeholders'
fi
if ! grep -Fq "$other_token" "$valid_output"; then
  fail 'valid output removed an unrelated sensitive token'
fi
mode_path=$(find "$valid_output" -type f -perm 600 -print)
if [ "$mode_path" != "$valid_output" ]; then
  fail 'valid output mode was not 0600'
fi

body_leak=$temporary/body-leak.html
body_leak_output=$temporary/body-leak.out
write_forms "$body_leak" "$csrf"
printf '%s\n' "<p>$csrf</p>" >>"$body_leak"
expect_failure body-leak "$body_leak" "$body_leak_output" "$csrf" /refresh /logout

attribute_leak=$temporary/attribute-leak.html
attribute_leak_output=$temporary/attribute-leak.out
write_forms "$attribute_leak" "$csrf"
printf '%s\n' "<div data-csrf=\"$csrf\"></div>" >>"$attribute_leak"
expect_failure attribute-leak "$attribute_leak" "$attribute_leak_output" "$csrf" /refresh /logout

extra_hidden=$temporary/extra-hidden.html
extra_hidden_output=$temporary/extra-hidden.out
{
  printf '%s\n' '<!doctype html><html><body>'
  printf '%s\n' "<form method=\"post\" action=\"/refresh\"><input type=\"hidden\" name=\"csrf_token\" value=\"$csrf\"><input type=\"hidden\" name=\"csrf_token\" value=\"$csrf\"><button>Refresh</button></form>"
  printf '%s\n' "<form method=\"post\" action=\"/logout\"><input type=\"hidden\" name=\"csrf_token\" value=\"$csrf\"><button>Logout</button></form>"
  printf '%s\n' '</body></html>'
} >"$extra_hidden"
expect_failure extra-hidden "$extra_hidden" "$extra_hidden_output" "$csrf" /refresh /logout

duplicate_action=$temporary/duplicate-action.html
duplicate_action_output=$temporary/duplicate-action.out
write_forms "$duplicate_action" "$csrf"
printf '%s\n' "<form method=\"post\" action=\"/refresh\"><input type=\"hidden\" name=\"csrf_token\" value=\"$csrf\"><button>Refresh again</button></form>" >>"$duplicate_action"
expect_failure duplicate-action "$duplicate_action" "$duplicate_action_output" "$csrf" /refresh /logout

missing_action=$temporary/missing-action.html
missing_action_output=$temporary/missing-action.out
write_refresh_only "$missing_action" "$csrf"
expect_failure missing-action "$missing_action" "$missing_action_output" "$csrf" /refresh /logout

invalid_shape=$temporary/invalid-shape.html
invalid_shape_output=$temporary/invalid-shape.out
write_forms "$invalid_shape" "$invalid_csrf"
expect_failure invalid-shape "$invalid_shape" "$invalid_shape_output" "$invalid_csrf" /refresh /logout

printf '%s\n' 'prepare-smoke-exposure fixture: PASS'
