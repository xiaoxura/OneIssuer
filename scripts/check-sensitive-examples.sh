#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
temporary=$(mktemp "${TMPDIR:-/tmp}/oneissuer-sensitive.XXXXXX")
file_list=
cleanup() {
  rm -f "$temporary"
  if [ -n "$file_list" ]; then
    rm -f "$file_list"
  fi
}
trap cleanup 0 HUP INT TERM
file_list=$(mktemp "${TMPDIR:-/tmp}/oneissuer-sensitive-files.XXXXXX")

# Scope this gate to maintained public documentation/contracts. Test
# fixtures intentionally contain synthetic secrets and are covered by runtime
# privacy assertions instead.
for file in \
  "$root/README.md" \
  "$root/SECURITY.md" \
  "$root/CONTRIBUTING.md"; do
  if [ ! -f "$file" ]; then
    echo "sensitive-example scan input is missing: $file" >&2
    exit 1
  fi
  printf '%s\n' "$file" >> "$file_list"
done

for directory in "$root/docs" "$root/examples" "$root/conformance"; do
  if [ ! -d "$directory" ]; then
    echo "sensitive-example scan directory is missing: $directory" >&2
    exit 1
  fi
done

find "$root/docs" -type f -name '*.md' -print >> "$file_list"
find "$root/examples" -type f -name 'README*.md' -print >> "$file_list"
find "$root/conformance" -type f -name '*.json' -print >> "$file_list"
LC_ALL=C sort -u -o "$file_list" "$file_list"

: > "$temporary"
while IFS= read -r file; do
  # Real-format clear opaque values and PHC digests must never be documentation fixtures.
  grep -nE '(^|[^A-Za-z0-9_-])(ois_sec_v1_|s1_|p1_|c1_|t1_|r1_|lt1_|lc1_)[A-Za-z0-9_-]{43}([^A-Za-z0-9_-]|$)|\$argon2id\$v=[0-9]+' "$file" |
    while IFS=: read -r line _; do
      printf '%s:%s: opaque credential or password digest\n' "$file" "$line"
    done >> "$temporary" || true
  # Reject obvious literal credential assignments while permitting placeholders,
  # variable names, prose, and the documented no-password CLI option.
  grep -nEi '(^|[,{[:space:]])("?(password|client_secret|session_token|csrf_token)"?)[[:space:]]*[:=][[:space:]]*["'"'"'`][^<$[{][^"'"'"'`]{7,}["'"'"'`]' "$file" |
    while IFS=: read -r line _; do
      printf '%s:%s: literal credential assignment\n' "$file" "$line"
    done >> "$temporary" || true
done < "$file_list"

if [ -s "$temporary" ]; then
  echo "public documentation contains a secret-shaped example:" >&2
  cat "$temporary" >&2
  exit 1
fi
