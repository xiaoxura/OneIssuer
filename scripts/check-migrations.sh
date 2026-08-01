#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
manifest="$root/migrations/checksums.sha256"
temporary=$(mktemp -d "${TMPDIR:-/tmp}/oneissuer-migrations.XXXXXX")
trap 'rm -rf "$temporary"' EXIT HUP INT TERM

if [ ! -f "$manifest" ]; then
  echo "migration checksum manifest is missing" >&2
  exit 1
fi

if ! awk '
  NF != 2 || length($1) != 64 || $1 !~ /^[0-9a-f]+$/ || $2 !~ /^migrations\/[0-9][0-9][0-9][0-9][0-9]_[a-z0-9_]+\.sql$/ { bad = 1 }
  seen[$2]++ > 0 { bad = 1 }
  END { exit bad }
' "$manifest"; then
  echo "migration checksum manifest has an invalid or duplicate entry" >&2
  exit 1
fi

(
  cd "$root"
  find migrations -maxdepth 1 -type f -name '[0-9][0-9][0-9][0-9][0-9]_*.sql' -print | LC_ALL=C sort
) > "$temporary/actual-files"
awk '{print $2}' "$manifest" | LC_ALL=C sort > "$temporary/manifest-files"

if ! diff -u "$temporary/manifest-files" "$temporary/actual-files"; then
  echo "migration checksum manifest and production SQL files differ" >&2
  exit 1
fi

if command -v sha256sum >/dev/null 2>&1; then
  (cd "$root" && sha256sum -c migrations/checksums.sha256)
elif command -v shasum >/dev/null 2>&1; then
  while read -r expected file; do
    actual=$(shasum -a 256 "$root/$file" | awk '{print $1}')
    if [ "$actual" != "$expected" ]; then
      echo "$file: checksum mismatch" >&2
      exit 1
    fi
    echo "$file: OK"
  done < "$manifest"
else
  echo "sha256sum or shasum is required" >&2
  exit 2
fi
