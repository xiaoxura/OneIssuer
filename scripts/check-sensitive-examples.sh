#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
temporary=$(mktemp "${TMPDIR:-/tmp}/oneissuer-sensitive.XXXXXX")
trap 'rm -f "$temporary"' EXIT HUP INT TERM

# Scope this gate to maintained public documentation/contracts. Test
# fixtures intentionally contain synthetic secrets and are covered by runtime
# privacy assertions instead.
set -- \
  "$root/README.md" \
  "$root/api/openapi.yaml" \
  "$root/docs/configuration.md" \
  "$root/docs/migrations.md" \
  "$root/docs/troubleshooting.md" \
  "$root/docs/operations.md" \
  "$root/docs/phase-2-release-notes.md" \
  "$root/docs/phase-2-threat-model.md" \
  "$root/docs/phase-3-handoff.md" \
  "$root/docs/phase-3-development-plan.md" \
  "$root/docs/adr/0001-phase-two-identity-and-client-security.md"

: > "$temporary"
for file in "$@"; do
  if [ ! -f "$file" ]; then
    echo "sensitive-example scan input is missing: $file" >&2
    exit 1
  fi
  # Real-format clear opaque values and PHC digests must never be documentation fixtures.
  grep -nE '(ois_sec_v1_|[spct]1_)[A-Za-z0-9_-]{32,}|\$argon2id\$v=[0-9]+' "$file" >> "$temporary" || true
  # Reject obvious literal credential assignments while permitting placeholders,
  # variable names, prose, and the documented no-password CLI option.
  grep -nEi '(^|[,{[:space:]])("?(password|client_secret|session_token|csrf_token)"?)[[:space:]]*[:=][[:space:]]*["'"'"'`][^<$[{][^"'"'"'`]{7,}["'"'"'`]' "$file" >> "$temporary" || true
done

if [ -s "$temporary" ]; then
  echo "public documentation contains a secret-shaped example:" >&2
  cat "$temporary" >&2
  exit 1
fi
