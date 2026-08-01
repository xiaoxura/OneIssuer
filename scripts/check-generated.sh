#!/bin/sh
set -eu

if [ "$#" -ne 1 ]; then
  echo "usage: $0 /absolute/path/to/sqlc" >&2
  exit 2
fi

sqlc=$1
root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
temporary=$(mktemp -d "${TMPDIR:-/tmp}/oneissuer-generate.XXXXXX")
trap 'rm -rf "$temporary"' EXIT HUP INT TERM

mkdir -p "$temporary/project/internal/storage/postgres"
cp "$root/sqlc.yaml" "$temporary/project/sqlc.yaml"
cp -R "$root/queries" "$temporary/project/queries"
cp -R "$root/migrations" "$temporary/project/migrations"

(cd "$temporary/project" && "$sqlc" generate)

if ! diff -ru "$root/internal/storage/postgres/sqlcgen" "$temporary/project/internal/storage/postgres/sqlcgen"; then
  echo "generated sqlc files are stale; run 'make generate'" >&2
  exit 1
fi
