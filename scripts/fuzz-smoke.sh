#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
fuzz_time=${ONEISSUER_FUZZ_TIME:-1s}

run_target() {
  package=$1
  target=$2
  echo "fuzz smoke: $package $target ($fuzz_time)"
  (cd "$root" && go test "$package" -run='^$' -fuzz="^${target}$" -fuzztime="$fuzz_time" -parallel=1)
}

run_target ./internal/identity FuzzIdentityNormalization
run_target ./internal/client FuzzClientURIAndScopes
run_target ./internal/authflow FuzzAuthorizationTransactionToken
run_target ./internal/httpserver FuzzAuthenticationFormParsing
run_target ./internal/pagination FuzzOpaqueCursor
