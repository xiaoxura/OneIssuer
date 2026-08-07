#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
spec="$root/api/openapi.yaml"
redocly_version=${REDOCLY_VERSION:-2.43.2}

if [ "$(grep -c '^  version: 0\.1\.0-dev\.4$' "$spec")" -ne 1 ]; then
  echo "OpenAPI info.version must be exactly 0.1.0-dev.4" >&2
  exit 1
fi

for path in \
  /health/live \
  /health/ready \
  /api/v1/me \
  /api/v1/me/sessions \
  '/api/v1/me/sessions/{id}/revoke' \
  /api/v1/me/sessions/revoke-others \
  /api/v1/me/grants \
  /api/v1/me/grants/revoke \
  /api/admin/v1/me \
  /api/admin/v1/users \
  '/api/admin/v1/users/{id}' \
  '/api/admin/v1/users/{id}/revoke-sessions' \
  /api/admin/v1/clients \
  '/api/admin/v1/clients/{id}' \
  '/api/admin/v1/clients/{id}/secrets/rotate' \
  /api/admin/v1/sessions \
  '/api/admin/v1/sessions/{id}/revoke' \
  /api/admin/v1/audit-events
do
  if ! grep -Fq "  $path:" "$spec"; then
    echo "OpenAPI is missing implemented path $path" >&2
    exit 1
  fi
done

if grep -Eq '^  /(\.well-known|oauth2|userinfo|connect)(/|:)' "$spec"; then
  echo "management OpenAPI must not duplicate standard OIDC/OAuth protocol paths" >&2
  exit 1
fi
if grep -Eiq '^[[:space:]]+(examples?|x-example):' "$spec"; then
  echo "OpenAPI examples are forbidden to prevent credential fixtures" >&2
  exit 1
fi
if grep -Eiq '^[[:space:]]+(password_hash|secret_hash|token_hash|csrf_hash|credential_hash):' "$spec"; then
  echo "OpenAPI read/write schemas expose an internal digest field" >&2
  exit 1
fi
if [ "$(grep -c '^[[:space:]]*writeOnly: true$' "$spec")" -lt 3 ]; then
  echo "OpenAPI must mark password and one-time clear values writeOnly" >&2
  exit 1
fi

command -v npx >/dev/null 2>&1 || {
  echo "npx is required for the pinned OpenAPI validator" >&2
  exit 2
}
cd "$root"
npx --yes "@redocly/cli@$redocly_version" lint api/openapi.yaml
