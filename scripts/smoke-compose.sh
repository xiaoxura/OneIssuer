#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$root"

compose_file=${COMPOSE_FILE:-deploy/docker-compose.yml}
http_port=${ONEISSUER_SMOKE_HTTP_PORT:-8080}
base_url=${ONEISSUER_SMOKE_URL:-http://127.0.0.1:$http_port}
session_cookie_name=${ONEISSUER_SMOKE_COOKIE_NAME:-oneissuer_smoke_session}
client_a_port=${ONEISSUER_SMOKE_CLIENT_A_PORT:-8081}
client_b_port=${ONEISSUER_SMOKE_CLIENT_B_PORT:-8082}
client_a_url=http://localhost:$client_a_port
client_b_url=http://localhost:$client_b_port
alpine_image='alpine:3.23.5@sha256:fd791d74b68913cbb027c6546007b3f0d3bc45125f797758156952bc2d6daf40'

# Export every acceptance-specific override so values from a developer .env do
# not silently weaken or redirect the test. PostgreSQL stays on the internal
# Compose network; host port zero asks Docker to choose a collision-free port.
export ONEISSUER_HTTP_PORT=$http_port
export ONEISSUER_ISSUER=${ONEISSUER_SMOKE_ISSUER:-$base_url}
export ONEISSUER_ENV=development
export ONEISSUER_REGISTRATION_ENABLED=true
export ONEISSUER_COOKIE_NAME=$session_cookie_name
export ONEISSUER_COOKIE_SECURE=false
export ONEISSUER_VERSION=${ONEISSUER_VERSION:-v0.1.0-dev.4}
export ONEISSUER_AUTHORIZATION_CODE_TTL=30s
export ONEISSUER_REFRESH_TOKEN_TTL=${ONEISSUER_SMOKE_REFRESH_TOKEN_TTL:-1h}
export ONEISSUER_REFRESH_TOKEN_ABSOLUTE_TTL=${ONEISSUER_SMOKE_REFRESH_TOKEN_ABSOLUTE_TTL:-24h}
export ONEISSUER_LOGOUT_TRANSACTION_TTL=${ONEISSUER_SMOKE_LOGOUT_TRANSACTION_TTL:-1m}
export ONEISSUER_LOGOUT_MAX_ACTIVE_PER_SESSION=${ONEISSUER_SMOKE_LOGOUT_MAX_ACTIVE_PER_SESSION:-3}
export ONEISSUER_LOGOUT_ID_TOKEN_HINT_MAX_AGE=${ONEISSUER_SMOKE_LOGOUT_HINT_MAX_AGE:-24h}
export ONEISSUER_OAUTH_RATE_PER_MINUTE=60000
export ONEISSUER_OAUTH_RATE_BURST=1000
export ONEISSUER_OAUTH_GLOBAL_RATE_PER_SECOND=10000
export ONEISSUER_OAUTH_GLOBAL_BURST=20000
# The smoke suite intentionally creates many independent browser flows in a few
# seconds from one host. Unit/HTTP tests own limiter behavior; give this bounded
# acceptance workload the documented maximum test budget so it exercises OIDC
# semantics rather than sleeping for token refill.
export ONEISSUER_AUTH_RATE_PER_MINUTE=60000
export ONEISSUER_AUTH_RATE_BURST=1000
export ONEISSUER_AUTH_GLOBAL_RATE_PER_SECOND=10000
export ONEISSUER_AUTH_GLOBAL_BURST=20000
export POSTGRES_PORT=${ONEISSUER_SMOKE_POSTGRES_PORT:-0}
export EXAMPLE_CLIENT_A_PORT=$client_a_port
export EXAMPLE_CLIENT_B_PORT=$client_b_port
export EXAMPLE_CLIENT_A_REDIRECT_URI=$client_a_url/callback
export EXAMPLE_CLIENT_B_REDIRECT_URI=$client_b_url/callback
export EXAMPLE_CLIENT_A_POST_LOGOUT_REDIRECT_URI=$client_a_url/logged-out
export EXAMPLE_CLIENT_B_POST_LOGOUT_REDIRECT_URI=$client_b_url/logged-out

temporary=$(mktemp -d "${TMPDIR:-/tmp}/oneissuer-compose-smoke.XXXXXX")
chmod 700 "$temporary"
signing_key=$temporary/signing-key.jwk
go run ./cmd/oneissuer keys generate --alg RS256 --out "$signing_key" >/dev/null
# The runtime is deliberately UID/GID 65532 and the loader deliberately rejects
# any group/world permission. Preserve mode 0600 while transferring ownership;
# making the bind-mounted private JWK world-readable would turn the smoke test
# into an unsafe deployment example.
docker run --rm --user 0:0 --entrypoint /bin/sh \
  --mount "type=bind,source=$signing_key,target=/run/oneissuer-secret" \
  "$alpine_image" -c 'chown 65532:65532 /run/oneissuer-secret && chmod 0600 /run/oneissuer-secret'
export ONEISSUER_SIGNING_KEY_HOST_FILE=$signing_key
sensitive_values=$temporary/sensitive-values
sensitive_labels=$temporary/sensitive-labels
exposure_surface=$temporary/exposure-surface
: >"$sensitive_values"
chmod 600 "$sensitive_values"
: >"$sensitive_labels"
chmod 600 "$sensitive_labels"

compose() {
  docker compose -f "$compose_file" "$@"
}

cleanup() {
  cleanup_status=$?
  trap - EXIT HUP INT TERM
  compose --profile oidc-demo down -v --remove-orphans >/dev/null 2>&1 || true
  rm -rf "$temporary"
  exit "$cleanup_status"
}
trap cleanup EXIT HUP INT TERM

fail() {
  printf 'compose smoke: %s\n' "$1" >&2
  exit 1
}

assert_status() {
  assert_actual=$1
  assert_expected=$2
  assert_label=$3
  if [ "$assert_actual" != "$assert_expected" ]; then
    fail "$assert_label returned HTTP $assert_actual; expected $assert_expected"
  fi
}

assert_equal() {
  assert_actual=$1
  assert_expected=$2
  assert_label=$3
  if [ "$assert_actual" != "$assert_expected" ]; then
    fail "$assert_label was '$assert_actual'; expected '$assert_expected'"
  fi
}

assert_prefix() {
  assert_actual=$1
  assert_expected=$2
  assert_label=$3
  case "$assert_actual" in
    "$assert_expected"*) ;;
    *) fail "$assert_label was '$assert_actual'; expected prefix '$assert_expected'" ;;
  esac
}

assert_file_contains() {
  assert_file=$1
  assert_needle=$2
  assert_label=$3
  if ! grep -Fq -- "$assert_needle" "$assert_file"; then
    fail "$assert_label did not contain the expected contract marker"
  fi
}

assert_file_excludes() {
  assert_file=$1
  assert_needle=$2
  assert_label=$3
  if grep -Fq -- "$assert_needle" "$assert_file"; then
    fail "$assert_label exposed a forbidden field"
  fi
}

curl_request() {
  curl --silent --show-error --connect-timeout 3 --max-time 30 "$@"
}

wait_status() {
  wait_url=$1
  wait_expected=$2
  wait_attempts=${3:-60}
  wait_last=none
  while [ "$wait_attempts" -gt 0 ]; do
    wait_last=$(curl_request --max-time 5 -o /dev/null -w '%{http_code}' "$wait_url" 2>/dev/null || true)
    if [ "$wait_last" = "$wait_expected" ]; then
      return 0
    fi
    wait_attempts=$((wait_attempts - 1))
    sleep 1
  done
  fail "timed out waiting for $wait_url to return $wait_expected (last: $wait_last)"
}

header_value() {
  header_name=$1
  header_file=$2
  awk -F ':' -v wanted="$header_name" '
    tolower($1) == tolower(wanted) {
      value = substr($0, index($0, ":") + 1)
      sub(/^[[:space:]]+/, "", value)
      sub(/\r$/, "", value)
    }
    END { print value }
  ' "$header_file"
}

hidden_value() {
  hidden_name=$1
  hidden_file=$2
  sed -n 's/.*name="'"$hidden_name"'" value="\([^"]*\)".*/\1/p' "$hidden_file" | head -n 1
}

json_string() {
  json_name=$1
  json_file=$2
  sed -n 's/.*"'"$json_name"'":"\([^"]*\)".*/\1/p' "$json_file" | head -n 1
}

cookie_value() {
  cookie_name=$1
  cookie_jar=$2
  awk -v wanted="$cookie_name" 'NF >= 7 && $6 == wanted { value = $7 } END { print value }' "$cookie_jar"
}

query_value() {
  query_name=$1
  query_url=$2
  printf '%s\n' "$query_url" | sed -n 's/.*[?&]'"$query_name"'=\([^&#]*\).*/\1/p' | head -n 1
}

absolute_url() {
  absolute_base=$1
  absolute_location=$2
  case "$absolute_location" in
    http://*|https://*) printf '%s\n' "$absolute_location" ;;
    /*) printf '%s%s\n' "$absolute_base" "$absolute_location" ;;
    *) fail "received unsafe relative Location '$absolute_location'" ;;
  esac
}

write_curl_url_config() {
  config_url=$1
  config_file=$2
  case "$config_url" in
    *'"'*) fail "callback URL was not safe for curl config" ;;
  esac
  printf 'url = "%s"\n' "$config_url" >"$config_file"
  chmod 600 "$config_file"
}

record_sensitive() {
  sensitive_value=$1
  sensitive_label=$2
  if [ -z "$sensitive_value" ]; then
    fail "$sensitive_label was unexpectedly empty"
  fi
  printf '%s\n' "$sensitive_value" >>"$sensitive_values"
  printf '%s\n' "$sensitive_label" >>"$sensitive_labels"
}

prepare_exposure_copy() {
  exposure_input=$1
  exposure_output=$2
  exposure_csrf=$3
  exposure_label=$4
  shift 4
  if ! "$root/scripts/prepare-smoke-exposure.sh" "$exposure_input" "$exposure_output" "$exposure_csrf" "$@" \
    >/dev/null 2>&1; then
    fail "$exposure_label could not be prepared for exposure scan"
  fi
}

write_csrf_header() {
  csrf_value=$1
  csrf_file=$2
  printf 'X-CSRF-Token: %s\n' "$csrf_value" >"$csrf_file"
  chmod 600 "$csrf_file"
}

begin_auth() {
  auth_path=$1
  auth_jar=$2
  auth_headers=$3
  auth_body=$4
  auth_status=$(curl_request -b "$auth_jar" -c "$auth_jar" -D "$auth_headers" -o "$auth_body" \
    -w '%{http_code}' "$base_url$auth_path")
  assert_status "$auth_status" 200 "GET $auth_path"
  auth_csrf=$(hidden_value csrf_token "$auth_body")
  auth_transaction=$(hidden_value transaction "$auth_body")
  record_sensitive "$auth_csrf" "$auth_path form CSRF token"
  record_sensitive "$auth_transaction" "$auth_path transaction token"
  auth_preauth=$(cookie_value "${session_cookie_name}_preauth" "$auth_jar")
  record_sensitive "$auth_preauth" "$auth_path pre-auth cookie"
}

# Acceptance always starts from an empty PostgreSQL volume.
compose down -v --remove-orphans >/dev/null 2>&1 || true
compose up --build -d

wait_status "$base_url/health/live" 200
wait_status "$base_url/health/ready" 200

# Preserve the phase-one health, metrics, request-ID, non-root, migration, and
# build-version contracts before exercising identity state.
metrics_file=$temporary/metrics
curl_request --fail "$base_url/metrics" >"$metrics_file"
for family in \
  oneissuer_build_info \
  oneissuer_http_requests_total \
  oneissuer_http_request_duration_seconds \
  oneissuer_http_in_flight_requests \
  oneissuer_database_pool_connections \
  oneissuer_readiness_status \
  oneissuer_oidc_authorization_total \
  oneissuer_oidc_token_operations_total; do
  assert_file_contains "$metrics_file" "$family" "metrics response"
done

health_headers=$temporary/health-headers
curl_request -D "$health_headers" -o /dev/null "$base_url/health/live"
request_id=$(header_value X-Request-ID "$health_headers")
[ -n "$request_id" ] || fail "health response omitted X-Request-ID"

# Discovery must describe only the complete live Phase-four route set.
discovery_body=$temporary/discovery-body
discovery_status=$(curl_request -o "$discovery_body" -w '%{http_code}' "$base_url/.well-known/openid-configuration")
assert_status "$discovery_status" 200 "OIDC Discovery"
for marker in '"grant_types_supported":["authorization_code","refresh_token"]' '"scopes_supported":["openid","profile","email","offline_access"]' '"revocation_endpoint":"' '"introspection_endpoint":"' '"end_session_endpoint":"' '"code_challenge_methods_supported":["S256"]' '"id_token_signing_alg_values_supported":["RS256"]'; do
  assert_file_contains "$discovery_body" "$marker" "OIDC Discovery"
done
for forbidden in registration_endpoint frontchannel_logout_supported backchannel_logout_supported sid; do
  assert_file_excludes "$discovery_body" "$forbidden" "OIDC Discovery"
done
jwks_body=$temporary/jwks-body
jwks_status=$(curl_request -o "$jwks_body" -w '%{http_code}' "$base_url/oauth2/jwks")
assert_status "$jwks_status" 200 "OIDC JWKS"
assert_file_contains "$jwks_body" '"alg": "RS256"' "OIDC JWKS"
for private_member in '"d"' '"p"' '"q"' '"dp"' '"dq"' '"qi"'; do
  assert_file_excludes "$jwks_body" "$private_member" "OIDC JWKS"
done
protocol_body=$temporary/protocol-boundary-body
authorize_status=$(curl_request -o "$protocol_body" -w '%{http_code}' "$base_url/oauth2/authorize")
assert_status "$authorize_status" 400 "malformed Authorize request"
token_status=$(curl_request -X POST -o "$protocol_body" -w '%{http_code}' "$base_url/oauth2/token")
assert_status "$token_status" 400 "malformed Token request"
userinfo_get_status=$(curl_request -o "$protocol_body" -w '%{http_code}' "$base_url/oauth2/userinfo")
assert_status "$userinfo_get_status" 401 "unauthenticated GET UserInfo"
userinfo_post_status=$(curl_request -X POST -o "$protocol_body" -w '%{http_code}' "$base_url/oauth2/userinfo")
assert_status "$userinfo_post_status" 401 "unauthenticated POST UserInfo"
for protocol_path in /oauth2/revoke /oauth2/introspect /oauth2/logout; do
  protocol_status=$(curl_request -X POST -o "$protocol_body" -w '%{http_code}' "$base_url$protocol_path")
  assert_status "$protocol_status" 400 "malformed POST $protocol_path"
done

migrate_id=$(compose ps -aq migrate)
[ -n "$migrate_id" ] || fail "initial migration container was not created"
assert_equal "$(docker inspect "$migrate_id" --format '{{.State.ExitCode}}')" 0 "initial migration exit code"

oneissuer_id=$(compose ps -q oneissuer)
[ -n "$oneissuer_id" ] || fail "application container was not created"
assert_equal "$(docker inspect "$oneissuer_id" --format '{{.Config.User}}')" "65532:65532" "configured image user"
assert_equal "$(compose exec -T oneissuer id -u)" 65532 "effective application UID"
assert_equal "$(compose exec -T oneissuer id -g)" 65532 "effective application GID"
version_output=$(compose exec -T oneissuer /usr/local/bin/oneissuer version)
case "$version_output" in
  *"version=$ONEISSUER_VERSION"*) ;;
  *) fail "running binary version did not match $ONEISSUER_VERSION" ;;
esac

# A second production migration run must be a no-op success against the same
# volume, rather than relying only on the initial one-shot service.
repeat_migration_output=$temporary/repeat-migration-output
if ! compose run --rm --no-deps -T migrate >"$repeat_migration_output" 2>&1; then
  fail "repeated migrate up failed"
fi

nonce="$(date +%s)-$$"
bootstrap_password="BootstrapSmoke-${nonce}-StrongPassword"
user_password="UserSmoke-${nonce}-StrongPassword"
admin_username="smokeadmin${nonce}"
user_username="smokeuser${nonce}"
admin_email="${admin_username}@example.invalid"
user_email="${user_username}@example.invalid"
record_sensitive "$user_password" "user password"

# Bootstrap receives two confirmation lines through stdin. The clear password
# is never a command argument, environment variable, Compose field, or file.
bootstrap_output=$temporary/bootstrap-output
set +e
printf '%s\n%s\n' "$bootstrap_password" "$bootstrap_password" | \
  compose run --rm --no-deps -T oneissuer admin bootstrap \
    --username "$admin_username" --email "$admin_email" --password-stdin \
    >"$bootstrap_output" 2>&1
bootstrap_code=$?
set -e
assert_equal "$bootstrap_code" 0 "first bootstrap exit code"
assert_file_contains "$bootstrap_output" 'status=created' "first bootstrap output"

# Bootstrap is one-shot and must reject the same controlled retry with the
# stable conflict exit code without replacing the administrator.
bootstrap_rejected_output=$temporary/bootstrap-rejected-output
set +e
printf '%s\n%s\n' "$bootstrap_password" "$bootstrap_password" | \
  compose run --rm --no-deps -T oneissuer admin bootstrap \
    --username "$admin_username" --email "$admin_email" --password-stdin \
    >"$bootstrap_rejected_output" 2>&1
bootstrap_rejected_code=$?
set -e
assert_equal "$bootstrap_rejected_code" 3 "second bootstrap exit code"
assert_file_contains "$bootstrap_rejected_output" 'administrator already exists' "second bootstrap output"

# Register a normal user through the hosted form, retaining the server-issued
# transaction, pre-auth, Session, and CSRF values only in the private temp dir.
user_jar=$temporary/user-cookies
old_user_jar=$temporary/old-user-cookies
second_user_jar=$temporary/second-user-cookies
admin_jar=$temporary/admin-cookies
: >"$user_jar"
: >"$second_user_jar"
: >"$admin_jar"
chmod 600 "$user_jar" "$second_user_jar" "$admin_jar"

register_headers=$temporary/register-get-headers
register_page=$temporary/register-page
begin_auth /register "$user_jar" "$register_headers" "$register_page"
register_csrf=$auth_csrf
register_transaction=$auth_transaction

register_form=$temporary/register-form
printf 'csrf_token=%s&transaction=%s&username=%s&display_name=%s&email=%s&password=%s' \
  "$register_csrf" "$register_transaction" "$user_username" SmokeUser "$user_email" "$user_password" \
  >"$register_form"
chmod 600 "$register_form"
register_post_headers=$temporary/register-post-headers
register_post_body=$temporary/register-post-body
register_status=$(curl_request -b "$user_jar" -c "$user_jar" -D "$register_post_headers" \
  -o "$register_post_body" -w '%{http_code}' -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-binary @"$register_form" "$base_url/register")
assert_status "$register_status" 303 "POST /register"
assert_equal "$(header_value Location "$register_post_headers")" /auth/complete "registration redirect"
assert_file_contains "$register_post_headers" "${session_cookie_name}=" "registration session cookie"
assert_file_contains "$register_post_headers" 'HttpOnly; SameSite=Lax' "registration session cookie attributes"
assert_file_contains "$register_post_headers" "${session_cookie_name}_csrf=" "registration CSRF cookie"
assert_file_contains "$register_post_headers" 'SameSite=Strict' "registration CSRF cookie attributes"

first_session_token=$(cookie_value "$session_cookie_name" "$user_jar")
first_csrf_cookie=$(cookie_value "${session_cookie_name}_csrf" "$user_jar")
record_sensitive "$first_session_token" "registered session cookie"
record_sensitive "$first_csrf_cookie" "registered CSRF cookie"

complete_body=$temporary/register-complete
complete_status=$(curl_request -b "$user_jar" -c "$user_jar" -o "$complete_body" -w '%{http_code}' "$base_url/auth/complete")
assert_status "$complete_status" 200 "registration completion"
assert_file_contains "$complete_body" SmokeUser "registration completion page"

user_me_headers=$temporary/user-me-headers
user_me_body=$temporary/user-me-body
user_me_status=$(curl_request -b "$user_jar" -c "$user_jar" -D "$user_me_headers" -o "$user_me_body" \
  -w '%{http_code}' "$base_url/api/v1/me")
assert_status "$user_me_status" 200 "registered user GET /api/v1/me"
user_id=$(json_string id "$user_me_body")
first_session_id=$(json_string session_id "$user_me_body")
user_csrf=$(header_value X-CSRF-Token "$user_me_headers")
[ -n "$user_id" ] || fail "registered user response omitted id"
[ -n "$first_session_id" ] || fail "registered user response omitted session_id"
record_sensitive "$user_csrf" "registered API CSRF token"
cp "$user_jar" "$old_user_jar"
chmod 600 "$old_user_jar"

# Logging in again in the same browser must rotate both the clear cookie and the
# server-side Session identifier, and the copied old cookie must stop working.
login_get_headers=$temporary/user-login-get-headers
login_page=$temporary/user-login-page
begin_auth /login "$user_jar" "$login_get_headers" "$login_page"
login_csrf=$auth_csrf
login_transaction=$auth_transaction
login_form=$temporary/user-login-form
printf 'csrf_token=%s&transaction=%s&identifier=%s&password=%s' \
  "$login_csrf" "$login_transaction" "$user_username" "$user_password" >"$login_form"
chmod 600 "$login_form"
login_post_headers=$temporary/user-login-post-headers
login_post_body=$temporary/user-login-post-body
login_status=$(curl_request -b "$user_jar" -c "$user_jar" -D "$login_post_headers" -o "$login_post_body" \
  -w '%{http_code}' -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-binary @"$login_form" "$base_url/login")
assert_status "$login_status" 303 "POST /login for session rotation"
assert_equal "$(header_value Location "$login_post_headers")" /auth/complete "login redirect"
rotated_session_token=$(cookie_value "$session_cookie_name" "$user_jar")
rotated_csrf_cookie=$(cookie_value "${session_cookie_name}_csrf" "$user_jar")
record_sensitive "$rotated_session_token" "rotated session cookie"
record_sensitive "$rotated_csrf_cookie" "rotated CSRF cookie"
[ "$rotated_session_token" != "$first_session_token" ] || fail "login reused the registered clear Session cookie"

rotated_me_headers=$temporary/rotated-me-headers
rotated_me_body=$temporary/rotated-me-body
rotated_me_status=$(curl_request -b "$user_jar" -c "$user_jar" -D "$rotated_me_headers" -o "$rotated_me_body" \
  -w '%{http_code}' "$base_url/api/v1/me")
assert_status "$rotated_me_status" 200 "rotated user GET /api/v1/me"
rotated_session_id=$(json_string session_id "$rotated_me_body")
user_csrf=$(header_value X-CSRF-Token "$rotated_me_headers")
record_sensitive "$user_csrf" "rotated API CSRF token"
[ "$rotated_session_id" != "$first_session_id" ] || fail "login reused the registered server Session id"

old_cookie_body=$temporary/old-cookie-me-body
old_cookie_status=$(curl_request -b "$old_user_jar" -c "$old_user_jar" -o "$old_cookie_body" \
  -w '%{http_code}' "$base_url/api/v1/me")
assert_status "$old_cookie_status" 401 "superseded Session cookie"

# State changes reject a missing double-submit/header token.
missing_csrf_body=$temporary/missing-csrf-body
missing_csrf_status=$(curl_request -X POST -b "$user_jar" -c "$user_jar" -o "$missing_csrf_body" \
  -w '%{http_code}' "$base_url/api/v1/me/sessions/revoke-others")
assert_status "$missing_csrf_status" 403 "Session mutation without CSRF"
assert_file_contains "$missing_csrf_body" csrf_failed "missing-CSRF response"

# Create a second browser Session, list it from the first browser, revoke it by
# opaque UUID with a CSRF header file, and prove that browser immediately loses
# authority.
second_login_get_headers=$temporary/second-login-get-headers
second_login_page=$temporary/second-login-page
begin_auth /login "$second_user_jar" "$second_login_get_headers" "$second_login_page"
second_login_csrf=$auth_csrf
second_login_transaction=$auth_transaction
second_login_form=$temporary/second-login-form
printf 'csrf_token=%s&transaction=%s&identifier=%s&password=%s' \
  "$second_login_csrf" "$second_login_transaction" "$user_email" "$user_password" >"$second_login_form"
chmod 600 "$second_login_form"
second_login_headers=$temporary/second-login-headers
second_login_body=$temporary/second-login-body
second_login_status=$(curl_request -b "$second_user_jar" -c "$second_user_jar" -D "$second_login_headers" \
  -o "$second_login_body" -w '%{http_code}' -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-binary @"$second_login_form" "$base_url/login")
assert_status "$second_login_status" 303 "normalized-email login"
second_session_token=$(cookie_value "$session_cookie_name" "$second_user_jar")
second_csrf_cookie=$(cookie_value "${session_cookie_name}_csrf" "$second_user_jar")
record_sensitive "$second_session_token" "second browser Session cookie"
record_sensitive "$second_csrf_cookie" "second browser CSRF cookie"

second_me_headers=$temporary/second-me-headers
second_me_body=$temporary/second-me-body
second_me_status=$(curl_request -b "$second_user_jar" -c "$second_user_jar" -D "$second_me_headers" \
  -o "$second_me_body" -w '%{http_code}' "$base_url/api/v1/me")
assert_status "$second_me_status" 200 "second browser GET /api/v1/me"
second_session_id=$(json_string session_id "$second_me_body")
second_api_csrf=$(header_value X-CSRF-Token "$second_me_headers")
record_sensitive "$second_api_csrf" "second browser API CSRF token"
[ -n "$second_session_id" ] || fail "second browser response omitted session_id"

sessions_body=$temporary/user-sessions-body
sessions_headers=$temporary/user-sessions-headers
sessions_status=$(curl_request -b "$user_jar" -c "$user_jar" -D "$sessions_headers" -o "$sessions_body" \
  -w '%{http_code}' "$base_url/api/v1/me/sessions?limit=100")
assert_status "$sessions_status" 200 "GET current-user Sessions"
assert_file_contains "$sessions_body" "$rotated_session_id" "current-user Session list"
assert_file_contains "$sessions_body" "$second_session_id" "current-user Session list"

user_csrf_header=$temporary/user-csrf-header
write_csrf_header "$user_csrf" "$user_csrf_header"
revoke_body=$temporary/revoke-second-session-body
revoke_status=$(curl_request -X POST -b "$user_jar" -c "$user_jar" -H @"$user_csrf_header" \
  -o "$revoke_body" -w '%{http_code}' "$base_url/api/v1/me/sessions/$second_session_id/revoke")
assert_status "$revoke_status" 204 "revoke owned Session"
second_revoked_body=$temporary/second-revoked-me-body
second_revoked_status=$(curl_request -b "$second_user_jar" -c "$second_user_jar" -o "$second_revoked_body" \
  -w '%{http_code}' "$base_url/api/v1/me")
assert_status "$second_revoked_status" 401 "revoked second browser Session"

# Sign in as the bootstrapped administrator and exercise Public/Confidential
# Client creation, forbidden Public rotation, one-time Confidential Secret
# creation/rotation, credential-free reads, and audit listing.
admin_login_get_headers=$temporary/admin-login-get-headers
admin_login_page=$temporary/admin-login-page
begin_auth /login "$admin_jar" "$admin_login_get_headers" "$admin_login_page"
admin_login_csrf=$auth_csrf
admin_login_transaction=$auth_transaction
admin_login_headers=$temporary/admin-login-headers
admin_login_body=$temporary/admin-login-body
admin_login_status=$(printf 'csrf_token=%s&transaction=%s&identifier=%s&password=%s' \
  "$admin_login_csrf" "$admin_login_transaction" "$admin_username" "$bootstrap_password" | \
  curl_request -b "$admin_jar" -c "$admin_jar" -D "$admin_login_headers" \
    -o "$admin_login_body" -w '%{http_code}' -H 'Content-Type: application/x-www-form-urlencoded' \
    --data-binary @- "$base_url/login")
assert_status "$admin_login_status" 303 "administrator login"
admin_session_token=$(cookie_value "$session_cookie_name" "$admin_jar")
admin_csrf_cookie=$(cookie_value "${session_cookie_name}_csrf" "$admin_jar")
record_sensitive "$admin_session_token" "administrator Session cookie"
record_sensitive "$admin_csrf_cookie" "administrator CSRF cookie"

admin_me_headers=$temporary/admin-me-headers
admin_me_body=$temporary/admin-me-body
admin_me_status=$(curl_request -b "$admin_jar" -c "$admin_jar" -D "$admin_me_headers" -o "$admin_me_body" \
  -w '%{http_code}' "$base_url/api/admin/v1/me")
assert_status "$admin_me_status" 200 "GET administrator identity"
admin_csrf=$(header_value X-CSRF-Token "$admin_me_headers")
record_sensitive "$admin_csrf" "administrator API CSRF token"
admin_csrf_header=$temporary/admin-csrf-header
write_csrf_header "$admin_csrf" "$admin_csrf_header"

public_payload=$temporary/public-client-payload
cat >"$public_payload" <<EOF
{"client_type":"public","name":"Compose Smoke Public","description":"phase-four Public RP acceptance","registration_enabled":true,"redirect_uris":["$client_a_url/callback"],"logout_uris":["$client_a_url/logged-out"],"scopes":["openid","profile","email","offline_access"]}
EOF
public_headers=$temporary/public-client-headers
public_body=$temporary/public-client-body
public_status=$(curl_request -X POST -b "$admin_jar" -c "$admin_jar" -H @"$admin_csrf_header" \
  -H 'Content-Type: application/json' --data-binary @"$public_payload" -D "$public_headers" \
  -o "$public_body" -w '%{http_code}' "$base_url/api/admin/v1/clients")
assert_status "$public_status" 201 "create Public Client"
assert_equal "$(header_value Cache-Control "$public_headers")" no-store "Public Client create cache policy"
assert_file_excludes "$public_body" '"client_secret":' "Public Client create response"
public_client_id=$(json_string id "$public_body")
public_protocol_client_id=$(json_string client_id "$public_body")
[ -n "$public_client_id" ] || fail "Public Client response omitted id"
[ -n "$public_protocol_client_id" ] || fail "Public Client response omitted client_id"

public_rotate_body=$temporary/public-rotate-body
public_rotate_status=$(curl_request -X POST -b "$admin_jar" -c "$admin_jar" -H @"$admin_csrf_header" \
  -o "$public_rotate_body" -w '%{http_code}' \
  "$base_url/api/admin/v1/clients/$public_client_id/secrets/rotate")
assert_status "$public_rotate_status" 422 "rotate Public Client Secret"
assert_file_contains "$public_rotate_body" invalid_input "Public Client rotation error"

confidential_payload=$temporary/confidential-client-payload
cat >"$confidential_payload" <<EOF
{"client_type":"confidential","name":"Compose Smoke Confidential","description":"phase-four Confidential RP acceptance","registration_enabled":false,"redirect_uris":["$client_b_url/callback"],"logout_uris":["$client_b_url/logged-out"],"scopes":["openid","profile","email","offline_access"]}
EOF
confidential_headers=$temporary/confidential-client-headers
confidential_body=$temporary/confidential-client-body
confidential_status=$(curl_request -X POST -b "$admin_jar" -c "$admin_jar" -H @"$admin_csrf_header" \
  -H 'Content-Type: application/json' --data-binary @"$confidential_payload" -D "$confidential_headers" \
  -o "$confidential_body" -w '%{http_code}' "$base_url/api/admin/v1/clients")
assert_status "$confidential_status" 201 "create Confidential Client"
assert_equal "$(header_value Cache-Control "$confidential_headers")" no-store "Confidential Client create cache policy"
confidential_client_id=$(json_string id "$confidential_body")
confidential_protocol_client_id=$(json_string client_id "$confidential_body")
confidential_secret=$(json_string client_secret "$confidential_body")
[ -n "$confidential_client_id" ] || fail "Confidential Client response omitted id"
[ -n "$confidential_protocol_client_id" ] || fail "Confidential Client response omitted client_id"
record_sensitive "$confidential_secret" "one-time Confidential Client Secret"

rotate_headers=$temporary/confidential-rotate-headers
rotate_body=$temporary/confidential-rotate-body
rotate_status=$(curl_request -X POST -b "$admin_jar" -c "$admin_jar" -H @"$admin_csrf_header" \
  -D "$rotate_headers" -o "$rotate_body" -w '%{http_code}' \
  "$base_url/api/admin/v1/clients/$confidential_client_id/secrets/rotate")
assert_status "$rotate_status" 200 "rotate Confidential Client Secret"
assert_equal "$(header_value Cache-Control "$rotate_headers")" no-store "Confidential Secret rotation cache policy"
rotated_client_secret=$(json_string client_secret "$rotate_body")
record_sensitive "$rotated_client_secret" "rotated Confidential Client Secret"
[ "$rotated_client_secret" != "$confidential_secret" ] || fail "Client Secret rotation returned the previous clear value"

client_read_before_restart=$temporary/client-read-before-restart
client_read_status=$(curl_request -b "$admin_jar" -c "$admin_jar" -o "$client_read_before_restart" \
  -w '%{http_code}' "$base_url/api/admin/v1/clients/$confidential_client_id")
assert_status "$client_read_status" 200 "read Confidential Client"
assert_file_excludes "$client_read_before_restart" '"client_secret":' "Confidential Client read model"
assert_file_excludes "$client_read_before_restart" '"secret_hash":' "Confidential Client read model"

# Start the same strict server-side example RP twice: A is Public and B is
# Confidential. The clear B Secret stays in a 0600 bind mount owned by the
# runtime UID; it never enters Compose environment, argv, logs, or an image.
client_b_secret_file=$temporary/example-client-b-secret
printf '%s' "$rotated_client_secret" >"$client_b_secret_file"
chmod 600 "$client_b_secret_file"
docker run --rm --user 0:0 --entrypoint /bin/sh \
  --mount "type=bind,source=$client_b_secret_file,target=/run/oneissuer-secret" \
  "$alpine_image" -c 'chown 65532:65532 /run/oneissuer-secret && chmod 0600 /run/oneissuer-secret'
export EXAMPLE_CLIENT_A_ID=$public_protocol_client_id
export EXAMPLE_CLIENT_B_ID=$confidential_protocol_client_id
export EXAMPLE_CLIENT_B_SECRET_FILE=$client_b_secret_file
compose --profile oidc-demo up --build -d client-a client-b >/dev/null
wait_status "$client_a_url/health/ready" 200 90
wait_status "$client_b_url/health/ready" 200 90
assert_equal "$(compose --profile oidc-demo exec -T client-a id -u)" 65532 "Client A effective UID"
assert_equal "$(compose --profile oidc-demo exec -T client-b id -u)" 65532 "Client B effective UID"

# Client A starts with prompt=create in a fresh browser. The RP owns state,
# nonce, and verifier; OneIssuer restores all protocol context from its opaque
# server transaction while registration POST carries only account fields plus
# CSRF/transaction tokens.
oidc_jar=$temporary/oidc-browser-jar
: >"$oidc_jar"
chmod 600 "$oidc_jar"
oidc_username="oidcuser${nonce}"
oidc_email="${oidc_username}@example.invalid"
oidc_password="OIDCUser-${nonce}-StrongPassword"
record_sensitive "$oidc_password" "OIDC demonstration user password"

a_begin_headers=$temporary/client-a-begin-headers
a_begin_body=$temporary/client-a-begin-body
a_begin_status=$(curl_request -b "$oidc_jar" -c "$oidc_jar" -D "$a_begin_headers" -o "$a_begin_body" \
  -w '%{http_code}' "$client_a_url/login?prompt=create")
assert_status "$a_begin_status" 302 "Client A begin prompt=create"
a_authorize=$(header_value Location "$a_begin_headers")
assert_prefix "$a_authorize" "$base_url/oauth2/authorize?" "Client A authorization Location"
a_state=$(query_value state "$a_authorize")
a_nonce=$(query_value nonce "$a_authorize")
record_sensitive "$a_state" "Client A state"
record_sensitive "$a_nonce" "Client A nonce"
client_a_cookie=$(cookie_value oneissuer_example_a "$oidc_jar")
record_sensitive "$client_a_cookie" "Client A browser Session"

a_authorize_headers=$temporary/client-a-authorize-headers
a_authorize_body=$temporary/client-a-authorize-body
a_authorize_status=$(curl_request -b "$oidc_jar" -c "$oidc_jar" -D "$a_authorize_headers" -o "$a_authorize_body" \
  -w '%{http_code}' "$a_authorize")
assert_status "$a_authorize_status" 303 "OneIssuer prompt=create decision"
a_register_location=$(header_value Location "$a_authorize_headers")
assert_prefix "$a_register_location" "/register?transaction=" "prompt=create registration continuation"

a_register_page=$temporary/client-a-register-page
a_register_headers=$temporary/client-a-register-headers
a_register_url=$(absolute_url "$base_url" "$a_register_location")
a_register_status=$(curl_request -b "$oidc_jar" -c "$oidc_jar" -D "$a_register_headers" -o "$a_register_page" \
  -w '%{http_code}' "$a_register_url")
assert_status "$a_register_status" 200 "OIDC hosted registration"
a_register_csrf=$(hidden_value csrf_token "$a_register_page")
a_transaction=$(hidden_value transaction "$a_register_page")
record_sensitive "$a_register_csrf" "OIDC registration CSRF"
record_sensitive "$a_transaction" "OIDC authorization transaction"
a_register_form=$temporary/client-a-register-form
printf 'csrf_token=%s&transaction=%s&username=%s&display_name=OIDC%%20Smoke%%20User&email=%s&password=%s' \
  "$a_register_csrf" "$a_transaction" "$oidc_username" "$oidc_email" "$oidc_password" >"$a_register_form"
chmod 600 "$a_register_form"
a_register_post_headers=$temporary/client-a-register-post-headers
a_register_post_body=$temporary/client-a-register-post-body
a_register_post_status=$(curl_request -b "$oidc_jar" -c "$oidc_jar" -D "$a_register_post_headers" -o "$a_register_post_body" \
  -w '%{http_code}' -H "Origin: $base_url" -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-binary @"$a_register_form" "$base_url/register")
assert_status "$a_register_post_status" 303 "OIDC prompt=create registration POST"
a_continue_location=$(header_value Location "$a_register_post_headers")
assert_prefix "$a_continue_location" "/oauth2/authorize/continue?transaction=" "post-registration authorization continuation"
oidc_session_token=$(cookie_value "$session_cookie_name" "$oidc_jar")
oidc_csrf_cookie=$(cookie_value "${session_cookie_name}_csrf" "$oidc_jar")
record_sensitive "$oidc_session_token" "OIDC OneIssuer Session"
record_sensitive "$oidc_csrf_cookie" "OIDC OneIssuer CSRF cookie"

a_continue_headers=$temporary/client-a-continue-headers
a_continue_body=$temporary/client-a-continue-body
a_continue_status=$(curl_request -b "$oidc_jar" -c "$oidc_jar" -D "$a_continue_headers" -o "$a_continue_body" \
  -w '%{http_code}' "$(absolute_url "$base_url" "$a_continue_location")")
assert_status "$a_continue_status" 303 "Client A post-registration continuation"
a_consent_location=$(header_value Location "$a_continue_headers")
assert_prefix "$a_consent_location" "/consent?transaction=" "Client A first Consent Location"

a_consent_page=$temporary/client-a-consent-page
a_consent_headers=$temporary/client-a-consent-headers
a_consent_status=$(curl_request -b "$oidc_jar" -c "$oidc_jar" -D "$a_consent_headers" -o "$a_consent_page" \
  -w '%{http_code}' "$(absolute_url "$base_url" "$a_consent_location")")
assert_status "$a_consent_status" 200 "Client A Consent page"
assert_file_contains "$a_consent_page" 'Compose Smoke Public' "Client A Consent page"
a_consent_csrf=$(hidden_value csrf_token "$a_consent_page")
a_consent_transaction=$(hidden_value transaction "$a_consent_page")
record_sensitive "$a_consent_csrf" "Client A Consent CSRF"
record_sensitive "$a_consent_transaction" "Client A Consent transaction"
a_consent_form=$temporary/client-a-consent-form
printf 'csrf_token=%s&transaction=%s&decision=approve' "$a_consent_csrf" "$a_consent_transaction" >"$a_consent_form"
chmod 600 "$a_consent_form"
a_consent_post_headers=$temporary/client-a-consent-post-headers
a_consent_post_body=$temporary/client-a-consent-post-body
a_consent_post_status=$(curl_request -b "$oidc_jar" -c "$oidc_jar" -D "$a_consent_post_headers" -o "$a_consent_post_body" \
  -w '%{http_code}' -H "Origin: $base_url" -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-binary @"$a_consent_form" "$base_url/consent")
assert_status "$a_consent_post_status" 302 "Client A Consent approval"
a_callback_url=$(header_value Location "$a_consent_post_headers")
assert_prefix "$a_callback_url" "$client_a_url/callback?code=" "Client A callback Location"
a_code=$(query_value code "$a_callback_url")
record_sensitive "$a_code" "Client A Authorization Code"
a_callback_config=$temporary/client-a-callback-curl
write_curl_url_config "$a_callback_url" "$a_callback_config"
a_callback_headers=$temporary/client-a-callback-headers
a_callback_body=$temporary/client-a-callback-body
a_callback_status=$(curl_request -b "$oidc_jar" -c "$oidc_jar" -D "$a_callback_headers" -o "$a_callback_body" \
  -w '%{http_code}' --config "$a_callback_config")
assert_status "$a_callback_status" 303 "Client A strict callback"
assert_equal "$(header_value Location "$a_callback_headers")" / "Client A callback completion"
a_home=$temporary/client-a-home
a_home_status=$(curl_request -b "$oidc_jar" -c "$oidc_jar" -o "$a_home" -w '%{http_code}' "$client_a_url/")
assert_status "$a_home_status" 200 "Client A signed-in home"
assert_file_contains "$a_home" 'Signed in as <strong>OIDC Smoke User</strong>' "Client A verified identity"
assert_file_excludes "$a_home" 'access_token' "Client A page"
assert_file_excludes "$a_home" 'id_token' "Client A page"

# The example RP mutates its server-side Session through a same-origin,
# Session-bound POST. Keep the hidden CSRF value in a mode-restricted form file;
# the Refresh Token remains server-side and never enters this request.
a_refresh_csrf=$(hidden_value csrf_token "$a_home")
record_sensitive "$a_refresh_csrf" "Client A refresh CSRF"
a_home_exposure=$temporary/client-a-home-exposure
prepare_exposure_copy "$a_home" "$a_home_exposure" "$a_refresh_csrf" \
  "Client A signed-in home" /refresh /logout
a_refresh_form=$temporary/client-a-refresh-form
printf 'csrf_token=%s' "$a_refresh_csrf" >"$a_refresh_form"
chmod 600 "$a_refresh_form"
a_refresh_headers=$temporary/client-a-refresh-headers
a_refresh_body=$temporary/client-a-refresh-body
a_refresh_status=$(curl_request -X POST -b "$oidc_jar" -c "$oidc_jar" -D "$a_refresh_headers" \
  -H "Origin: $client_a_url" -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-binary @"$a_refresh_form" -o "$a_refresh_body" -w '%{http_code}' "$client_a_url/refresh")
assert_status "$a_refresh_status" 303 "Client A RP Refresh POST"
assert_equal "$(header_value Location "$a_refresh_headers")" / "Client A RP Refresh redirect"
a_refreshed_home=$temporary/client-a-refreshed-home
a_refreshed_home_status=$(curl_request -b "$oidc_jar" -c "$oidc_jar" -o "$a_refreshed_home" \
  -w '%{http_code}' "$client_a_url/")
assert_status "$a_refreshed_home_status" 200 "Client A refreshed home"
assert_file_contains "$a_refreshed_home" 'Signed in as <strong>OIDC Smoke User</strong>' "Client A refreshed identity"
assert_file_excludes "$a_refreshed_home" 'access_token' "Client A refreshed page"
assert_file_excludes "$a_refreshed_home" 'id_token' "Client A refreshed page"
a_refreshed_home_csrf=$(hidden_value csrf_token "$a_refreshed_home")
record_sensitive "$a_refreshed_home_csrf" "Client A refreshed home CSRF"
a_refreshed_home_exposure=$temporary/client-a-refreshed-home-exposure
prepare_exposure_copy "$a_refreshed_home" "$a_refreshed_home_exposure" "$a_refreshed_home_csrf" \
  "Client A refreshed home" /refresh /logout

# A consumed Code remains unusable outside the RP after its successful callback.
a_replay_form=$temporary/client-a-replay-form
printf 'grant_type=authorization_code&code=%s&redirect_uri=http%%3A%%2F%%2Flocalhost%%3A%s%%2Fcallback&client_id=%s&code_verifier=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' \
  "$a_code" "$client_a_port" "$public_protocol_client_id" >"$a_replay_form"
chmod 600 "$a_replay_form"
a_replay_body=$temporary/client-a-replay-body
a_replay_status=$(curl_request -X POST -H 'Content-Type: application/x-www-form-urlencoded' --data-binary @"$a_replay_form" \
  -o "$a_replay_body" -w '%{http_code}' "$base_url/oauth2/token")
assert_status "$a_replay_status" 400 "Client A consumed Code replay"
assert_file_contains "$a_replay_body" '"error":"invalid_grant"' "Client A replay response"
assert_file_excludes "$a_replay_body" "$a_code" "Client A replay response"

# Client B uses the same OneIssuer browser Session but receives a separate
# Consent page and validates a distinct audience with client_secret_basic.
b_begin_headers=$temporary/client-b-begin-headers
b_begin_body=$temporary/client-b-begin-body
b_begin_status=$(curl_request -b "$oidc_jar" -c "$oidc_jar" -D "$b_begin_headers" -o "$b_begin_body" \
  -w '%{http_code}' "$client_b_url/login")
assert_status "$b_begin_status" 302 "Client B begin"
b_authorize=$(header_value Location "$b_begin_headers")
assert_prefix "$b_authorize" "$base_url/oauth2/authorize?" "Client B authorization Location"
b_state=$(query_value state "$b_authorize")
b_nonce=$(query_value nonce "$b_authorize")
record_sensitive "$b_state" "Client B state"
record_sensitive "$b_nonce" "Client B nonce"
client_b_cookie=$(cookie_value oneissuer_example_b "$oidc_jar")
record_sensitive "$client_b_cookie" "Client B browser Session"
b_authorize_headers=$temporary/client-b-authorize-headers
b_authorize_body=$temporary/client-b-authorize-body
b_authorize_status=$(curl_request -b "$oidc_jar" -c "$oidc_jar" -D "$b_authorize_headers" -o "$b_authorize_body" \
  -w '%{http_code}' "$b_authorize")
assert_status "$b_authorize_status" 303 "Client B SSO authorization"
b_consent_location=$(header_value Location "$b_authorize_headers")
assert_prefix "$b_consent_location" "/consent?transaction=" "Client B independent Consent Location"
assert_file_excludes "$b_authorize_headers" '/login?transaction=' "Client B SSO authorization"
b_consent_page=$temporary/client-b-consent-page
b_consent_headers=$temporary/client-b-consent-headers
b_consent_status=$(curl_request -b "$oidc_jar" -c "$oidc_jar" -D "$b_consent_headers" -o "$b_consent_page" \
  -w '%{http_code}' "$(absolute_url "$base_url" "$b_consent_location")")
assert_status "$b_consent_status" 200 "Client B Consent page"
assert_file_contains "$b_consent_page" 'Compose Smoke Confidential' "Client B Consent page"
b_consent_csrf=$(hidden_value csrf_token "$b_consent_page")
b_consent_transaction=$(hidden_value transaction "$b_consent_page")
record_sensitive "$b_consent_csrf" "Client B Consent CSRF"
record_sensitive "$b_consent_transaction" "Client B Consent transaction"
b_consent_form=$temporary/client-b-consent-form
printf 'csrf_token=%s&transaction=%s&decision=approve' "$b_consent_csrf" "$b_consent_transaction" >"$b_consent_form"
chmod 600 "$b_consent_form"
b_consent_post_headers=$temporary/client-b-consent-post-headers
b_consent_post_body=$temporary/client-b-consent-post-body
b_consent_post_status=$(curl_request -b "$oidc_jar" -c "$oidc_jar" -D "$b_consent_post_headers" -o "$b_consent_post_body" \
  -w '%{http_code}' -H "Origin: $base_url" -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-binary @"$b_consent_form" "$base_url/consent")
assert_status "$b_consent_post_status" 302 "Client B Consent approval"
b_callback_url=$(header_value Location "$b_consent_post_headers")
assert_prefix "$b_callback_url" "$client_b_url/callback?code=" "Client B callback Location"
b_code=$(query_value code "$b_callback_url")
record_sensitive "$b_code" "Client B Authorization Code"
b_callback_config=$temporary/client-b-callback-curl
write_curl_url_config "$b_callback_url" "$b_callback_config"
b_callback_headers=$temporary/client-b-callback-headers
b_callback_body=$temporary/client-b-callback-body
b_callback_status=$(curl_request -b "$oidc_jar" -c "$oidc_jar" -D "$b_callback_headers" -o "$b_callback_body" \
  -w '%{http_code}' --config "$b_callback_config")
assert_status "$b_callback_status" 303 "Client B strict callback"
b_home=$temporary/client-b-home
b_home_status=$(curl_request -b "$oidc_jar" -c "$oidc_jar" -o "$b_home" -w '%{http_code}' "$client_b_url/")
assert_status "$b_home_status" 200 "Client B signed-in home"
assert_file_contains "$b_home" 'Signed in as <strong>OIDC Smoke User</strong>' "Client B verified identity"
assert_file_excludes "$b_home" 'access_token' "Client B page"
assert_file_excludes "$b_home" 'id_token' "Client B page"

# Exercise the protocol endpoints with a known RFC 7636 S256 vector. Clear
# Code/verifier/JWT values are kept in 0600 files or shell memory and are added
# to the exact-value privacy scan; none is placed in a curl command argument.
pkce_verifier=dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk
pkce_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM
wrong_verifier=BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB
record_sensitive "$pkce_verifier" "direct Token PKCE verifier"
record_sensitive "$pkce_challenge" "direct Authorize PKCE challenge"
direct_state="direct-state-${nonce}"
direct_nonce="direct-nonce-${nonce}"
record_sensitive "$direct_state" "direct Public state"
record_sensitive "$direct_nonce" "direct Public nonce"
public_redirect_encoded=http%3A%2F%2Flocalhost%3A${client_a_port}%2Fcallback
confidential_redirect_encoded=http%3A%2F%2Flocalhost%3A${client_b_port}%2Fcallback
direct_public_authorize="$base_url/oauth2/authorize?client_id=$public_protocol_client_id&redirect_uri=$public_redirect_encoded&response_type=code&response_mode=query&scope=openid%20profile%20email&state=$direct_state&nonce=$direct_nonce&code_challenge=$pkce_challenge&code_challenge_method=S256"
direct_public_headers=$temporary/direct-public-authorize-headers
direct_public_body=$temporary/direct-public-authorize-body
direct_public_status=$(curl_request -b "$oidc_jar" -c "$oidc_jar" -D "$direct_public_headers" -o "$direct_public_body" \
  -w '%{http_code}' "$direct_public_authorize")
assert_status "$direct_public_status" 302 "Public Grant reuse authorization"
direct_public_callback=$(header_value Location "$direct_public_headers")
assert_prefix "$direct_public_callback" "$client_a_url/callback?code=" "Public direct callback"
direct_public_code=$(query_value code "$direct_public_callback")
record_sensitive "$direct_public_code" "direct Public Authorization Code"

direct_public_wrong_form=$temporary/direct-public-wrong-verifier-form
printf 'grant_type=authorization_code&code=%s&redirect_uri=%s&client_id=%s&code_verifier=%s' \
  "$direct_public_code" "$public_redirect_encoded" "$public_protocol_client_id" "$wrong_verifier" >"$direct_public_wrong_form"
chmod 600 "$direct_public_wrong_form"
direct_public_wrong_body=$temporary/direct-public-wrong-verifier-body
direct_public_wrong_status=$(curl_request -X POST -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-binary @"$direct_public_wrong_form" -o "$direct_public_wrong_body" -w '%{http_code}' "$base_url/oauth2/token")
assert_status "$direct_public_wrong_status" 400 "Public wrong PKCE verifier"
assert_file_contains "$direct_public_wrong_body" '"error":"invalid_grant"' "wrong-verifier response"
assert_file_excludes "$direct_public_wrong_body" "$direct_public_code" "wrong-verifier response"

direct_public_form=$temporary/direct-public-token-form
printf 'grant_type=authorization_code&code=%s&redirect_uri=%s&client_id=%s&code_verifier=%s' \
  "$direct_public_code" "$public_redirect_encoded" "$public_protocol_client_id" "$pkce_verifier" >"$direct_public_form"
chmod 600 "$direct_public_form"
direct_public_token_headers=$temporary/direct-public-token-headers
direct_public_token_body=$temporary/direct-public-token-body
direct_public_token_status=$(curl_request -X POST -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-binary @"$direct_public_form" -D "$direct_public_token_headers" -o "$direct_public_token_body" \
  -w '%{http_code}' "$base_url/oauth2/token")
assert_status "$direct_public_token_status" 200 "Public Code exchange after wrong verifier"
assert_equal "$(header_value Cache-Control "$direct_public_token_headers")" no-store "Public Token cache policy"
assert_file_contains "$direct_public_token_body" '"token_type":"Bearer"' "Public Token response"
assert_file_excludes "$direct_public_token_body" 'refresh_token' "Public Token response"
public_access_token=$(json_string access_token "$direct_public_token_body")
public_id_token=$(json_string id_token "$direct_public_token_body")
record_sensitive "$public_access_token" "Public Access Token"
record_sensitive "$public_id_token" "Public ID Token"
public_bearer_header=$temporary/public-bearer-header
printf 'Authorization: Bearer %s\n' "$public_access_token" >"$public_bearer_header"
chmod 600 "$public_bearer_header"
public_userinfo_headers=$temporary/public-userinfo-headers
public_userinfo_body=$temporary/public-userinfo-body
public_userinfo_status=$(curl_request -H @"$public_bearer_header" -D "$public_userinfo_headers" -o "$public_userinfo_body" \
  -w '%{http_code}' "$base_url/oauth2/userinfo")
assert_status "$public_userinfo_status" 200 "Public Access Token UserInfo"
assert_file_contains "$public_userinfo_body" '"name":"OIDC Smoke User"' "Public UserInfo profile"
assert_file_contains "$public_userinfo_body" '"email_verified":false' "Public UserInfo email verification"

direct_public_replay_body=$temporary/direct-public-replay-body
direct_public_replay_status=$(curl_request -X POST -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-binary @"$direct_public_form" -o "$direct_public_replay_body" -w '%{http_code}' "$base_url/oauth2/token")
assert_status "$direct_public_replay_status" 400 "Public direct Code replay"
assert_file_contains "$direct_public_replay_body" '"error":"invalid_grant"' "Public direct replay response"

# The acceptance profile fixes the smoke Code TTL at its supported 30-second
# minimum. A missing verifier is rejected before repository exchange and leaves
# the Code unconsumed; after the real TTL elapses, that same Code with the right
# verifier fails generically as an expired grant and never returns a Token.
expiry_state="expiry-state-${nonce}"
record_sensitive "$expiry_state" "expiring Code state"
expiry_authorize_headers=$temporary/expiry-authorize-headers
expiry_authorize_body=$temporary/expiry-authorize-body
expiry_authorize_status=$(curl_request -b "$oidc_jar" -c "$oidc_jar" -D "$expiry_authorize_headers" \
  -o "$expiry_authorize_body" -w '%{http_code}' \
  "$base_url/oauth2/authorize?client_id=$public_protocol_client_id&redirect_uri=$public_redirect_encoded&response_type=code&scope=openid&state=$expiry_state&code_challenge=$pkce_challenge&code_challenge_method=S256")
assert_status "$expiry_authorize_status" 302 "expiring Code authorization"
expiry_callback=$(header_value Location "$expiry_authorize_headers")
assert_prefix "$expiry_callback" "$client_a_url/callback?code=" "expiring Code callback"
expiry_code=$(query_value code "$expiry_callback")
[ -n "$expiry_code" ] || fail "expiring authorization omitted Code"
record_sensitive "$expiry_code" "expiring Authorization Code"
missing_verifier_form=$temporary/missing-verifier-token-form
printf 'grant_type=authorization_code&code=%s&redirect_uri=%s&client_id=%s' \
  "$expiry_code" "$public_redirect_encoded" "$public_protocol_client_id" >"$missing_verifier_form"
chmod 600 "$missing_verifier_form"
missing_verifier_body=$temporary/missing-verifier-token-body
missing_verifier_status=$(curl_request -X POST -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-binary @"$missing_verifier_form" -o "$missing_verifier_body" -w '%{http_code}' "$base_url/oauth2/token")
assert_status "$missing_verifier_status" 400 "missing PKCE verifier"
assert_file_contains "$missing_verifier_body" '"error":"invalid_request"' "missing-verifier response"
assert_file_excludes "$missing_verifier_body" "$expiry_code" "missing-verifier response"
assert_file_excludes "$missing_verifier_body" 'access_token' "missing-verifier response"

sleep 31
expired_code_form=$temporary/expired-code-token-form
printf 'grant_type=authorization_code&code=%s&redirect_uri=%s&client_id=%s&code_verifier=%s' \
  "$expiry_code" "$public_redirect_encoded" "$public_protocol_client_id" "$pkce_verifier" >"$expired_code_form"
chmod 600 "$expired_code_form"
expired_code_body=$temporary/expired-code-token-body
expired_code_status=$(curl_request -X POST -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-binary @"$expired_code_form" -o "$expired_code_body" -w '%{http_code}' "$base_url/oauth2/token")
assert_status "$expired_code_status" 400 "expired Authorization Code"
assert_file_contains "$expired_code_body" '"error":"invalid_grant"' "expired-Code response"
assert_file_excludes "$expired_code_body" "$expiry_code" "expired-Code response"
assert_file_excludes "$expired_code_body" 'access_token' "expired-Code response"
assert_file_excludes "$expired_code_body" 'id_token' "expired-Code response"

# Phase-four Public Client flow: requesting offline_access adds a Grant scope,
# returns a three-token initial response, and then rotates the family.
offline_state="offline-state-${nonce}"
record_sensitive "$offline_state" "offline_access state"
offline_headers=$temporary/offline-authorize-headers
offline_body=$temporary/offline-authorize-body
offline_status=$(curl_request -b "$oidc_jar" -c "$oidc_jar" -D "$offline_headers" -o "$offline_body" -w '%{http_code}' \
  "$base_url/oauth2/authorize?client_id=$public_protocol_client_id&redirect_uri=$public_redirect_encoded&response_type=code&scope=openid%20profile%20offline_access&state=$offline_state&prompt=consent&code_challenge=$pkce_challenge&code_challenge_method=S256")
assert_status "$offline_status" 303 "offline_access Consent redirect"
offline_consent_location=$(header_value Location "$offline_headers")
assert_prefix "$offline_consent_location" "/consent?transaction=" "offline_access Consent page"
offline_consent_page=$temporary/offline-consent-page
offline_consent_status=$(curl_request -b "$oidc_jar" -c "$oidc_jar" -o "$offline_consent_page" -w '%{http_code}' \
  "$(absolute_url "$base_url" "$offline_consent_location")")
assert_status "$offline_consent_status" 200 "offline_access Consent page"
assert_file_contains "$offline_consent_page" 'Offline access' "offline_access Consent disclosure"
offline_consent_csrf=$(hidden_value csrf_token "$offline_consent_page")
offline_consent_transaction=$(hidden_value transaction "$offline_consent_page")
record_sensitive "$offline_consent_csrf" "offline_access Consent CSRF"
record_sensitive "$offline_consent_transaction" "offline_access Consent transaction"
offline_consent_form=$temporary/offline-consent-form
printf 'csrf_token=%s&transaction=%s&decision=approve' "$offline_consent_csrf" "$offline_consent_transaction" >"$offline_consent_form"
chmod 600 "$offline_consent_form"
offline_consent_headers=$temporary/offline-consent-headers
offline_consent_post_body=$temporary/offline-consent-post-body
offline_consent_post_status=$(curl_request -b "$oidc_jar" -c "$oidc_jar" -D "$offline_consent_headers" \
  -o "$offline_consent_post_body" -w '%{http_code}' -H "Origin: $base_url" \
  -H 'Content-Type: application/x-www-form-urlencoded' --data-binary @"$offline_consent_form" "$base_url/consent")
assert_status "$offline_consent_post_status" 302 "offline_access Consent approval"
offline_callback=$(header_value Location "$offline_consent_headers")
assert_prefix "$offline_callback" "$client_a_url/callback?code=" "offline_access callback"
offline_code=$(query_value code "$offline_callback")
record_sensitive "$offline_code" "offline_access Authorization Code"
offline_form=$temporary/offline-token-form
printf 'grant_type=authorization_code&code=%s&redirect_uri=%s&client_id=%s&code_verifier=%s' \
  "$offline_code" "$public_redirect_encoded" "$public_protocol_client_id" "$pkce_verifier" >"$offline_form"
chmod 600 "$offline_form"
offline_token_headers=$temporary/offline-token-headers
offline_token_body=$temporary/offline-token-body
offline_token_status=$(curl_request -X POST -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-binary @"$offline_form" -D "$offline_token_headers" -o "$offline_token_body" \
  -w '%{http_code}' "$base_url/oauth2/token")
assert_status "$offline_token_status" 200 "offline_access initial token response"
assert_file_contains "$offline_token_body" '"refresh_token":"r1_' "offline_access initial Refresh Token"
offline_access_token=$(json_string access_token "$offline_token_body")
offline_id_token=$(json_string id_token "$offline_token_body")
offline_refresh_token=$(json_string refresh_token "$offline_token_body")
record_sensitive "$offline_access_token" "offline_access initial Access Token"
record_sensitive "$offline_id_token" "offline_access initial ID Token"
record_sensitive "$offline_refresh_token" "offline_access initial Refresh Token"
refresh_form=$temporary/refresh-grant-form
printf 'grant_type=refresh_token&refresh_token=%s&client_id=%s' "$offline_refresh_token" "$public_protocol_client_id" >"$refresh_form"
chmod 600 "$refresh_form"
refresh_body=$temporary/refresh-grant-body
refresh_headers=$temporary/refresh-grant-headers
refresh_status=$(curl_request -X POST -H 'Content-Type: application/x-www-form-urlencoded' --data-binary @"$refresh_form" \
  -D "$refresh_headers" -o "$refresh_body" -w '%{http_code}' "$base_url/oauth2/token")
assert_status "$refresh_status" 200 "Public Refresh rotation"
assert_file_contains "$refresh_body" '"refresh_token":"r1_' "Public Refresh replacement"
assert_file_excludes "$refresh_body" '"id_token"' "Public Refresh response"
replacement_refresh_token=$(json_string refresh_token "$refresh_body")
replacement_access_token=$(json_string access_token "$refresh_body")
record_sensitive "$replacement_refresh_token" "Public replacement Refresh Token"
record_sensitive "$replacement_access_token" "Public replacement Access Token"
replay_refresh_body=$temporary/replay-refresh-body
replay_refresh_status=$(curl_request -X POST -H 'Content-Type: application/x-www-form-urlencoded' --data-binary @"$refresh_form" \
  -o "$replay_refresh_body" -w '%{http_code}' "$base_url/oauth2/token")
assert_status "$replay_refresh_status" 400 "consumed Refresh replay"
assert_file_contains "$replay_refresh_body" '"error":"invalid_grant"' "consumed Refresh replay"
invalid_scope_state="invalid-scope-state-${nonce}"
record_sensitive "$invalid_scope_state" "invalid_scope state"
invalid_scope_headers=$temporary/invalid-scope-authorize-headers
invalid_scope_body=$temporary/invalid-scope-authorize-body
invalid_scope_status=$(curl_request -b "$oidc_jar" -c "$oidc_jar" -D "$invalid_scope_headers" -o "$invalid_scope_body" -w '%{http_code}' \
  "$base_url/oauth2/authorize?client_id=$public_protocol_client_id&redirect_uri=$public_redirect_encoded&response_type=code&scope=openid%20address&state=$invalid_scope_state&code_challenge=$pkce_challenge&code_challenge_method=S256")
assert_status "$invalid_scope_status" 302 "unregistered scope rejection"
invalid_scope_location=$(header_value Location "$invalid_scope_headers")
assert_prefix "$invalid_scope_location" "$client_a_url/callback?error=invalid_scope" "unregistered scope error redirect"
assert_file_contains "$invalid_scope_headers" "state=$invalid_scope_state" "unregistered scope state round trip"

none_state="none-state-${nonce}"
record_sensitive "$none_state" "prompt=none state"
none_jar=$temporary/prompt-none-cookie-jar
: >"$none_jar"
chmod 600 "$none_jar"
none_headers=$temporary/prompt-none-headers
none_body=$temporary/prompt-none-body
none_status=$(curl_request -b "$none_jar" -c "$none_jar" -D "$none_headers" -o "$none_body" -w '%{http_code}' \
  "$base_url/oauth2/authorize?client_id=$public_protocol_client_id&redirect_uri=$public_redirect_encoded&response_type=code&scope=openid&state=$none_state&prompt=none&code_challenge=$pkce_challenge&code_challenge_method=S256")
assert_status "$none_status" 302 "prompt=none without Session"
none_location=$(header_value Location "$none_headers")
assert_prefix "$none_location" "$client_a_url/callback?error=login_required" "prompt=none login_required redirect"
assert_file_contains "$none_headers" "state=$none_state" "prompt=none state round trip"

# A different, already-authenticated User has no Grant for Client A. Silent
# authorization must return consent_required directly to the trusted callback;
# it must not render a login or Consent interaction and State remains byte-exact.
none_grant_state="none-grant-state-${nonce}"
record_sensitive "$none_grant_state" "prompt=none missing-Grant state"
none_grant_headers=$temporary/prompt-none-missing-grant-headers
none_grant_body=$temporary/prompt-none-missing-grant-body
none_grant_status=$(curl_request -b "$user_jar" -c "$user_jar" -D "$none_grant_headers" -o "$none_grant_body" -w '%{http_code}' \
  "$base_url/oauth2/authorize?client_id=$public_protocol_client_id&redirect_uri=$public_redirect_encoded&response_type=code&scope=openid&state=$none_grant_state&prompt=none&code_challenge=$pkce_challenge&code_challenge_method=S256")
assert_status "$none_grant_status" 302 "prompt=none without Grant"
none_grant_location=$(header_value Location "$none_grant_headers")
assert_prefix "$none_grant_location" "$client_a_url/callback?error=consent_required" "prompt=none consent_required redirect"
assert_file_contains "$none_grant_headers" "state=$none_grant_state" "prompt=none missing-Grant state round trip"
assert_file_excludes "$none_grant_headers" '/login?transaction=' "prompt=none missing-Grant response"
assert_file_excludes "$none_grant_headers" '/consent?transaction=' "prompt=none missing-Grant response"

# An existing covering Grant does not bypass prompt=consent. Prove the hosted
# page is forced, then deny the one request and preserve State without issuing a
# Code or mutating the previously accepted Grant.
forced_consent_state="forced-consent-state-${nonce}"
record_sensitive "$forced_consent_state" "prompt=consent state"
forced_consent_headers=$temporary/forced-consent-authorize-headers
forced_consent_body=$temporary/forced-consent-authorize-body
forced_consent_status=$(curl_request -b "$oidc_jar" -c "$oidc_jar" -D "$forced_consent_headers" \
  -o "$forced_consent_body" -w '%{http_code}' \
  "$base_url/oauth2/authorize?client_id=$public_protocol_client_id&redirect_uri=$public_redirect_encoded&response_type=code&scope=openid&state=$forced_consent_state&prompt=consent&code_challenge=$pkce_challenge&code_challenge_method=S256")
assert_status "$forced_consent_status" 303 "prompt=consent authorization"
forced_consent_location=$(header_value Location "$forced_consent_headers")
assert_prefix "$forced_consent_location" "/consent?transaction=" "prompt=consent forced page"
forced_consent_page=$temporary/forced-consent-page
forced_consent_page_headers=$temporary/forced-consent-page-headers
forced_consent_page_status=$(curl_request -b "$oidc_jar" -c "$oidc_jar" -D "$forced_consent_page_headers" \
  -o "$forced_consent_page" -w '%{http_code}' "$(absolute_url "$base_url" "$forced_consent_location")")
assert_status "$forced_consent_page_status" 200 "prompt=consent hosted page"
forced_consent_csrf=$(hidden_value csrf_token "$forced_consent_page")
forced_consent_transaction=$(hidden_value transaction "$forced_consent_page")
record_sensitive "$forced_consent_csrf" "prompt=consent CSRF"
record_sensitive "$forced_consent_transaction" "prompt=consent transaction"
forced_consent_form=$temporary/forced-consent-form
printf 'csrf_token=%s&transaction=%s&decision=deny' "$forced_consent_csrf" "$forced_consent_transaction" >"$forced_consent_form"
chmod 600 "$forced_consent_form"
forced_consent_deny_headers=$temporary/forced-consent-deny-headers
forced_consent_deny_body=$temporary/forced-consent-deny-body
forced_consent_deny_status=$(curl_request -b "$oidc_jar" -c "$oidc_jar" -D "$forced_consent_deny_headers" \
  -o "$forced_consent_deny_body" -w '%{http_code}' -H "Origin: $base_url" \
  -H 'Content-Type: application/x-www-form-urlencoded' --data-binary @"$forced_consent_form" "$base_url/consent")
assert_status "$forced_consent_deny_status" 302 "prompt=consent denial"
assert_prefix "$(header_value Location "$forced_consent_deny_headers")" "$client_a_url/callback?error=access_denied" "prompt=consent denial callback"
assert_file_contains "$forced_consent_deny_headers" "state=$forced_consent_state" "prompt=consent denial state round trip"
assert_file_excludes "$forced_consent_deny_headers" 'code=' "prompt=consent denial"

# prompt=create is a registration-only request. An already-authenticated Session
# created before this authorization cannot satisfy it and must fail silently with
# interaction_required rather than minting a Code for the existing identity.
active_create_state="active-create-state-${nonce}"
record_sensitive "$active_create_state" "active-Session prompt=create state"
active_create_headers=$temporary/active-create-authorize-headers
active_create_body=$temporary/active-create-authorize-body
active_create_status=$(curl_request -b "$oidc_jar" -c "$oidc_jar" -D "$active_create_headers" \
  -o "$active_create_body" -w '%{http_code}' \
  "$base_url/oauth2/authorize?client_id=$public_protocol_client_id&redirect_uri=$public_redirect_encoded&response_type=code&scope=openid&state=$active_create_state&prompt=create&code_challenge=$pkce_challenge&code_challenge_method=S256")
assert_status "$active_create_status" 302 "active Session prompt=create"
assert_prefix "$(header_value Location "$active_create_headers")" "$client_a_url/callback?error=interaction_required" "active Session prompt=create callback"
assert_file_contains "$active_create_headers" "state=$active_create_state" "active Session prompt=create state round trip"
assert_file_excludes "$active_create_headers" 'code=' "active Session prompt=create response"

# prompt=login must force credential entry despite the valid Session, rotate that
# Session, and then resume the same server-side transaction. The existing Grant
# may be reused only after the fresh authentication succeeds.
prompt_login_state="prompt-login-state-${nonce}"
record_sensitive "$prompt_login_state" "prompt=login state"
prompt_login_old_session=$(cookie_value "$session_cookie_name" "$oidc_jar")
prompt_login_headers=$temporary/prompt-login-authorize-headers
prompt_login_body=$temporary/prompt-login-authorize-body
prompt_login_status=$(curl_request -b "$oidc_jar" -c "$oidc_jar" -D "$prompt_login_headers" \
  -o "$prompt_login_body" -w '%{http_code}' \
  "$base_url/oauth2/authorize?client_id=$public_protocol_client_id&redirect_uri=$public_redirect_encoded&response_type=code&scope=openid&state=$prompt_login_state&prompt=login&code_challenge=$pkce_challenge&code_challenge_method=S256")
assert_status "$prompt_login_status" 303 "prompt=login authorization"
prompt_login_location=$(header_value Location "$prompt_login_headers")
assert_prefix "$prompt_login_location" "/login?transaction=" "prompt=login credential continuation"
prompt_login_page=$temporary/prompt-login-page
prompt_login_page_headers=$temporary/prompt-login-page-headers
prompt_login_page_status=$(curl_request -b "$oidc_jar" -c "$oidc_jar" -D "$prompt_login_page_headers" \
  -o "$prompt_login_page" -w '%{http_code}' "$(absolute_url "$base_url" "$prompt_login_location")")
assert_status "$prompt_login_page_status" 200 "prompt=login hosted page"
prompt_login_csrf=$(hidden_value csrf_token "$prompt_login_page")
prompt_login_transaction=$(hidden_value transaction "$prompt_login_page")
prompt_login_preauth=$(cookie_value "${session_cookie_name}_preauth" "$oidc_jar")
record_sensitive "$prompt_login_csrf" "prompt=login CSRF"
record_sensitive "$prompt_login_transaction" "prompt=login transaction"
record_sensitive "$prompt_login_preauth" "prompt=login pre-auth cookie"
prompt_login_form=$temporary/prompt-login-form
printf 'csrf_token=%s&transaction=%s&identifier=%s&password=%s' \
  "$prompt_login_csrf" "$prompt_login_transaction" "$oidc_email" "$oidc_password" >"$prompt_login_form"
chmod 600 "$prompt_login_form"
prompt_login_post_headers=$temporary/prompt-login-post-headers
prompt_login_post_body=$temporary/prompt-login-post-body
prompt_login_post_status=$(curl_request -b "$oidc_jar" -c "$oidc_jar" -D "$prompt_login_post_headers" \
  -o "$prompt_login_post_body" -w '%{http_code}' -H "Origin: $base_url" \
  -H 'Content-Type: application/x-www-form-urlencoded' --data-binary @"$prompt_login_form" "$base_url/login")
assert_status "$prompt_login_post_status" 303 "prompt=login credential POST"
prompt_login_continue=$(header_value Location "$prompt_login_post_headers")
assert_prefix "$prompt_login_continue" "/oauth2/authorize/continue?transaction=" "prompt=login authorization resume"
prompt_login_new_session=$(cookie_value "$session_cookie_name" "$oidc_jar")
record_sensitive "$prompt_login_new_session" "prompt=login rotated Session"
[ "$prompt_login_new_session" != "$prompt_login_old_session" ] || fail "prompt=login did not rotate the existing Session"
prompt_login_continue_headers=$temporary/prompt-login-continue-headers
prompt_login_continue_body=$temporary/prompt-login-continue-body
prompt_login_continue_status=$(curl_request -b "$oidc_jar" -c "$oidc_jar" -D "$prompt_login_continue_headers" \
  -o "$prompt_login_continue_body" -w '%{http_code}' "$(absolute_url "$base_url" "$prompt_login_continue")")
assert_status "$prompt_login_continue_status" 302 "prompt=login resumed authorization"
prompt_login_callback=$(header_value Location "$prompt_login_continue_headers")
assert_prefix "$prompt_login_callback" "$client_a_url/callback?code=" "prompt=login callback"
assert_file_contains "$prompt_login_continue_headers" "state=$prompt_login_state" "prompt=login state round trip"
prompt_login_code=$(query_value code "$prompt_login_callback")
record_sensitive "$prompt_login_code" "prompt=login Authorization Code"
prompt_login_token_form=$temporary/prompt-login-token-form
printf 'grant_type=authorization_code&code=%s&redirect_uri=%s&client_id=%s&code_verifier=%s' \
  "$prompt_login_code" "$public_redirect_encoded" "$public_protocol_client_id" "$pkce_verifier" >"$prompt_login_token_form"
chmod 600 "$prompt_login_token_form"
prompt_login_token_body=$temporary/prompt-login-token-body
prompt_login_token_status=$(curl_request -X POST -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-binary @"$prompt_login_token_form" -o "$prompt_login_token_body" -w '%{http_code}' "$base_url/oauth2/token")
assert_status "$prompt_login_token_status" 200 "prompt=login Code exchange"
prompt_login_access_token=$(json_string access_token "$prompt_login_token_body")
prompt_login_id_token=$(json_string id_token "$prompt_login_token_body")
record_sensitive "$prompt_login_access_token" "prompt=login Access Token"
record_sensitive "$prompt_login_id_token" "prompt=login ID Token"

bad_redirect_headers=$temporary/bad-redirect-headers
bad_redirect_body=$temporary/bad-redirect-body
bad_redirect_status=$(curl_request -D "$bad_redirect_headers" -o "$bad_redirect_body" -w '%{http_code}' \
  "$base_url/oauth2/authorize?client_id=$public_protocol_client_id&redirect_uri=http%3A%2F%2Flocalhost%3A65530%2Fcallback&response_type=code&scope=openid&state=must-not-leave&code_challenge=$pkce_challenge&code_challenge_method=S256")
assert_status "$bad_redirect_status" 400 "unregistered Redirect URI"
assert_equal "$(header_value Location "$bad_redirect_headers")" "" "unregistered Redirect URI local failure"
assert_file_excludes "$bad_redirect_body" 'localhost:65530' "unregistered Redirect URI body"

# Confidential authentication is strictly Basic. A wrong Secret returns one
# generic 401 without consuming the Code; the correct header can then exchange
# that same S256-bound Code exactly once.
confidential_state="confidential-state-${nonce}"
confidential_nonce="confidential-nonce-${nonce}"
record_sensitive "$confidential_state" "direct Confidential state"
record_sensitive "$confidential_nonce" "direct Confidential nonce"
direct_confidential_headers=$temporary/direct-confidential-authorize-headers
direct_confidential_body=$temporary/direct-confidential-authorize-body
direct_confidential_status=$(curl_request -b "$oidc_jar" -c "$oidc_jar" -D "$direct_confidential_headers" \
  -o "$direct_confidential_body" -w '%{http_code}' \
  "$base_url/oauth2/authorize?client_id=$confidential_protocol_client_id&redirect_uri=$confidential_redirect_encoded&response_type=code&scope=openid%20profile%20email&state=$confidential_state&nonce=$confidential_nonce&code_challenge=$pkce_challenge&code_challenge_method=S256")
assert_status "$direct_confidential_status" 302 "Confidential Grant reuse authorization"
direct_confidential_callback=$(header_value Location "$direct_confidential_headers")
direct_confidential_code=$(query_value code "$direct_confidential_callback")
record_sensitive "$direct_confidential_code" "direct Confidential Authorization Code"
direct_confidential_form=$temporary/direct-confidential-token-form
printf 'grant_type=authorization_code&code=%s&redirect_uri=%s&code_verifier=%s' \
  "$direct_confidential_code" "$confidential_redirect_encoded" "$pkce_verifier" >"$direct_confidential_form"
chmod 600 "$direct_confidential_form"
wrong_basic=$(printf '%s:%s' "$confidential_protocol_client_id" invalid-client-secret | base64 | tr -d '\n')
correct_basic=$(printf '%s:%s' "$confidential_protocol_client_id" "$rotated_client_secret" | base64 | tr -d '\n')
record_sensitive "$correct_basic" "Confidential Basic credential"
wrong_basic_header=$temporary/wrong-basic-header
correct_basic_header=$temporary/correct-basic-header
printf 'Authorization: Basic %s\n' "$wrong_basic" >"$wrong_basic_header"
printf 'Authorization: Basic %s\n' "$correct_basic" >"$correct_basic_header"
chmod 600 "$wrong_basic_header" "$correct_basic_header"
wrong_secret_headers=$temporary/wrong-secret-headers
wrong_secret_body=$temporary/wrong-secret-body
wrong_secret_status=$(curl_request -X POST -H @"$wrong_basic_header" -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-binary @"$direct_confidential_form" -D "$wrong_secret_headers" -o "$wrong_secret_body" \
  -w '%{http_code}' "$base_url/oauth2/token")
assert_status "$wrong_secret_status" 401 "Confidential wrong Secret"
assert_equal "$(header_value WWW-Authenticate "$wrong_secret_headers")" Basic "Confidential invalid_client challenge"
assert_file_contains "$wrong_secret_body" '"error":"invalid_client"' "Confidential wrong-Secret response"
assert_file_excludes "$wrong_secret_body" "$direct_confidential_code" "Confidential wrong-Secret response"

confidential_token_headers=$temporary/confidential-token-headers
confidential_token_body=$temporary/confidential-token-body
confidential_token_status=$(curl_request -X POST -H @"$correct_basic_header" -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-binary @"$direct_confidential_form" -D "$confidential_token_headers" -o "$confidential_token_body" \
  -w '%{http_code}' "$base_url/oauth2/token")
assert_status "$confidential_token_status" 200 "Confidential Code exchange after wrong Secret"
assert_file_excludes "$confidential_token_body" 'refresh_token' "Confidential Token response"
confidential_access_token=$(json_string access_token "$confidential_token_body")
confidential_id_token=$(json_string id_token "$confidential_token_body")
record_sensitive "$confidential_access_token" "Confidential Access Token"
record_sensitive "$confidential_id_token" "Confidential ID Token"
confidential_bearer_header=$temporary/confidential-bearer-header
printf 'Authorization: Bearer %s\n' "$confidential_access_token" >"$confidential_bearer_header"
chmod 600 "$confidential_bearer_header"
confidential_userinfo_body=$temporary/confidential-userinfo-body
confidential_userinfo_status=$(curl_request -H @"$confidential_bearer_header" -o "$confidential_userinfo_body" \
  -w '%{http_code}' "$base_url/oauth2/userinfo")
assert_status "$confidential_userinfo_status" 200 "Confidential Access Token UserInfo"
confidential_replay_body=$temporary/confidential-replay-body
confidential_replay_status=$(curl_request -X POST -H @"$correct_basic_header" -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-binary @"$direct_confidential_form" -o "$confidential_replay_body" -w '%{http_code}' "$base_url/oauth2/token")
assert_status "$confidential_replay_status" 400 "Confidential Code replay"
assert_file_contains "$confidential_replay_body" '"error":"invalid_grant"' "Confidential replay response"

# Confidential Client B must receive the same explicit offline_access Consent
# and rotating family semantics. Its owning Basic credential is required for
# Refresh and Introspection; the public Client cannot use this boundary.
b_offline_state="b-offline-state-${nonce}"
record_sensitive "$b_offline_state" "Confidential offline state"
b_offline_headers=$temporary/b-offline-authorize-headers
b_offline_body=$temporary/b-offline-authorize-body
b_offline_status=$(curl_request -b "$oidc_jar" -c "$oidc_jar" -D "$b_offline_headers" -o "$b_offline_body" -w '%{http_code}' \
  "$base_url/oauth2/authorize?client_id=$confidential_protocol_client_id&redirect_uri=$confidential_redirect_encoded&response_type=code&scope=openid%20offline_access&state=$b_offline_state&prompt=consent&code_challenge=$pkce_challenge&code_challenge_method=S256")
assert_status "$b_offline_status" 303 "Confidential offline Consent redirect"
b_offline_consent_location=$(header_value Location "$b_offline_headers")
assert_prefix "$b_offline_consent_location" "/consent?transaction=" "Confidential offline Consent page"
b_offline_consent_page=$temporary/b-offline-consent-page
b_offline_consent_status=$(curl_request -b "$oidc_jar" -c "$oidc_jar" -o "$b_offline_consent_page" -w '%{http_code}' \
  "$(absolute_url "$base_url" "$b_offline_consent_location")")
assert_status "$b_offline_consent_status" 200 "Confidential offline Consent page"
assert_file_contains "$b_offline_consent_page" 'Offline access' "Confidential offline Consent disclosure"
b_offline_csrf=$(hidden_value csrf_token "$b_offline_consent_page")
b_offline_transaction=$(hidden_value transaction "$b_offline_consent_page")
record_sensitive "$b_offline_csrf" "Confidential offline Consent CSRF"
record_sensitive "$b_offline_transaction" "Confidential offline Consent transaction"
b_offline_consent_form=$temporary/b-offline-consent-form
printf 'csrf_token=%s&transaction=%s&decision=approve' "$b_offline_csrf" "$b_offline_transaction" >"$b_offline_consent_form"
chmod 600 "$b_offline_consent_form"
b_offline_consent_headers=$temporary/b-offline-consent-headers
b_offline_consent_body=$temporary/b-offline-consent-body
b_offline_consent_post_status=$(curl_request -b "$oidc_jar" -c "$oidc_jar" -D "$b_offline_consent_headers" -o "$b_offline_consent_body" \
  -w '%{http_code}' -H "Origin: $base_url" -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-binary @"$b_offline_consent_form" "$base_url/consent")
assert_status "$b_offline_consent_post_status" 302 "Confidential offline Consent approval"
b_offline_callback=$(header_value Location "$b_offline_consent_headers")
assert_prefix "$b_offline_callback" "$client_b_url/callback?code=" "Confidential offline callback"
b_offline_code=$(query_value code "$b_offline_callback")
record_sensitive "$b_offline_code" "Confidential offline Authorization Code"
b_offline_token_form=$temporary/b-offline-token-form
printf 'grant_type=authorization_code&code=%s&redirect_uri=%s&code_verifier=%s' \
  "$b_offline_code" "$confidential_redirect_encoded" "$pkce_verifier" >"$b_offline_token_form"
chmod 600 "$b_offline_token_form"
b_offline_token_body=$temporary/b-offline-token-body
b_offline_token_status=$(curl_request -X POST -H @"$correct_basic_header" -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-binary @"$b_offline_token_form" -o "$b_offline_token_body" -w '%{http_code}' "$base_url/oauth2/token")
assert_status "$b_offline_token_status" 200 "Confidential offline initial token response"
assert_file_contains "$b_offline_token_body" '"refresh_token":"r1_' "Confidential offline initial Refresh Token"
b_offline_access_token=$(json_string access_token "$b_offline_token_body")
b_offline_refresh_token=$(json_string refresh_token "$b_offline_token_body")
record_sensitive "$b_offline_access_token" "Confidential offline Access Token"
record_sensitive "$b_offline_refresh_token" "Confidential offline Refresh Token"
b_refresh_form=$temporary/b-refresh-form
printf 'grant_type=refresh_token&refresh_token=%s' "$b_offline_refresh_token" >"$b_refresh_form"
chmod 600 "$b_refresh_form"
b_refresh_body=$temporary/b-refresh-body
b_refresh_status=$(curl_request -X POST -H @"$correct_basic_header" -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-binary @"$b_refresh_form" -o "$b_refresh_body" -w '%{http_code}' "$base_url/oauth2/token")
assert_status "$b_refresh_status" 200 "Confidential Refresh rotation"
b_replacement_refresh_token=$(json_string refresh_token "$b_refresh_body")
b_replacement_access_token=$(json_string access_token "$b_refresh_body")
record_sensitive "$b_replacement_refresh_token" "Confidential replacement Refresh Token"
record_sensitive "$b_replacement_access_token" "Confidential replacement Access Token"
# Introspection is owner-bound and returns a minimal active snapshot. A Public
# Client is rejected before token lookup, while B cannot probe A's token.
b_introspect_form=$temporary/b-introspect-form
printf 'token=%s' "$b_replacement_access_token" >"$b_introspect_form"
chmod 600 "$b_introspect_form"
b_introspect_body=$temporary/b-introspect-body
b_introspect_status=$(curl_request -X POST -H @"$correct_basic_header" -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-binary @"$b_introspect_form" -o "$b_introspect_body" -w '%{http_code}' "$base_url/oauth2/introspect")
assert_status "$b_introspect_status" 200 "owning Confidential Introspection"
assert_file_contains "$b_introspect_body" '"active":true' "owning Confidential Introspection"
public_introspect_form=$temporary/public-introspect-form
printf 'token=%s&client_id=%s' "$b_offline_access_token" "$public_protocol_client_id" >"$public_introspect_form"
chmod 600 "$public_introspect_form"
public_introspect_body=$temporary/public-introspect-body
public_introspect_status=$(curl_request -X POST -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-binary @"$public_introspect_form" -o "$public_introspect_body" -w '%{http_code}' "$base_url/oauth2/introspect")
assert_status "$public_introspect_status" 401 "Public Introspection rejection"
assert_file_contains "$public_introspect_body" '"error":"invalid_client"' "Public Introspection rejection"
cross_introspect_form=$temporary/cross-introspect-form
printf 'token=%s' "$public_access_token" >"$cross_introspect_form"
chmod 600 "$cross_introspect_form"
cross_introspect_body=$temporary/cross-introspect-body
cross_introspect_status=$(curl_request -X POST -H @"$correct_basic_header" -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-binary @"$cross_introspect_form" -o "$cross_introspect_body" -w '%{http_code}' "$base_url/oauth2/introspect")
assert_status "$cross_introspect_status" 200 "cross-Client Introspection response"
assert_file_contains "$cross_introspect_body" '"active":false' "cross-Client Introspection response"

wrong_owner_refresh_form=$temporary/wrong-owner-refresh-form
printf 'grant_type=refresh_token&refresh_token=%s&client_id=%s' "$b_replacement_refresh_token" "$public_protocol_client_id" >"$wrong_owner_refresh_form"
chmod 600 "$wrong_owner_refresh_form"
wrong_owner_refresh_body=$temporary/wrong-owner-refresh-body
wrong_owner_refresh_status=$(curl_request -X POST -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-binary @"$wrong_owner_refresh_form" -o "$wrong_owner_refresh_body" -w '%{http_code}' "$base_url/oauth2/token")
assert_status "$wrong_owner_refresh_status" 400 "wrong-owner Refresh"
assert_file_contains "$wrong_owner_refresh_body" '"error":"invalid_grant"' "wrong-owner Refresh"

# Reusing the consumed first generation revokes the entire B family, including
# the replacement Access/Refresh metadata just introspected above.
b_refresh_replay_body=$temporary/b-refresh-replay-body
b_refresh_replay_status=$(curl_request -X POST -H @"$correct_basic_header" -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-binary @"$b_refresh_form" -o "$b_refresh_replay_body" -w '%{http_code}' "$base_url/oauth2/token")
assert_status "$b_refresh_replay_status" 400 "Confidential consumed Refresh replay"
assert_file_contains "$b_refresh_replay_body" '"error":"invalid_grant"' "Confidential consumed Refresh replay"

b_replay_introspect_form=$temporary/b-replay-introspect-form
printf 'token=%s&token_type_hint=access_token' "$b_replacement_access_token" >"$b_replay_introspect_form"
chmod 600 "$b_replay_introspect_form"
b_replay_introspect_body=$temporary/b-replay-introspect-body
b_replay_introspect_status=$(curl_request -X POST -H @"$correct_basic_header" -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-binary @"$b_replay_introspect_form" -o "$b_replay_introspect_body" -w '%{http_code}' "$base_url/oauth2/introspect")
assert_status "$b_replay_introspect_status" 200 "replayed-family Access Introspection"
assert_equal "$(cat "$b_replay_introspect_body")" '{"active":false}' "replayed-family Access Introspection body"

# RFC 7009 revocation is uniform and cascades through the owning metadata.
unknown_revoke_form=$temporary/unknown-revoke-form
printf 'token=opaque-unknown&token_type_hint=refresh_token' >"$unknown_revoke_form"
chmod 600 "$unknown_revoke_form"
unknown_revoke_body=$temporary/unknown-revoke-body
unknown_revoke_status=$(curl_request -X POST -H @"$correct_basic_header" -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-binary @"$unknown_revoke_form" -o "$unknown_revoke_body" -w '%{http_code}' "$base_url/oauth2/revoke")
assert_status "$unknown_revoke_status" 200 "unknown Refresh revocation"
assert_equal "$(wc -c <"$unknown_revoke_body" | tr -d '[:space:]')" 0 "unknown Refresh revocation body length"
revoke_b_form=$temporary/revoke-b-form
printf 'token=%s&token_type_hint=access_token' "$b_replacement_access_token" >"$revoke_b_form"
chmod 600 "$revoke_b_form"
revoke_b_body=$temporary/revoke-b-body
revoke_b_status=$(curl_request -X POST -H @"$correct_basic_header" -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-binary @"$revoke_b_form" -o "$revoke_b_body" -w '%{http_code}' "$base_url/oauth2/revoke")
assert_status "$revoke_b_status" 200 "Confidential Access revocation"
b_replacement_bearer_header=$temporary/b-replacement-bearer-header
printf 'Authorization: Bearer %s\n' "$b_replacement_access_token" >"$b_replacement_bearer_header"
chmod 600 "$b_replacement_bearer_header"
b_revoked_userinfo_body=$temporary/b-revoked-userinfo-body
b_revoked_userinfo_status=$(curl_request -H @"$b_replacement_bearer_header" -o "$b_revoked_userinfo_body" -w '%{http_code}' "$base_url/oauth2/userinfo")
assert_status "$b_revoked_userinfo_status" 401 "revoked Confidential Access UserInfo"
b_revoked_refresh_form=$temporary/b-revoked-refresh-form
printf 'grant_type=refresh_token&refresh_token=%s' "$b_replacement_refresh_token" >"$b_revoked_refresh_form"
chmod 600 "$b_revoked_refresh_form"
b_revoked_refresh_body=$temporary/b-revoked-refresh-body
b_revoked_refresh_status=$(curl_request -X POST -H @"$correct_basic_header" -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-binary @"$b_revoked_refresh_form" -o "$b_revoked_refresh_body" -w '%{http_code}' "$base_url/oauth2/token")
assert_status "$b_revoked_refresh_status" 400 "revoked Confidential Refresh family"
assert_file_contains "$b_revoked_refresh_body" '"error":"invalid_grant"' "revoked Confidential Refresh family"

# A fresh Public Code is raced through two independent HTTP requests. Exactly
# one response commits JWT metadata; the loser is a generic invalid_grant.
concurrent_state="concurrent-state-${nonce}"
record_sensitive "$concurrent_state" "concurrent exchange state"
concurrent_authorize_headers=$temporary/concurrent-authorize-headers
concurrent_authorize_body=$temporary/concurrent-authorize-body
concurrent_authorize_status=$(curl_request -b "$oidc_jar" -c "$oidc_jar" -D "$concurrent_authorize_headers" \
  -o "$concurrent_authorize_body" -w '%{http_code}' \
  "$base_url/oauth2/authorize?client_id=$public_protocol_client_id&redirect_uri=$public_redirect_encoded&response_type=code&scope=openid%20profile%20email&state=$concurrent_state&code_challenge=$pkce_challenge&code_challenge_method=S256")
assert_status "$concurrent_authorize_status" 302 "concurrent exchange authorization"
concurrent_callback=$(header_value Location "$concurrent_authorize_headers")
concurrent_code=$(query_value code "$concurrent_callback")
record_sensitive "$concurrent_code" "concurrent Authorization Code"
concurrent_form=$temporary/concurrent-token-form
printf 'grant_type=authorization_code&code=%s&redirect_uri=%s&client_id=%s&code_verifier=%s' \
  "$concurrent_code" "$public_redirect_encoded" "$public_protocol_client_id" "$pkce_verifier" >"$concurrent_form"
chmod 600 "$concurrent_form"
concurrent_body_one=$temporary/concurrent-token-body-one
concurrent_body_two=$temporary/concurrent-token-body-two
concurrent_status_one=$temporary/concurrent-token-status-one
concurrent_status_two=$temporary/concurrent-token-status-two
(curl_request -X POST -H 'Content-Type: application/x-www-form-urlencoded' --data-binary @"$concurrent_form" \
  -o "$concurrent_body_one" -w '%{http_code}' "$base_url/oauth2/token" >"$concurrent_status_one") &
concurrent_pid_one=$!
(curl_request -X POST -H 'Content-Type: application/x-www-form-urlencoded' --data-binary @"$concurrent_form" \
  -o "$concurrent_body_two" -w '%{http_code}' "$base_url/oauth2/token" >"$concurrent_status_two") &
concurrent_pid_two=$!
wait "$concurrent_pid_one"
wait "$concurrent_pid_two"
concurrent_one=$(cat "$concurrent_status_one")
concurrent_two=$(cat "$concurrent_status_two")
if [ "$concurrent_one" = 200 ] && [ "$concurrent_two" = 400 ]; then
  concurrent_success_body=$concurrent_body_one
  concurrent_failure_body=$concurrent_body_two
elif [ "$concurrent_one" = 400 ] && [ "$concurrent_two" = 200 ]; then
  concurrent_success_body=$concurrent_body_two
  concurrent_failure_body=$concurrent_body_one
else
  fail "concurrent Code exchange statuses were $concurrent_one/$concurrent_two; expected one 200 and one 400"
fi
assert_file_contains "$concurrent_failure_body" '"error":"invalid_grant"' "concurrent exchange loser"
concurrent_access_token=$(json_string access_token "$concurrent_success_body")
concurrent_id_token=$(json_string id_token "$concurrent_success_body")
record_sensitive "$concurrent_access_token" "concurrent Access Token"
record_sensitive "$concurrent_id_token" "concurrent ID Token"
concurrent_bearer_header=$temporary/concurrent-bearer-header
printf 'Authorization: Bearer %s\n' "$concurrent_access_token" >"$concurrent_bearer_header"
chmod 600 "$concurrent_bearer_header"
concurrent_userinfo_body=$temporary/concurrent-userinfo-body
concurrent_userinfo_status=$(curl_request -H @"$concurrent_bearer_header" -o "$concurrent_userinfo_body" \
  -w '%{http_code}' "$base_url/oauth2/userinfo")
assert_status "$concurrent_userinfo_status" 200 "concurrent exchange winner UserInfo"

# Verify the HTTP winner corresponds to exactly one committed Access metadata
# row. Only a SHA-256 digest reaches the 0600 SQL input; the clear Code remains
# out of psql argv, Compose logs, and test reports.
concurrent_code_hash=$(printf 'oneissuer:authorization-code:v1:%s' "$concurrent_code" | sha256sum | awk '{print $1}')
if [ "${#concurrent_code_hash}" -ne 64 ]; then
  fail "could not derive the concurrent Code digest"
fi
case "$concurrent_code_hash" in
  *[!0-9a-f]*) fail "could not derive the concurrent Code digest" ;;
esac
concurrent_metadata_query=$temporary/concurrent-metadata-query.sql
printf "SELECT count(*) FROM access_tokens WHERE authorization_code_id=(SELECT id FROM authorization_codes WHERE code_hash=decode('%s','hex'));\n" \
  "$concurrent_code_hash" >"$concurrent_metadata_query"
chmod 600 "$concurrent_metadata_query"
concurrent_metadata_rows=$(compose exec -T postgres sh -c \
  'psql --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" --no-align --tuples-only --quiet' \
  <"$concurrent_metadata_query" | tr -d '[:space:]')
assert_equal "$concurrent_metadata_rows" 1 "concurrent exchange committed Access metadata rows"

# The example RP rejects a callback whose state does not match its server-side
# pending attempt. Feed the callback URL through a protected curl config so the
# unconsumed Code never appears in process arguments.
state_check_headers=$temporary/state-check-begin-headers
state_check_body=$temporary/state-check-begin-body
state_check_begin_status=$(curl_request -b "$oidc_jar" -c "$oidc_jar" -D "$state_check_headers" -o "$state_check_body" \
  -w '%{http_code}' "$client_a_url/login")
assert_status "$state_check_begin_status" 302 "Client A state-check begin"
state_check_authorize=$(header_value Location "$state_check_headers")
state_check_original=$(query_value state "$state_check_authorize")
record_sensitive "$state_check_original" "Client A state-check original state"
state_check_authorize_headers=$temporary/state-check-authorize-headers
state_check_authorize_body=$temporary/state-check-authorize-body
state_check_authorize_status=$(curl_request -b "$oidc_jar" -c "$oidc_jar" -D "$state_check_authorize_headers" \
  -o "$state_check_authorize_body" -w '%{http_code}' "$state_check_authorize")
assert_status "$state_check_authorize_status" 302 "Client A state-check authorization"
state_check_callback=$(header_value Location "$state_check_authorize_headers")
state_check_code=$(query_value code "$state_check_callback")
record_sensitive "$state_check_code" "state-check Authorization Code"
tampered_state="tampered-state-${nonce}"
record_sensitive "$tampered_state" "Client A tampered callback state"
state_check_tampered=$(printf '%s\n' "$state_check_callback" | sed 's/\([?&]state=\)[^&]*/\1'"$tampered_state"'/')
state_check_config=$temporary/state-check-callback-curl
write_curl_url_config "$state_check_tampered" "$state_check_config"
state_check_callback_body=$temporary/state-check-callback-body
state_check_callback_status=$(curl_request -b "$oidc_jar" -c "$oidc_jar" -o "$state_check_callback_body" \
  -w '%{http_code}' --config "$state_check_config")
assert_status "$state_check_callback_status" 400 "Client A mismatched state callback"
assert_file_excludes "$state_check_callback_body" "$state_check_code" "Client A mismatched-state error"

# Current Client and User status is authoritative for both Code exchange and
# UserInfo. Administrative disablement fails closed; re-enabling does not consume
# a Code that was rejected while authority was disabled.
disabled_client_exchange_state="disabled-client-exchange-state-${nonce}"
record_sensitive "$disabled_client_exchange_state" "disabled-Client exchange state"
disabled_client_exchange_headers=$temporary/disabled-client-exchange-authorize-headers
disabled_client_exchange_body=$temporary/disabled-client-exchange-authorize-body
disabled_client_exchange_authorize_status=$(curl_request -b "$oidc_jar" -c "$oidc_jar" \
  -D "$disabled_client_exchange_headers" -o "$disabled_client_exchange_body" -w '%{http_code}' \
  "$base_url/oauth2/authorize?client_id=$confidential_protocol_client_id&redirect_uri=$confidential_redirect_encoded&response_type=code&scope=openid&state=$disabled_client_exchange_state&code_challenge=$pkce_challenge&code_challenge_method=S256")
assert_status "$disabled_client_exchange_authorize_status" 302 "pre-disable Client exchange authorization"
disabled_client_exchange_callback=$(header_value Location "$disabled_client_exchange_headers")
assert_prefix "$disabled_client_exchange_callback" "$client_b_url/callback?code=" "pre-disable Client exchange callback"
disabled_client_exchange_code=$(query_value code "$disabled_client_exchange_callback")
[ -n "$disabled_client_exchange_code" ] || fail "pre-disable Client authorization omitted Code"
record_sensitive "$disabled_client_exchange_code" "pre-disable Client Authorization Code"
disabled_client_exchange_form=$temporary/disabled-client-exchange-form
printf 'grant_type=authorization_code&code=%s&redirect_uri=%s&code_verifier=%s' \
  "$disabled_client_exchange_code" "$confidential_redirect_encoded" "$pkce_verifier" >"$disabled_client_exchange_form"
chmod 600 "$disabled_client_exchange_form"

client_disable_payload=$temporary/client-disable-payload
client_enable_payload=$temporary/client-enable-payload
printf '%s' '{"status":"disabled"}' >"$client_disable_payload"
printf '%s' '{"status":"active"}' >"$client_enable_payload"
client_disable_body=$temporary/client-disable-body
client_disable_status=$(curl_request -X PATCH -b "$admin_jar" -c "$admin_jar" -H @"$admin_csrf_header" \
  -H 'Content-Type: application/json' --data-binary @"$client_disable_payload" -o "$client_disable_body" \
  -w '%{http_code}' "$base_url/api/admin/v1/clients/$confidential_client_id")
assert_status "$client_disable_status" 200 "disable Confidential Client"
disabled_client_userinfo_headers=$temporary/disabled-client-userinfo-headers
disabled_client_userinfo_body=$temporary/disabled-client-userinfo-body
disabled_client_userinfo_status=$(curl_request -H @"$confidential_bearer_header" -D "$disabled_client_userinfo_headers" \
  -o "$disabled_client_userinfo_body" -w '%{http_code}' "$base_url/oauth2/userinfo")
assert_status "$disabled_client_userinfo_status" 401 "disabled Client UserInfo"
assert_equal "$(header_value WWW-Authenticate "$disabled_client_userinfo_headers")" Bearer "disabled Client Bearer challenge"
disabled_client_authorize_headers=$temporary/disabled-client-authorize-headers
disabled_client_authorize_body=$temporary/disabled-client-authorize-body
disabled_client_authorize_status=$(curl_request -b "$oidc_jar" -c "$oidc_jar" -D "$disabled_client_authorize_headers" \
  -o "$disabled_client_authorize_body" -w '%{http_code}' \
  "$base_url/oauth2/authorize?client_id=$confidential_protocol_client_id&redirect_uri=$confidential_redirect_encoded&response_type=code&scope=openid&state=disabled-client-state&code_challenge=$pkce_challenge&code_challenge_method=S256")
assert_status "$disabled_client_authorize_status" 400 "disabled Client authorization"
assert_equal "$(header_value Location "$disabled_client_authorize_headers")" "" "disabled Client local error"
disabled_client_exchange_headers_result=$temporary/disabled-client-exchange-headers
disabled_client_exchange_failure_body=$temporary/disabled-client-exchange-failure-body
disabled_client_exchange_status=$(curl_request -X POST -H @"$correct_basic_header" \
  -H 'Content-Type: application/x-www-form-urlencoded' --data-binary @"$disabled_client_exchange_form" \
  -D "$disabled_client_exchange_headers_result" -o "$disabled_client_exchange_failure_body" \
  -w '%{http_code}' "$base_url/oauth2/token")
assert_status "$disabled_client_exchange_status" 401 "disabled Client Code exchange"
assert_equal "$(header_value WWW-Authenticate "$disabled_client_exchange_headers_result")" Basic "disabled Client invalid_client challenge"
assert_file_contains "$disabled_client_exchange_failure_body" '"error":"invalid_client"' "disabled Client exchange response"
assert_file_excludes "$disabled_client_exchange_failure_body" "$disabled_client_exchange_code" "disabled Client exchange response"
assert_file_excludes "$disabled_client_exchange_failure_body" 'access_token' "disabled Client exchange response"
client_enable_body=$temporary/client-enable-body
client_enable_status=$(curl_request -X PATCH -b "$admin_jar" -c "$admin_jar" -H @"$admin_csrf_header" \
  -H 'Content-Type: application/json' --data-binary @"$client_enable_payload" -o "$client_enable_body" \
  -w '%{http_code}' "$base_url/api/admin/v1/clients/$confidential_client_id")
assert_status "$client_enable_status" 200 "re-enable Confidential Client"
reenabled_client_userinfo_body=$temporary/reenabled-client-userinfo-body
reenabled_client_userinfo_status=$(curl_request -H @"$confidential_bearer_header" -o "$reenabled_client_userinfo_body" \
  -w '%{http_code}' "$base_url/oauth2/userinfo")
assert_status "$reenabled_client_userinfo_status" 401 "re-enabled Client old Access remains revoked"
reenabled_client_token_body=$temporary/reenabled-client-token-body
reenabled_client_token_status=$(curl_request -X POST -H @"$correct_basic_header" \
  -H 'Content-Type: application/x-www-form-urlencoded' --data-binary @"$disabled_client_exchange_form" \
  -o "$reenabled_client_token_body" -w '%{http_code}' "$base_url/oauth2/token")
assert_status "$reenabled_client_token_status" 200 "re-enabled Client Code exchange"
reenabled_client_access_token=$(json_string access_token "$reenabled_client_token_body")
reenabled_client_id_token=$(json_string id_token "$reenabled_client_token_body")
[ -n "$reenabled_client_access_token" ] || fail "re-enabled Client exchange omitted Access Token"
[ -n "$reenabled_client_id_token" ] || fail "re-enabled Client exchange omitted ID Token"
record_sensitive "$reenabled_client_access_token" "re-enabled Client Access Token"
record_sensitive "$reenabled_client_id_token" "re-enabled Client ID Token"

oidc_me_headers=$temporary/oidc-user-me-headers
oidc_me_body=$temporary/oidc-user-me-body
oidc_me_status=$(curl_request -b "$oidc_jar" -c "$oidc_jar" -D "$oidc_me_headers" -o "$oidc_me_body" \
  -w '%{http_code}' "$base_url/api/v1/me")
assert_status "$oidc_me_status" 200 "OIDC user current identity"
oidc_user_id=$(json_string id "$oidc_me_body")
[ -n "$oidc_user_id" ] || fail "OIDC current-user response omitted id"

disabled_user_state="disabled-user-state-${nonce}"
record_sensitive "$disabled_user_state" "disabled-user authorization state"
disabled_user_authorize_headers=$temporary/disabled-user-authorize-headers
disabled_user_authorize_body=$temporary/disabled-user-authorize-body
disabled_user_authorize_status=$(curl_request -b "$oidc_jar" -c "$oidc_jar" -D "$disabled_user_authorize_headers" \
  -o "$disabled_user_authorize_body" -w '%{http_code}' \
  "$base_url/oauth2/authorize?client_id=$public_protocol_client_id&redirect_uri=$public_redirect_encoded&response_type=code&scope=openid%20profile%20email&state=$disabled_user_state&code_challenge=$pkce_challenge&code_challenge_method=S256")
assert_status "$disabled_user_authorize_status" 302 "pre-disable User authorization"
disabled_user_code=$(query_value code "$(header_value Location "$disabled_user_authorize_headers")")
record_sensitive "$disabled_user_code" "pre-disable User Authorization Code"
disabled_user_form=$temporary/disabled-user-token-form
printf 'grant_type=authorization_code&code=%s&redirect_uri=%s&client_id=%s&code_verifier=%s' \
  "$disabled_user_code" "$public_redirect_encoded" "$public_protocol_client_id" "$pkce_verifier" >"$disabled_user_form"
chmod 600 "$disabled_user_form"

user_disable_payload=$temporary/user-disable-payload
user_enable_payload=$temporary/user-enable-payload
printf '%s' '{"status":"disabled"}' >"$user_disable_payload"
printf '%s' '{"status":"active"}' >"$user_enable_payload"
user_disable_body=$temporary/user-disable-body
user_disable_status=$(curl_request -X PATCH -b "$admin_jar" -c "$admin_jar" -H @"$admin_csrf_header" \
  -H 'Content-Type: application/json' --data-binary @"$user_disable_payload" -o "$user_disable_body" \
  -w '%{http_code}' "$base_url/api/admin/v1/users/$oidc_user_id")
assert_status "$user_disable_status" 200 "disable OIDC User"
disabled_user_new_state="disabled-user-new-state-${nonce}"
record_sensitive "$disabled_user_new_state" "disabled User new-authorization state"
disabled_user_new_headers=$temporary/disabled-user-new-authorize-headers
disabled_user_new_body=$temporary/disabled-user-new-authorize-body
disabled_user_new_status=$(curl_request -b "$oidc_jar" -c "$oidc_jar" -D "$disabled_user_new_headers" \
  -o "$disabled_user_new_body" -w '%{http_code}' \
  "$base_url/oauth2/authorize?client_id=$public_protocol_client_id&redirect_uri=$public_redirect_encoded&response_type=code&scope=openid&state=$disabled_user_new_state&code_challenge=$pkce_challenge&code_challenge_method=S256")
assert_status "$disabled_user_new_status" 303 "disabled User new authorization"
assert_prefix "$(header_value Location "$disabled_user_new_headers")" "/login?transaction=" "disabled User login continuation"
assert_file_excludes "$disabled_user_new_headers" 'code=' "disabled User new authorization"
assert_file_excludes "$disabled_user_new_headers" "$client_a_url/callback" "disabled User new authorization"
disabled_user_userinfo_headers=$temporary/disabled-user-userinfo-headers
disabled_user_userinfo_body=$temporary/disabled-user-userinfo-body
disabled_user_userinfo_status=$(curl_request -H @"$public_bearer_header" -D "$disabled_user_userinfo_headers" \
  -o "$disabled_user_userinfo_body" -w '%{http_code}' "$base_url/oauth2/userinfo")
assert_status "$disabled_user_userinfo_status" 401 "disabled User UserInfo"
disabled_user_token_body=$temporary/disabled-user-token-body
disabled_user_token_status=$(curl_request -X POST -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-binary @"$disabled_user_form" -o "$disabled_user_token_body" -w '%{http_code}' "$base_url/oauth2/token")
assert_status "$disabled_user_token_status" 400 "disabled User Code exchange"
assert_file_contains "$disabled_user_token_body" '"error":"invalid_grant"' "disabled User exchange response"

user_enable_body=$temporary/user-enable-body
user_enable_status=$(curl_request -X PATCH -b "$admin_jar" -c "$admin_jar" -H @"$admin_csrf_header" \
  -H 'Content-Type: application/json' --data-binary @"$user_enable_payload" -o "$user_enable_body" \
  -w '%{http_code}' "$base_url/api/admin/v1/users/$oidc_user_id")
assert_status "$user_enable_status" 200 "re-enable OIDC User"
reenabled_user_userinfo_body=$temporary/reenabled-user-userinfo-body
reenabled_user_userinfo_status=$(curl_request -H @"$public_bearer_header" -o "$reenabled_user_userinfo_body" \
  -w '%{http_code}' "$base_url/oauth2/userinfo")
assert_status "$reenabled_user_userinfo_status" 401 "revoked pre-disable User UserInfo"
reenabled_user_token_body=$temporary/reenabled-user-token-body
reenabled_user_token_status=$(curl_request -X POST -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-binary @"$disabled_user_form" -o "$reenabled_user_token_body" -w '%{http_code}' "$base_url/oauth2/token")
assert_status "$reenabled_user_token_status" 200 "re-enabled User Code exchange"
reenabled_user_access_token=$(json_string access_token "$reenabled_user_token_body")
reenabled_user_id_token=$(json_string id_token "$reenabled_user_token_body")
record_sensitive "$reenabled_user_access_token" "re-enabled User Access Token"
record_sensitive "$reenabled_user_id_token" "re-enabled User ID Token"
reenabled_user_bearer_header=$temporary/reenabled-user-bearer-header
printf 'Authorization: Bearer %s\n' "$reenabled_user_access_token" >"$reenabled_user_bearer_header"
chmod 600 "$reenabled_user_bearer_header"

# Disabling the User revoked its browser Session. Sign in again so post-restart
# Grant reuse proves persisted Consent independently of stale browser authority.
oidc_relogin_headers=$temporary/oidc-relogin-get-headers
oidc_relogin_page=$temporary/oidc-relogin-page
begin_auth /login "$oidc_jar" "$oidc_relogin_headers" "$oidc_relogin_page"
oidc_relogin_csrf=$auth_csrf
oidc_relogin_transaction=$auth_transaction
oidc_relogin_form=$temporary/oidc-relogin-form
printf 'csrf_token=%s&transaction=%s&identifier=%s&password=%s' \
  "$oidc_relogin_csrf" "$oidc_relogin_transaction" "$oidc_username" "$oidc_password" >"$oidc_relogin_form"
chmod 600 "$oidc_relogin_form"
oidc_relogin_post_headers=$temporary/oidc-relogin-post-headers
oidc_relogin_post_body=$temporary/oidc-relogin-post-body
oidc_relogin_status=$(curl_request -b "$oidc_jar" -c "$oidc_jar" -D "$oidc_relogin_post_headers" \
  -o "$oidc_relogin_post_body" -w '%{http_code}' -H "Origin: $base_url" \
  -H 'Content-Type: application/x-www-form-urlencoded' --data-binary @"$oidc_relogin_form" "$base_url/login")
assert_status "$oidc_relogin_status" 303 "OIDC User re-login after enable"
assert_equal "$(header_value Location "$oidc_relogin_post_headers")" /auth/complete "OIDC User re-login completion"
oidc_relogin_session=$(cookie_value "$session_cookie_name" "$oidc_jar")
record_sensitive "$oidc_relogin_session" "OIDC re-login Session"

pre_restart_jwks_headers=$temporary/pre-restart-jwks-headers
pre_restart_jwks_body=$temporary/pre-restart-jwks-body
pre_restart_jwks_status=$(curl_request -D "$pre_restart_jwks_headers" -o "$pre_restart_jwks_body" \
  -w '%{http_code}' "$base_url/oauth2/jwks")
assert_status "$pre_restart_jwks_status" 200 "pre-restart JWKS"
pre_restart_jwks_etag=$(header_value ETag "$pre_restart_jwks_headers")
[ -n "$pre_restart_jwks_etag" ] || fail "pre-restart JWKS omitted ETag"
protocol_metrics=$temporary/protocol-metrics
curl_request --fail "$base_url/metrics" >"$protocol_metrics"
for marker in \
  'oneissuer_oidc_authorization_total{operation="issue",result="success"}' \
  'oneissuer_oidc_token_operations_total{operation="exchange",result="success"}' \
  'oneissuer_oidc_token_operations_total{operation="userinfo",result="success"}'; do
  assert_file_contains "$protocol_metrics" "$marker" "phase-three protocol metrics"
done

# Restart only the application process. PostgreSQL and its volume remain in
# place. User/admin authority, Client records, audit history, and revoked Session
# state must all be resolved from persisted database state afterwards.
compose restart oneissuer >/dev/null
wait_status "$base_url/health/live" 200
wait_status "$base_url/health/ready" 200 90

post_restart_jwks_headers=$temporary/post-restart-jwks-headers
post_restart_jwks_body=$temporary/post-restart-jwks-body
post_restart_jwks_status=$(curl_request -D "$post_restart_jwks_headers" -o "$post_restart_jwks_body" \
  -w '%{http_code}' "$base_url/oauth2/jwks")
assert_status "$post_restart_jwks_status" 200 "post-restart JWKS"
assert_equal "$(header_value ETag "$post_restart_jwks_headers")" "$pre_restart_jwks_etag" "stable signing Key/JWKS across restart"
if ! cmp -s "$pre_restart_jwks_body" "$post_restart_jwks_body"; then
  fail "public JWKS changed across an application restart"
fi

post_restart_userinfo_body=$temporary/post-restart-userinfo-body
post_restart_userinfo_status=$(curl_request -H @"$reenabled_user_bearer_header" -o "$post_restart_userinfo_body" \
  -w '%{http_code}' "$base_url/oauth2/userinfo")
assert_status "$post_restart_userinfo_status" 200 "Access metadata after application restart"
post_restart_replay_body=$temporary/post-restart-replay-body
post_restart_replay_status=$(curl_request -X POST -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-binary @"$disabled_user_form" -o "$post_restart_replay_body" -w '%{http_code}' "$base_url/oauth2/token")
assert_status "$post_restart_replay_status" 400 "consumed Code after application restart"
assert_file_contains "$post_restart_replay_body" '"error":"invalid_grant"' "post-restart Code replay"

post_restart_state="post-restart-state-${nonce}"
record_sensitive "$post_restart_state" "post-restart Grant-reuse state"
post_restart_authorize_headers=$temporary/post-restart-authorize-headers
post_restart_authorize_body=$temporary/post-restart-authorize-body
post_restart_authorize_status=$(curl_request -b "$oidc_jar" -c "$oidc_jar" -D "$post_restart_authorize_headers" \
  -o "$post_restart_authorize_body" -w '%{http_code}' \
  "$base_url/oauth2/authorize?client_id=$public_protocol_client_id&redirect_uri=$public_redirect_encoded&response_type=code&scope=openid%20profile%20email&state=$post_restart_state&code_challenge=$pkce_challenge&code_challenge_method=S256")
assert_status "$post_restart_authorize_status" 302 "post-restart persisted Grant reuse"
post_restart_callback=$(header_value Location "$post_restart_authorize_headers")
assert_prefix "$post_restart_callback" "$client_a_url/callback?code=" "post-restart Grant callback"
post_restart_code=$(query_value code "$post_restart_callback")
record_sensitive "$post_restart_code" "post-restart Authorization Code"
post_restart_form=$temporary/post-restart-token-form
printf 'grant_type=authorization_code&code=%s&redirect_uri=%s&client_id=%s&code_verifier=%s' \
  "$post_restart_code" "$public_redirect_encoded" "$public_protocol_client_id" "$pkce_verifier" >"$post_restart_form"
chmod 600 "$post_restart_form"
post_restart_token_body=$temporary/post-restart-token-body
post_restart_token_status=$(curl_request -X POST -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-binary @"$post_restart_form" -o "$post_restart_token_body" -w '%{http_code}' "$base_url/oauth2/token")
assert_status "$post_restart_token_status" 200 "post-restart Code exchange"
post_restart_access_token=$(json_string access_token "$post_restart_token_body")
post_restart_id_token=$(json_string id_token "$post_restart_token_body")
record_sensitive "$post_restart_access_token" "post-restart Access Token"
record_sensitive "$post_restart_id_token" "post-restart ID Token"

persisted_user_headers=$temporary/persisted-user-headers
persisted_user_body=$temporary/persisted-user-body
persisted_user_status=$(curl_request -b "$user_jar" -c "$user_jar" -D "$persisted_user_headers" \
  -o "$persisted_user_body" -w '%{http_code}' "$base_url/api/v1/me")
assert_status "$persisted_user_status" 200 "user Session after application restart"
assert_equal "$(json_string id "$persisted_user_body")" "$user_id" "persisted user id"
assert_equal "$(json_string session_id "$persisted_user_body")" "$rotated_session_id" "persisted current Session id"
user_csrf=$(header_value X-CSRF-Token "$persisted_user_headers")
record_sensitive "$user_csrf" "post-restart user CSRF token"

post_restart_revoked_body=$temporary/post-restart-revoked-body
post_restart_revoked_status=$(curl_request -b "$second_user_jar" -c "$second_user_jar" \
  -o "$post_restart_revoked_body" -w '%{http_code}' "$base_url/api/v1/me")
assert_status "$post_restart_revoked_status" 401 "revoked Session after application restart"
post_restart_old_body=$temporary/post-restart-old-body
post_restart_old_status=$(curl_request -b "$old_user_jar" -c "$old_user_jar" \
  -o "$post_restart_old_body" -w '%{http_code}' "$base_url/api/v1/me")
assert_status "$post_restart_old_status" 401 "rotated Session after application restart"

persisted_admin_headers=$temporary/persisted-admin-headers
persisted_admin_body=$temporary/persisted-admin-body
persisted_admin_status=$(curl_request -b "$admin_jar" -c "$admin_jar" -D "$persisted_admin_headers" \
  -o "$persisted_admin_body" -w '%{http_code}' "$base_url/api/admin/v1/me")
assert_status "$persisted_admin_status" 200 "administrator Session after application restart"
admin_csrf=$(header_value X-CSRF-Token "$persisted_admin_headers")
record_sensitive "$admin_csrf" "post-restart administrator CSRF token"
write_csrf_header "$admin_csrf" "$admin_csrf_header"

public_read_after_restart=$temporary/public-read-after-restart
public_read_status=$(curl_request -b "$admin_jar" -c "$admin_jar" -o "$public_read_after_restart" \
  -w '%{http_code}' "$base_url/api/admin/v1/clients/$public_client_id")
assert_status "$public_read_status" 200 "Public Client after application restart"
assert_file_contains "$public_read_after_restart" 'Compose Smoke Public' "persisted Public Client"
confidential_read_after_restart=$temporary/confidential-read-after-restart
confidential_read_status=$(curl_request -b "$admin_jar" -c "$admin_jar" -o "$confidential_read_after_restart" \
  -w '%{http_code}' "$base_url/api/admin/v1/clients/$confidential_client_id")
assert_status "$confidential_read_status" 200 "Confidential Client after application restart"
assert_file_contains "$confidential_read_after_restart" 'Compose Smoke Confidential' "persisted Confidential Client"
assert_file_excludes "$confidential_read_after_restart" '"client_secret":' "post-restart Client read model"
assert_file_excludes "$confidential_read_after_restart" '"secret_hash":' "post-restart Client read model"

audit_after_restart=$temporary/audit-after-restart
audit_headers=$temporary/audit-after-restart-headers
audit_status=$(curl_request -b "$admin_jar" -c "$admin_jar" -D "$audit_headers" -o "$audit_after_restart" \
  -w '%{http_code}' "$base_url/api/admin/v1/audit-events?limit=100")
assert_status "$audit_status" 200 "audit list after application restart"
for event_type in \
  admin_bootstrap_succeeded \
  admin_bootstrap_rejected \
  user_registered \
  login_succeeded \
  session_revoked \
  client_created \
  client_secret_rotated \
  authorization_granted \
  authorization_code_issued \
  authorization_code_exchange_succeeded \
  authorization_code_exchange_rejected \
  consent_grant_created \
  access_token_issued \
  signing_key_loaded; do
  event_audit=$temporary/audit-after-restart-$event_type
  event_audit_status=$(curl_request -b "$admin_jar" -c "$admin_jar" -o "$event_audit" \
    -w '%{http_code}' "$base_url/api/admin/v1/audit-events?limit=1&event_type=$event_type")
  assert_status "$event_audit_status" 200 "persisted $event_type audit query"
  assert_file_contains "$event_audit" "$event_type" "persisted $event_type audit query"
  printf '\n' >>"$audit_after_restart"
  cat "$event_audit" >>"$audit_after_restart"
done

# Owner-bound Grant API: the OIDC user can list the public Client projections and
# revoke A's Grant, while a different User cannot select it. Revocation must
# immediately invalidate the already-issued Public Access metadata.
oidc_me_headers=$temporary/oidc-me-headers
oidc_me_body=$temporary/oidc-me-body
oidc_me_status=$(curl_request -b "$oidc_jar" -c "$oidc_jar" -D "$oidc_me_headers" -o "$oidc_me_body" \
  -w '%{http_code}' "$base_url/api/v1/me")
assert_status "$oidc_me_status" 200 "OIDC user identity before Grant API"
oidc_api_csrf=$(header_value X-CSRF-Token "$oidc_me_headers")
record_sensitive "$oidc_api_csrf" "OIDC Grant API CSRF token"
oidc_api_csrf_header=$temporary/oidc-api-csrf-header
write_csrf_header "$oidc_api_csrf" "$oidc_api_csrf_header"
oidc_grants_body=$temporary/oidc-grants-body
oidc_grants_status=$(curl_request -b "$oidc_jar" -c "$oidc_jar" -H @"$oidc_api_csrf_header" \
  -o "$oidc_grants_body" -w '%{http_code}' "$base_url/api/v1/me/grants")
assert_status "$oidc_grants_status" 200 "owner Grant list"
assert_file_contains "$oidc_grants_body" "$public_protocol_client_id" "owner Grant list Public Client"
assert_file_contains "$oidc_grants_body" "$confidential_protocol_client_id" "owner Grant list Confidential Client"
grant_revoke_payload=$temporary/grant-revoke-payload
printf '{"client_id":"%s"}' "$public_protocol_client_id" >"$grant_revoke_payload"
chmod 600 "$grant_revoke_payload"
grant_revoke_body=$temporary/grant-revoke-body
grant_revoke_status=$(curl_request -X POST -b "$oidc_jar" -c "$oidc_jar" -H @"$oidc_api_csrf_header" \
  -H 'Content-Type: application/json' --data-binary @"$grant_revoke_payload" \
  -o "$grant_revoke_body" -w '%{http_code}' "$base_url/api/v1/me/grants/revoke")
assert_status "$grant_revoke_status" 200 "owner Public Grant revoke"
assert_file_contains "$grant_revoke_body" '"revoked_at"' "owner Public Grant revoke response"
public_after_grant_revoke_body=$temporary/public-after-grant-revoke-body
public_after_grant_revoke_status=$(curl_request -H @"$public_bearer_header" -o "$public_after_grant_revoke_body" \
  -w '%{http_code}' "$base_url/oauth2/userinfo")
assert_status "$public_after_grant_revoke_status" 401 "Access after Grant revoke"

wrong_owner_grant_body=$temporary/wrong-owner-grant-body
wrong_owner_grant_status=$(curl_request -X POST -b "$user_jar" -c "$user_jar" -H "X-CSRF-Token: $user_csrf" \
  -H 'Content-Type: application/json' --data-binary @"$grant_revoke_payload" \
  -o "$wrong_owner_grant_body" -w '%{http_code}' "$base_url/api/v1/me/grants/revoke")
if [ "$wrong_owner_grant_status" = 200 ]; then
  fail "a different User could revoke the OIDC user's Grant"
fi
assert_file_excludes "$wrong_owner_grant_body" "$public_protocol_client_id" "wrong-owner Grant response"

# RP-Initiated Logout is a form POST. The example keeps the ID Token Hint and
# state out of its URL, and only destroys its local Session after OneIssuer
# confirms the exact state on the registered post-logout URI.
rp_logout_home=$temporary/client-a-logout-home
rp_logout_home_status=$(curl_request -b "$oidc_jar" -c "$oidc_jar" -o "$rp_logout_home" -w '%{http_code}' "$client_a_url/")
assert_status "$rp_logout_home_status" 200 "Client A logout home"
rp_logout_home_csrf=$(hidden_value csrf_token "$rp_logout_home")
record_sensitive "$rp_logout_home_csrf" "Client A logout CSRF"
rp_logout_home_exposure=$temporary/client-a-logout-home-exposure
prepare_exposure_copy "$rp_logout_home" "$rp_logout_home_exposure" "$rp_logout_home_csrf" \
  "Client A logout home" /refresh /logout
rp_logout_mutation_form=$temporary/client-a-logout-form
printf 'csrf_token=%s' "$rp_logout_home_csrf" >"$rp_logout_mutation_form"
chmod 600 "$rp_logout_mutation_form"
rp_logout_form_body=$temporary/rp-logout-form-body
rp_logout_form_headers=$temporary/rp-logout-form-headers
rp_logout_form_status=$(curl_request -X POST -b "$oidc_jar" -c "$oidc_jar" -D "$rp_logout_form_headers" \
  -H "Origin: $client_a_url" -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-binary @"$rp_logout_mutation_form" -o "$rp_logout_form_body" -w '%{http_code}' "$client_a_url/logout")
assert_status "$rp_logout_form_status" 200 "Client A RP logout form"
rp_logout_action=$(sed -n 's/.*<form method="post" action="\([^"]*\)".*/\1/p' "$rp_logout_form_body" | head -n 1)
assert_equal "$rp_logout_action" "$base_url/oauth2/logout" "Client A RP logout endpoint"
rp_logout_hint=$(hidden_value id_token_hint "$rp_logout_form_body")
rp_logout_state=$(hidden_value state "$rp_logout_form_body")
record_sensitive "$rp_logout_hint" "Client A logout ID Token Hint"
record_sensitive "$rp_logout_state" "Client A logout State"
rp_logout_provider_form=$temporary/rp-logout-provider-form
printf 'client_id=%s&id_token_hint=%s&post_logout_redirect_uri=http%%3A%%2F%%2Flocalhost%%3A%s%%2Flogged-out&state=%s' \
  "$public_protocol_client_id" "$rp_logout_hint" "$client_a_port" "$rp_logout_state" >"$rp_logout_provider_form"
chmod 600 "$rp_logout_provider_form"
rp_logout_start_headers=$temporary/rp-logout-start-headers
rp_logout_start_body=$temporary/rp-logout-start-body
rp_logout_start_status=$(curl_request -X POST -b "$oidc_jar" -c "$oidc_jar" -D "$rp_logout_start_headers" \
  -H 'Content-Type: application/x-www-form-urlencoded' --data-binary @"$rp_logout_provider_form" \
  -o "$rp_logout_start_body" -w '%{http_code}' "$base_url/oauth2/logout")
assert_status "$rp_logout_start_status" 303 "RP logout provider POST"
assert_equal "$(header_value Location "$rp_logout_start_headers")" /oauth2/logout/confirm "RP logout confirmation redirect"
rp_logout_cookie=$(cookie_value "${session_cookie_name}_logout_transaction" "$oidc_jar")
record_sensitive "$rp_logout_cookie" "RP logout transaction cookie"
rp_logout_confirm_body=$temporary/rp-logout-confirm-body
rp_logout_confirm_status=$(curl_request -b "$oidc_jar" -c "$oidc_jar" -o "$rp_logout_confirm_body" -w '%{http_code}' \
  "$base_url/oauth2/logout/confirm")
assert_status "$rp_logout_confirm_status" 200 "RP logout confirmation page"
rp_logout_csrf=$(hidden_value csrf_token "$rp_logout_confirm_body")
record_sensitive "$rp_logout_csrf" "RP logout confirmation CSRF"
rp_logout_confirm_form=$temporary/rp-logout-confirm-form
printf 'csrf_token=%s&decision=confirm' "$rp_logout_csrf" >"$rp_logout_confirm_form"
chmod 600 "$rp_logout_confirm_form"
rp_logout_complete_headers=$temporary/rp-logout-complete-headers
rp_logout_complete_body=$temporary/rp-logout-complete-body
rp_logout_complete_status=$(curl_request -X POST -b "$oidc_jar" -c "$oidc_jar" -D "$rp_logout_complete_headers" \
  -H "Origin: $base_url" -H 'Content-Type: application/x-www-form-urlencoded' --data-binary @"$rp_logout_confirm_form" \
  -o "$rp_logout_complete_body" -w '%{http_code}' "$base_url/oauth2/logout/confirm")
assert_status "$rp_logout_complete_status" 303 "RP logout confirmation commit"
rp_logout_callback=$(header_value Location "$rp_logout_complete_headers")
assert_prefix "$rp_logout_callback" "$client_a_url/logged-out?state=" "RP logout registered callback"
rp_logout_wrong_callback_config=$temporary/rp-logout-wrong-callback-curl
write_curl_url_config "$client_a_url/logged-out?state=logout_wrong_${nonce}" "$rp_logout_wrong_callback_config"
rp_logout_wrong_callback_status=$(curl_request -b "$oidc_jar" -c "$oidc_jar" -o "$rp_logout_complete_body" \
  -w '%{http_code}' --config "$rp_logout_wrong_callback_config")
assert_status "$rp_logout_wrong_callback_status" 400 "RP logout wrong-state callback"
rp_logout_callback_config=$temporary/rp-logout-callback-curl
write_curl_url_config "$rp_logout_callback" "$rp_logout_callback_config"
rp_logout_callback_headers=$temporary/rp-logout-callback-headers
rp_logout_callback_body=$temporary/rp-logout-callback-body
rp_logout_callback_status=$(curl_request -b "$oidc_jar" -c "$oidc_jar" -D "$rp_logout_callback_headers" \
  -o "$rp_logout_callback_body" -w '%{http_code}' --config "$rp_logout_callback_config")
assert_status "$rp_logout_callback_status" 303 "Client A RP logout callback"
assert_equal "$(header_value Location "$rp_logout_callback_headers")" / "Client A RP logout clean redirect"
rp_logout_replay_status=$(curl_request -b "$oidc_jar" -c "$oidc_jar" -o "$rp_logout_callback_body" \
  -w '%{http_code}' --config "$rp_logout_callback_config")
assert_status "$rp_logout_replay_status" 400 "RP logout callback replay"
rp_logout_home_body=$temporary/client-a-logged-out-home
rp_logout_home_status=$(curl_request -b "$oidc_jar" -c "$oidc_jar" -o "$rp_logout_home_body" -w '%{http_code}' "$client_a_url/")
assert_status "$rp_logout_home_status" 200 "Client A post-logout home"
assert_file_excludes "$rp_logout_home_body" 'Signed in as' "Client A post-logout Session"

# Exercise the hosted logout form after persistence checks, then verify the
# current Session is unusable and the revocation audit is still queryable.
logout_form=$temporary/logout-form
printf 'csrf_token=%s' "$user_csrf" >"$logout_form"
chmod 600 "$logout_form"
logout_headers=$temporary/logout-headers
logout_body=$temporary/logout-body
logout_status=$(curl_request -b "$user_jar" -c "$user_jar" -D "$logout_headers" -o "$logout_body" \
  -w '%{http_code}' -H "Origin: $base_url" -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-binary @"$logout_form" "$base_url/logout")
assert_status "$logout_status" 303 "POST /logout"
assert_equal "$(header_value Location "$logout_headers")" /login "logout redirect"
logged_out_body=$temporary/logged-out-me-body
logged_out_status=$(curl_request -b "$user_jar" -c "$user_jar" -o "$logged_out_body" \
  -w '%{http_code}' "$base_url/api/v1/me")
assert_status "$logged_out_status" 401 "logged-out user Session"

final_audit=$temporary/final-audit
final_audit_status=$(curl_request -b "$admin_jar" -c "$admin_jar" -o "$final_audit" \
  -w '%{http_code}' "$base_url/api/admin/v1/audit-events?limit=100")
assert_status "$final_audit_status" 200 "final audit list"
assert_file_contains "$final_audit" session_revoked "logout audit event"

# Preserve the phase-one database-outage/recovery behavior after phase-two state
# has been exercised.
compose stop postgres >/dev/null
wait_status "$base_url/health/live" 200
wait_status "$base_url/health/ready" 503
compose start postgres >/dev/null
wait_status "$base_url/health/ready" 200 90

recovered_admin_body=$temporary/recovered-admin-body
recovered_admin_status=$(curl_request -b "$admin_jar" -c "$admin_jar" -o "$recovered_admin_body" \
  -w '%{http_code}' "$base_url/api/admin/v1/me")
assert_status "$recovered_admin_status" 200 "administrator Session after database recovery"

# Let OneIssuer own graceful shutdown and verify Docker observed a clean exit.
compose stop -t 20 oneissuer >/dev/null
oneissuer_id=$(compose ps -aq oneissuer)
[ -n "$oneissuer_id" ] || fail "stopped application container was not retained"
assert_equal "$(docker inspect "$oneissuer_id" --format '{{.State.ExitCode}}')" 0 "graceful shutdown exit code"

# Scan every maintained output surface that should be credential-free. The two
# one-time Secret response bodies and the hosted forms are deliberately omitted;
# their values are instead added as exact forbidden needles for logs, audit, and
# all subsequent read responses.
application_logs=$temporary/application-logs
compose_logs=$temporary/compose-logs
compose --profile oidc-demo logs --no-color oneissuer >"$application_logs"
compose --profile oidc-demo logs --no-color >"$compose_logs"
assert_file_contains "$application_logs" '"timestamp"' "application logs"
assert_file_contains "$application_logs" '"request_id"' "application logs"
assert_file_contains "$application_logs" '"duration_ms"' "application logs"

set -- \
  "$compose_logs" \
  "$bootstrap_output" \
  "$bootstrap_rejected_output" \
  "$repeat_migration_output" \
  "$user_me_body" \
  "$rotated_me_body" \
  "$sessions_body" \
  "$admin_me_body" \
  "$client_read_before_restart" \
  "$persisted_user_body" \
  "$persisted_admin_body" \
  "$public_read_after_restart" \
  "$confidential_read_after_restart" \
  "$a_home_exposure" \
  "$a_refresh_body" \
  "$a_refreshed_home_exposure" \
  "$b_home" \
  "$a_replay_body" \
  "$direct_public_wrong_body" \
  "$direct_public_replay_body" \
  "$replay_refresh_body" \
  "$missing_verifier_body" \
  "$expired_code_body" \
  "$none_grant_body" \
  "$forced_consent_deny_body" \
  "$active_create_body" \
  "$bad_redirect_body" \
  "$wrong_secret_body" \
  "$confidential_replay_body" \
  "$b_introspect_body" \
  "$b_replay_introspect_body" \
  "$public_introspect_body" \
  "$cross_introspect_body" \
  "$wrong_owner_refresh_body" \
  "$unknown_revoke_body" \
  "$revoke_b_body" \
  "$b_revoked_userinfo_body" \
  "$b_revoked_refresh_body" \
  "$public_after_grant_revoke_body" \
  "$oidc_grants_body" \
  "$grant_revoke_body" \
  "$rp_logout_home_exposure" \
  "$wrong_owner_grant_body" \
  "$rp_logout_start_body" \
  "$rp_logout_complete_body" \
  "$rp_logout_callback_body" \
  "$rp_logout_home_body" \
  "$concurrent_failure_body" \
  "$concurrent_userinfo_body" \
  "$state_check_callback_body" \
  "$disabled_client_userinfo_body" \
  "$disabled_client_authorize_body" \
  "$disabled_client_exchange_failure_body" \
  "$disabled_user_new_body" \
  "$disabled_user_userinfo_body" \
  "$disabled_user_token_body" \
  "$public_userinfo_body" \
  "$confidential_userinfo_body" \
  "$reenabled_client_userinfo_body" \
  "$reenabled_user_userinfo_body" \
  "$post_restart_userinfo_body" \
  "$post_restart_replay_body" \
  "$protocol_metrics" \
  "$pre_restart_jwks_body" \
  "$post_restart_jwks_body" \
  "$audit_after_restart" \
  "$final_audit" \
  "$recovered_admin_body"
: >"$exposure_surface"
for exposure_file do
  cat "$exposure_file" >>"$exposure_surface"
  printf '\n' >>"$exposure_surface"
done

# Include the known Compose database credential when it came from the process
# environment (or the documented local default). Custom .env-only values remain
# covered by the generic URL/key redaction tests in the Go suite.
database_password=${POSTGRES_PASSWORD:-oneissuer-local-only}
record_sensitive "$database_password" "Compose database password"

# Keep the Bootstrap password out of both argv and files even for this scan: the
# fixed-string pattern reaches grep only over stdin.
if printf '%s\n' "$bootstrap_password" | grep -Fq -f - "$exposure_surface"; then
  fail "logs, audit, or a credential-free response exposed the Bootstrap password"
fi
if grep -Fq -f "$sensitive_values" "$exposure_surface"; then
  for exposure_file do
    exposure_label=$(basename "$exposure_file")
    sensitive_index=0
    while IFS= read -r sensitive_value; do
      sensitive_index=$((sensitive_index + 1))
      if printf '%s\n' "$sensitive_value" | grep -Fq -f - "$exposure_file"; then
        sensitive_label=$(sed -n "${sensitive_index}p" "$sensitive_labels")
        [ -n "$sensitive_label" ] || sensitive_label='unknown sensitive value'
        fail "$exposure_label exposed known sensitive value ($sensitive_label)"
      else
        sensitive_match_status=$?
        [ "$sensitive_match_status" -eq 1 ] ||
          fail "$exposure_label could not be scanned for known sensitive values"
      fi
    done <"$sensitive_values"
  done
  fail "logs, audit, or a credential-free response exposed a known clear sensitive value"
else
  sensitive_scan_status=$?
  [ "$sensitive_scan_status" -eq 1 ] ||
    fail "logs, audit, or a credential-free response could not be scanned"
fi
for exposure_file do
  exposure_label=$(basename "$exposure_file")
  if grep -Eq '(s1_|p1_|c1_|r1_|t1_)[A-Za-z0-9_-]{20,}|ois_sec_v1_[A-Za-z0-9_-]{20,}|\$argon2id\$' "$exposure_file"; then
    fail "$exposure_label exposed token/Secret/hash-shaped material"
  fi
  if grep -Eq '"(password|password_hash|token_hash|csrf_hash|secret_hash)"[[:space:]]*:' "$exposure_file"; then
    fail "$exposure_label exposed a forbidden sensitive field"
  fi
done

printf '%s\n' 'phase-four compose smoke: PASS (empty volume, schema 15 migration/Bootstrap regression, Public+Confidential offline Consent and Refresh rotation/replay, Revocation and owner-bound Introspection, Grant cascade, RP-Initiated Logout state/CSRF, S256 prompt/Consent semantics, strict callbacks, Token/UserInfo expiry and concurrency, disabled/restart authority, privacy, outage recovery, and graceful shutdown)'
