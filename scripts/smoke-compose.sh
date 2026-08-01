#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$root"

compose_file=${COMPOSE_FILE:-deploy/docker-compose.yml}
http_port=${ONEISSUER_SMOKE_HTTP_PORT:-8080}
base_url=${ONEISSUER_SMOKE_URL:-http://127.0.0.1:$http_port}
session_cookie_name=${ONEISSUER_SMOKE_COOKIE_NAME:-oneissuer_smoke_session}

# Export every acceptance-specific override so values from a developer .env do
# not silently weaken or redirect the test. PostgreSQL stays on the internal
# Compose network; host port zero asks Docker to choose a collision-free port.
export ONEISSUER_HTTP_PORT=$http_port
export ONEISSUER_ISSUER=${ONEISSUER_SMOKE_ISSUER:-$base_url}
export ONEISSUER_ENV=development
export ONEISSUER_REGISTRATION_ENABLED=true
export ONEISSUER_COOKIE_NAME=$session_cookie_name
export ONEISSUER_COOKIE_SECURE=false
export ONEISSUER_VERSION=${ONEISSUER_VERSION:-v0.1.0-dev.2}
export POSTGRES_PORT=${ONEISSUER_SMOKE_POSTGRES_PORT:-0}

temporary=$(mktemp -d "${TMPDIR:-/tmp}/oneissuer-compose-smoke.XXXXXX")
chmod 700 "$temporary"
sensitive_values=$temporary/sensitive-values
exposure_surface=$temporary/exposure-surface
: >"$sensitive_values"
chmod 600 "$sensitive_values"

compose() {
  docker compose -f "$compose_file" "$@"
}

cleanup() {
  cleanup_status=$?
  trap - EXIT HUP INT TERM
  compose down -v --remove-orphans >/dev/null 2>&1 || true
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

record_sensitive() {
  sensitive_value=$1
  sensitive_label=$2
  if [ -z "$sensitive_value" ]; then
    fail "$sensitive_label was unexpectedly empty"
  fi
  printf '%s\n' "$sensitive_value" >>"$sensitive_values"
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
  oneissuer_readiness_status; do
  assert_file_contains "$metrics_file" "$family" "metrics response"
done

health_headers=$temporary/health-headers
curl_request -D "$health_headers" -o /dev/null "$base_url/health/live"
request_id=$(header_value X-Request-ID "$health_headers")
[ -n "$request_id" ] || fail "health response omitted X-Request-ID"

# Phase two must not counterfeit protocol success before the phase-three OIDC
# adapter exists. Check every planned Discovery/JWKS/Authorize/Token/UserInfo
# route (including both UserInfo methods) at the deployed HTTP boundary.
protocol_body=$temporary/unimplemented-protocol-body
for protocol_path in \
  /.well-known/openid-configuration \
  /oauth2/jwks \
  /oauth2/authorize \
  /oauth2/userinfo; do
  protocol_status=$(curl_request -o "$protocol_body" -w '%{http_code}' "$base_url$protocol_path")
  assert_status "$protocol_status" 404 "unimplemented GET $protocol_path"
done
for protocol_path in \
  /oauth2/token \
  /oauth2/userinfo \
  /oauth2/revoke \
  /oauth2/introspect; do
  protocol_status=$(curl_request -X POST -o "$protocol_body" -w '%{http_code}' "$base_url$protocol_path")
  assert_status "$protocol_status" 404 "unimplemented POST $protocol_path"
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
cat >"$public_payload" <<'EOF'
{"client_type":"public","name":"Compose Smoke Public","description":"phase-two acceptance","registration_enabled":true,"redirect_uris":["https://public.example.invalid/callback"],"logout_uris":["https://public.example.invalid/logout"],"scopes":["openid","profile"]}
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
[ -n "$public_client_id" ] || fail "Public Client response omitted id"

public_rotate_body=$temporary/public-rotate-body
public_rotate_status=$(curl_request -X POST -b "$admin_jar" -c "$admin_jar" -H @"$admin_csrf_header" \
  -o "$public_rotate_body" -w '%{http_code}' \
  "$base_url/api/admin/v1/clients/$public_client_id/secrets/rotate")
assert_status "$public_rotate_status" 422 "rotate Public Client Secret"
assert_file_contains "$public_rotate_body" invalid_input "Public Client rotation error"

confidential_payload=$temporary/confidential-client-payload
cat >"$confidential_payload" <<'EOF'
{"client_type":"confidential","name":"Compose Smoke Confidential","description":"phase-two acceptance","registration_enabled":false,"redirect_uris":["https://confidential.example.invalid/callback"],"logout_uris":["https://confidential.example.invalid/logout"],"scopes":["openid","email"]}
EOF
confidential_headers=$temporary/confidential-client-headers
confidential_body=$temporary/confidential-client-body
confidential_status=$(curl_request -X POST -b "$admin_jar" -c "$admin_jar" -H @"$admin_csrf_header" \
  -H 'Content-Type: application/json' --data-binary @"$confidential_payload" -D "$confidential_headers" \
  -o "$confidential_body" -w '%{http_code}' "$base_url/api/admin/v1/clients")
assert_status "$confidential_status" 201 "create Confidential Client"
assert_equal "$(header_value Cache-Control "$confidential_headers")" no-store "Confidential Client create cache policy"
confidential_client_id=$(json_string id "$confidential_body")
confidential_secret=$(json_string client_secret "$confidential_body")
[ -n "$confidential_client_id" ] || fail "Confidential Client response omitted id"
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

# Restart only the application process. PostgreSQL and its volume remain in
# place. User/admin authority, Client records, audit history, and revoked Session
# state must all be resolved from persisted database state afterwards.
compose restart oneissuer >/dev/null
wait_status "$base_url/health/live" 200
wait_status "$base_url/health/ready" 200 90

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
  client_secret_rotated; do
  assert_file_contains "$audit_after_restart" "$event_type" "persisted audit list"
done

# Exercise the hosted logout form after persistence checks, then verify the
# current Session is unusable and the revocation audit is still queryable.
logout_form=$temporary/logout-form
printf 'csrf_token=%s' "$user_csrf" >"$logout_form"
chmod 600 "$logout_form"
logout_headers=$temporary/logout-headers
logout_body=$temporary/logout-body
logout_status=$(curl_request -b "$user_jar" -c "$user_jar" -D "$logout_headers" -o "$logout_body" \
  -w '%{http_code}' -H 'Content-Type: application/x-www-form-urlencoded' \
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
compose logs --no-color oneissuer >"$application_logs"
compose logs --no-color >"$compose_logs"
assert_file_contains "$application_logs" '"timestamp"' "application logs"
assert_file_contains "$application_logs" '"request_id"' "application logs"
assert_file_contains "$application_logs" '"duration_ms"' "application logs"

cat \
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
  "$audit_after_restart" \
  "$final_audit" \
  "$recovered_admin_body" \
  >"$exposure_surface"

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
  fail "logs, audit, or a credential-free response exposed a known clear sensitive value"
fi
if grep -Eq '(s1_|p1_|c1_|t1_)[A-Za-z0-9_-]{20,}|ois_sec_v1_[A-Za-z0-9_-]{20,}|\$argon2id\$' "$exposure_surface"; then
  fail "logs, audit, or a credential-free response exposed token/Secret/hash-shaped material"
fi
if grep -Eq '"(password|password_hash|token_hash|csrf_hash|secret_hash)"[[:space:]]*:' "$exposure_surface"; then
  fail "logs, audit, or a credential-free response exposed a forbidden sensitive field"
fi

printf '%s\n' 'compose smoke: PASS (empty volume, repeated migration, Bootstrap, hosted auth, Session/CSRF, Client/audit persistence, absent OIDC routes, privacy, outage recovery, and graceful shutdown)'
