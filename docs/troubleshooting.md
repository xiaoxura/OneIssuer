# Troubleshooting

Start with the exact release binary/image and a redacted configuration check:

```bash
set -a
. ./.env
set +a
oneissuer version
oneissuer config check
```

Do not paste raw environment output, request URLs, authorization headers,
cookies, form bodies, private JWKs, Client Secrets, Codes, or Tokens into logs or
issues.

## `ONEISSUER_DATABASE_URL: is required`

The process does not load `.env` automatically. Source it explicitly only in a
trusted local shell, or inject variables through the deployment platform. Never
pass the database URL as a command argument; shell history and process listings
can expose it.

## Production database URL must use `sslmode=verify-full`

Every configuration scope parses `ONEISSUER_ENV`. With
`ONEISSUER_ENV=production`, `serve`, `config check`, `admin bootstrap`, and all
`migrate` commands reject a missing, duplicated, or weaker `sslmode` value. Use
exactly one `sslmode=verify-full` query parameter plus the CA/client-certificate
parameters required by your PostgreSQL deployment. Do not work around the check
with `require`, `verify-ca`, URL duplication, or a separate insecure migration
DSN.

Compose intentionally defaults to local `sslmode=disable`. For a reviewed TLS
deployment, set `ONEISSUER_COMPOSE_DATABASE_URL` to the complete container-
reachable URL; both `migrate` and `oneissuer` receive it. The native
`ONEISSUER_DATABASE_URL` in `.env.example` points at host `localhost` and is not
automatically suitable from inside a container.

## `ONEISSUER_SIGNING_KEY_FILE: is required`

`serve` and `config check` require an active private RS256 JWK. Migration and
Bootstrap commands deliberately do not. For a new local native environment:

```bash
mkdir -p .oneissuer-dev
oneissuer keys generate \
  --alg RS256 --out .oneissuer-dev/signing-key.jwk
chmod 0600 .oneissuer-dev/signing-key.jwk
export ONEISSUER_SIGNING_KEY_FILE=.oneissuer-dev/signing-key.jwk
```

Do not reuse that local key in production or commit it.

## Signing key store startup check fails

The loader intentionally returns a generic error without echoing private
material. Check, without printing the file:

- the configured path exists and is a normal file, not a directory or symlink;
- the active file has no group/world mode bits (normally `0600`);
- the service UID can read it;
- it contains one RSA private JWK with `alg=RS256`, `use=sig`, at least 2048 bits,
  and an RFC 7638 thumbprint `kid`;
- the optional verification file contains a non-empty public-only JWKS;
- no `kid` is duplicated between active and verification keys;
- the file was not truncated, rewritten in place, or replaced during startup.

Use `oneissuer keys public` into a new controlled destination to validate/export
public material. Do not run `jq`, `cat`, debug tracing, or support collection on
the private file. Follow [key-rotation-runbook.md](./key-rotation-runbook.md).

### Compose reports permission denied or invalid key material

The final container runs as UID/GID `65532`, and the private-key loader refuses a
world/group-readable workaround. On Linux, preserve `0600` while transferring
ownership to the runtime identity, as the smoke test does:

```bash
docker run --rm --user 0:0 --entrypoint /bin/sh \
  --mount "type=bind,source=$PWD/.oneissuer-dev/signing-key.jwk,target=/run/oneissuer-secret" \
  alpine:3.23.5@sha256:fd791d74b68913cbb027c6546007b3f0d3bc45125f797758156952bc2d6daf40 \
  -c 'chown 65532:65532 /run/oneissuer-secret && chmod 0600 /run/oneissuer-secret'
```

Verify only metadata (`stat`), not content. A platform-managed secret volume may
have a different ownership mechanism; it still must result in a readable regular
file with no group/world bits. Never change it to `0644`.

## Startup fails recording `signing_key_loaded`

OneIssuer records a fixed startup Audit event after key, database, and migration
checks and before listening. An Audit constraint/write failure is intentionally
fatal. Verify schema version 15 and PostgreSQL health; do not bypass the Audit
write or manually loosen its whitelist.

## Migration metadata, version, or checksum failure

Run the explicit release step using the same binary/image intended for startup:

```bash
oneissuer migrate up
oneissuer migrate status
oneissuer migrate version
oneissuer serve
```

Expected hardened `v0.1.0-dev.4` schema version is **15**. In Compose:

```bash
docker compose -f deploy/docker-compose.yml logs migrate
```

A checksum mismatch means a released migration was edited. Restore the approved
file; never bless an unexplained modification. Versions 00001–00005 are frozen.
Schema fixes add a new migration. If the database is newer than the binary,
deploy a compatible binary or restore a tested backup rather than running
production Down migrations.

After upgrading from version 5, old in-flight authorization transactions are
made terminal by design because they lack the stricter phase-three context. Start
a new authorization request; do not attempt to revive them.

## Discovery returns 404

Discovery is gated until Authorize, Token, UserInfo, and JWKS dependencies are all
assembled. In a normal `serve` process, a 404 indicates the wrong binary/router
or incomplete embedding rather than a feature flag. Check:

```bash
oneissuer version
curl -i "$ONEISSUER_ISSUER/.well-known/openid-configuration"
curl -i "$ONEISSUER_ISSUER/oauth2/jwks"
```

The configured Issuer must be a canonical origin without a trailing slash. Do
not substitute an internal service address or derive the request from an
untrusted `Host` header.

## Discovery Issuer or endpoint mismatch

Every advertised endpoint and every Token `iss` derives from
`ONEISSUER_ISSUER`. A mismatch normally means the RP is configured with another
origin, TLS termination is exposing the wrong URL, or the Issuer changed between
deployments. Correct the deployment/RP configuration; do not rewrite Discovery
at the proxy or disable Issuer validation.

Changing the Issuer creates a new protocol security domain. Existing RP caches
and Tokens are not migrated automatically.

## JWKS is unavailable, stale, or returns 304

- `304 Not Modified` is expected when `If-None-Match` matches the current ETag;
- Discovery and JWKS use `Cache-Control: public, max-age=300`;
- JWKS contains public RSA members only and should include the active `kid` plus
  any intentionally overlapped old/new public keys;
- an empty/invalid in-process public set fails closed rather than returning an
  empty success document.

During planned rotation, prepublish and retain overlap for the durations in the
key runbook. Do not remove the old public key immediately after switching the
active signer. During emergency removal, downstream verifiers may continue using
a cached old JWKS for approximately five minutes.

## Authorization request shows a local error instead of redirecting

This is expected when OneIssuer cannot first trust both the Client and exact
Redirect URI. Unknown/disabled Client IDs, missing/mismatched Redirect URIs, or
malformed initial input must not cause an external redirect.

After Client and Redirect URI are trusted, later protocol errors can return to
that exact URI with `error` and the original `state`. Check the registered string
byte-for-byte, including scheme, host, port, path, case-sensitive path, and query.
Fragments and wildcards are not allowed. Do not add a permissive prefix match.

## Authorization returns `invalid_request`

Common causes:

- a required parameter is missing or a security parameter is repeated;
- `response_type` is not exactly `code`;
- `response_mode` is present and not `query`;
- `scope` omits `openid`, requests `offline_access` without explicit Consent, or
  exceeds the registered `openid profile email offline_access` subset;
- `code_challenge_method` is absent or not exactly `S256`;
- the challenge is not a 43-character unpadded base64url SHA-256 output;
- state/nonce exceeds 1024 bytes;
- prompt values conflict (`none` with another value, or `create` with `login`);
- `max_age` is malformed or greater than 30 days;
- unsupported request-object parameters are present.

Do not work around this by omitting PKCE for a Confidential Client. Mandatory
S256 applies to every Client.

## `prompt=none` returns an interaction error

`prompt=none` never displays login, registration, or Consent. Depending on the
missing condition it returns `login_required`, `consent_required`, or
`interaction_required` to the verified Redirect URI. Establish a current Session
and covering Grant through an interactive authorization, then issue a new silent
request.

`max_age=0` requires immediate reauthentication. A stale Session plus
`prompt=none` returns `login_required`; clock skew does not extend Session age.

## `prompt=create` does not open registration

Both global `ONEISSUER_REGISTRATION_ENABLED=true` and the Client's
`registration_enabled` policy must allow it. An already authenticated browser
gets `interaction_required` rather than implicit account switching. Log out
explicitly and start a new request.

Browser registration receives only an opaque server transaction. It cannot
supply a replacement Client ID, Redirect URI, Scope, state, nonce, or PKCE value.
An expired/consumed transaction requires a new authorization request.

## Consent repeats or a previously granted Scope no longer works

Consent is stored once per `(User, Client)` and reused only when the requested
Scope is covered by both the current Grant and current Client policy.
`prompt=consent` deliberately forces the page again. Adding Scope expands the
Grant after approval; shrinking the Client's allowed Scope immediately limits
what can be issued without rewriting the historical Grant.

Disabling the User/Client makes the Grant unusable. Current-user Grant revocation
is available at `POST /api/v1/me/grants/revoke` with a same-origin Session and
CSRF proof; it is atomic with family/Access cascade. Do not delete rows manually.

## Refresh Token rotation and reuse

Refresh values are opaque `r1_` strings and are stored only as SHA-256 digests.
Every successful `refresh_token` exchange consumes the presented generation and
returns one replacement. A second use of a consumed generation is `invalid_grant`
and revokes the whole family plus linked live Access metadata; there is no grace
retry. Clear the RP's stored family and start a new Authorization Code flow.

`POST /oauth2/revoke` returns the same empty `200` response for unknown, expired,
wrong-owner, and already-revoked authenticated values. `POST /oauth2/introspect`
is restricted to the owning Confidential Client and returns exactly
`{"active":false}` for inactive or cross-Client values.

## RP-Initiated Logout

`GET`/`POST /oauth2/logout` only creates a short-lived zero-authority transaction
and redirects to clean `/oauth2/logout/confirm`. The clean GET binds the current
Session; only the cookie-only confirm POST with transaction-bound CSRF can revoke
the Session binding. Invalid or stale hints never cause an external redirect.

## Token endpoint returns `invalid_client`

For a Public Client:

- send exactly one form `client_id`;
- send no `Authorization` header and no `client_secret` form field;
- ensure the registered method is `none`.

For a Confidential Client:

- send one RFC 6749 Basic header using the one-time current Secret;
- do not duplicate credentials in the form;
- ensure the registered method is `client_secret_basic` and Client is Active.

Malformed Basic, unknown Client, wrong/rotated Secret, wrong method, disabled
Client, and multiple authentication channels intentionally share a generic
failure. Confidential failures may include HTTP 401 and `WWW-Authenticate:
Basic`. OneIssuer does not support `client_secret_post`.

## Token endpoint returns `invalid_grant`

The response intentionally merges unknown, malformed, expired, consumed,
wrong-Client, Redirect URI mismatch, wrong verifier, stale Consent, and disabled
User/Client cases. Verify the RP retained the exact Code binding and original
PKCE verifier without logging either value.

Most importantly, Code exchange has at-most-once delivery. PostgreSQL may have
committed while the response connection failed. Retrying then returns
`invalid_grant`; the original Token Response cannot be recovered. Start a new
authorization request. Never reset database consumption state.

## Token endpoint returns `unsupported_grant_type`

The supported grants are `authorization_code` and rotating `refresh_token`.
Client Credentials, password, and device grants remain outside the profile. A
Refresh Token is returned only after explicit `offline_access` Consent and a live
Grant.

## UserInfo returns `401 invalid_token`

UserInfo requires one Bearer header containing a phase-four RS256 Access Token
and an exact committed metadata match. It checks signature, `typ=at+jwt`, `kid`,
Issuer, UserInfo Audience, Subject, Client ID, `jti` digest, Scope, time claims,
current User/Client status, current Consent/Client Scope coverage, and live Access
metadata. Revoked or family-reused values fail closed.

Likely causes are expiry, a token from another issuer/audience, malformed or
unsupported JWT, missing/revoked metadata, disabled User/Client, or changed
Scope/Grant authority. Do not accept the token in another API merely because its
signature verifies. A Confidential owning Client may use `/oauth2/introspect` for
the minimal active snapshot.

Re-enabling a User/Client does not restore a value that was explicitly revoked or
whose Refresh family was consumed. For incident containment, use the documented
Revocation, Grant, Session, and disable cascades rather than assuming external JWT
verifiers have global revocation.

## Browser login/API problems

### Bootstrap says an administrator already exists

This is intended. Bootstrap is one-time/concurrency-safe and never resets an
administrator. Sign in with the existing administrator or use a separately
reviewed recovery procedure; do not edit roles or credentials manually.

### Registration returns `registration_disabled`

Self-registration is deny-by-default. Set the global flag only after an explicit
policy decision and restart. Client-specific policy can still reject a verified
`prompt=create` transaction.

### Login always returns the same credential error

Unknown, disabled, malformed, and wrong-password identities intentionally share
`invalid_credentials` to prevent enumeration. Use administrator APIs and fixed
Audit event types—not raw login logs—to inspect a known account.

A `429 temporarily_unavailable` with `Retry-After: 60` on Authorize/login/
registration means the built-in per-IP or process-wide browser limiter rejected
the request. Wait for refill and inspect edge traffic; do not respond by making
the in-process tables unbounded. `Retry-After: 1` on a password submission means
the Argon2 concurrency gate is full. Benchmark/tune capacity and keep the
configured memory × concurrency product at or below 1048576 KiB.

Each issued login/registration form has a separate five-submission PostgreSQL
budget. After five failed/malformed submissions, the next request returns
`invalid_authentication_flow` before credential lookup/Argon2; start with a new
form. This is expected and does not indicate database corruption.

### Authenticated API returns 401 or 403

- `401 authentication_required`: cookie missing/invalid, Session expired/revoked,
  idle timeout elapsed, or User disabled;
- `403 csrf_failed`: mutation lacks matching CSRF header/cookie, it expired, or
  Origin/Referer differs from the Issuer origin;
- `403 forbidden`: active User is not an administrator;
- `403 recent_authentication_required`: sign in again before a sensitive action.

Fetch `/api/v1/me` or `/api/admin/v1/me` in the same browser context to receive a
fresh `X-CSRF-Token`, then send it on the mutation. Never store or log it.

### A Session disappeared or became unusable

Session validity is server-side. Login rotation revokes the previous browser
Session, logout revokes the current one, administrators can revoke Sessions,
role/status changes revoke affected Sessions, and absolute/idle expiry applies
before cleanup. Restart does not restore authority.

### A Client Secret was lost

Clear Confidential Secrets appear only in a successful create/rotate response
with `no-store`. They cannot be read back. Rotate through an authenticated recent
administrator Session, store the replacement in the RP's secret manager, and
update the RP. Rotation invalidates the old Secret atomically.

## PostgreSQL startup or readiness failure

Application errors are classified without host, username, SQL, or driver details.
For local Compose:

```bash
docker compose -f deploy/docker-compose.yml ps
docker compose -f deploy/docker-compose.yml logs postgres
docker compose -f deploy/docker-compose.yml exec postgres \
  pg_isready -U "$POSTGRES_USER" -d "$POSTGRES_DB"
```

Liveness remaining 200 while readiness returns 503 is expected during a database
outage. Readiness uses a separate short ping and recovers automatically. Protocol
authority operations fail closed; there is no in-memory fallback.

## Cleanup reports a deadline after deleting rows

Cleanup commits in batches of 250. A five-second operation deadline can therefore
return an error together with a positive committed-row count; this is deliberate
partial progress, and the next interval resumes from remaining rows. Inspect
`oneissuer_cleanup_operations_total`, `oneissuer_cleanup_rows_total`, and
`oneissuer_cleanup_duration_seconds`. A timeout in one cleanup class does not
reuse its canceled context for later classes. Persistent failures still require
investigating PostgreSQL locks, query plans, capacity, and retention volume.

Any increase in `oneissuer_audit_write_failures_total` is higher priority: an
Audit append failed, and atomic authority transitions roll back. Startup Audit
failure is fatal. Do not disable Audit constraints/triggers to clear the alert.

## Production configuration rejected

Production requires explicit HTTPS Issuer, PostgreSQL TLS, Secure `__Host-`
cookies, an explicit registration decision, and a valid key ring. Run `config
check` in the exact container identity and secret-mount context. Validation
reports field/reason pairs without rejected values.

## Ready never becomes healthy in Compose

```bash
docker compose -f deploy/docker-compose.yml ps
docker compose -f deploy/docker-compose.yml logs --no-log-prefix migrate oneissuer
docker inspect oneissuer-oneissuer-1 --format '{{json .State.Health}}'
```

Confirm migration exited zero, version 14 is compatible, PostgreSQL is healthy,
the key mount is readable by UID 65532 with mode `0600`, configuration passed,
and startup Audit insertion succeeded.

## Tests cannot start PostgreSQL

Integration tests use Testcontainers and need a working Docker socket. Check
`docker info` and current-user access. Phase-four acceptance requires real
PostgreSQL, concurrent lifecycle tests, Compose smoke, and the final image gate;
unit-only results are not a substitute.

## `make generate-check` reports stale code

Run `make generate`, inspect SQL/schema changes, and commit source plus generated
output. The check copies all production migrations because they are sqlc's schema
source. Tool versions are pinned; do not regenerate with `latest`.

## Container scan or SBOM gate fails

Inspect the JSON reports in `.artifacts/supply-chain/` without weakening the
threshold. Rebuild the exact final image after dependency/base updates. Private
JWK/JWKS files or secret-shaped key material in the image are release-blocking.
The scan rejects fixable High/Critical vulnerabilities; record and review any
non-fixable residual finding rather than deleting the report.

The Dockerfile frontend, Go builder, Alpine runtime, and Compose PostgreSQL image
are pinned by digest. Update each digest as an explicit reviewed change and rerun
both image builds/scans. Do not reintroduce build-time `apk upgrade`: it makes the
same source resolve to mutable package state and defeats reproducible review.

## Conformance results differ

Use the pinned suite release, source commit, container digests, non-certification
plan, static registration, and templates in the [Phase-four matrix](../conformance/phase-4/matrix.json)
and [Phase-four result](../conformance/phase-4/results/2026-08-03.json). The
Phase-three record is the historical baseline. Many upstream Code Flow
modules omit PKCE and cannot run against mandatory S256; never weaken OneIssuer
or expand Discovery to make those tests pass. Raw exports may include a runtime
Client Secret and belong only in restricted ignored `.artifacts/` storage.

Passing the applicable modules is not OpenID Foundation certification.

## Graceful shutdown exits non-zero

An active handler exceeded `ONEISSUER_SHUTDOWN_TIMEOUT`. The server became Not
Ready, stopped accepting work, and force-closed to preserve the bound. Investigate
slow handlers/dependencies rather than configuring an unbounded timeout. Set the
container stop grace period slightly above the application timeout so the process
can report its own outcome.
