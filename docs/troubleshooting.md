# Troubleshooting

## `ONEISSUER_DATABASE_URL: is required`

The process does not load `.env` automatically. For local development only:

```bash
cp .env.example .env
set -a; . ./.env; set +a
oneissuer config check
```

Never place the database URL in a command argument; shell history and process
listings can expose it.

## Migration metadata, version, or checksum failure

If startup reports uninitialized or incompatible migration metadata, run the
explicit release step with the same binary/image intended for service startup:

```bash
oneissuer migrate up
oneissuer migrate status
oneissuer migrate version
oneissuer serve
```

In Compose, inspect the one-shot job:

```bash
docker compose -f deploy/docker-compose.yml logs migrate
```

A checksum mismatch means a released migration file was edited. Restore the
approved file; do not bless an unexplained change. Schema fixes require a new
migration. If the database version is newer than the binary, deploy a compatible
binary rather than running production Down migrations.

## Bootstrap says an administrator already exists

This is the intended conflict behavior. Bootstrap is a one-time, concurrency-safe
operation and never resets an existing administrator. Sign in with the existing
administrator or follow a separately reviewed recovery procedure; do not edit
role or credential rows manually.

To Bootstrap an empty local database:

```bash
oneissuer migrate status
oneissuer admin bootstrap --username admin --email admin@example.invalid
```

Input is hidden and must match. There is no `--password` option. In a non-TTY
environment use documented `--password-stdin` secret handling, which requires two
matching lines; see [operations.md](./operations.md).

## Bootstrap cannot connect in Compose

Start PostgreSQL and run migrations first, then use the `oneissuer` service image
on the Compose network:

```bash
docker compose -f deploy/docker-compose.yml up -d postgres
docker compose -f deploy/docker-compose.yml run --rm migrate
docker compose -f deploy/docker-compose.yml run --rm --no-deps oneissuer \
  admin bootstrap --username admin --email admin@example.invalid
```

Do not add a Bootstrap password to Compose environment, image layers, or command
arguments.

## Registration returns `registration_disabled`

Self-registration is deny-by-default. Set
`ONEISSUER_REGISTRATION_ENABLED=true` only after an explicit policy decision,
then restart the service. Production validation requires the variable to be
present even when the decision is `false`. Client-specific registration policy
can still deny a future verified Client transaction.

## Login always returns the same credential error

Unknown, disabled, malformed, and wrong-password identities intentionally share
the external `invalid_credentials` response to prevent account enumeration. Use
administrator APIs and fixed audit event types—not raw login logs—to confirm a
known account's status. OneIssuer never logs the submitted username/email or
password.

A `429 temporarily_unavailable` with `Retry-After` means the configured Argon2
concurrency budget is full. Do not disable the bound. Benchmark/tune Argon2 and
allocate sufficient memory; see [configuration.md](./configuration.md).

## Authenticated API returns 401 or 403

- `401 authentication_required`: cookie missing/invalid, Session expired/revoked,
  idle timeout elapsed, or user disabled;
- `403 csrf_failed`: mutation lacks a matching `X-CSRF-Token`/CSRF cookie, the
  token expired, or Origin/Referer is not the configured Issuer origin;
- `403 forbidden`: active user is not an administrator;
- `403 recent_authentication_required`: sign in again before a sensitive
  administrator action.

Fetch `/api/v1/me` or `/api/admin/v1/me` in the same browser context to obtain a
fresh `X-CSRF-Token`, then send that header on the mutation. Do not store or log
the value.

## A Session disappeared or became unusable

Session validity is server-side. Login rotation revokes the previous browser
Session, logout revokes the current Session, administrators can revoke any
Session, role/status changes revoke affected Sessions, and absolute/idle expiry
applies even before cleanup deletes rows. Restart does not restore authority.

Current users can inspect `/api/v1/me/sessions`; administrators can inspect
`/api/admin/v1/sessions`. A foreign current-user Session UUID deliberately returns
404 rather than revealing ownership.

## A Client Secret was lost

Clear confidential Secrets are shown only in the successful create or rotate
response with `Cache-Control: no-store`. GET/list responses and audit events never
contain either the clear value or digest. A lost value cannot be recovered;
perform an authenticated rotation, store the replacement in the relying party's
secret manager, and update it before discarding the response. Rotation invalidates
old Secrets atomically. Public Clients never have Secrets.

## PostgreSQL startup or readiness failure

Application errors are classified without host, username, SQL, or driver details.
For local Compose:

```bash
docker compose -f deploy/docker-compose.yml ps
docker compose -f deploy/docker-compose.yml logs postgres
docker compose -f deploy/docker-compose.yml exec postgres \
  pg_isready -U "$POSTGRES_USER" -d "$POSTGRES_DB"
```

`/health/live` remaining 200 while `/health/ready` returns 503 is expected during
a database outage. Readiness uses a separate one-second ping timeout and recovers
automatically.

## Production configuration rejected

Run `oneissuer config check` in the exact deployment environment. Production
requires explicit HTTPS Issuer, PostgreSQL TLS, Secure `__Host-` cookies, and an
explicit registration decision. Validation reports field names/reasons without
printing values.

## Ready never becomes healthy in Compose

```bash
docker compose -f deploy/docker-compose.yml ps
docker compose -f deploy/docker-compose.yml logs --no-log-prefix migrate oneissuer
docker inspect oneissuer-oneissuer-1 --format '{{json .State.Health}}'
```

Confirm `migrate` exited zero, PostgreSQL is healthy, configuration passed, and
migration version 5 is compatible.

## Tests cannot start PostgreSQL

The integration suite uses Testcontainers and needs a working Docker socket.
Check `docker info` and current-user access. Phase-two acceptance requires the
real PostgreSQL integration and Compose smoke tests; unit-only results are not a
substitute.

## `make generate-check` reports stale code

Run `make generate`, inspect query/schema changes, and commit source plus generated
output. The script now copies production migrations because they are sqlc's schema
source. Tool versions are pinned; do not regenerate with `latest`.

## Graceful shutdown exits non-zero

An active handler exceeded `ONEISSUER_SHUTDOWN_TIMEOUT`. The server first became
Not Ready, stopped the Session/transaction cleanup loop, and then force-closed to
preserve the bound. Investigate slow handlers or dependencies rather than setting
an unbounded timeout.
