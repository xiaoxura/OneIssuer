# PostgreSQL migrations and sqlc

## Explicit release model

`oneissuer serve` never changes the database. Startup opens and pings the pgx
pool, then compares `goose_db_version` with the production migrations embedded
in the binary. Missing, pending, or newer-than-binary migrations stop startup
before the HTTP listener opens.

Run exactly one migration job before application replicas:

```bash
oneissuer migrate up
oneissuer migrate status
oneissuer migrate version
```

Compose models this with a one-shot `migrate` service and starts `oneissuer` only
after that service exits successfully.

## Phase-two production schema

The expected production version is **5**. The application generates every UUID
and random value, so no undeclared PostgreSQL extension is required.

| Version | File | Purpose |
| --- | --- | --- |
| 1 | `00001_users_credentials.sql` | users, stable subjects, normalized unique identifiers, `user`/`admin` role, active/disabled status, and one Argon2id password credential per user |
| 2 | `00002_oidc_clients.sql` | public/confidential Clients, exact redirect/logout URI arrays, scope arrays, status, registration policy, and digest-only secret records |
| 3 | `00003_login_sessions.sql` | digest-only authenticated/pre-auth sessions, CSRF digest/expiry, absolute/idle expiry, revocation, and privacy-reduced metadata |
| 4 | `00004_audit_events.sql` | fixed append-only audit events plus triggers that reject UPDATE and DELETE |
| 5 | `00005_auth_transactions.sql` | short-lived digest-only local/verified transaction context, expiry, failure, and single consumption |

All times use `timestamptz`. Foreign keys preserve identity/client history; phase
two disables users and Clients rather than physically deleting them. Audit rows
contain fixed field names, not arbitrary metadata or changed values.

## Embedded source and immutability

`migrations/embed.go` embeds `*.sql` at compile time. `migrate`, `serve`, tests,
and the final static image all use that same read-only filesystem. Test-only
migrations under `internal/storage/postgres/testdata/` are never embedded.

Released migration files are immutable. `migrations/checksums.sha256` records the
approved SHA-256 digest for each production SQL file, and CI runs the checksum
script before tests. A schema correction must add the next monotonically numbered
migration; never edit an existing approved file.

For a new migration:

1. choose the next five-digit version and descriptive name;
2. include both `-- +goose Up` and `-- +goose Down` sections for development/test,
   or document why a safe Down is impossible;
3. use transactional DDL where possible and review lock duration;
4. update the checksum manifest intentionally after security/schema review;
5. run empty-database Up, repeated Up, complete test-only Down/Up, sqlc generation,
   and integration tests;
6. document rollout/backfill requirements and the new expected version.

Large backfills or long-lock changes require a separate expand/backfill/contract
rollout, not a normal blocking migration.

## Down migrations and production rollback

Down sections exist to verify reversibility on disposable development/test
databases. **Do not run Down against production identity data.** Application
rollback means restoring a compatible binary or restoring a tested database
backup; deleting User, credential, Session, Client, transaction, or Audit tables
is not an acceptable production rollback.

Before a release migration:

- take and verify an encrypted PostgreSQL backup;
- confirm the new binary understands both the current and target rollout state as
  documented by the migration;
- run only one migration actor;
- inspect `migrate status` before starting replicas.

See [operations.md](./operations.md) for backup and restore rehearsal.

## sqlc

Production migrations are the schema source of truth in `sqlc.yaml`; there is no
hand-maintained duplicate `queries/schema.sql`. Use-case queries are grouped in:

```text
queries/system.sql
queries/identity.sql
queries/session.sql
queries/client.sql
queries/audit.sql
queries/authflow.sql
```

Run:

```bash
make generate
make generate-check
```

`generate-check` copies both `queries/` and `migrations/` into a temporary project,
runs the pinned sqlc binary, and compares all output. Never edit
`internal/storage/postgres/sqlcgen/` by hand. Query names describe a use case and
all values remain parameterized; HTTP handlers never construct SQL.
