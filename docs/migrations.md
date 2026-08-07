# PostgreSQL migrations and sqlc

## Explicit release model

`oneissuer serve` never changes the database. Startup opens and pings the pgx
pool, then compares `goose_db_version` with the production migrations embedded
in the binary. Missing, pending, failed, or newer-than-binary migrations stop
startup before the HTTP listener opens.

Run exactly one migration actor before application replicas:

```bash
oneissuer migrate up
oneissuer migrate status
oneissuer migrate version
```

Compose models this with a one-shot `migrate` service and starts `oneissuer`
only after that service exits successfully.

## Phase-four production schema

The phase-four working-tree migration target is schema **15**. The repository
default binary is `v0.1.0-dev.4`; release gates remain pending.
The application generates UUIDs and random values, so no undeclared PostgreSQL
extension is required.

| Version | File | Purpose |
| --- | --- | --- |
| 1 | `00001_users_credentials.sql` | Users, stable Subjects, normalized identifiers, role/status, and one Argon2id credential per User |
| 2 | `00002_oidc_clients.sql` | Public/Confidential Clients, exact URI arrays, scope policy, status, registration policy, and digest-only Secrets |
| 3 | `00003_login_sessions.sql` | Digest-only authenticated/pre-auth Sessions, CSRF digest/expiry, absolute/idle expiry, revocation, and reduced metadata |
| 4 | `00004_audit_events.sql` | Fixed append-only Audit events with triggers rejecting UPDATE and DELETE |
| 5 | `00005_auth_transactions.sql` | Short-lived digest-only local/authorization transaction context, expiry, failure, and single consumption |
| 6 | `00006_phase_three_protocol_events.sql` | Extends fixed Audit event, target, and changed-field constraints for Consent, Code, Token, and key-load transitions |
| 7 | `00007_auth_transaction_protocol_context.sql` | Adds strict Code response, prompt, `max_age`, Scope, and S256 context constraints |
| 8 | `00008_consent_grants.sql` | One persistent canonical Scope grant per `(user_id, client_id)` |
| 9 | `00009_authorization_codes.sql` | Digest-only, bound, short-lived, single-use Authorization Code metadata |
| 10 | `00010_access_tokens.sql` | Digest-only JWT `jti` metadata tied to Code, Grant, User, Client, Scope, and expiry |
| 11 | `00011_security_hardening.sql` | Monotonic bigint User/Client versions, per-form attempt count, replay-Audit uniqueness, and bounded-cleanup indexes |
| 12 | `00012_phase_four_grants_and_session_bindings.sql` | Grant revoke/version, offline Scope constraints, stable Session bindings, and phase-four Audit vocabulary |
| 13 | `00013_refresh_families_and_access_lifecycle.sql` | Digest-only rotating Refresh families/generations and Access issuance/revocation metadata |
| 14 | `00014_logout_transactions_and_lifecycle_cleanup.sql` | Cookie-only RP logout transactions, bounded CSRF stages, reuse evidence, and retention indexes |
| 15 | `00015_allow_authorization_code_detach.sql` | Authority-preserving detach of Code-sourced Access metadata after bounded Code cleanup |

All times use `timestamptz`. Foreign keys retain identity/Client history; Users
and Clients are disabled rather than physically deleted. Audit rows contain a
fixed schema and changed-field names, never arbitrary metadata or changed values.

## Upgrading from phase two

The supported upgrade path is schema version 5 to 15 using the phase-four
binary's `migrate up` command. Take and verify a backup first, stop old writers,
run one migration actor, inspect version/status, and only then start phase-four
replicas. A populated schema-11 fixture must retain all existing authority and
must not fabricate Grants, Refresh families, or Session bindings beyond the
documented stable-row backfill.

Migration 7 deliberately makes every pre-existing phase-two authorization
transaction terminal. The older rows do not contain enough frozen protocol
context to resume safely under the stronger profile. They are preserved for
bounded retention/audit but cannot continue through login, registration,
Consent, or Code issuance; the Client must start a new authorization request.

No User, credential, Session, Client, or Audit authority is re-created in a
parallel store. New Code and Access Token tables reference the existing stable
User/Client/transaction records.

Migration 11 assigns existing Users and Clients version `1` and changes
optimistic writes to compare/increment that monotonic `bigint`, so two updates
with the same timestamp can no longer evade stale-writer detection. Existing
pre-authentication rows receive attempt count `0`; application reservation is an
atomic conditional update and permits at most five form submissions.

Migration 12 backfills Grant version and stable Session bindings without
rewriting 00001–00011. Migration 13 leaves legacy Code/Access rows on the
`authorization_code` source and creates no Refresh authority for them. Migration
14 stores only lookup/proof digests for Hosted logout and can be applied to a
live schema-13 database before the new binary is started. Migration 15 permits
only the foreign-key-driven detach of Code-sourced Access metadata after its
parent Code is deleted; inserts and all other authority mutations retain the
strict source checks. Its Down section refuses detached rows before restoring
the schema-14 constraints. The 00013 Down section separately refuses a populated
downgrade when any Access row is refresh-sourced or detached from a Code; there
is no lossless representation for those rows in the old schema. Restore a
verified pre-upgrade backup instead.

## Embedded source and immutability

`migrations/embed.go` embeds `*.sql` at compile time. `migrate`, `serve`, tests,
and the final image use that same read-only filesystem. Test-only migrations in
`internal/storage/postgres/testdata/` are never embedded.

Released migration files are immutable. `migrations/checksums.sha256` records
the approved SHA-256 digest for every production SQL file through version 15. In particular,
**versions 00001 through 00011 are the frozen phase-three input and their bytes and
checksums must never change**. A schema correction adds the next monotonically
numbered migration; it never rewrites history.

For a new migration:

1. select the next five-digit version and a descriptive filename;
2. include `-- +goose Up` and a disposable-development `Down`, or document why
   no safe `Down` exists;
3. use transactional DDL where possible and review locks/table scans;
4. update the checksum manifest intentionally after schema/security review;
5. run empty-database Up, repeated Up, test-only full Down/Up, the phase-two
   upgrade fixture, sqlc generation, and real PostgreSQL integration tests;
6. document rollout/backfill, cleanup, rollback, and the expected version.

Large backfills or long-lock changes need a separate
expand/backfill/contract rollout rather than a normal blocking migration.

## Transactional protocol authority

The schema and repository adapters make PostgreSQL the race arbiter:

- authorization-transaction consumption, Consent Grant create/expand,
  Authorization Code insert, and success Audit commit together;
- Code locking/revalidation, JWT minting, Access metadata insert, Code
  consumption, and protocol Audit commit together;
- a concurrent approval creates at most one Code;
- a concurrent Code exchange commits at most one Token Response state;
- signer, Audit, constraint, or commit failure rolls back the authority change.

The clear Code, Access Token, ID Token, PKCE verifier, Client Secret, and private
key are never schema fields. PostgreSQL stores domain-separated Code and `jti`
digests plus bounded binding/lifecycle metadata.

## Cleanup and retention

Expiry is enforced in query/transaction paths before cleanup, so delayed or
failed cleanup cannot extend authority.

| Data | Application behavior |
| --- | --- |
| live elapsed authorization transaction | marked terminal/expired |
| terminal authorization transaction | deleted after 24 hours |
| expired/consumed Authorization Code metadata | eligible 24 hours after Code expiry |
| expired Access Token metadata | eligible 24 hours after Token expiry |
| Consent Grant | retained; revoked rows/version require interactive re-consent |
| Refresh Token family/digest | retained through family absolute expiry plus reuse evidence |
| Logout transaction | retained through TTL; terminal rows at least 24 hours before cleanup |
| expired/revoked login Session | retained 30 days, then deleted |
| Audit event | not deleted or updated by the application |

Access metadata references Code metadata with `ON DELETE RESTRICT`, so cleanup
deletes eligible Access rows before eligible Code rows. Retention preserves
bounded operational evidence; it does not allow a replay or expired UserInfo
request.

Cleanup candidates are selected in stable batches of 250 with `FOR UPDATE SKIP
LOCKED`. Each batch commits independently. Cancellation/deadline errors therefore
return the number of rows committed by earlier batches rather than rolling back
all progress; the next scheduled run resumes safely. Session, authorization-
transaction, protocol-artifact, and active-session-count operations each receive
an independent five-second context so one timeout cannot poison later work.

## Down migrations and production rollback

Down sections verify reversibility on disposable test databases. **Never run Down
against production identity/protocol data.** Application rollback means deploying
a compatible binary or restoring a tested database backup. Dropping User,
credential, Session, Client, transaction, Grant, Code, Token metadata, or Audit
tables is not a production rollback strategy.

Before a release migration:

- take and verify an encrypted PostgreSQL backup;
- confirm the new binary and runbook understand current and target versions;
- stop incompatible writers and run only one migration actor;
- inspect `migrate status` before starting replicas;
- retain the prior immutable image and record whether it is schema-compatible.

After version 14 is applied, phase-three binaries expect version 11 and correctly
refuse to start. Restore a pre-upgrade backup for a true binary rollback rather
than forcing an old binary onto the new schema.

## sqlc

Production migrations are the schema source of truth in `sqlc.yaml`; there is no
hand-maintained `queries/schema.sql`. Use-case queries are grouped in:

```text
queries/system.sql
queries/identity.sql
queries/session.sql
queries/client.sql
queries/audit.sql
queries/authflow.sql
queries/authorization.sql
queries/consent.sql
queries/token.sql
```

Run:

```bash
make generate
make generate-check
```

`generate-check` copies `queries/` and `migrations/` into a temporary project,
runs the pinned sqlc binary, and compares all generated output. Never edit
`internal/storage/postgres/sqlcgen/` by hand. Query names describe use cases, all
values remain parameterized, and HTTP handlers never construct SQL.

See [operations.md](./operations.md) for backup and restore rehearsal.
