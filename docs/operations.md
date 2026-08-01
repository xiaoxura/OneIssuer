# Phase-two operations

This guide covers first-administrator Bootstrap, deployment sequencing, backups,
restore rehearsal, cleanup, and audit retention. OneIssuer `v0.1.0-dev.2` is a
development release; adapt the controls to a reviewed production platform rather
than deploying the local Compose file publicly.

## Release sequence

Use one migration actor and do not let `serve` own schema changes:

1. build/verify the exact immutable image and migration checksums;
2. take a tested encrypted PostgreSQL backup;
3. run `oneissuer migrate status` and `oneissuer migrate up` once;
4. run `oneissuer migrate status` again (expected phase-two version: 5);
5. Bootstrap only if this is a new installation;
6. start application replicas and wait for `/health/ready`;
7. retain the previous compatible image and backup under the rollback policy.

An empty installation with no administrator is a safe unconfigured state. It does
not enable web first-admin capture and does not make readiness pretend PostgreSQL
is broken. Keep self-registration disabled until policy is explicit.

## First administrator Bootstrap

### Controlled TTY

Preferred:

```bash
oneissuer admin bootstrap --username admin --email admin@example.invalid
```

The terminal disables echo and asks for confirmation. The command checks
migration compatibility, hashes outside the database lock, acquires a PostgreSQL
advisory lock, rechecks the administrator set, and atomically inserts User,
credential, and audit event. Output contains only status, internal UUID, and
username.

A second or concurrent attempt fails with a stable conflict exit. It cannot reset
an existing password and prints no existing account details.

### Local Compose

```bash
docker compose -f deploy/docker-compose.yml up -d postgres
docker compose -f deploy/docker-compose.yml run --rm migrate
docker compose -f deploy/docker-compose.yml run --rm --no-deps oneissuer \
  admin bootstrap --username admin --email admin@example.invalid
```

Never place an administrator password in Compose YAML, environment variables,
Docker build arguments, image layers, or the command line.

### Controlled non-interactive input

`--password-stdin` exists for a secret-injection mechanism that cannot allocate a
TTY. It requires exactly two matching newline-terminated entries. The producer
must avoid shell history, logs, process arguments, persistent files, and reusable
CI output. Prefer an ephemeral secret file/descriptor mounted read-only from the
platform, pipe it directly, then destroy/revoke the source.

Do not use `echo` with a literal. Do not retain the Bootstrap secret after it has
been placed in the operator's password manager. The service never accepts
`--password`.

## Reverse proxy and endpoint exposure

- terminate browser TLS and configure the exact HTTPS Issuer;
- set `ONEISSUER_TRUSTED_PROXIES` only to direct proxy networks;
- forward the original scheme/host without allowing public clients to choose
  them; OneIssuer still uses its fixed Issuer;
- restrict `/metrics`, database access, and administrator paths by network policy
  where practical;
- do not cache hosted auth pages or one-time Secret responses;
- preserve `Set-Cookie`, `X-Request-ID`, `X-CSRF-Token`, `Cache-Control`, and
  security headers;
- never add a permissive CORS proxy around password or management endpoints.

## PostgreSQL backup

The database contains identity PII, credential digests, active authority digests,
Client policy, and audit history. Treat every backup as sensitive even though
clear passwords/Secrets are absent.

A typical logical backup (credentials supplied through PostgreSQL's protected
mechanism, not a command argument) is:

```bash
pg_dump --format=custom --no-owner --no-acl \
  --file oneissuer-backup.dump "$ONEISSUER_DATABASE_URL"
sha256sum oneissuer-backup.dump > oneissuer-backup.dump.sha256
```

Required operator controls:

- encrypt before leaving the trusted host and use separate key management;
- restrict read/delete access, enable immutable/versioned storage where possible,
  and log access;
- define backup frequency and recovery-point/recovery-time objectives;
- retain checksum, application version, migration version, PostgreSQL version,
  and UTC timestamp alongside the artifact;
- avoid writing raw database URLs to job output;
- test restoration regularly, not only backup creation.

Physical backup/PITR is preferable for larger deployments but remains platform
specific. Coordinate it with PostgreSQL WAL retention and encryption.

## Restore rehearsal

Restore into an isolated database/network first:

1. verify the encrypted artifact and SHA-256 checksum;
2. create an empty compatible PostgreSQL instance;
3. restore with `pg_restore --no-owner --no-acl` under controlled credentials;
4. run the matching OneIssuer binary's `migrate status`;
5. apply only documented forward migrations if the restored version is older;
6. start OneIssuer without external traffic and test health, administrator login,
   disabled-user rejection, Session revocation state, Client read/Secret rotation,
   and Audit pagination;
7. destroy the rehearsal environment and any clear temporary artifact.

Restoring an old backup revives the authority state captured at that time. Treat
all Sessions and Client Secrets created/rotated after the recovery point as an
incident concern; revoke/rotate as policy requires before reopening traffic.

## Cleanup and retention

The cancellable in-process cleanup loop runs at
`ONEISSUER_CLEANUP_INTERVAL`. Expiry is enforced on reads before cleanup, so a
late cleanup does not extend authority.

Current application retention behavior:

| Data | Application behavior |
| --- | --- |
| expired/consumed pre-auth sessions | eligible for prompt deletion |
| expired/revoked login sessions | retained for 30 days, then deleted |
| live elapsed auth transactions | marked expired |
| terminal auth transactions | deleted after 24 hours |
| users, credentials, Clients | retained; disabled rather than deleted |
| audit events | retained indefinitely by the application; no delete/update API |

### Audit retention policy

Choose and document a policy based on legal, incident-response, privacy, and
storage requirements. For a development/reference deployment, retain online
Audit events for at least 365 days and retain encrypted backups according to the
same approved schedule. This is an operational recommendation, not automatic
behavior.

The phase-two database trigger rejects Audit UPDATE and DELETE, including ad hoc
application maintenance. Any future archival/deletion must be an explicit,
reviewed maintenance design that:

1. exports a verifiable immutable archive in event order;
2. preserves IDs, actor/target, request ID, changed-field names, and timestamps;
3. verifies archive completeness and access controls;
4. uses a new migration/controlled role to alter the append-only guard for a
   bounded operation;
5. records the retention action outside the rows being removed;
6. updates threat model, runbook, backups, and tests.

Monitor table/index sizes and free space. Do not silently truncate Audit events to
solve capacity pressure.

## Secret and incident actions

- **Lost one-time Client Secret:** rotate; it cannot be read back.
- **Suspected Client Secret compromise:** rotate atomically and update the relying
  party; inspect fixed Audit events.
- **Suspected Session theft:** revoke the specific Session or all User Sessions;
  disabling the User immediately invalidates remaining Sessions.
- **Administrator compromise:** use another active administrator to disable the
  account/revoke Sessions and rotate affected Clients; preserve Audit/backup
  evidence. The final-admin guard means emergency recovery needs a separately
  reviewed database/operator procedure.
- **Database/backup compromise:** assume credential digests, Session/Client
  digests, PII, and audit history are exposed; expire Sessions, rotate Secrets,
  assess password reset, and follow breach response.

Never add credential material to an incident ticket or diagnostic log.
