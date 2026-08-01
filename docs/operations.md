# Phase-three operations

This guide covers release sequencing, first-administrator Bootstrap, endpoint
exposure, backups, restore rehearsal, protocol delivery semantics, cleanup, and
incident actions for OneIssuer `v0.1.0-dev.3`. It is a development release; adapt
these controls to a reviewed production platform rather than exposing the local
Compose file.

Signing-key generation, overlap rotation, and emergency removal are in the
separate [key-rotation runbook](./key-rotation-runbook.md).

## Release sequence

Use one migration actor and never let `serve` own schema changes:

1. build and verify the exact immutable image, migration checksums, SBOM, and
   vulnerability report;
2. validate the canonical HTTPS Issuer, Client Redirect URIs, database TLS,
   cookies, trusted proxies, and explicit registration policy;
3. stage the active private JWK and public overlap JWKS with the required file
   ownership/permissions, without placing private material in the image;
4. take and verify an encrypted PostgreSQL backup; independently verify the
   protected signing-key backup/escrow policy;
5. stop incompatible writers, run `oneissuer migrate status`, then one
   `oneissuer migrate up`;
6. run status/version again (expected phase-three version: **10**);
7. run `oneissuer config check` in the exact service identity/mount namespace;
8. Bootstrap only for a new installation;
9. start replicas and wait for `/health/ready`;
10. verify Discovery, JWKS, their cache headers, and a monitored test Client flow;
11. retain the previous image and pre-migration backup under the rollback policy.

Startup loads and validates the signing ring, connects to PostgreSQL, verifies
migration compatibility, and appends the fixed `signing_key_loaded` Audit event
before opening the listener. Key, database, migration, or Audit failure is fatal.
`/health/ready` subsequently fails during a database outage while liveness stays
available.

Version 10 is not backward-compatible with a phase-two binary expecting version
5. Restore the pre-upgrade database for a true rollback; do not run production
Down migrations or force the old binary to ignore the schema.

## First administrator Bootstrap

### Controlled TTY

Preferred:

```bash
oneissuer admin bootstrap --username admin --email admin@example.invalid
```

The terminal disables echo and asks for confirmation. The command checks
migration compatibility, hashes outside the database lock, acquires a PostgreSQL
advisory lock, rechecks the administrator set, and atomically inserts the User,
credential, and Audit event. Output contains only status, internal UUID, and
username.

A second or concurrent attempt fails with a stable conflict exit. It cannot reset
an existing password and reveals no existing account details. An empty
installation with no administrator is a safe unconfigured state; it does not
enable browser first-admin capture.

### Local Compose

After preparing the key mount as documented by the key runbook:

```bash
docker compose -f deploy/docker-compose.yml up -d postgres
docker compose -f deploy/docker-compose.yml run --rm migrate
docker compose -f deploy/docker-compose.yml run --rm --no-deps oneissuer \
  admin bootstrap --username admin --email admin@example.invalid
```

Never place an administrator password in Compose YAML, environment variables,
Docker build arguments, image layers, or the command line.

### Controlled non-interactive input

`--password-stdin` is for a secret-injection mechanism that cannot allocate a
TTY. It requires exactly two matching newline-terminated entries. The producer
must avoid shell history, logs, process arguments, persistent files, and reusable
CI output. Prefer an ephemeral descriptor/mount, pipe it directly, and destroy
or revoke the source.

Do not use `echo` with a literal. Do not retain the Bootstrap secret outside the
operator's password manager. OneIssuer never accepts `--password`.

## Client provisioning and protocol exposure

Clients are statically provisioned through authenticated administrator APIs; no
Dynamic Client Registration endpoint exists. Public Clients receive no Secret and
use `none`. Confidential Clients receive a clear Secret exactly once and use
`client_secret_basic`; transfer it immediately into the RP's secret manager.
Every Client must use S256.

At the reverse proxy:

- terminate browser TLS and configure the exact external HTTPS Issuer;
- set `ONEISSUER_TRUSTED_PROXIES` only to direct proxy networks;
- preserve the external origin without allowing request headers to rewrite the
  configured Issuer;
- expose Discovery, JWKS, Authorize, Token, and UserInfo only under the fixed
  Issuer paths;
- restrict `/metrics`, PostgreSQL, and administrator routes with network policy
  where practical;
- do not cache hosted auth/Consent pages, redirects, Token/UserInfo responses, or
  one-time Secret responses; Discovery/JWKS may honor their five-minute public
  cache headers;
- preserve `Set-Cookie`, `X-Request-ID`, `X-CSRF-Token`, `Cache-Control`,
  `Pragma`, `ETag`, `WWW-Authenticate`, and security headers;
- set request/body/header/time limits at least as strict as the reviewed service
  envelope without truncating valid OAuth form encoding;
- never add permissive CORS around password, protocol, or management endpoints.

Monitor a complete synthetic Code Flow, not only health. Check that Discovery
does not begin advertising a capability that the deployed binary lacks.

## At-most-once Code exchange

Code consumption and Access Token metadata commit atomically. HTTP delivery
cannot be transactional with PostgreSQL: the server can commit and then lose the
connection before the Client receives the Token Response. A retry with that Code
returns `invalid_grant`, and OneIssuer cannot reconstruct the same ID/Access
Token response.

Client/operator action is to start a **new authorization request**. Do not replay
the Code, restore the Code row, clear `consumed_at`, or infer that `invalid_grant`
means the prior commit did not happen. The bounded replay Audit records at most
one rejection event per consumed Code to avoid storage amplification.

Disabling the bound User or Client causes both exchange and UserInfo to fail
closed. Re-enabling does not revive a consumed or expired Code. A still-
unconsumed, unexpired Code may continue only after all current User, Client,
Redirect URI, Scope, Consent, and PKCE checks pass.

## PostgreSQL backup

The database contains identity PII, credential digests, active authority
digests, Client policy, Consent Grants, protocol metadata, and Audit history.
Treat every backup as sensitive even though clear passwords, Client Secrets,
Codes, and Tokens are absent.

A typical logical backup (credentials supplied through PostgreSQL's protected
mechanism, not a command argument) is:

```bash
pg_dump --format=custom --no-owner --no-acl \
  --file oneissuer-backup.dump "$ONEISSUER_DATABASE_URL"
sha256sum oneissuer-backup.dump > oneissuer-backup.dump.sha256
```

Required controls:

- encrypt before leaving the trusted host and use separate key management;
- restrict read/delete access and use immutable/versioned storage where possible;
- define backup frequency and recovery-point/recovery-time objectives;
- retain checksum, application version, migration version, PostgreSQL version,
  canonical Issuer, and UTC timestamp alongside the artifact;
- avoid writing database URLs or credentials to job output;
- test restoration regularly, not just backup creation.

The active signing private key is **not** in PostgreSQL. Back it up/escrow under a
separate, least-privilege key policy so a database backup alone cannot leak it and
so disaster recovery does not silently change `kid`. Record association through
public fingerprints/metadata, never by copying private JWK content into the
database backup manifest or ticket.

Physical backup/PITR may be preferable for larger deployments but is platform-
specific. Coordinate it with PostgreSQL WAL retention and encryption.

## Restore rehearsal

Restore into an isolated database/network first:

1. verify encrypted artifacts and SHA-256 checksums;
2. create a compatible isolated PostgreSQL instance;
3. restore with `pg_restore --no-owner --no-acl` using controlled credentials;
4. stage the intended private key and verification ring through the secret mount;
5. run the matching OneIssuer binary's `migrate status` and `config check`;
6. apply only documented forward migrations if the backup is older;
7. start without external traffic and test health, Discovery/JWKS, administrator
   login, disabled-User rejection, Session revocation, Client Secret rotation,
   Consent/Code/Access metadata state, and Audit pagination;
8. run a new throwaway Client authorization; never reuse an archived Code/Token;
9. destroy the rehearsal environment and clear temporary artifacts.

Restoring an old backup revives authority state captured at that time. Treat all
Sessions, Client Secrets, Consent changes, User/Client status changes, and key
changes after the recovery point as incident concerns. Codes and Access Tokens
are short-lived and checked by current time, but do not rely on cleanup to make
them invalid. Revoke/rotate/reconcile before reopening traffic.

## Cleanup and retention

The cancellable cleanup loop runs every `ONEISSUER_CLEANUP_INTERVAL`. Expiry is
enforced on reads and exchanges first, so a late/failed cleanup does not extend
authority.

| Data | Application behavior |
| --- | --- |
| expired/consumed pre-auth Session | eligible for prompt deletion |
| expired/revoked login Session | retained for 30 days, then deleted |
| live elapsed authorization transaction | marked expired |
| terminal authorization transaction | deleted after 24 hours |
| Authorization Code metadata | deleted no earlier than 24 hours after expiry |
| Access Token metadata | deleted no earlier than 24 hours after expiry |
| Consent Grant | retained; no phase-three self-service revoke/delete |
| Users, credentials, Clients | retained; disabled rather than deleted |
| Audit event | retained indefinitely; no application delete/update API |

### Audit retention policy

Choose an explicit policy based on law, incident response, privacy, and capacity.
For a development/reference deployment, retaining online Audit events for at
least 365 days is an operational recommendation, not automatic behavior.

The database trigger rejects Audit UPDATE and DELETE. Any future archival/deletion
must be an explicit, reviewed maintenance design that exports a verifiable
immutable sequence, proves completeness, uses a bounded privileged operation,
records the retention action elsewhere, and updates threat model/runbooks/tests.
Never silently truncate Audit events to solve capacity pressure.

Monitor table/index size, cleanup failures, available storage, request results,
Code exchange failures, UserInfo failures, key-load readiness, and PostgreSQL pool
pressure. Metric labels are intentionally low-cardinality and cannot identify a
specific User, Client, Code, Token, or key.

## Secret and incident actions

- **Lost one-time Client Secret:** rotate; it cannot be read back.
- **Suspected Client Secret compromise:** rotate atomically, update the RP, and
  inspect fixed Audit events. Existing Access Tokens cannot be individually
  revoked in phase three; disable the Client if immediate fail-closed UserInfo is
  required.
- **Suspected Session theft:** revoke the Session or all User Sessions; disabling
  the User invalidates remaining Sessions and UserInfo immediately.
- **Suspected signing-key compromise:** execute the emergency procedure in the
  key runbook. Removing the public key invalidates old Tokens for fresh verifiers,
  but external JWKS caches can retain it for roughly five minutes.
- **Administrator compromise:** use another active administrator to disable the
  account, revoke Sessions, and rotate affected Clients; preserve Audit/backup
  evidence. Final-admin recovery needs a separately reviewed operator procedure.
- **Database/backup compromise:** assume credential, Session/Client/Code/`jti`
  digests, PII, Grants, metadata, and Audit history are exposed; expire Sessions,
  rotate Secrets/keys as risk requires, assess password reset, and follow breach
  response.
- **Database unavailable:** readiness and authority operations fail closed. Do not
  bypass PostgreSQL with cached/in-memory identity or metadata.

Phase three has no Refresh Token, Revocation, Introspection, or RP Logout. Do not
promise global instantaneous Token invalidation or create ad hoc database edits
that imitate those lifecycles. Never add credential or private-key material to an
incident ticket or diagnostic log.
