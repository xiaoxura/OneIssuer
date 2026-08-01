# Phase two release notes — `v0.1.0-dev.2`

Date: 2026-08-01  
Status: **Verified** — local Definition of Done acceptance complete

## Delivered

- five embedded production migrations through version 5 for Users/Credentials,
  Clients, Sessions/pre-auth, append-only Audit, and authentication transactions;
- NFC/case-fold identity normalization, independent opaque subjects, active or
  disabled users, and minimal `user`/`admin` roles;
- bounded Argon2id PHC hashing, dummy unknown-user verification, and successful
  login rehash;
- digest-only 256-bit Session/CSRF/pre-auth values, absolute/idle expiry, rotation,
  revocation, owner-scoped Session APIs, and cancellable cleanup;
- hosted bilingual login/registration/logout forms with same-origin CSRF, strict
  CSP, contextual escaping, fixed completion, and no arbitrary redirect;
- public/confidential Clients with exact URI checks, fixed scopes, digest-only
  one-time Secrets, and atomic rotation;
- concurrency-safe `oneissuer admin bootstrap` with hidden/confirmed input and no
  password argument;
- administrator Users, Clients, Sessions, and append-only Audit JSON APIs with
  recent-authentication and final-administrator protection;
- stable error classes, opaque keyset pagination, fixed-field audit events, and
  low-cardinality phase-two metrics;
- phase-two OpenAPI 3.1 contract, threat model/ADR, configuration, migration,
  troubleshooting, operations, and phase-three handoff documents.

## Database and rollout

Expected Goose production version: **5**.

```text
00001_users_credentials.sql
00002_oidc_clients.sql
00003_login_sessions.sql
00004_audit_events.sql
00005_auth_transactions.sql
```

`serve` remains read-only with respect to schema. Run `oneissuer migrate up` as a
single release job before starting the new binary. Existing approved migrations
are protected by `migrations/checksums.sha256`. Production rollback must restore a
compatible binary/backup; phase-two Down migrations are for disposable tests only.

New command:

```text
oneissuer admin bootstrap --username <name> --email <address> [--password-stdin]
```

There is no default administrator and no `--password` option.

## Security properties verified by design/tests

- no password, Argon2 digest, clear Cookie, CSRF value, transaction token, Client
  Secret/digest, State, Nonce, or PKCE value belongs in logs/audit/read models;
- unknown, disabled, and wrong-password login responses are externally uniform;
- login rotates Session ID and all authority/revocation survives restart;
- every state-changing same-origin API requires Cookie plus CSRF;
- owner Session access hides foreign IDs;
- Secret create/rotate responses are `no-store`, and old Secrets fail after
  rotation;
- final active administrator cannot be disabled or demoted;
- Audit UPDATE/DELETE is rejected by PostgreSQL;
- no metric label contains user/client ID, email, username, IP, or raw URI.

## Verification record

The following gates were executed from the repository root on 2026-08-01. The
Compose run used loopback port `18080` to avoid relying on a shared host port.
The checked-in GitHub Actions workflow remains the authoritative repeat of these
gates on push/pull request; its YAML and expressions were also checked locally
with pinned actionlint `v1.7.7`.

| Gate | Command | Result |
| --- | --- | --- |
| Generated/schema immutability | `make generate-check migration-check` | **PASS** — sqlc temporary regeneration matched; the five-file migration set and every SHA-256 digest matched |
| Public contracts/privacy | `make sensitive-check openapi-check` | **PASS** — sensitive-example scan passed; Redocly `2.43.2` validated OpenAPI 3.1 with no warning |
| Vet and lint | `go vet ./...` and `.tools/bin/golangci-lint run --max-issues-per-linter=0 --max-same-issues=0 ./...` | **PASS** — golangci-lint `v2.12.2` reported `0 issues` |
| Unit/Testcontainers | `go test ./... -count=1` | **PASS** — all packages, migration lifecycle, and phase-two PostgreSQL integration tests passed |
| Race | `go test -race ./...` | **PASS** — all packages, including PostgreSQL integration, passed under the race detector |
| Fuzz smoke | `ONEISSUER_FUZZ_TIME=2s make fuzz-smoke` | **PASS** — identity, Client, auth-transaction, form-parser, and cursor targets passed |
| Go vulnerabilities | `.tools/bin/govulncheck ./...` (`v1.6.0`) | **PASS** — 0 reachable vulnerabilities; one required-module advisory was reported as not called by OneIssuer |
| Web prototype | `npm run check`; Node `24.18.0`/npm `11.16.0` `npm audit --audit-level=high` | **PASS** — oxlint, TypeScript, and Vite build passed; audit found 0 vulnerabilities |
| Static binary | `make build` | **PASS** — static `bin/oneissuer` built with `v0.1.0-dev.2` metadata |
| Empty-volume Compose | `ONEISSUER_SMOKE_HTTP_PORT=18080 ./scripts/smoke-compose.sh` | **PASS** — initial/repeated migration, Bootstrap/rejection, hosted registration/login, Session rotation/CSRF/revoke/logout, Client Secret lifecycle, restart persistence, absent OIDC protocol routes, privacy scan, database outage/recovery, non-root execution, and graceful shutdown all passed |
| Image vulnerabilities/non-root | image inspect/runtime UID/GID plus Trivy `0.69.3 --ignore-unfixed --severity HIGH,CRITICAL` | **PASS** — configured/effective identity `65532:65532`; Alpine and Go binary each had 0 High/Critical findings |
| Workflow/docs integrity | actionlint `v1.7.7`, Ruby YAML parse, and local-link scan | **PASS** — CI/metadata YAML parsed, actionlint emitted no issue, and all local links across 18 maintained Markdown files resolved |

## Compatibility and known limits

Phase-one health, metrics, request ID, trusted proxy, migration, and graceful
shutdown contracts remain. The API is a development contract and carries no
production compatibility promise yet.

The following are intentionally absent: Discovery, JWKS, Authorize, Token,
Authorization Code issuance, full PKCE verification, ID/Access/Refresh Token,
UserInfo, Revocation, Introspection, signing keys, MFA, email verification,
recovery, distributed rate limiting, generic RBAC, and multi-tenancy. See
[phase-3-handoff.md](./phase-3-handoff.md).
