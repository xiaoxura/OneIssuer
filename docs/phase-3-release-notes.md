# OneIssuer `v0.1.0-dev.3` phase-three release notes

Status: **Verified** — local Definition of Done and final repository-wide verification complete
Release date: 2026-08-01
Previous version: `v0.1.0-dev.2`
Schema: 5 → 10

> [!WARNING]
> This is a development release, not production-ready software. OneIssuer has not
> obtained OpenID Foundation certification. The recorded Conformance results are
> applicable interoperability evidence only.

## Summary

Phase three turns the accepted phase-two identity/Session/Client foundation into
a minimal, real OIDC Provider path:

```text
Discovery + JWKS
→ Authorization Code request
→ hosted login or prompt=create registration
→ hosted Consent
→ digest-only one-time Code with S256
→ atomic Token exchange
→ RS256 ID Token + RFC 9068 Access Token
→ UserInfo
```

The implementation remains single-Issuer and PostgreSQL-authoritative. It does
not add a tenant/Realm/Organization model or use the React mock as identity
authority.

## Added protocol surface

| Endpoint | Implemented profile |
| --- | --- |
| `/.well-known/openid-configuration` | accurate phase-three capabilities only |
| `/oauth2/jwks` | public RSA keys, ETag, five-minute public cache |
| `/oauth2/authorize` | Code response, query mode, exact Redirect URI, S256 |
| `/oauth2/token` | form-encoded Authorization Code Grant only |
| `/oauth2/userinfo` | Bearer Access Token, GET/empty POST, minimized claims |

Supported:

- Public `none` and Confidential `client_secret_basic`;
- mandatory S256 PKCE for **both** Client types;
- `openid`, `profile`, and `email`;
- Session reuse, `prompt=none/login/consent/create`, prompt combinations, and
  `max_age`/`auth_time`;
- persistent per-User/Client Consent with Scope reuse/expansion;
- RS256 ID Tokens and RFC 9068 JWT Access Tokens;
- current Active User, Active Client, Consent, Scope, and Access metadata checks
  at UserInfo.

Not implemented or advertised:

- Refresh Token, `offline_access`, Revocation, Introspection, RP-Initiated Logout;
- Dynamic Registration, `client_secret_post`, Implicit/Hybrid, Client
  Credentials, password/device/token-exchange grants;
- PAR/JAR/JARM, Request Object/URI, DPoP, mTLS, private-key JWT;
- general business-API Access Tokens, multi-resource Audience, pairwise Subject,
  or multi-tenancy;
- hot/automatic key rotation, KMS/HSM, or remote signing.

## Signing keys and CLI

New commands:

```text
oneissuer keys generate --alg RS256 --out <private-jwk>
oneissuer keys public --in <private-jwk> --out <public-jwks>
```

The active private JWK is required by `serve`/`config check` and is loaded before
the listener. It must be a regular non-symlink file, normally mode `0600`, with
RSA/RS256/`sig` metadata and an RFC 7638 `kid`. The final container runs as
UID/GID 65532 and reads a read-only secret mount; no key is copied into the image,
database, environment, log, Audit, or response.

`ONEISSUER_VERIFICATION_KEYS_FILE` accepts an optional public-only overlap set.
Rotation is restart-style and documented in
[key-rotation-runbook.md](./key-rotation-runbook.md). Startup appends a fixed
`signing_key_loaded` Audit event and fails closed if that event cannot commit.

## Database changes

New immutable migrations:

| Version | Change |
| --- | --- |
| 00006 | protocol Audit event/target/changed-field whitelist |
| 00007 | strict response/prompt/max-age/S256 authorization context |
| 00008 | canonical persistent Consent Grants |
| 00009 | digest-only bound Authorization Codes |
| 00010 | digest-only Access Token `jti` metadata |

Versions 00001–00005 and their checksums remain unchanged. Upgrade migration 7
safely makes old phase-two authorization transactions terminal; they cannot be
resumed because they lack the new frozen context. Users, credentials, Sessions,
Clients, and Audit history remain in their original authoritative tables.

The PostgreSQL suite builds a real schema-5 authority from the production
00001–00005 migration bytes, inserts representative User/Credential, Public
Client children, active Session, pre-auth state, Audit, and legacy authorization
rows, and then applies the production schema-10 upgrade twice. It verifies exact
authority preservation through both SQL and the login, Client, Session, and
authorization services; the legacy authorization is safely terminal after the
upgrade.

New sqlc sources are `queries/authorization.sql`, `queries/consent.sql`, and
`queries/token.sql`. Expected schema version is 10.

Code and Access metadata are eligible for cleanup 24 hours after expiry, while
read/exchange paths enforce expiry immediately. Consent Grants persist. Audit is
not deleted by application cleanup.

## Atomicity and delivery semantics

- Grant create/expand, authorization-transaction consumption, Code insert, and
  Audit commit in one PostgreSQL transaction;
- User/Client/Grant/URI/Scope/PKCE revalidation, JWT minting, Access metadata,
  Code consumption, and Audit commit in one transaction;
- concurrent approval produces at most one Code;
- concurrent Code exchange commits at most one Token Response state;
- disabling either the User or Client while an authorization page is open
  leaves the transaction unconsumed with no Code; restoring authority allows
  that same live transaction to complete only after every check passes again;
- signing, Audit, database, or commit failure leaves no partial authority;
- real PostgreSQL trigger injection covers Audit insertion failure and a
  deferred constraint-trigger failure at Commit, after minting has begun; both
  leave the Code unconsumed with zero Access metadata/Audit rows, and the same
  Code can succeed after the fault is removed;
- cleanup cancellation (the shutdown path) and an operation deadline are
  injected after Access metadata deletion but before Code deletion; both roll
  the transaction back without a partial cleanup;
- consumed-Code replay Audit is bounded to at most one rejection row per Code.

HTTP response delivery remains at-most-once. If commit succeeds but the Client
disconnects before receiving the response, retry returns `invalid_grant`; the
same Token Response cannot be recovered. The Client must start a new
authorization.

Disabling a User or Client makes exchange and UserInfo fail closed. Re-enabling
does not restore a consumed/expired Code; only an unconsumed and unexpired Code
can continue after every current check passes.

## Token and claim profile

- ID Token protected header: `alg=RS256`, `typ=JWT`, active `kid`;
- ID Token required claims: `iss`, `sub`, Client `aud`, Client `azp`, `exp`,
  `iat`, `auth_time`; optional requested `nonce` and scope-mapped profile/email;
- Access Token protected header: `alg=RS256`, `typ=at+jwt`, active `kid`;
- Access claims: `iss`, `sub`, UserInfo `aud`, `client_id`, canonical `scope`,
  `iat`, `exp`, and random `jti`;
- only the domain-separated `jti` digest and binding/lifecycle metadata persist;
- UserInfo returns `sub`, plus `name`/`preferred_username` for `profile` and
  `email`/`email_verified` for `email`.

The Access Token is only for this Issuer's UserInfo endpoint. Signature
verification alone does not make it a general resource API credential.

## Security and observability

- strict duplicate parameter/header/channel rejection and bounded request bodies;
- untrusted Client/Redirect URI errors stay local; only a verified URI receives
  OAuth errors/state;
- strict Basic/Bearer parsing, no Client authentication downgrade;
- fixed RS256 allow-lists, key/header/claim checks, public-only JWKS;
- hosted Consent uses server-restored context, CSRF, CSP, no-store, escaping, and
  fixed decisions;
- Code, Token, state, nonce, verifier, challenge, Cookie, Secret, and private key
  are excluded from logs/Audit/metric labels;
- fixed protocol Audit whitelist and low-cardinality preinitialized metrics;
- database, signer, Audit, disabled-principal, and shutdown failures are fail-
  closed.

The phase-three threat model and accepted security profile are:

- [`phase-3-threat-model.md`](./phase-3-threat-model.md);
- [`adr/0002-phase-three-oidc-security-profile.md`](./adr/0002-phase-three-oidc-security-profile.md);
- [`phase-3-dependency-spike.md`](./phase-3-dependency-spike.md).

## Example RP and Compose

`examples/oidc-client/` is a strict server-side interoperability example, not a
production SDK. Compose can run it twice:

- A: Public / `none` / loopback callback;
- B: Confidential / `client_secret_basic` / Secret file mount.

It stores state/nonce/verifier server-side, performs S256, validates ID Token
signature/Issuer/Audience/nonce/time, compares UserInfo Subject, links the mock
identity by `(iss, sub)`, and never renders/logs Tokens.

`make phase-3-smoke` starts an empty database, migrates, Bootstraps, creates A/B,
tests `prompt=create`, SSO and independent Consent, exchanges Tokens, calls
UserInfo, exercises replay/concurrency/disabled principals/restart/database
outage/privacy, and checks non-root/read-only/graceful shutdown behavior.

## Conformance evidence

Official suite pin:

- release `release-v5.2.1`;
- source commit `932b46f1e507871eb0b34621aaef65ff04442e6f`;
- non-certification plan `oidcc-test-plan`;
- server/Nginx/Mongo images pinned by digest in the result summary.

Passed on 2026-08-01:

- Discovery/JWKS module `xQE2fnqPaU7ymSS`;
- Public static S256 module `DfkEM7EHpMoKA1z`;
- Confidential `client_secret_basic` static S256 module
  `s87ygoiKOOu6JtQ`.

Secret-free matrix/templates/results are under `conformance/phase-3/`; raw exports
remain in ignored restricted `.artifacts/` because a Confidential export may
contain its runtime Secret. Many older suite modules omit PKCE and cannot run
without weakening mandatory S256; this is recorded, not bypassed. See
[phase-3-conformance.md](./phase-3-conformance.md).

These results are **not** an OpenID Foundation certification claim.

## Supply-chain changes

- CycloneDX JSON SBOM and SHA-256 manifest generation through pinned Syft 1.50.0;
- final-image fixable High/Critical scan through pinned Trivy 0.72.0;
- image inspection rejects private JWK/JWKS files and secret key material;
- discovered `github.com/go-jose/go-jose/v3` CVE-2026-34986 was remediated by
  upgrading the transitive Fosite dependency path to v3.0.5;
- runtime JOSE remains `github.com/go-jose/go-jose/v4` v4.1.4; Fosite v0.49.0 is
  isolated behind `internal/oidc` adapters;
- final container remains non-root UID/GID 65532 and read-only compatible.

Artifacts are written to ignored `.artifacts/supply-chain/`. A clean scan means
no fixable High/Critical result under the configured gate; it is not a guarantee
that the image has no residual vulnerability.

## Upgrade checklist

1. read the threat model, Client integration guide, migration guide, operations
   guide, and key runbook;
2. back up PostgreSQL and independently stage/backup the private signing key;
3. configure a canonical HTTPS Issuer, Secure `__Host-` cookie, PostgreSQL TLS,
   registration decision, and key mount;
4. stop phase-two writers and apply migrations 6–10 with one actor;
5. verify expected version 10 and run `oneissuer config check` as the service UID;
6. start the service and verify startup Audit, readiness, Discovery, and JWKS;
7. statically create/review Clients, transfer Confidential Secrets once, and
   require S256 in each RP;
8. perform a full monitored Code/UserInfo flow and a restart test;
9. retain the pre-upgrade backup and record the rollback boundary.

## Final verification record

The following gates were rerun from the repository root against the final
phase-three worktree on 2026-08-01. The checked-in GitHub Actions workflow is the
authoritative repeat on push and pull requests.

| Gate | Command | Result |
| --- | --- | --- |
| Module, formatting, and whitespace | `GOPROXY='https://goproxy.cn,direct' go mod tidy`; `make fmt-check`; `git diff --check` | **PASS** — tidy produced no unexpected dependency change and all Go/whitespace checks passed |
| Unit and race tests | `go test ./...`; `go test -race ./...` | **PASS** — every package passed, including the strict example RP and PostgreSQL suites |
| Real PostgreSQL | `go test -run '^TestPostgresIntegration$' -count=1 ./internal/storage/postgres` | **PASS** — real schema-5→10 authority upgrade, signer/Audit/deferred-Commit rollback, canceled/deadline cleanup rollback, concurrency, restart, outage, and recovery contracts passed |
| Vet, lint, and bounded Fuzz | `go vet ./...`; `.tools/bin/golangci-lint run ./...`; `ONEISSUER_FUZZ_TIME=1s ./scripts/fuzz-smoke.sh` | **PASS** — golangci-lint `v2.12.2` reported `0 issues`; all 11 Fuzz targets passed |
| Reachable Go vulnerabilities | `GOTELEMETRY=off .tools/bin/govulncheck ./...` | **PASS** — 0 reachable vulnerabilities; the non-reachable imported-package/module advisories remain documented in the dependency Spike |
| Schema and generated code | `./scripts/check-migrations.sh`; `./scripts/check-generated.sh "$PWD/.tools/bin/sqlc"` | **PASS** — migrations 1–10 matched, including unchanged 1–5 checksums, and sqlc regeneration had no drift |
| Privacy and recorded evidence | `./scripts/check-sensitive-examples.sh`; `./scripts/check-conformance-record.py` | **PASS** — examples were secret-free and the committed matrix/result digests validated |
| Workflow, docs, and OpenAPI | `make workflow-check`; `./scripts/check-doc-links.py`; `REDOCLY_VERSION=2.43.2 ./scripts/check-openapi.sh` | **PASS** — actionlint `v1.7.7` reported no issue, 83 links across 31 Markdown files resolved, and OpenAPI 3.1 validated |
| Web prototype | `cd web && npm ci && npm run check && npm audit --audit-level=high ...` | **PASS** — oxlint, TypeScript, and Vite passed; npm reported 0 vulnerabilities |
| Compose configuration and E2E | `docker compose -f deploy/docker-compose.yml config --quiet`; `ONEISSUER_BUILD_GOPROXY='https://goproxy.cn,direct' make phase-3-smoke` | **PASS** — empty-volume migration/Bootstrap, both S256 Client profiles, prompt/Consent/SSO, missing/wrong verifier, real Code expiry, wrong Secret/replay, exact concurrent metadata, disabled authority, restart/privacy/outage/graceful-shutdown checks passed |
| Final image supply chain | `make container-check` | **PASS** — CycloneDX SBOM validated 162 components, private key material was absent, and pinned Trivy found no fixable High/Critical image vulnerability |
| Static binary metadata | `make build`; `./bin/oneissuer version` | **PASS** — static build reported `v0.1.0-dev.3` with Go `1.26.5` |
| Final repository review | `git diff --check`; `git status`; ignored-artifact and sensitive-pattern review | **PASS** — no tracked private JWK/JWKS, runtime Client Secret, raw Conformance export, `.env`, or generated supply-chain artifact is included |

Definition of Done closure:

- [x] `go mod tidy` leaves no unexpected diff;
- [x] unit and race-enabled Go tests;
- [x] real PostgreSQL integration/concurrency/restart tests;
- [x] `go vet`, golangci-lint, govulncheck, and bounded Fuzz smoke;
- [x] migration checksum and sqlc generated-code checks;
- [x] sensitive examples, Conformance record, OpenAPI, and documentation links;
- [x] Web lint/typecheck/build and high-severity npm audit;
- [x] Compose configuration validation and `make phase-3-smoke`;
- [x] CycloneDX/private-key image inspection and Trivy gate;
- [x] `git diff --check` and final Git/sensitive-artifact review.
