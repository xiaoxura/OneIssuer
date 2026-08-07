# OneIssuer

OneIssuer is a lightweight, self-hosted, **single-Issuer** identity service.
The current repository default is **`v0.1.0-dev.4`**; this working tree
implements phase four with release gates still pending. It joins
the existing identity, password, browser-session, Client registry,
administrator, and audit foundations to a minimal OpenID Connect Authorization
Code Flow.

> [!WARNING]
> OneIssuer is a development release, not a production-ready identity product.
> It has not been certified by the OpenID Foundation. Complete a deployment-
> specific security review, HTTPS/reverse-proxy design, key-management plan,
> backup rehearsal, capacity test, and incident runbook before exposing it.

## Implemented profile

- one process, one PostgreSQL database, and one canonical Issuer; no tenant,
  Realm, Organization, or hidden multi-tenant mode;
- OIDC Discovery and a public-only JWKS;
- Authorization Code Flow through `/oauth2/authorize`;
- S256 PKCE required for **both** Public and Confidential Clients;
- Public Client authentication method `none` and Confidential Client method
  `client_secret_basic`;
- hosted login, optional registration, Session reuse, `prompt=none`, `login`,
  `consent`, and `create`, plus `max_age`;
- hosted Consent and persistent `(user, client)` grants;
- explicit `offline_access` Consent, rotating Refresh Token families, reuse
  detection, Revocation, and owner-bound Introspection;
- owner-bound Grant management, Session/Grant/family cascade revocation, and
  RP-Initiated Logout with transaction-bound confirmation;
- digest-only, short-lived, single-use Authorization Codes with atomic exchange;
- RS256 ID Tokens and RFC 9068 JWT Access Tokens;
- UserInfo with scope-minimized `profile` and `email` claims and current
  User/Client/Grant status checks;
- administrator Users, Clients, Sessions, and append-only Audit APIs;
- explicit migrations through production schema version 15, low-cardinality
  metrics, non-root/read-only Compose services, an A/B example RP, SBOM and
  container vulnerability gates.

The Discovery document is the machine-readable protocol contract. The supported
scope set is exactly `openid`, `profile`, `email`, and `offline_access`.

### Intentionally not implemented

Phase four does **not** implement Dynamic Client Registration, `client_secret_post`,
Implicit/Hybrid flows, PAR/JAR/JARM, DPoP, mTLS, or a
general-purpose resource-server authorization model. Requests for these
capabilities fail rather than return placeholder success, and Discovery does not
advertise them.

An Access Token issued here is intended only for this OneIssuer instance's
UserInfo endpoint. Do not treat it as a general business API token.

## Automated phase-four demonstration

With Go 1.26.x, Docker with Compose, Make, and curl installed:

```bash
make tools
make phase-4-smoke
```

The smoke test creates a disposable signing key and empty database, applies all
migrations explicitly, Bootstraps an administrator, creates Public Client A and
Confidential Client B, and verifies registration, Session reuse, separate
Consent, offline Access and rotating Refresh families, Revocation,
owner-bound Introspection and Grant management, RP-Initiated Logout, S256 Code
exchange, ID Token/UserInfo processing, concurrent exchanges, disabled
principals, restart persistence, privacy, database outage, non-root/read-only
operation, and graceful shutdown. It removes the stack and clear runtime
material on exit.

The Relying Party under `examples/oidc-client/` is an interoperability example,
**not a production SDK**. It validates state, nonce, Issuer, Audience, signature,
time claims, the Token endpoint's actual granted Scope, and UserInfo subject
instead of merely decoding JWTs. Its in-memory Session store is capped at 1024
entries and fails closed when full.

## Native local development

```bash
cp .env.example .env
mkdir -p .oneissuer-dev
go run ./cmd/oneissuer keys generate \
  --alg RS256 --out .oneissuer-dev/signing-key.jwk

set -a
. ./.env
set +a

make tools
docker compose -f deploy/docker-compose.yml up -d postgres
go run ./cmd/oneissuer migrate up

# Hidden TTY input is requested twice; there is no password argument.
go run ./cmd/oneissuer admin bootstrap \
  --username admin --email admin@example.invalid

go run ./cmd/oneissuer serve
```

Then inspect:

```bash
curl --fail http://localhost:8080/health/ready
curl --fail http://localhost:8080/.well-known/openid-configuration
curl --fail http://localhost:8080/oauth2/jwks
```

`serve` verifies that migrations and the active RS256 signing key are usable,
but **never changes the schema**. The application never loads `.env` itself;
the shell and selected Make targets source it only as a local convenience.

For the non-root Compose service, the mounted private JWK must remain a regular,
non-symlink file with no group/world permission bits (normally mode `0600`) and
must be readable by runtime UID/GID `65532`. Follow the
[key runbook](./docs/key-rotation-runbook.md); never relax the file to `0644`.

Clean up the local database volume:

```bash
docker compose -f deploy/docker-compose.yml \
  --profile oidc-demo down -v --remove-orphans
```

## Protocol endpoints

| Endpoint | Method/profile |
| --- | --- |
| `/.well-known/openid-configuration` | `GET`; exact implemented metadata |
| `/oauth2/jwks` | `GET`; public RSA keys only, ETag and five-minute cache |
| `/oauth2/authorize` | browser `GET`; `response_type=code`, query response mode, S256 |
| `/oauth2/token` | `POST application/x-www-form-urlencoded`; Code and rotating Refresh Grants |
| `/oauth2/userinfo` | `GET` or empty-body `POST`; Bearer header only |
| `/oauth2/revoke` | `POST application/x-www-form-urlencoded`; RFC 7009 uniform response |
| `/oauth2/introspect` | `POST application/x-www-form-urlencoded`; Confidential owning Client only |
| `/oauth2/logout` | `GET` or form `POST`; RP-Initiated Logout with hosted confirmation |

Hosted browser routes are `GET/POST /login`, `GET/POST /register`,
`GET/POST /consent`, `POST /logout`, and internal continuation routes. The
current-user and administrator JSON APIs remain documented in
[`api/openapi.yaml`](./api/openapi.yaml). Standard OIDC endpoints are
intentionally not duplicated in that management OpenAPI document.

`GET /oauth2/authorize` and the login/registration form endpoints have bounded
per-client and process-wide token buckets before database/password work. Each
issued pre-authentication form also permits at most five submissions. These
in-process controls complement, and do not replace, an edge/distributed limiter.

Redirect URIs are registered and compared byte-for-byte. Production Clients use
HTTPS; explicit loopback HTTP is allowed only for local development. State,
nonce, and PKCE values are never authority stores and are not logged or audited.

## Token and lifecycle delivery semantics

Authorization Code consumption and Access Token metadata insertion commit in one
PostgreSQL transaction. Delivery is therefore **at most once**: if the database
commits but the connection fails before the Client receives the response, retrying
the same Code returns `invalid_grant`. OneIssuer cannot reproduce the original
Token Response; the Client must start a new authorization request.

Disabling a User or Client causes exchange and UserInfo to fail closed. Re-
enabling it does not restore a consumed Code; only a still-unconsumed and
unexpired Code can proceed. Expired Code and Access Token metadata are retained
for an additional 24 hours for bounded security evidence, while every read path
enforces expiry immediately. Cleanup commits in batches of 250 and reports
already committed rows even if a later batch reaches its operation deadline.

Refresh Tokens are clear-value, single-use generations held only by the Client;
successful exchange atomically replaces the generation. Reuse or Revocation
invalidates the family and linked live Access metadata. JWTs presented to external
resource servers cannot be revoked centrally; OneIssuer UserInfo and Introspection
observe lifecycle state immediately.

## Common development commands

```text
make generate                  regenerate sqlc output
make generate-check            verify generated code without mutation
make fmt                       format handwritten Go
make lint                      lint Go and Web
make test                      run race-enabled Go tests
make check                     run the Go/Web quality gate
make contract-check            validate migrations, docs, workflow, Conformance, OpenAPI
make migrate-up                explicitly apply embedded migrations
make migrate-status            display current and expected versions
make phase-4-smoke             run the complete disposable Compose acceptance test
make sbom                      generate a CycloneDX image SBOM
make container-scan            reject fixable High/Critical image vulnerabilities
make container-check           run SBOM, private-key, and vulnerability gates
```

The binary contract is:

```text
oneissuer serve
oneissuer migrate up
oneissuer migrate status
oneissuer migrate version
oneissuer admin bootstrap --username <name> --email <address> [--password-stdin]
oneissuer keys generate --alg RS256 --out <private-jwk>
oneissuer keys public --in <private-jwk> --out <public-jwks>
oneissuer config check
oneissuer version
```

`admin bootstrap` deliberately rejects `--password`. `--password-stdin` expects
two matching newline-terminated entries from a controlled secret source; see the
[operations guide](./docs/operations.md).

## Configuration and operations

- [Documentation index](./docs/README.md)
- [OIDC Client integration](./docs/oidc-client-integration.md)
- [Configuration reference](./docs/configuration.md)
- [Migration and sqlc guide](./docs/migrations.md)
- [Operations, backup, and retention](./docs/operations.md)
- [Signing-key generation and rotation](./docs/key-rotation-runbook.md)
- [Troubleshooting](./docs/troubleshooting.md)
- [Phase-three release notes](./docs/phase-3-release-notes.md) (historical baseline)
- [Conformance evidence and limitations](./docs/phase-3-conformance.md)
- [Phase-four Conformance matrix and result](./conformance/phase-4/matrix.json)
- [Phase-four development plan](./docs/phase-4-development-plan.md)
- [Phase-four threat model](./docs/phase-4-threat-model.md)
- [ADR 0003: phase-four token lifecycle](./docs/adr/0003-phase-four-token-lifecycle.md)
- [Phase-four release notes](./docs/phase-4-release-notes.md)

## Repository layout

```text
cmd/oneissuer/                 binary and CLI
internal/identity/             users, normalization, credentials
internal/session/              opaque sessions, cookies, CSRF, revocation
internal/client/               Client URI/scope/secret rules
internal/authflow/             short-lived server-side browser flow context
internal/authorization/        Consent decisions, Codes, and S256
internal/consent/              persistent per-User/Client grants
internal/keystore/             active RS256 signer and public verification ring
internal/oidc/                 wire profile and Fosite adapter boundary
internal/token/                ID/Access Token and UserInfo authority
internal/httpserver/           protocol, hosted forms, APIs, health, metrics
internal/storage/postgres/     pgx/sqlc adapters and atomic transactions
migrations/                    embedded production Goose migrations
queries/                       sqlc query source
api/openapi.yaml               management/current-user JSON contract
examples/oidc-client/          strict server-side interoperability example
conformance/phase-3/           historical secret-free suite matrix and result summary
conformance/phase-4/           current secret-free suite matrix and pending evidence
deploy/docker-compose.yml      local PostgreSQL/application/example stack
web/                           independent non-authoritative React mock
```

## Project documents

See the [contributor guide](./CONTRIBUTING.md),
[security policy](./SECURITY.md), and [code of conduct](./CODE_OF_CONDUCT.md).

## License

Copyright OneIssuer contributors. Licensed under the
[Apache License 2.0](./LICENSE).
