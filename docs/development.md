# Development guide

## Prerequisites

- Go 1.26.x (the container builder is fixed to 1.26.5 and pinned by digest);
- Node.js 22.12+ and npm for `web/`;
- Docker Engine with Compose for PostgreSQL, integration tests, examples, image
  scans, and acceptance tests;
- Make, a POSIX shell, Python 3, and curl.

Windows contributors should use WSL2 so the same Make and shell commands apply.

## First native run

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
go run ./cmd/oneissuer serve
```

The service listens on `http://localhost:8080`. Verify the complete protocol
surface only through its actual Discovery document:

```bash
curl --fail http://localhost:8080/.well-known/openid-configuration
curl --fail http://localhost:8080/oauth2/jwks
```

The React prototype is separate:

```bash
make web
# http://localhost:5173
```

Hosted login, registration, and Consent are served by Go on the configured
Issuer origin. The Vite mock must never receive a real password, Session, Code,
Token, Client Secret, or private key and is not a source of identity/protocol
state. Do not add permissive CORS around authentication, protocol, or management
routes.

## Configuration loading

The Go process reads environment variables only. It does not discover or load
`.env`. `make dev`, `make migrate-up`, and `make migrate-status` source it as a
local convenience. See [configuration.md](./configuration.md).

Key files under `.oneissuer-dev/` are ignored local material. Never use a checked-
in deterministic key outside a test fixture. The service loader requires a
regular, non-symlink private file with mode `0600`; Compose additionally needs
runtime UID/GID `65532` to own/read the mount. See
[key-rotation-runbook.md](./key-rotation-runbook.md).

## Quality workflow

Before opening a pull request, run the relevant focused tests while iterating,
then the complete release gates:

```bash
make generate
make contract-check
make check
make phase-4-smoke
make container-check
git diff --check
```

`make check` verifies formatting, generated sqlc code, migration checksums,
sensitive public examples, `go vet`, golangci-lint, race-enabled Go tests,
bounded Fuzz smoke, `govulncheck`, a static binary build, Web lint/typecheck/build,
high-severity npm audit results, and the management OpenAPI document.

`make contract-check` additionally validates the secret-free historical Phase-three
record and the Phase-four matrix/result scaffold.
It also runs pinned actionlint over GitHub Actions workflows and checks local
Markdown link targets.
`make phase-4-smoke` is the disposable real-PostgreSQL A/B OIDC acceptance gate,
including offline Consent, Refresh rotation, lifecycle endpoint, Grant, and
logout checks; `make phase-3-smoke` remains the compatibility alias.
`make container-check` generates a CycloneDX SBOM, rejects private-key artifacts,
and rejects fixable High/Critical findings in the final runtime image. Reports go
under ignored `.artifacts/`; do not publish a raw Conformance export until it has
been reviewed for runtime Client Secrets and other clear values.

Useful individual commands:

```bash
go test ./...
go test -race ./...
go test -run '^TestPostgresIntegration$' -count=1 \
  ./internal/storage/postgres
go vet ./...
.tools/bin/golangci-lint run ./...
ONEISSUER_FUZZ_TIME=1s ./scripts/fuzz-smoke.sh
.tools/bin/govulncheck ./...
./scripts/check-migrations.sh
./scripts/check-generated.sh "$PWD/.tools/bin/sqlc"
./scripts/check-sensitive-examples.sh
./scripts/check-conformance-record.py
./scripts/check-openapi.sh
docker compose -f deploy/docker-compose.yml config
```

The real PostgreSQL integration and Compose gates require a working Docker
socket. Unit-only results are not a substitute.

## Generated code and migration discipline

Files under `internal/storage/postgres/sqlcgen/` must never be edited by hand.
Change `queries/*.sql`, add rather than rewrite a migration, run `make generate`,
and commit source plus generated output. `make generate-check` regenerates into a
temporary directory without mutating the worktree.

Production migrations 00001–00011 are frozen phase-three input. The checksum gate
must prove their bytes are unchanged. The current expected schema is version 15;
see [migrations.md](./migrations.md).

All released migration bytes through 00011 are checksum-pinned. The Dockerfile
frontend, Go builder, Alpine runtime, and Compose PostgreSQL image are likewise
digest-pinned. Base refreshes are explicit review changes; do not add a mutable
build-time `apk upgrade` step.

## Build metadata

```bash
make build VERSION=v0.1.0-dev.4 \
  COMMIT="$(git rev-parse --short=12 HEAD)"
./bin/oneissuer version
```

The Makefile and Dockerfile inject version, commit, and UTC build time through
linker values. Process logs and `oneissuer_build_info` expose the same bounded
metadata. Never inject a key, Secret, credential, database URL, Code, or Token as
build metadata or a Docker build argument.

## Test organization

- unit/table/Fuzz tests cover configuration and Issuer canonicalization; key/JWK
  validation; Client URI/scope/Secret rules; Session/Cookie/CSRF; Authorize
  parsing, redirect safety, prompt/max-age; Consent; Code/PKCE; Basic Client
  authentication; JWT claims/signatures; UserInfo; audit/privacy; metrics;
  request IDs; proxy trust; panic recovery; and shutdown bounds;
- real PostgreSQL/Testcontainers tests cover all fourteen production migrations,
  a populated version-5 authority upgrade, identity/Client/Session/Audit
  lifecycle, transaction/Grant/Code atomicity, concurrent approval and
  exchange, mid-flow disabled User/Client checks, signer/Audit/deferred-Commit
  rollback, atomic five-attempt form reservation, monotonic User/Client optimistic
  versions, first-batch cleanup rollback, later-batch partial progress, retention,
  and reopen persistence;
- `scripts/smoke-compose.sh` exercises an empty volume, explicit migration,
  Bootstrap, Public A and Confidential B, `prompt=create/none/login/consent`,
  Session reuse/rotation, separate Consent, S256 exchange, ID Token/UserInfo,
  missing/wrong verifier and real Code expiry, replay/concurrent metadata,
  offline Consent, Refresh rotation/replay, Revocation/Introspection, Grant and
  RP logout semantics, disabled principals, restart, database outage/recovery, privacy surfaces,
  non-root/read-only containers, and graceful shutdown;
- `conformance/phase-3/` records the pinned, applicable non-certification OpenID
  Conformance Suite subset and its limitations; `conformance/phase-4/` freezes
  the applicable lifecycle modules without claiming they have run;
- `scripts/container-security.sh` inspects the final runtime image and writes
  reproducible tool/version/digest evidence.

Tests must not depend on shared ports or databases. Test-only migrations live in
`internal/storage/postgres/testdata/migrations` and are absent from the final
image. Test keys must be clearly synthetic and must not be copied into examples,
Compose, release artifacts, or production.

## Example Relying Party development

`examples/oidc-client/` is built as a separate server-side executable. It keeps
state, nonce, and verifier in an in-memory server Session; uses Discovery;
requires S256; validates RS256 signature and ID Token claims; compares UserInfo
`sub`; authorizes optional claims from the Token endpoint's actual granted Scope;
and keys its mock JIT identity by `(iss, sub)`. Its Session map is capped at 1024,
rejects stale re-insertion/double completion, and never renders or logs Tokens.

Run the tested A/B form through `make phase-4-smoke`. Do not turn this example
into a generic SDK by adding loose metadata parsing, disabled verification,
browser localStorage, or a fallback Client authentication method.

## Conformance updates

The current Phase-four suite release, source commit, container digests, selected
modules, configuration placeholders, pending results, and non-applicable
categories are documented in the [Phase-four matrix](../conformance/phase-4/matrix.json)
and [Phase-four result](../conformance/phase-4/results/2026-08-03.json). The
Phase-three record remains the historical baseline. A rerun must:

1. use a temporary HTTPS Issuer and throwaway static Clients;
2. keep clear Client Secrets out of Git and console output;
3. export raw evidence into permission-restricted `.artifacts/conformance/`;
4. record SHA-256 digests and secret-free summaries under `conformance/phase-4/`;
5. rerun `./scripts/check-conformance-record.py`;
6. never claim OpenID Foundation certification.

Do not weaken mandatory S256 or advertise an unimplemented feature merely to make
an upstream test module runnable.

## Shutdown behavior

On SIGINT or SIGTERM, the process:

1. sets readiness false;
2. stops accepting new connections;
3. waits for active HTTP work within `ONEISSUER_SHUTDOWN_TIMEOUT`;
4. force-closes and exits non-zero if that deadline is exceeded;
5. stops the cleanup loop and closes PostgreSQL after HTTP shutdown.

Use `docker compose stop oneissuer` or `Ctrl+C` to exercise the normal path.
