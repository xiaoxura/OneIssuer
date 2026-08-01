# Development guide

## Prerequisites

- Go 1.26.x (the container builder is fixed to 1.26.5);
- Node.js 22.12+ and npm for `web/`;
- Docker Engine with Compose for PostgreSQL and integration tests;
- Make, a POSIX shell, and curl.

Windows contributors should use WSL2 so the same Make and shell commands apply.

## First native run

```bash
cp .env.example .env
make tools
docker compose -f deploy/docker-compose.yml up -d postgres
make migrate-up
make dev
```

The service listens on `http://localhost:8080`; the Web prototype is separate:

```bash
make web
# http://localhost:5173
```

The phase-two login/registration forms are served by Go on the configured Issuer
origin. The Vite mock UI remains separate and must never receive a real password.
Do not add permissive CORS around authentication or management APIs.

## Configuration loading

The Go process reads environment variables only. It does not discover or load
`.env`. `make dev`, `make migrate-up`, and `make migrate-status` source the file
explicitly as a local convenience. See [configuration.md](./configuration.md).

## Quality workflow

Before opening a pull request:

```bash
make generate
make check
make compose-smoke
```

`make check` verifies formatting, generated code, `go vet`, golangci-lint,
race-enabled Go tests, `govulncheck`, a static binary build, Web lint,
TypeScript/Vite build, and high-severity npm audit results. Integration tests
use a real disposable PostgreSQL through Testcontainers when Docker is
available.

Phase-two CI additionally validates migration checksums, OpenAPI `0.1.0-dev.2`,
privacy-sensitive examples, and bounded fuzz smoke targets. Run the pinned
scripts rather than an unversioned global OpenAPI/Fuzz tool.

Generated files under `internal/storage/postgres/sqlcgen/` must never be edited
by hand. Change `queries/*.sql`, run `make generate`, and commit both source and
generated output. `make generate-check` copies queries and production migrations
and regenerates into a temporary directory,
so it does not mutate the worktree.

## Build metadata

```bash
make build VERSION=v0.1.0-dev.2 COMMIT="$(git rev-parse --short HEAD)"
./bin/oneissuer version
```

The Makefile and Dockerfile inject version, commit, and UTC build time using
linker values. Process logs and `oneissuer_build_info` expose the same bounded
metadata.

## Test organization

- package unit/Fuzz tests cover normalization, Argon2id, Client URI/scope/Secret,
  opaque cursors/tokens, Cookie/CSRF, audit whitelist, configuration, request IDs,
  proxy trust, metrics, panic privacy, and shutdown bounds;
- PostgreSQL/Testcontainers tests cover all five production migrations,
  registration/login, concurrent uniqueness/Bootstrap, Session ownership and
  revocation, Client Secret rotation, final-admin protection, audit privacy, and
  reopen persistence;
- `scripts/smoke-compose.sh` verifies the final non-root empty-volume phase-two
  behavior, including initial/repeated migration, one-shot Bootstrap, hosted
  registration/login, Session rotation/CSRF/revocation/logout, Public and
  Confidential Client/Secret handling, audit persistence, restart, database
  outage recovery, graceful shutdown, and clear-value log/read-model privacy.

Tests must not depend on global ports or shared databases. Test-only migrations
live under `internal/storage/postgres/testdata/migrations` and are absent from
the final image.

## Shutdown behavior

On SIGINT or SIGTERM, the process:

1. sets readiness to false;
2. stops accepting new connections;
3. waits for active HTTP work within `ONEISSUER_SHUTDOWN_TIMEOUT`;
4. force-closes and exits non-zero if that deadline is exceeded;
5. closes the PostgreSQL pool after HTTP shutdown.

Use `docker compose stop oneissuer` or `Ctrl+C` to exercise the normal path.
