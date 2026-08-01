# OneIssuer

OneIssuer is a lightweight, self-hosted, **single-Issuer** identity service.
The repository is currently at **`v0.1.0-dev.2` / phase two**. It implements
identity, password, browser-session, OIDC Client registry, administrator, and
audit foundations on top of the phase-one Go/PostgreSQL runtime.

> [!WARNING]
> OneIssuer is not yet a complete OpenID Connect Provider and is not
> production-ready. Discovery, JWKS, Authorize, Token, ID Token, Access Token,
> UserInfo, Revocation, and Introspection are not implemented. The phase-two
> hosted pages authenticate users only to OneIssuer itself; they do not emit a
> fake OAuth/OIDC success response. The React application under `web/` remains
> an independently runnable mock UI and is not an identity source of truth.

## What phase two provides

- one process, one PostgreSQL database, and one configured Issuer, with no
  tenant, Realm, Organization, or hidden multi-tenant mode;
- normalized users with stable opaque subjects, `user`/`admin` roles, active or
  disabled status, and Argon2id password credentials;
- enumeration-resistant login, deny-by-default self-registration, and
  server-hosted bilingual login/registration/logout forms;
- opaque digest-only login sessions, bounded absolute and idle lifetimes,
  session rotation, revocation, and same-origin CSRF protection;
- public and confidential Client records, exact Redirect/Logout URI matching,
  fixed scopes, and one-time digest-only Client Secrets;
- an explicit, concurrency-safe first-administrator Bootstrap command;
- current-user session APIs and administrator Users, Clients, Sessions, and
  append-only Audit APIs;
- short-lived, single-consumption server-side authentication transactions for a
  future protocol adapter;
- low-cardinality identity/session/client/audit metrics and privacy-safe logs;
- five embedded production migrations, sqlc generation, Testcontainers tests,
  and non-root Compose assets.

The detailed implementation and completion criteria are in
[`docs/phase-2-development-plan.md`](./docs/phase-2-development-plan.md). The
security decisions and residual risks are in
[`docs/phase-2-threat-model.md`](./docs/phase-2-threat-model.md).

## Docker-only local demonstration

Docker with Compose is the only prerequisite for this path. The example stack
binds HTTP and PostgreSQL to loopback and uses intentionally local-only database
credentials; never expose or reuse it as a production manifest.

```bash
cp .env.example .env
# For an intentional local registration demo, set this exact non-secret flag:
sed -i 's/ONEISSUER_REGISTRATION_ENABLED=false/ONEISSUER_REGISTRATION_ENABLED=true/' .env

docker compose -f deploy/docker-compose.yml build migrate oneissuer
docker compose -f deploy/docker-compose.yml up -d postgres
docker compose -f deploy/docker-compose.yml run --rm migrate

# Interactive TTY input is hidden and confirmed; no password argument exists.
docker compose -f deploy/docker-compose.yml run --rm --no-deps oneissuer \
  admin bootstrap --username admin --email admin@example.invalid

docker compose -f deploy/docker-compose.yml up -d oneissuer
curl -i http://localhost:8080/health/live
curl -i http://localhost:8080/health/ready
```

Open `http://localhost:8080/login` to sign in. Use `/register` only when the
registration flag was intentionally enabled. An authenticated browser obtains a
new HttpOnly session cookie; the server stores only its SHA-256 digest.

A second Bootstrap attempt fails with a stable non-zero conflict exit and does
not print or change the existing administrator. `serve` verifies migration
compatibility but **never changes the schema**.

Clean up the development volume:

```bash
docker compose -f deploy/docker-compose.yml down -v --remove-orphans
```

The automated empty-volume, Bootstrap, authentication, revocation, persistence,
and privacy demonstration is:

```bash
make compose-smoke
```

## Native development

Install Go 1.26.x, Node.js 22.12 or newer, npm, Docker, and Make. Then:

```bash
cp .env.example .env
make tools
docker compose -f deploy/docker-compose.yml up -d postgres
make migrate-up

# Bootstrap once using hidden terminal input.
go run ./cmd/oneissuer admin bootstrap \
  --username admin --email admin@example.invalid

make dev
```

The application never loads `.env` itself. Make targets source it only as a
local convenience; deployments must inject trusted environment variables.

Common commands:

```text
make generate        regenerate sqlc output
make generate-check  verify generated code without mutating the worktree
make fmt             format handwritten Go
make lint            lint Go and Web
make test            run race-enabled unit and integration tests
make check           run the complete Go and Web quality gate
make migrate-up      apply embedded production migrations explicitly
make migrate-status  show current and expected migration versions
make web             run the independent Vite mock prototype on :5173
make compose-smoke   run the complete local acceptance scenario
```

The binary contract is:

```text
oneissuer serve
oneissuer migrate up
oneissuer migrate status
oneissuer migrate version
oneissuer admin bootstrap --username <name> --email <address> [--password-stdin]
oneissuer config check
oneissuer version
```

`admin bootstrap` deliberately rejects `--password`. `--password-stdin` expects
two matching newline-terminated entries and is intended only for a controlled
secret/pipe; see [`docs/operations.md`](./docs/operations.md).

## Implemented HTTP boundary

- hosted HTML: `GET/POST /login`, `GET/POST /register`, `POST /logout`, and
  `GET /auth/complete`;
- current user JSON: `/api/v1/me` and `/api/v1/me/sessions...`;
- administrator JSON: `/api/admin/v1/me`, Users, Clients, Sessions, and Audit;
- operations: `/health/live`, `/health/ready`, and `/metrics`.

The exact JSON contract is [`api/openapi.yaml`](./api/openapi.yaml). It documents
Cookie authentication, `X-CSRF-Token`, opaque pagination, stable error classes,
and the one-time Secret response. It intentionally excludes HTML forms and all
unimplemented OIDC endpoints.

`/metrics` is operational rather than a public business API. Restrict it with a
reverse proxy, firewall, or network policy. Metric labels never include request
IDs, raw URLs, user/client IDs, usernames, emails, or IP addresses.

## Configuration and operations

- [Configuration reference](./docs/configuration.md)
- [Migration and sqlc guide](./docs/migrations.md)
- [Operations, Bootstrap, backup, and retention](./docs/operations.md)
- [Troubleshooting](./docs/troubleshooting.md)
- [Phase-two release notes](./docs/phase-2-release-notes.md)
- [Phase-three protocol handoff](./docs/phase-3-handoff.md)
- [Phase-three development plan](./docs/phase-3-development-plan.md)

Production validation requires an explicit HTTPS Issuer, PostgreSQL TLS, Secure
`__Host-` cookies, and an explicit registration decision. Argon2 memory multiplied
by maximum hashing concurrency is an intentional capacity budget and must be
benchmarked for the deployment.

## Repository layout

```text
cmd/oneissuer/                 binary and CLI
internal/app/                  dependency assembly, cleanup, and lifecycle
internal/identity/             users, normalization, passwords, login policy
internal/session/              opaque sessions, cookies, CSRF, revocation
internal/client/               Client URI/scope/secret rules
internal/authflow/             short-lived server-side flow context
internal/admin/                Bootstrap and administrator use cases
internal/audit/                fixed append-only event schema
internal/httpserver/           hosted forms, JSON APIs, middleware, health
internal/observability/        slog and Prometheus setup
internal/storage/postgres/     pgx/sqlc adapters and transactions
migrations/                    embedded production Goose migrations
queries/                       sqlc query source
api/openapi.yaml               implemented phase-two JSON contract
deploy/docker-compose.yml      local PostgreSQL/migrate/application stack
web/                           independent bilingual mock prototype
```

## Project documents

See the [documentation index](./docs/README.md), [contributor guide](./CONTRIBUTING.md),
[security policy](./SECURITY.md), and [code of conduct](./CODE_OF_CONDUCT.md).

## License

Copyright OneIssuer contributors. Licensed under the
[Apache License 2.0](./LICENSE).
