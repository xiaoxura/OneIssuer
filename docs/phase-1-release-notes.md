# Phase one release notes — `v0.1.0-dev.1`

Date: 2026-08-01  
Status: implemented and verified

## Delivered

- modular Go foundation with `serve`, migration, config-check, and version CLI;
- aggregate typed configuration validation and privacy-safe diagnostics;
- pgxpool, Goose metadata/migration commands, and sqlc-generated readiness ping;
- live/ready/metrics endpoints, bounded request IDs, stable JSON errors,
  structured access logs, panic recovery, and security headers;
- signal-driven readiness drain and bounded graceful HTTP/database shutdown;
- non-root multi-stage image and local PostgreSQL/migrate/application Compose;
- fixed-version Go tooling, Go/Web/container/security CI, and onboarding docs;
- unchanged independently buildable bilingual Web mock prototype.

No identity/OIDC/admin business behavior, multi-tenant field, or placeholder
business table/module was introduced.

## Verification record

The following results were collected from the current worktree on 2026-08-01.
They are execution evidence rather than implementation intent.

| Gate | Command | Result |
| --- | --- | --- |
| Go + Web quality | `make check` | PASS — format and generated-code checks, Vet, golangci-lint, race-enabled unit/integration tests, govulncheck, static binary build, Web lint/type-check/build, and high-severity npm audit all passed |
| Empty-volume stack | `ONEISSUER_SMOKE_HTTP_PORT=18080 ./scripts/smoke-compose.sh` | PASS — started from an empty volume and completed all health, fault, recovery, privacy, and shutdown assertions; `18080` was used only because another local project owned shared-host port `8080` |
| Image user | `docker image inspect oneissuer:v0.1.0-dev.1 --format '{{.Config.User}}'` plus effective UID/GID check | PASS — configured and effective identity is `65532:65532` |
| Image vulnerabilities | Trivy `0.69.3`, vulnerability scanner, `--ignore-unfixed --severity HIGH,CRITICAL` | PASS — Alpine packages: 0; Go binary: 0 High/Critical vulnerabilities |

The Compose smoke script asserts Live/Ready/Metrics, response request ID,
PostgreSQL outage (`live=200`, `ready=503`), automatic recovery, and a zero exit
code after SIGTERM. See the CI container job for the same repeatable evidence.

The PostgreSQL integration suite used a real Testcontainers PostgreSQL instance
and covered connection lifecycle, maximum-connection configuration, sanitized
authentication failures, empty-database migration metadata, idempotent Up,
test-only Down/Up, dependency outage, and automatic readiness recovery. The
production `migrations/` directory remains free of placeholder business schema.

The completion audit also confirmed that third-party GitHub Actions are pinned
to full commit SHAs, production code contains no tenant/OIDC placeholder module,
and tool and container references do not use floating `latest` versions.
