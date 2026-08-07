# OneIssuer `v0.1.0-dev.4` Phase-four release notes

Status: **Engineering snapshot; release gates pending**  
Evidence refreshed: 2026-08-07  
Working-tree/default artifact: `v0.1.0-dev.4` (release gates remain pending)  
Previous authority: schema 11 / phase-three binary  
Target schema: **15**

> [!WARNING]
> This snapshot is not production-ready and is not OpenID Foundation
> certification evidence. The Phase-four Conformance record intentionally marks
> every applicable module `NOT_RUN`. The local PostgreSQL and Compose checks
> below are engineering evidence only. The current browser rerun is blocked
> until a visible Chrome exposes its DevTools endpoint, and the browser edge-case
> matrix is not checked in as a runnable artifact.

## Delivered in the working tree

- explicit `offline_access` Consent and discovery metadata;
- digest-only, single-use rotating Refresh Token families with rolling and
  absolute lifetime limits and fail-closed reuse detection;
- Access Token issuance-source metadata, immediate UserInfo/Introspection
  checks, RFC 7009-style uniform Revocation, and owner-bound Introspection;
- owner-bound Grant list/revoke APIs with Session, family, and live Access
  cascade semantics;
- transaction-bound RP-Initiated Logout with clean GET/POST handling,
  cookie-only confirmation, exact Redirect URI validation, bounded CSRF, replay
  rejection, and cookie cleanup;
- bounded protocol endpoint rate limiting, 250-row lifecycle cleanup, metrics,
  A/B example coverage, and updated operational/configuration guidance.
- one bounded transaction retry for PostgreSQL `40001`/`40P01` operation
  failures; begin and commit failures remain terminal, and retryable attempts
  reset transient responses, candidates, counters, and Audit observations.

## Delivery and replay semantics

Code exchange and Refresh rotation commit metadata, authority changes, and Audit
events before an HTTP response is written. A disconnected response is therefore
at-most-once: a replayed Code or consumed Refresh generation returns
`invalid_grant`, and the Client must start a new authorization. Reuse revokes the
whole family and linked live Access metadata without a grace window.

Refresh scope narrowing affects only the new Access Token. The replacement
Refresh generation retains the presented family's original Scope authority and
never expands it. Clear Token values are CSPRNG material and are never stored in
PostgreSQL, logs, metrics, Audit, or responses after issuance.

## Introspection and logout

Introspection accepts only the owning Confidential Client and returns a fixed
inactive body for unknown, cross-owner, expired, revoked, disabled, or
otherwise invalid values. Revocation has the same non-oracle behavior for
unknown and already-inactive values.

RP logout never mutates authority during a clean request. Bind/confirm performs
the exact Session and transaction checks, then atomically revokes the Session
binding, Refresh families, and live Access metadata before returning a verified
post-logout redirect with its matching `state`. Front-channel and back-channel
logout remain out of scope.

## Database and rollback boundary

Migrations 00012-00015 extend a populated schema-11 authority to schema 15.
Migration 00013 preserves legacy Code-sourced Access rows and creates no
Refresh authority for them. Migration 00015 permits only the foreign-key-driven
detach of Code-sourced Access metadata after Code cleanup while retaining strict
authority checks for inserts and all other mutations. Refresh cleanup retires
generations before families and skips a family while Access metadata still
references it; protocol cleanup must run before the final family pass.

Production rollback is a verified pre-upgrade backup restore. Down migrations
are disposable-database tools only. Migration 00015 refuses to restore the
schema-14 constraints while detached Code-sourced Access rows exist; Migration
00013 separately refuses a downgrade when a refresh-sourced or detached Access
row exists. These checks prevent a partially representable downgrade.

## Evidence status

| Gate | Status in this snapshot | Record |
| --- | --- | --- |
| sqlc generation/checksums | PASS | `make check`, `make contract-check`, and `make migration-check` on 2026-08-06 |
| Go compile, race, unit, lint, and Fuzz smoke | PASS | `make check` on 2026-08-06; Fuzz smoke uses the checked-in 5-second per-target budget |
| Go vulnerability database lookup | PASS | `govulncheck ./...` reported no reachable vulnerabilities |
| real PostgreSQL upgrade/lifecycle/cleanup | PASS | `make integration-test` plus `go test -count=1 -race -run Integration ./internal/storage/postgres ./internal/httpserver ./internal/app` |
| A/B Compose acceptance | PASS for current source/image | `BUILDX_BUILDER=default make phase-4-smoke` rebuilt `v0.1.0-dev.4` and passed on 2026-08-06; no run artifact is committed |
| CycloneDX SBOM | PASS | `make container-check` validated 162 components in `.artifacts/supply-chain/oneissuer.cdx.json` |
| Trivy High/Critical scan | PASS | On 2026-08-07, the unchanged `make container-check` target used the pinned Trivy 0.72.0 scanner and a fresh, digest-verified official GHCR database; `.artifacts/supply-chain/trivy-high-critical.json` is valid and contains 0 High/Critical findings |
| browser GET/POST/cookie/redirect matrix | BLOCKED in current rerun | Vite returned HTTP 200, but Chrome auto-connect found no `DevToolsActivePort`; desktop/mobile layout, focus, console/network, and RP Logout edge cases remain unverified after the fixes |
| bounded serialization retry and lifecycle interleavings | PASS for the checked-in PostgreSQL suite | Race-enabled tests cover bounded retry, authority cascades, batch boundaries, concurrent revocation/lock ordering, and cleanup sequencing |
| npm audit advisory lookup | PASS | `make web-check` reported 0 vulnerabilities |
| Phase-four Conformance | `NOT_RUN` | [`matrix.json`](../conformance/phase-4/matrix.json), [`2026-08-03.json`](../conformance/phase-4/results/2026-08-03.json) |

The Trivy database was recovered from the official
`ghcr.io/aquasecurity/trivy-db:2` OCI artifact with resumable Range requests
after non-resumable scanner downloads were interrupted. The manifest and sole
database layer were pinned and SHA-256 verified, the layer size, media type,
archive paths, schema version, and update window were validated, and the local
download-completion timestamp was recorded without changing the upstream
`UpdatedAt` or `NextUpdate` values. The exact digests and checks are retained in
`.artifacts/supply-chain/trivy-db-provenance.json`; the original project target
then completed without skip-update or severity overrides.

## Residual limits

JWT resource servers that validate Access Tokens without calling OneIssuer can
observe revocation only after their own bounded cache expires. Logout and
redirect interoperability is intentionally narrower than a complete OpenID
profile: a verified ID Token Hint or registered Client context is required, and
front-/back-channel channels are not advertised. The repository remains a
single-Issuer development service with no Dynamic Client Registration, PAR/JAR,
DPoP, mTLS, or certification claim.
