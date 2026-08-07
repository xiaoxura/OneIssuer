# Contributing to OneIssuer

Thank you for improving OneIssuer. The current scope is a lightweight,
self-hosted, single-Issuer service; proposals that add hidden multi-tenancy or
premature business abstractions should start with a design discussion.

## Development setup

Read [`docs/development.md`](./docs/development.md), copy `.env.example`, install
the fixed tools with `make tools`, and use Docker for disposable PostgreSQL.
Never commit `.env`, credentials, private keys, tokens, production data, or
unredacted diagnostic output. Raw Conformance exports and supply-chain reports
belong under ignored `.artifacts/`; review them for runtime Secrets before any
controlled sharing.

## Branches and commits

- branch from the current default branch and keep each change reviewable;
- use descriptive branches such as `feat/http-health` or `fix/config-redaction`;
- write imperative commits with the reason for security/lifecycle decisions;
- do not rewrite released migrations or generated sqlc files by hand;
- keep unrelated formatting/refactors out of behavior changes.

## Required checks

```bash
make generate
make contract-check
make check
make phase-4-smoke
make container-check
git diff --check
```

Add tests for changed behavior. Security and lifecycle fixes should include a
regression test. Integration tests must use isolated databases/containers and
clean them up. The final runtime image must remain non-root/read-only compatible,
contain no private JWK, and pass the pinned SBOM/vulnerability gate.

## Pull requests

Describe the problem, scope, security/privacy impact, configuration/migration
impact, and exact verification performed. Update OpenAPI/docs for externally
visible contracts. Keep phase boundaries honest: a mock or placeholder must not
claim that login/OIDC behavior exists. Never weaken mandatory S256 or expand
Discovery merely to make an upstream protocol test runnable, and never imply that
Conformance evidence is OpenID Foundation certification.

Reviewers may ask for smaller commits, threat analysis, rollback notes, or
evidence that metrics/logging labels remain bounded and secret-free.

## Issues and security

Use the issue templates for public bugs/features, but **do not disclose an
unfixed vulnerability in a public issue**. Follow [`SECURITY.md`](./SECURITY.md)
for private reporting.

Participation is governed by [`CODE_OF_CONDUCT.md`](./CODE_OF_CONDUCT.md).
