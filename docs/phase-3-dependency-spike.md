# Phase-three protocol dependency Spike

Status: accepted implementation input
Date: 2026-08-01
Scope: P3-01 for `v0.1.0-dev.3`

## Questions

1. Can the current Go toolchain compile the selected Fosite and go-jose releases?
2. Can OneIssuer expose a Fosite `Storage`/Client adapter without exposing Secret
   digests or replacing its domain services?
3. Can go-jose v4 create a fixed RS256 signer without algorithm negotiation?
4. Does Fosite's all-enabled composition match the phase-three support matrix?
5. Do the selected direct dependencies have a compatible license and reachable
   vulnerability finding at the time of selection?

## Environment and versions

| Item | Observed value |
| --- | --- |
| Go | `go1.26.5-X:nodwarf5 linux/amd64` |
| Module proxy | `https://proxy.golang.org,direct` |
| Ory Fosite | `github.com/ory/fosite v0.49.0` |
| JOSE | `github.com/go-jose/go-jose/v4 v4.1.4` |
| Fosite license | Apache-2.0 |
| go-jose license | Apache-2.0 |
| Vulnerability tool | project-pinned `govulncheck v1.6.0` |

The tags were selected from the versions available through the configured Go
module proxy on 2026-08-01. Both modules are pinned rather than using branches or
pseudo-versions.

## Compile and vulnerability probe

A disposable module imported Fosite's root API and go-jose v4, asserted a minimal
implementation of `fosite.Storage`, generated a temporary 2048-bit RSA test key,
and constructed a go-jose RS256 signer with fixed `typ=JWT`.

```text
go mod tidy
go test ./...
/path/to/govulncheck ./...
go list -m github.com/ory/fosite github.com/go-jose/go-jose/v4
```

Observed result:

```text
ok   oneissuer-phase-three-spike
No vulnerabilities found.
github.com/ory/fosite v0.49.0
github.com/go-jose/go-jose/v4 v4.1.4
```

This result is selection-time evidence, not a permanent security statement. The
repository's normal `govulncheck`, dependency update, SBOM, and container gates
remain required after actual imports and on every release candidate.

## API fit findings

### Useful Fosite surfaces

- `fosite.Storage` has a narrow root requirement based on `ClientManager`, making a
  domain Client adapter possible;
- authorization/access request entry points provide standard OAuth error and
  handler contracts;
- handlers can be assembled selectively instead of using the all-enabled helper;
- configuration supports allowed prompts, PKCE enforcement, lifetimes, scope,
  redirect security, and debug-message suppression.

### Mismatches requiring an Adapter

- `ComposeAllEnabled` installs Implicit, Client Credentials, Refresh, password,
  assertion, Introspection, Revocation, PKCE, PAR, and multiple OIDC handlers;
  most are explicitly outside phase three;
- the explicit-code factory expects Fosite Core/TokenRevocation storage and access,
  refresh, and code strategies, while OneIssuer needs a single custom transaction
  for Code consumption and Access metadata;
- Fosite's default Client authentication expects a hashed Secret on its Client
  model, while OneIssuer intentionally hides digests and requires
  `client.Service.ValidateSecret`;
- Fosite transitively imports `go-jose/go-jose/v3`; the release graph explicitly
  pins its fixed `v3.0.5`, while OneIssuer's KeyStore and
  JWT code use the current v4 API and do not expose either version to domains;
- full module graph resolution is materially larger than go-jose alone, so only
  imported packages/surfaces should enter the application binary.

## Decision and implementation contract

1. Pin Fosite `v0.49.0` and go-jose/v4 `v4.1.4` when the first production Adapter
   and KeyStore code lands.
2. Never call `ComposeAllEnabled`; compose only the phase-three profile or use the
   relevant request/handler contracts behind `internal/oidc`.
3. Run OneIssuer strict duplicate/size/content-type/redirect preflight first.
4. Implement a Fosite Client adapter whose authentication strategy delegates to
   the existing Client service and never serializes a digest.
5. Keep Consent, Code, Token metadata, and cross-table transactions in OneIssuer
   repositories.
6. Use only go-jose/v4 for OneIssuer KeyStore, JWK, JWS, JWT, and claim validation.
7. Add compile-time interface assertions and positive/negative adapter tests before
   mounting protocol routes.
8. Re-run `govulncheck`, licenses, SBOM, race, and conformance gates after the real
   dependency graph is present.

### Post-implementation dependency finding

The first final-image Trivy run found `CVE-2026-34986` (High) in the Fosite
transitive `github.com/go-jose/go-jose/v3 v3.0.3`; upstream fixes it in v3.0.5.
The release graph was upgraded and tidied to v3.0.5, the image was rebuilt, and
the fixable High/Critical image gate then passed.

The final `govulncheck v1.6.0` symbol scan reports zero reachable
vulnerabilities. Its verbose output also reports `GO-2026-4985` in an imported
OpenTelemetry OTLP package and `GO-2026-5932` for the required `x/crypto` module,
but no OneIssuer call path reaches either vulnerable symbol/package. This is a
reviewed residual dependency signal rather than a claim that the module graph is
vulnerability-free; the final binary SBOM/Trivy and future dependency updates
remain required.

## Conformance baseline

The initial OpenID Provider suite configuration uses static pre-registered public
and confidential Clients and the Authorization Code profile. Applicable behavior:

- Provider Configuration and JWKS retrieval;
- `response_type=code`, query response mode, exact Issuer;
- public and confidential token endpoint authentication declared by Discovery;
- S256 PKCE success, missing/downgrade/wrong verifier rejection;
- `state`, `nonce`, ID Token signature/claims, `max_age`, and `auth_time`;
- UserInfo Bearer and scope-gated claims;
- malformed request and safe Redirect URI handling.

Dynamic Registration, Refresh, Logout, Request Objects, PAR/JAR/JARM, Implicit,
Hybrid, pairwise Subject, signed/encrypted UserInfo, and FAPI tests are explicitly
not applicable because Discovery does not declare those capabilities. The exact
suite image/digest and generated plan identifiers must be recorded in the phase
three release notes when the executable endpoints exist.

## Exit status

The Spike exits **accepted**: dependency versions, adapter boundary, rejected
composition, security checks, and conformance scope are sufficient to start P3-02.
Any implementation that needs a different Fosite storage model, signing library,
algorithm, or capability must amend ADR 0002 before merging.
