# ADR 0002: Phase-three OIDC security profile and protocol adapter

- Status: Accepted
- Date: 2026-08-01
- Decision owners: OneIssuer maintainers
- Scope: `v0.1.0-dev.3`
- Supersedes: no phase-two decision; extends ADR 0001

## Context

Phase two deliberately stopped before OAuth/OIDC protocol endpoints. Phase three
must add a usable Authorization Code Flow without weakening the stable identity,
Client, browser Session, exact Redirect URI, Secret, audit, and transaction
boundaries accepted in ADR 0001.

The main design tension is between standards reuse and OneIssuer's stronger
transaction requirements. Ory Fosite provides mature OAuth/OIDC request and error
handling, but its all-enabled composition includes grants, storage interfaces,
token strategies, and lifecycle behavior outside the phase-three scope. Adopting
that composition unchanged would either advertise unsupported features or force
OneIssuer to maintain a second authority store. Reimplementing JOSE or an entire
OAuth server locally is also unacceptable.

## Decision

### Protocol profile

- Keep one configured Issuer and one PostgreSQL authority domain. The phase-three
  Issuer is a canonical origin URL with no path, query, fragment, userinfo, or
  trailing slash. Production requires HTTPS; explicit loopback HTTP is allowed in
  development/test only.
- Support only OIDC Authorization Code Flow:
  `response_type=code`, `response_mode=query`, and
  `grant_type=authorization_code`.
- Require S256 PKCE for every public and confidential Client. Do not accept
  `plain`, missing PKCE, or a per-Client downgrade flag.
- Public Clients use token endpoint auth method `none`; confidential Clients use
  only `client_secret_basic`. Reject credentials in more than one channel.
- Protocol scopes are `openid`, `profile`, and `email`. Although the phase-two
  registry can store `offline_access`, phase three rejects it and does not return
  Refresh Tokens.
- Support `state`, `nonce`, `prompt=none|login|consent|create`, and `max_age` with
  the exact state machine in the phase-three development plan.
- Persist reusable Consent Grants keyed by User and Client. First/new Scope
  approval is interactive; covered Scope may be reused unless
  `prompt=consent` is present.
- Generate 256-bit opaque Authorization Codes, store only domain-separated
  SHA-256 digests, bind all security context, and consume once under PostgreSQL
  locking/conditional update.
- Return RS256 ID Tokens and RFC 9068 RS256 JWT Access Tokens. The Access Token
  audience is the OneIssuer UserInfo endpoint; it is not a general business API
  token in phase three.
- UserInfo requires both valid JWT cryptography/claims and committed Access Token
  metadata, then rechecks current User and Client status.

Refresh Token, Revocation, Introspection, RP-Initiated Logout, PAR, JAR, JARM,
Dynamic Registration, Request Objects, Implicit/Hybrid, DPoP, mTLS, and additional
Client authentication methods remain phase-four-or-later work and are absent from
Discovery.

### Library boundary

- Pin Ory Fosite `v0.49.0` for the selected OAuth/OIDC request, client adapter,
  standard error, and handler contracts.
- Pin `github.com/go-jose/go-jose/v4` `v4.1.4` for all OneIssuer-owned JWK/JWS/JWT
  parsing, signing, public-key serialization, and strict algorithm handling.
- Do not use Fosite `ComposeAllEnabled`. Assemble only the handlers/surfaces needed
  by the phase-three profile, behind `internal/oidc` adapters.
- Run a OneIssuer duplicate-parameter, request-size, content-type, and safe
  Redirect preflight before Fosite. Fosite never receives ambiguous security
  parameters.
- Adapt the existing Client read model to Fosite without exposing a stored Secret
  digest. A custom authentication strategy delegates confidential validation to
  `client.Service.ValidateSecret` and applies the existing generic failure.
- Keep Fosite and go-jose types inside `internal/oidc`, `internal/token`, and
  `internal/keystore`; existing identity/session/client packages remain library
  independent.
- OneIssuer owns Consent, authorization transaction, Code, and Access Token
  repositories. Fosite callbacks may request operations, but handlers never
  directly read their SQL tables.
- Code approval and Code exchange use explicit OneIssuer PostgreSQL transaction
  methods. A local in-memory RSA signature may execute inside the bounded exchange
  transaction; future remote KMS signing requires a new transaction design.
- Fosite transitively uses go-jose v3 internally. OneIssuer does not import that
  module directly; all project JOSE code uses v4. Both versions stay covered by
  dependency and vulnerability checks until Fosite removes the older dependency.

### Issuer and endpoint metadata

- `ONEISSUER_ISSUER` is the only source for metadata and Token `iss` values.
  Request Host and forwarded host/scheme never affect it.
- Discovery is built from a typed capability model rather than handwritten JSON.
  The public route is mounted only after every advertised endpoint works.
- Discovery declares only `code`, `query`, `authorization_code`, public subjects,
  RS256, `none|client_secret_basic`, `openid|profile|email`, S256, and the supported
  prompt values.
- JWKS publishes only public signing material, sorted by `kid`, with ETag and
  bounded caching. It never serializes private JWK members.

### Signing keys

- The initial KeyStore loads one active private RSA JWK and an optional public JWK
  set at startup. It does not silently generate a service key.
- RS256 is the only signing algorithm. Generation defaults to 3072-bit RSA;
  loading rejects RSA keys smaller than 2048 bits.
- `kid` is the RFC 7638 SHA-256 thumbprint of the public RSA JWK. Supplied values
  must match; duplicates fail startup.
- The private file must be a regular, non-symlink file with no group/world access.
  Generation uses exclusive creation, mode `0600`, and never prints private key
  material.
- Rotation is restart-based with pre-published/new and retained/old public keys.
  Automated rotation, remote signers, and hot reload are not phase-three features.

### Token and claims

- Authorization Code default TTL is 60 seconds; ID Token 5 minutes; Access Token
  10 minutes; verification clock skew defaults to 30 seconds and is capped at two
  minutes.
- ID Token always contains `iss`, stable `sub`, single Client `aud`, `azp`, `iat`,
  `exp`, and `auth_time`; it contains `nonce` when requested and scope-gated
  profile/email claims.
- Access Token uses `typ=at+jwt` and contains `iss`, stable `sub`, fixed UserInfo
  `aud`, `client_id`, canonical `scope`, `iat`, `exp`, and random `jti`.
- UserInfo always returns the same `sub` as the ID Token and only the claims
  authorized by the committed Access Token Scope.
- Internal UUID, normalized identifiers, role/admin state, Session data, and audit
  identifiers are never protocol claims.

### Error, privacy, and atomicity

- Unknown/disabled Client and missing/mismatched Redirect URI produce a local
  error and never an external redirect. Only a verified exact Redirect URI may
  receive an OAuth/OIDC error and original `state`.
- Token endpoint errors are uniform for Client and grant failures and never expose
  lookup, Secret, verifier, database, or signing details.
- State, Nonce, PKCE values, clear transaction values, Code, verifier, Basic/Bearer
  credentials, ID/Access Tokens, `jti`, and private key data are forbidden from
  logs, audit values, metric labels, and ordinary error bodies.
- Successful Consent/Code issuance commits transaction consumption, Grant update,
  Code digest, and audit together. Successful Code exchange commits Code
  consumption, Access Token metadata, and audit together before writing the HTTP
  response.
- Database, audit, signing, or current User/Client status failure is fail closed.

## Alternatives rejected

- **Fosite `ComposeAllEnabled`:** enables handlers and storage contracts for
  unsupported grants, Refresh, Introspection, Revocation, PAR, and other behavior;
  it obscures the intended phase-three capability surface.
- **Fosite memory store or a second protocol database:** breaks restart authority
  and atomicity with the existing PostgreSQL domain.
- **Handwritten JOSE/RSA/JWK:** unnecessary cryptographic implementation risk.
- **Only go-jose with a fully handwritten OAuth server:** loses mature standard
  request/error contracts and increases conformance risk.
- **Optional PKCE for confidential Clients:** creates downgrade/configuration
  ambiguity and conflicts with the chosen OAuth security BCP profile.
- **Opaque Access Tokens in phase three:** would avoid JWT complexity but would not
  exercise the planned JWKS/offline validation format; the fixed UserInfo audience
  limits the initial exposure.
- **General API audience:** no resource registry or authorization model exists yet.
- **Database/private-key auto-generation at startup:** hides an operator security
  event and can cause key drift after volume loss.
- **Issuer derived from request Host:** permits proxy/header confusion and breaks
  stable discovery/claim validation.

## Consequences

Positive:

- protocol behavior has one explicit, testable capability profile;
- standard request/error behavior and mature JOSE are reused without duplicating
  the phase-two authority stores;
- every authorization and exchange race is resolved by PostgreSQL;
- metadata cannot claim unimplemented endpoints;
- all Clients receive the same strong PKCE policy;
- the fixed UserInfo audience keeps initial Access Tokens narrowly scoped.

Costs and limitations:

- selective Fosite integration needs adapters and more tests than its all-enabled
  example composition;
- the Fosite module has a large transitive graph and currently brings go-jose v3
  alongside the project's v4 dependency;
- local RSA signing occurs during a bounded database transaction;
- restart-based rotation requires operator coordination and a cache-overlap window;
- browsers cannot switch/create an account inside an existing authenticated
  `prompt=create` request; they must explicitly log out and restart;
- browser logout does not immediately revoke an already issued Access Token;
- no Refresh/Revocation/Introspection/Logout or general resource API support exists
  until phase four.

See [the phase-three threat model](../phase-3-threat-model.md),
[dependency Spike record](../phase-3-dependency-spike.md), and
[development plan](../phase-3-development-plan.md).
