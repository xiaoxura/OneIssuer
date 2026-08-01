# Security policy

## Supported versions

OneIssuer is a pre-release engineering project. No version is declared
production-ready. Maintainers accept and triage reports affecting the default
branch and newest development release, currently `v0.1.0-dev.3`.

## Private vulnerability reporting

Use this repository's **GitHub private vulnerability reporting** page
(`Security` → `Advisories` → `Report a vulnerability`). If it is unavailable,
contact the maintainers through a private channel listed on the repository owner
profile and request a secure reporting address before sending sensitive details.

Do not open a public issue, discussion, pull request, or paste containing an
unfixed vulnerability, exploit, credential, database URL, Session, Client Secret,
Authorization Code, Token, private key, production log, or personal data.

Include, where safely possible:

- affected commit/version and deployment model;
- impact and prerequisites;
- a minimal reproduction using synthetic placeholders, never real authority;
- suggested mitigation;
- whether the issue is public or actively exploited.

Maintainers aim to acknowledge a report within 3 business days, provide an
initial assessment within 7 business days, coordinate remediation/disclosure,
and credit reporters who request attribution. Timelines can vary by severity and
maintainer availability.

## Current security surface

The phase-three development release implements:

- local identity, Argon2id passwords, browser Sessions, CSRF, registration, and
  administrator operations;
- statically managed Public/Confidential OIDC Clients and one-time digest-only
  Client Secrets;
- Discovery, public JWKS, Authorization Code Flow, hosted Consent, Token, RS256
  ID/Access Tokens, and UserInfo;
- mandatory S256 PKCE for every Client and only `none`/
  `client_secret_basic` Client authentication;
- PostgreSQL-backed single-use authority, fixed append-only Audit events,
  privacy-safe logs, low-cardinality metrics, and explicit migrations;
- a file-mounted active private RS256 JWK and public verification overlap ring.

Reports about authentication/authorization bypass; URI validation/open redirect;
PKCE or Code replay; OAuth error handling; JWT/JWK algorithm/key confusion;
Issuer/Audience/Subject validation; UserInfo authority; Consent isolation;
User/Client disable behavior; Session/CSRF; password/Secret/private-key handling;
sensitive-data exposure; administration; audit integrity; migration atomicity;
container privilege; and supply-chain configuration are in scope.

The React application under `web/` is a non-authoritative mock. It must not
receive real credentials or protocol authority and cannot demonstrate a backend
identity-state change. The server-side example RP is an interoperability example,
not a production SDK.

## Deliberate phase-three limits

Refresh Tokens, `offline_access`, Revocation, Introspection, RP-Initiated Logout,
Dynamic Client Registration, `client_secret_post`, automatic/online key rotation,
HSM/KMS integration, and general business-API Access Tokens are not implemented.
Reports that an undocumented endpoint is absent are feature requests; reports
that OneIssuer falsely advertises one, returns placeholder success, bypasses the
documented fail-closed boundary, or leaks authority remain security issues.

Access Tokens are accepted only by OneIssuer UserInfo and require committed
metadata plus current User/Client/Grant authority. Code/Token HTTP delivery is
at-most-once: a committed exchange whose response is lost cannot be replayed or
recovered. The Client must initiate a new authorization.

Planned key rotation is restart-style. Emergency public-key removal cannot force
external verifiers to discard an already cached JWKS for up to approximately five
minutes. Phase three therefore makes no claim of global instantaneous Token
revocation.

## Key and evidence handling

Never attach private JWKs, raw Conformance exports, container layers containing
secret files, or unredacted diagnostics to a report. A raw OpenID Conformance
export can contain a runtime Client Secret even when its checked-in summary is
safe. Share only through the agreed encrypted private channel after minimizing
the artifact.

Passing the recorded applicable OpenID Conformance Suite modules does not mean
OneIssuer has OpenID Foundation certification, and the project makes no such
claim.
