# Phase three OIDC threat model

Status: accepted implementation baseline; verification evidence will be tracked in
the phase-three release notes
Date: 2026-08-01
Scope: `v0.1.0-dev.3`, one process, one PostgreSQL database, one Issuer

## Security objective and non-objective

Phase three must safely issue and consume Authorization Codes, sign narrowly scoped
ID/Access Tokens, expose accurate Discovery/JWKS, obtain user Consent, and authorize
UserInfo while preserving all phase-two identity, Session, Client, URI, Secret,
audit, and migration controls.

It supports only Authorization Code Flow with S256. Refresh, Revocation,
Introspection, RP-Initiated Logout, general resource API audiences, distributed
abuse prevention, online key rotation, MFA, and production certification are
outside this model. Their absence must be visible in Discovery and operational
documentation rather than hidden behind placeholders.

## Assets

Highest-impact phase-three assets are:

1. active RSA signing private key and operator key backups;
2. clear Authorization Code during redirect and Code verifier at the Token
   endpoint;
3. clear ID/Access Tokens during a successful Token response and Bearer request;
4. State, Nonce, PKCE challenge, and authorization transaction clear value;
5. Consent Grant and exact Scope decision;
6. Code digest/bindings/consumed state and Access Token `jti` metadata;
7. canonical Issuer, endpoint metadata, public JWKS, algorithm and `kid` policy;
8. stable Subject, current User/Client status, authentication time, and exact
   Redirect URI inherited from phase two;
9. protocol audit history, low-cardinality metrics, and privacy-safe logs;
10. database backup, key files, deployment configuration, and system clock.

User profile/email claims remain personal data. Public Client IDs, public JWKs,
Issuer, and Endpoint URLs are not secrets, but putting them into unbounded metric
labels or attacker-controlled logs still creates privacy/cardinality risk.

## Trust boundaries and data flow

```text
Relying Party backend/browser state store
  | state + nonce + S256 verifier ownership
  v
untrusted browser / user agent
  | TLS redirects, OneIssuer Session cookie, hosted forms
  v
trusted reverse proxy (optional, explicit CIDRs only)
  | bounded HTTP; configured Issuer remains authoritative
  v
OneIssuer OIDC preflight / Fosite adapter / hosted UI
  | already-validated domain inputs; no Handler SQL
  v
identity + client + session + authflow + consent + authorization + token
  | explicit repository calls and cross-table PostgreSQL transactions
  v
PostgreSQL

OneIssuer process -> mounted active private JWK / public overlap JWKS
Relying Party/API <- Discovery + public JWKS
Relying Party     <- Code redirect; Token response; UserInfo response
operator          -> key generation/rotation/backup and explicit migrations
```

The browser, all protocol parameters, Client network behavior, and Bearer Tokens
are untrusted input. A Client becomes trusted only for its registered metadata and
successful configured authentication method. PostgreSQL, the mounted private key,
the OneIssuer binary/image, and direct trusted proxy peers are privileged. Public
JWKS consumers are not trusted to drive key selection or remote fetches in the
OneIssuer verifier.

## Assumptions

- TLS protects production browser, Token, UserInfo, proxy, and PostgreSQL traffic;
- RP implementations generate high-entropy State, Nonce, and verifier and validate
  State, Issuer, Audience, signature, time, and Nonce;
- private key files/backups are access-controlled and not copied into Git/images;
- host/process/database-superuser compromise can defeat application controls and
  needs infrastructure incident response;
- system time is monitored and close enough for configured TTL/skew bounds;
- operators coordinate JWKS cache overlap during restart-based rotation;
- edge controls bound Internet traffic until distributed/adaptive limits exist.

## Threats, controls, and required evidence

| Threat | Primary controls | Required evidence |
| --- | --- | --- |
| Issuer/endpoint mix-up | Canonical configured origin; exact `iss`; all URLs derived from it; Host/forwarded data ignored; fixed UserInfo audience | config tests, metadata/token cross-test, proxy spoof tests |
| Discovery overclaim | typed capability model; route enabled only after endpoints exist; no deferred endpoints/grants/scopes | metadata snapshot plus live-route matrix |
| Open redirect | resolve Active Client; exact registered Redirect URI before redirect; local errors before trust; URL builder for query merge | negative HTTP matrix including query/CRLF/fragment encodings |
| Duplicate/ambiguous parameters | 8 KiB request-target bound; percent/UTF-8 validation; exactly one security parameter before Fosite | table tests and parser fuzz corpus |
| Authorization login CSRF | RP State round trip; server opaque transaction; SameSite Session; no arbitrary return target | wrong/missing State rejected by example RP; browser flow tests |
| Consent CSRF/confusion | authenticated server Session, same-origin + CSRF, server-restored Client/Scope only, no browser resubmission | cross-session/user, altered field, double-submit tests |
| Account substitution | Session resolved from DB; `prompt=login` rotates Session; authenticated `prompt=create` cannot silently switch identity | prompt state-machine integration tests |
| Stale authentication | `max_age` compared to `Principal.AuthenticatedAt`; `auth_time` bound through Code into ID Token | boundary/clock tests |
| Client/Scope changes mid-flow | User and Client status, URI, registered Scope rechecked before Code and exchange; current policy intersects Grant | disable/shrink-during-flow integration tests |
| PKCE interception/downgrade | S256 required for every Client; exact 43-char challenge; strict 43–128 verifier; constant-time comparison | public/confidential success and missing/plain/malformed/wrong tests |
| Code prediction/disclosure | 256-bit CSPRNG opaque Code; short TTL; digest-only DB; no logs/audit; no self-contained content | deterministic random-source tests, schema/privacy scans |
| Code replay/race | row lock/conditional consumed update; Code + metadata/audit commit together; at most one concurrent success | multi-goroutine/Testcontainers race evidence |
| Redirect/Code binding confusion | bind Client, exact URI, Scope, User, PKCE, Nonce, auth time, transaction and Grant | mismatch matrix with no metadata side effect |
| Confidential Client enumeration/brute force | one Basic channel; strict decode; existing constant-time digest validation; generic `invalid_client`; body/timeout/concurrency bounds | response comparison, malformed Basic fuzz, privacy tests |
| Public Client impersonation | public ID is not authentication; Code binding plus mandatory S256 is authority | stolen Code without verifier/client mismatch tests |
| Token endpoint request smuggling | POST form only, 8 KiB bound, single Authorization Header, duplicate rejection, no JSON/multipart, server timeouts | HTTP parser/content-type/header matrix |
| JWT algorithm confusion | go-jose v4; hard RS256 allow-list; required `kid`/`typ`; no `none`/HMAC/key URL; claims verified after signature | HS/none/wrong typ/kid/kty/jku/x5u negative tests |
| Private key disclosure | explicit mounted `0600` regular file; no stdout; private members stripped from JWKS; redacted config/log; not in image/DB | file-mode/symlink tests, JWKS structural assertion, image and staged-file scan |
| `kid` collision/key substitution | RFC 7638 public thumbprint; supplied ID must match; unique ring; only configured local keys | collision/mismatch/duplicate tests |
| Unsafe key rotation | prepublish, cache wait, active switch, old public retention, restart-only loading; no silent generated fallback | active/old/future JWKS tests and documented runbook drill |
| Token claim substitution | fixed issuer/audience/subject/client/scope builders; User subject is domain source; no input claim map | signed-token claim table tests |
| Token replay/theft | TLS, no-store, no token logging/storage, 10-minute Access TTL, UserInfo requires committed `jti` metadata | replay/expiry tests and privacy canary scan |
| UserInfo token confusion | Bearer Header only; RS256/typ/iss/fixed aud/time/jti/client/scope; metadata and current status checks | query/body/wrong audience/status/scope negative tests |
| Disabled authority | current User/Client status checked before Code, exchange, and each UserInfo call | disable-before-each-step integration tests |
| Database/signing partial failure | explicit transactions; local bounded signer; audit in success transaction; HTTP written only after commit | injected signing/audit/commit failures and state inspection |
| Metadata/cache leakage | Discovery/JWKS contain only public values; stable ETag; no private fields; browser protocol pages no-store/no-referrer | header/body snapshots |
| Log/audit/metric exfiltration | denylisted/redacted headers and token shapes; fixed audit enums/no values; low-cardinality label enums | synthetic canary across logs, DB audit, metrics, errors |
| Storage DoS through audit | malformed traffic counted with bounded metrics/logs; only meaningful transitions/replay classifications reach append-only audit | high-volume rejected request test and audit count bound |
| Migration tampering | immutable `00001`–`00005`; new checksum entries; explicit migrate; constraints and upgrade tests | checksum, empty/repeat/upgrade/Down-Up gates |
| Dependency compromise | pinned versions, checksums, Apache licenses, govulncheck, update automation, SBOM | CI vulnerability/license/SBOM record |

## Protocol error redirect state machine

1. Before an Active Client and exact Redirect URI are both established, return a
   local no-store error and no external `Location`.
2. After both are established, standard request/user errors may be returned by
   query response mode to that exact URI with the original State.
3. State is only round-tripped at the protocol boundary. It is never placed in a
   local error body, log, audit value, or metric label.
4. Deny and success consume the server transaction once. Back/refresh cannot
   issue a second response.
5. Internal storage/signing failure returns `server_error` only when safe to
   redirect; otherwise it remains local. Internal causes stay server-side and
   classified without sensitive values.

## Fixed privacy boundaries

The following may exist only at their minimum functional boundary and must never
be logged, audited as a value, used as a metric label, or returned in an ordinary
read/error model:

- active/private/backup signing key material and private JWK members;
- Authorization or Cookie Headers and Client Secret/digest;
- auth transaction clear value, State, Nonce, PKCE challenge, verifier, clear Code;
- full ID/Access Token, Access Token `jti`, Code/Token lookup digest;
- raw Redirect URI or Scope string in general logs/labels;
- password/credential digest and all phase-two forbidden data;
- SQL parameters, database credential, stack trace, or arbitrary library error.

The database necessarily stores already-validated State, Nonce, PKCE challenge,
URI/Scope context, Code digest, Grant, and Token metadata for short-lived protocol
correctness. Their access is repository-scoped, retention bounded, and excluded
from generic audit metadata and management read models.

## Residual risks and deferred controls

- Browser logout does not revoke an already issued Access Token; UserInfo exposure
  is bounded by its default 10-minute lifetime. Phase four adds lifecycle endpoints.
- JWT offline verification cannot observe current User/Client disable; phase-three
  Tokens are intentionally audience-bound to online OneIssuer UserInfo.
- No distributed/adaptive limiter, IP reputation, bot control, or Client lockout
  exists. Request/concurrency bounds and edge enforcement are required.
- RSA signing occurs inside a bounded database transaction. Remote KMS latency and
  retry semantics are not supported by this design.
- Restart-based key rotation is operationally error-prone if cache overlap is not
  followed. Automated rotation and incident workflow are deferred.
- Fosite adds a large transitive dependency graph and an internal go-jose v3 copy;
  reachable-code scanning and dependency updates remain ongoing requirements.
- PostgreSQL or host administrators, process-memory disclosure, TLS termination
  compromise, or stolen key backups defeat application-layer controls.
- Consent cannot yet be self-revoked by a user; Client/User disable still blocks
  new issuance and UserInfo.
- Email remains unverified; `email_verified=false` must be preserved.
- This development release has not earned an OpenID certification or production
  readiness claim.

## Security change review

Any change to Issuer canonicalization, endpoints, response/grant/auth method,
Redirect comparison, PKCE, prompt/max-age, Consent reuse, Code format/TTL/bindings,
JWT algorithm/header/claims/audience/lifetime, KeyStore/rotation, UserInfo checks,
protocol errors, audit events, privacy fields, or migration checksums requires:

1. ADR and threat-model review;
2. positive, negative, concurrency, and privacy tests as applicable;
3. Discovery/Client/operations documentation updates;
4. `govulncheck`, race, Fuzz, SBOM, and sensitive-value evidence;
5. applicable OpenID Conformance rerun;
6. explicit phase-four compatibility assessment.
