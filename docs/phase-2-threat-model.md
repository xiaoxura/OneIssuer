# Phase two threat model

Status: implemented design; verification evidence is tracked in
[phase-2-release-notes.md](./phase-2-release-notes.md)  
Date: 2026-08-01  
Scope: `v0.1.0-dev.2`, one process, one PostgreSQL database, one Issuer

## Security objective and non-objective

Phase two must safely answer who may authenticate to OneIssuer, which Clients are
registered, how browser authority is represented and revoked, and how an
administrator observes/manages those records. It does **not** issue OAuth/OIDC
codes or tokens. Discovery, JWKS, Authorize, Token, UserInfo, MFA, email recovery,
distributed abuse prevention, and conformance are outside this model.

This is a pre-production development release. The controls below prevent known
unsafe shortcuts; they are not a production-readiness claim.

## Assets

Highest-impact assets are:

1. clear user passwords during a single request;
2. Argon2id credential digests;
3. clear Session, pre-auth, CSRF, authorization-transaction, and Client Secret
   values at their narrow issuance/validation boundaries;
4. server-side digests and authority/status records in PostgreSQL;
5. administrator authority and recent-authentication timestamps;
6. exact Client Redirect/Logout URI and Scope policy;
7. append-only audit history and privacy-safe logs;
8. database backup material and deployment configuration.

Usernames, emails, display names, coarse IP prefixes, and user-agent digests are
personal data even when they are not authenticators.

## Trust boundaries and data flow

```text
browser
  | TLS + same-origin HTML/JSON + cookies
  v
trusted reverse proxy (optional, explicit CIDRs only)
  | bounded HTTP, fixed Issuer, sanitized forwarding data
  v
OneIssuer handlers
  | validated use-case inputs; no Handler SQL
  v
identity/session/client/authflow/admin/audit services
  | parameterized repository operations and explicit transactions
  v
PostgreSQL

operator TTY/controlled stdin -> Bootstrap CLI -> same identity/admin repository
operator backup tooling       -> PostgreSQL snapshot -> protected backup store
```

The browser is untrusted input. A reverse proxy is trusted only when its direct
network is configured. PostgreSQL and the host/container runtime are privileged
components. The independent Vite mock UI is outside the authentication trust
boundary and never receives a real password.

## Assumptions

- production transport uses TLS from browser to the trusted termination point;
- PostgreSQL transport, credentials, host, and backups are protected;
- the binary, image, migration manifest, and deployment environment are trusted;
- host compromise, malicious database superuser, and process memory disclosure
  can defeat application-layer controls and require infrastructure response;
- system time is sufficiently correct for bounded expiry/recent-auth decisions;
- operators restrict `/metrics`, PostgreSQL, and administrative network access.

## Threats and controls

| Threat | Primary controls | Verification |
| --- | --- | --- |
| Password database disclosure | Argon2id PHC only; 64 MiB/time 3/threads 2 defaults; safe lower/upper bounds; per-hash random salt; no reversible password | PHC/parameter/rehash unit tests, migration/schema inspection, sensitive-output scan |
| Unknown-account timing enumeration | Normalize without revealing namespace; always run Argon2id using a precomputed dummy digest; unknown/disabled/wrong password share browser status/message | integration response comparison and identity tests |
| Password resource exhaustion | 64 KiB request-body bound, 1024-byte default/4096-byte hard password maximum, Argon2 maximums, bounded in-process hash gate, `429` + retry hint | config boundary and busy-path tests; deployment benchmark required |
| Duplicate registration/Bootstrap race | normalized unique constraints, sorted advisory locks, transaction recheck, stable classified conflict | concurrent Testcontainers tests |
| Session theft | 256-bit random opaque value; only domain-separated SHA-256 digest in DB; HttpOnly, SameSite, production Secure/`__Host-`; absolute/idle expiry; revocation | token/cookie tests and restart-persistence integration |
| Session fixation | successful login/registration creates a new identifier; an existing browser Session is revoked in the same login transaction | integration rotation assertion |
| Disabled user retains authority | each authenticated request joins current user status and checks Session revocation/expiry; status/role changes revoke Sessions | disable-and-reuse integration test |
| CSRF | pre-auth token bound to CSRF digest; authenticated double-submit cookie/header; constant-time comparison; authoritative expiry; Origin/Referer same-origin check; all mutations gated | missing/cross-session/invalid CSRF and cookie tests |
| Open redirect | no arbitrary `return_to`; browser carries only opaque server transaction token; any future authorization context stores a previously validated exact URI | negative HTTP test and authflow validation tests |
| Transaction replay | 256-bit opaque value, digest-only lookup, short TTL, consumed timestamp, conditional one-time database update | resolve/consume integration tests |
| Redirect URI confusion | absolute structural parse; HTTPS except explicitly enabled development loopback HTTP; no userinfo/fragment/wildcard; byte-for-byte registered match | Client URI unit/integration tests |
| Scope escalation | fixed phase-two allowlist; `openid` required; canonical unique bounded set; stored verified transaction only | Client scope tests |
| Client Secret disclosure | 256-bit service-generated clear value; digest-only DB; constant-time comparison; shown only on create/rotate; `no-store`; absent from GET/audit/log | lifecycle and privacy integration tests |
| Secret rotation split-brain | revoke old digest, insert replacement, and append audit in one transaction; old secret fails immediately | rotation integration test |
| Administrator privilege misuse | active `admin` role checked per request; CSRF; recent authentication for high-risk operations; actor/target audit | HTTP/admin integration tests |
| Administrative lockout | administrator-set advisory lock and count under transaction; final active administrator cannot be disabled/demoted | last-admin and concurrency tests |
| SQL/sort injection | sqlc parameterized statements, fixed sort order, opaque keyset cursor, bounded fixed query keys | generation check, cursor tests, static analysis |
| XSS/clickjacking/tracking | `html/template` contextual escaping, no remote scripts/fonts/logo fetch, strict CSP `default-src 'none'`, `frame-ancestors 'none'`, `form-action 'self'` | escaped display-name integration and header tests |
| Proxy-header spoofing | forwarding data accepted only from explicit CIDRs; configured Issuer never derived from request host | phase-one proxy/config tests |
| Sensitive log/error/metric leakage | no body/cookie/auth-header logging; stable errors; redacting logger; fixed audit field enum with no values; fixed metric label enums; coarse IP only in session summary | privacy tests, static sensitive scan, metric tests |
| Audit tampering through app | no update/delete API; database triggers reject UPDATE/DELETE; security state and success audit commit together | migration/integration tests |
| Migration tampering | embedded single schema source, generated-code check, SHA-256 migration manifest, empty/repeated/Down-Up tests | CI scripts and Testcontainers |
| Stale authority after restart | all authority/revocation lives in PostgreSQL, not process memory or signed self-contained cookie | reopen/restart integration and Compose smoke |

## Fixed privacy boundaries

The following must never be logged, audited, used as metric labels, or returned in
ordinary read models:

- password or Argon2id digest;
- Cookie header or clear Session/pre-auth/CSRF value;
- clear Client Secret or its digest;
- authorization transaction clear token, State, Nonce, or PKCE challenge;
- SQL parameters, database URL credentials, or stack traces.

Audit accepts only fixed event/result/target enums, internal UUIDs, bounded
request ID, time, and a whitelist of **field names**. It has no arbitrary metadata
map. Login rejection events intentionally omit the submitted account identifier.

Current-user Session access is owner-scoped and hides foreign UUIDs as 404.
Administrator session summaries may include username/status and a coarse network
prefix, so administrator API access remains privacy-sensitive.

## Residual risks and deferred controls

- There is no distributed rate limiter, IP reputation, CAPTCHA, MFA, or breached
  password service. Internet-facing production use is not approved.
- Dummy Argon2 reduces a direct fast path but cannot guarantee perfectly identical
  end-to-end timing under every database/cache/load condition.
- SHA-256 is appropriate for high-entropy opaque values, but process-memory or TLS
  compromise can expose a clear value while in use.
- Audit append-only triggers do not protect against a database owner/superuser or
  backup administrator.
- Email is not verified; account recovery and ownership proof do not exist.
- Client `logo_uri` is stored but hosted credential pages do not fetch/display it.
- In-process hash concurrency is per replica; a future multi-replica deployment
  still needs edge/distributed abuse controls.
- Backup encryption, access control, retention, restore tests, clock monitoring,
  and incident response remain operator responsibilities.
- Phase three must add protocol-specific threat analysis for mix-up, PKCE,
  authorization-code replay, signing keys, token audience/issuer, nonce, and
  refresh-token reuse.

## Security change review

Any change to normalization, password bounds, opaque token format/domain prefix,
Cookie attributes, exact URI comparison, allowed scopes, recent-auth policy,
audit enums, migration checksums, or stable error mapping requires:

1. an ADR/security review;
2. negative and concurrency tests where applicable;
3. OpenAPI/config/migration documentation updates;
4. privacy scan evidence;
5. explicit third-stage compatibility assessment.
