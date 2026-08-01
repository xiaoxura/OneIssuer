# ADR 0001: Phase-two identity and Client security boundaries

- Status: Accepted
- Date: 2026-08-01
- Decision owners: OneIssuer maintainers
- Scope: `v0.1.0-dev.2`

## Context

Phase one intentionally contained no identity business schema. Phase two needs
real users, passwords, browser authority, Clients, Bootstrap, and audit while
remaining a single-Issuer service and without pretending to implement OIDC
protocol endpoints. The main design risk is creating convenience shortcuts that
become insecure protocol or deployment contracts in phase three.

## Decision

### Deployment and identity

- Keep one Issuer, one process, and one PostgreSQL database. Do not add
  `tenant_id`, Realm, Organization, or a generic RBAC system.
- Generate an internal UUID and independent 256-bit random `sub_...` subject.
  Username and email are mutable login identifiers and never become `sub`.
- User status is `active|disabled`; role is `user|admin`; no physical user deletion
  is exposed in phase two.

### Normalization and passwords

- Username: trim edge whitespace, NFC, validate 3–64 Unicode letters/digits plus
  `.`, `_`, `-` with alphanumeric edges, then Unicode case-fold for uniqueness.
- Email: trim, NFC, validate a plain addr-spec, case-fold local part and lowercase
  domain. Do not remove dots or `+tag` content.
- Passwords are exact UTF-8 input: no trim/normalization/composition rules;
  minimum 15 code points and default 1024-byte bound.
- Store Argon2id PHC only. Defaults are 64 MiB, time 3, threads 2. Always verify a
  dummy digest for an unknown identity, bound concurrent hashes, and rehash only
  after a successful login when parameters differ.

### Browser sessions and CSRF

- Generate versioned 256-bit random clear values for Session, pre-auth, CSRF, and
  authentication transaction tokens. Store only domain-separated SHA-256 digests.
- Authenticate each request against PostgreSQL and current user status. Apply
  absolute plus idle expiry, revocation, cleanup retention, and fresh Session ID
  after login/registration.
- Session and pre-auth cookies are HttpOnly; CSRF uses a readable strict SameSite
  cookie plus matching header/form token and same-origin checks. Production
  requires Secure `__Host-` cookies.
- Browser success resumes only an opaque server-held transaction or fixed local
  completion page; never accept arbitrary `return_to`.

### Client registry

- Public Clients use `none` and never receive a Secret. Confidential Clients use
  `client_secret_basic` in the stored phase-two model.
- Redirect/Logout URIs are structurally validated and compared byte-for-byte.
  HTTPS is required except explicitly enabled loopback HTTP in development; no
  wildcard, fragment, or userinfo.
- Allowed scopes are the fixed set `openid`, `profile`, `email`, and
  `offline_access`; `openid` is required.
- Generate 256-bit Client Secrets, store domain-separated digests, compare in
  constant time, reveal only during successful create/rotate, and rotate
  atomically with audit.

### Administration, errors, and audit

- Create the first administrator only through an explicit hidden-input CLI using
  a PostgreSQL advisory lock. Never ship a default credential or accept a
  password argument.
- Require active admin Session, CSRF, and recent authentication for sensitive
  operations. Protect the final active administrator under a database lock.
- Map persistence failures to stable domain errors. Unknown/disabled/wrong login
  responses are deliberately indistinguishable.
- Audit is an append-only fixed schema with no arbitrary values. Security-state
  success audit writes occur in the same transaction; database triggers reject
  event updates/deletes.
- API pagination is bounded keyset pagination with an opaque time/UUID cursor.
  Metrics use fixed low-cardinality labels only.

### Protocol boundary

Do not mount Discovery, JWKS, Authorize, Token, UserInfo, Revocation, or
Introspection. `authflow` accepts only already-validated protocol context and is
not an OIDC parser. Phase three must call domain services rather than read tables
or reimplement password/Session/URI/Secret checks in handlers.

## Alternatives rejected

- **Email or username as subject:** leaks/marries identity to mutable PII.
- **JWT/self-contained browser Session:** cannot immediately reflect user disable
  or server revocation without a second mechanism.
- **Bcrypt or fast hash:** weaker memory-hard posture for new credentials.
- **Provider-specific email rewrites:** surprising collisions and account takeover
  risk; only the explicitly frozen normalization is used.
- **Prefix/wildcard Redirect matching:** creates open-redirect/client-confusion
  risk.
- **Reversible Client Secret storage:** unnecessary; validation needs only digest.
- **Bootstrap on first web request/startup:** enables race/remote first-admin
  capture and hidden default state.
- **Arbitrary JSON audit metadata:** invites credential and PII leakage.
- **Management bearer token:** introduces a second long-lived authority model
  without a phase-two lifecycle use case.

## Consequences

Positive:

- immediate disable/revocation semantics survive restart;
- read models structurally exclude credential digests;
- protocol work has reusable validated boundaries;
- security races are closed in PostgreSQL transactions, not only in Go;
- a single source of migration truth is testable and embeddable.

Costs/limitations:

- authenticated requests require a database read;
- clear one-time Secrets cannot be recovered;
- operators must perform explicit Bootstrap, migration, backup, and Secret storage;
- changing normalization/token formats is a compatibility event;
- abuse prevention and OIDC protocol security remain incomplete until later phases.

See [the threat model](../phase-2-threat-model.md) for controls and residual risk
and [the phase-three handoff](../phase-3-handoff.md) for frozen interfaces.
