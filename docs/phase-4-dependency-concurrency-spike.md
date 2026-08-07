# Phase-four dependency, concurrency, and browser Spike

Status: **accepted implementation input**
Date: 2026-08-02
Scope: P4-00 for `v0.1.0-dev.4`
Decision owner: OneIssuer maintainers

## Questions and exit criteria

This Spike closes the design gate in the phase-four development plan. It answers:

1. which Fosite surfaces may be reused without surrendering OneIssuer's PostgreSQL
   family state machine;
2. which schema, lock order, retry, and response-delivery contracts migrations
   12–14 must implement;
3. how a stable Session binding survives same-principal login rotation without
   crossing principals;
4. which ID Token Hint time and verification-key policy authorizes an RP redirect;
5. whether a cross-site RP form POST can continue through a `SameSite=Lax`,
   cookie-only, clean confirmation GET without propagating Hint or State;
6. which wire snapshots, example-RP storage rules, and Conformance categories are
   frozen before implementation.

The Spike exits only if every question has a fail-closed decision and no unresolved
decision lacks an owner. It is engineering evidence, not OpenID certification or a
production-readiness claim.

## Environment and selected dependencies

| Item | Observed/frozen value |
| --- | --- |
| Go | `go1.26.5-X:nodwarf5 linux/amd64` |
| Ory Fosite | `github.com/ory/fosite v0.49.0` |
| JOSE | `github.com/go-jose/go-jose/v4 v4.1.4` |
| PostgreSQL driver | `github.com/jackc/pgx/v5 v5.10.0` |
| sqlc | `v1.31.1` |
| Chromium browser probe | Chrome for Testing `151.0.7922.34` |
| Firefox browser probe | Firefox `153.0` |

The existing dependency pins remain unchanged. The phase-three tests, including the
real PostgreSQL container suite and its deferred-commit/Audit failure probes, passed
before this decision was accepted.

## Fosite reuse boundary

Source review of the pinned Fosite release found the following mismatches:

- `oauth2.RefreshTokenGrantHandler` models rotation through request IDs and stored
  Fosite request/session objects. Its storage contract does not express an immutable
  family Scope, generation lineage, stable Session binding, absolute family expiry,
  or OneIssuer's Grant-version checks.
- its serialization-failure branch asks a caller to retry, while OneIssuer must make
  a committed duplicate presentation trigger fail-closed family reuse handling;
- `oauth2.TokenRevocationHandler` attempts both Access and Refresh revocation for a
  recognized request ID and returns an ownership error. Phase four instead requires
  Access-only revocation, whole-family Refresh revocation, and byte-equivalent `200`
  results for unknown, inactive, and wrong-owner Tokens;
- the generic Introspection response/session model permits fields outside the fixed
  OneIssuer per-token response matrix;
- `ComposeAllEnabled` continues to mount grants and protocol surfaces outside the
  reviewed support matrix.

Decision:

1. do not compose the Fosite Refresh, Revocation, or Introspection handlers and do
   not implement their storage interfaces;
2. retain Fosite only for reviewed constants/error vocabulary and the existing
   credential-free Client adapter where useful;
3. keep strict form/authentication parsing in `internal/oidc`, lifecycle policy and
   clear Refresh generation in `internal/token`, and every race/authority mutation
   in `internal/storage/postgres`;
4. never call `ComposeAllEnabled`; Discovery remains closed until the corresponding
   custom route and negative semantics are live.

This is the same adapter direction as phase three and introduces no new dependency.

## Frozen schema shape

### Migration 00012

Migration 12 extends existing authority without fabricating offline access:

- add `consent_grants.revoked_at` and positive `version` (default/backfill `1`),
  plus active/current-user ordering indexes;
- add positive `authorization_codes.consent_grant_version`; schema-11 rows receive
  their referenced Grant's current version;
- add nullable `authorization_codes.origin_session_id` and
  `authorization_codes.session_binding_id`; legacy rows remain null, while all
  phase-four inserts carry both values and an offline Code requires a binding;
- add non-null `login_sessions.session_binding_id`, backfilled to each Session's own
  ID, and add `account_switch` to the fixed revoke-reason check;
- extend persisted protocol Scope checks from three values to the canonical four
  values `email`, `offline_access`, `openid`, and `profile`;
- extend Audit event, target, and changed-field checks for Grant reactivation/revoke,
  Refresh issue/reuse/revoke, Access revoke, lifecycle cascade, and RP logout.

### Migration 00013

Migration 13 creates `refresh_token_families` and `refresh_tokens` and extends
`access_tokens` exactly as described in section 16.2 of the development plan:

- one 32-byte unique digest per Refresh generation and one unique monotonically
  increasing `(family_id, generation)` pair;
- one canonical family Scope containing `openid` and `offline_access`;
- a rolling deadline no later than the family's absolute deadline and a hard schema
  cap of 30 days rolling / 365 days absolute;
- nullable origin Code/Session foreign keys use `ON DELETE SET NULL`; stable binding,
  Grant, User, and Client links remain authoritative;
- Access metadata records immutable issuance source, nullable source rows, optional
  family/binding linkage, and explicit revoke state/reason;
- legacy Access rows are backfilled as `authorization_code`, receive no family or
  binding, and remain valid only under the phase-three checks until their own expiry.

### Migration 00014

Migration 14 creates bounded `logout_transactions` with:

- unique 32-byte lookup digest and nullable 32-byte one-time CSRF digest;
- `pre_confirm`, `bound_confirmable`, `confirmed`, and `canceled` stages with
  monotonic timestamps and a bounded attempt counter;
- verified Client/URI/State authority that starts with no User, Session, or binding;
- one-time bind columns for User, Session, and stable Session binding;
- expiry/terminal cleanup indexes, Refresh-family evidence indexes, and the partial
  unique reuse-Audit index.

Migration 12–14 production `Down` is not a rollback mechanism. Restore the schema-11
backup after stopping phase-four writers. The populated upgrade fixture must include
active and expired Session, Grant, Code, and Access rows and prove that no legacy row
receives `offline_access`, family authority, or a fabricated binding.

## Locking, retry, and delivery decisions

The canonical orders are:

```text
Code exchange: Code → User → Client → Consent Grant → new family/token/access rows
Lifecycle:     User → Client → Consent Grant → Refresh family → Refresh Token → Access
Session:       Session/binding → families ordered by UUID → Access ordered by UUID
RP confirm:    Logout transaction → Session/binding → ordered families → ordered Access
```

Candidate lookup by digest may occur before locking, but every digest, owner, Scope,
version, status, and deadline is rechecked under the locked transaction. Set-based
updates and UUID ordering are mandatory for multiple families; no user-controlled
iteration order may become lock order. Refresh never locks a browser Session merely
because an origin Session is passively expired.

The clean logout bind uses **reject-current** when the per-Session live transaction
cap is reached. It does not replace another transaction, avoiding transaction-to-
transaction lock inversion.

Retry policy is deliberately narrow:

- an operation may retry at most once after PostgreSQL SQLSTATE `40001` or `40P01`
  returned before commit;
- begin failures, context expiry, validation/authority failures, and any commit
  error are not retried;
- clear replacement values are never returned from a failed attempt; a Service
  returns only the result of a known successful commit;
- an ambiguous commit is a fixed `server_error`. The caller must not receive or
  automatically retry a possibly committed clear Token;
- if another Refresh commits while a deadlock victim retries, the re-lock observes
  consumed state and applies the ordinary reuse rule. There is no benign-retry grace.

The real PostgreSQL test matrix must cover every pair listed in section 17 of the
plan and inject signer, Audit, insert, operation, and deferred-commit failures.

## Stable Session binding decision

Every new login Session proposes its own ID as a fresh binding. `CommitLogin` locks
the presented existing Session, if any, and decides under the same transaction:

| Existing browser Session | New principal | Result |
| --- | --- | --- |
| active and same User | same User | revoke old as `rotation`; inherit its binding |
| active and different User | different User | revoke old as `account_switch`; cascade its binding; keep fresh new binding |
| expired, idle-expired, or already revoked | any | never inherit; keep fresh binding; no offline cascade caused solely by passive expiry |
| missing/invalid cookie | any | keep fresh binding |

The repository, not an HTTP handler, makes this decision because it owns both the
row lock and the atomic account-switch cascade. Registration always starts a fresh
binding. Explicit user/admin/local/RP logout reasons cascade; `rotation` and passive
`expired` do not.

## ID Token Hint time and key policy

External post-logout Redirect and State authority require a valid phase-three ID
Token Hint. The accepted policy is:

- exactly one compact RS256 JWS with `typ=JWT`, a unique known `kid`, no embedded
  JWK/X.509/critical extension, exact Issuer, scalar Audience, matching `azp`, and a
  non-empty Subject;
- `iat > 0`, `exp > iat`, no future `iat` beyond configured clock skew, and the
  encoded ID Token lifetime may not exceed 15 minutes;
- an unexpired Hint is accepted through `exp + clock_skew`;
- a recently expired Hint is accepted only while
  `now <= iat + logout_hint_max_age + clock_skew`;
- `ONEISSUER_LOGOUT_ID_TOKEN_HINT_MAX_AGE` defaults to `24h`, is bounded from `5m`
  through `720h`, and is reported in safe configuration;
- an old public verification key must remain in the startup verification ring for
  at least `logout_hint_max_age + clock_skew` after its last possible issuance.

The 24-hour default matches the default OneIssuer absolute browser Session lifetime,
but not the 90-day Refresh family lifetime. An RP Session that keeps only the initial
ID Token may therefore lose external redirect after 24 hours; confirmed local logout
remains available. Phase four does not silently issue ID Tokens during Refresh to
avoid that tradeoff. Operators choosing a larger Hint age accept a proportionally
longer old-key overlap and must retain the key through the stated deadline.

## SameSite, redirect, and cookie browser probe

An isolated two-origin harness used an RP at `127.0.0.1` and an Issuer at
`localhost`. It seeded a host-only `SameSite=Lax` main Session, cross-site form-POSTed
Hint/State, returned a `Referrer-Policy: no-referrer` 303, set a transient HttpOnly
cookie scoped to `/oauth2/logout/confirm`, loaded the clean GET, probed an unrelated
path, cleared the cookie with the same Path/attributes, and revisited confirmation.

Both Chromium 151 and Firefox 153 produced the same security-relevant observations:

1. the cross-site POST carried Origin/Referer but **did not carry the Lax main
   Session cookie**;
2. the 303 clean GET carried both the main Session and transient transaction cookie;
3. the clean GET had no Referer, so the original RP URL and posted Hint/State were
   not propagated;
4. `/probe` carried only the main Session cookie; the path-scoped transaction cookie
   was absent;
5. terminal clearing removed the transaction cookie, while the main host cookie
   remained; a later confirmation GET could not recover the transaction.

Only cookie names and fixed route/method facts were captured; the probe did not log
Hint, State, or cookie values. This proves the continuation shape for the tested
engines. P4-08 must check in an equivalent automated browser matrix, including two
tabs, cookie overwrite, stale forms, cookie loss, cancel, and terminal replay.

## Frozen wire and metadata snapshots

Routes and exact request channels:

| Route | Channel | Frozen success/error shape |
| --- | --- | --- |
| `/oauth2/token` | POST form, no query | Code: ID + Access and optional Refresh; Refresh: Access + replacement Refresh, no ID Token |
| `/oauth2/revoke` | POST form, no query | authenticated/identified valid request is empty `200`; unknown/wrong/inactive are indistinguishable |
| `/oauth2/introspect` | Confidential Basic POST form, no query | inactive is exactly `{"active":false}\n`; active fields follow the type matrix only |
| `/oauth2/logout` | GET query or POST form, never mixed | no authority mutation; no-referrer `303` to clean confirm and transient cookie |
| `/oauth2/logout/confirm` GET | transaction cookie only | hosted fixed page or fixed local result; rotates one-time bound CSRF |
| `/oauth2/logout/confirm` POST | cookie + strict form | `decision=confirm|cancel` plus CSRF only; mutation/redirect at most once |
| `/api/v1/me/grants` | current Session GET | owner-only safe projection and versioned time/public-client cursor |
| `/api/v1/me/grants/revoke` | current Session JSON POST | strict public `client_id` selector; owner-bound `404`; idempotent safe model |

All lifecycle forms are at most 8 KiB, reject invalid UTF-8/percent/NUL/duplicates,
use `no-store`/`no-cache`, and do not enable CORS. Unknown `token_type_hint` is ignored;
duplicate or empty required fields are `invalid_request`. Invalid Client credentials
remain `401` with the existing Basic challenge policy.

Discovery is opened in lockstep only after live routes exist and then adds:

```json
{
  "grant_types_supported": ["authorization_code", "refresh_token"],
  "scopes_supported": ["openid", "profile", "email", "offline_access"],
  "revocation_endpoint_auth_methods_supported": ["none", "client_secret_basic"],
  "introspection_endpoint_auth_methods_supported": ["client_secret_basic"]
}
```

It also publishes absolute `revocation_endpoint`, `introspection_endpoint`, and
`end_session_endpoint` URLs from the canonical Issuer. Array order and compact JSON
remain snapshot-tested.

## Example RP storage contract

- Refresh Tokens live only in a server-side, bounded Session entry and are never
  copied to browser storage, URLs, logs, argv, or committed fixtures.
- A successful refresh replaces the stored value with compare-and-swap semantics;
  the old value is dropped immediately. Concurrent use cannot write an older result
  over a newer Session state.
- `invalid_grant` deletes the local family and starts a new interactive Authorization
  Request. It is never automatically retried.
- per-request Access Scope narrowing does not overwrite the stored Refresh family
  Scope expectation.
- the initial ID Token Hint is kept in the same restricted server-side Session only
  for RP logout; logout uses form POST by default and validates returned State before
  destroying the RP Session.

## Conformance applicability freeze

The phase-three pinned official `release-v5.2.1` non-certification plan remains the
baseline. The phase-four applicability matrix must add available modules/categories
for:

- Authorization Code with `offline_access`, initial Refresh issuance, and Refresh
  Grant for both static Client profiles where the suite can express mandatory S256;
- RP-Initiated Logout GET/POST, ID Token Hint, registered post-logout URI, and State;
- Discovery declarations for Refresh and end-session metadata;
- RFC 7009 Revocation and RFC 7662 Introspection only if the pinned suite exposes
  modules compatible with the restricted owning-Client profile.

Front-/Back-Channel Logout, Session Management, Dynamic Registration, Public
Introspection, resource-server/Audience registration, PAR/JAR/JARM, Implicit/Hybrid,
Client Credentials, Device/ROPC/Exchange, DPoP, mTLS, private-key JWT, FAPI, and
certification plans remain not applicable. Mandatory S256 and the Hint-required
external Redirect narrowing must be recorded as profile limitations, not hidden or
reported as unconditional standards coverage.

## Capacity inputs and owners

At defaults, the process-wide pre-Hint limiter (`100/s`, burst `200`) and five-minute
logout TTL have a deliberately conservative theoretical arrival envelope of 30,200
zero-authority rows per process if cleanup is completely stalled. Deployment review
must set a lower edge rate where needed and alert well before that envelope. Bind-time
per-Session live rows are capped at three and reject the current bind.

Refresh capacity must be estimated from deployment-specific daily offline grants and
refresh frequency; the immutable safety floor is 90 days of family authority plus 30
days of terminal evidence. No guessed traffic number is treated as launch evidence.

| Residual/decision | Owner |
| --- | --- |
| protocol/profile changes and Conformance applicability | OneIssuer maintainers |
| schema capacity, vacuum, backup, clock, edge limits, and old-key overlap | deployment operator |
| at-most-once refresh loss, local Token replacement, RP Session destruction | RP integrator |
| dependency advisories and release-gate remediation | OneIssuer maintainers |
| browser SameSite/referrer regression evidence | OneIssuer maintainers |

## Exit status

P4-00 exits **accepted**. The Fosite boundary, migrations 12–14 shape, lock order,
Session lineage, Hint time/key policy, failure semantics, browser continuation,
wire snapshots, RP storage contract, residual owners, and Conformance scope are
sufficient to begin P4-01. Any implementation that changes them must amend ADR 0003,
the threat model, this Spike, and the relevant tests before merge.
