# Phase-four token lifecycle threat model

Status: **Accepted implementation input**
Date: 2026-08-02
Baseline: `v0.1.0-dev.3`, schema 11, ADR 0001/0002 and the accepted phase-three
threat model
Accepted decision: [ADR 0003](./adr/0003-phase-four-token-lifecycle.md)

## Security objective and non-objective

Phase four must add offline access, Refresh Token rotation/reuse detection,
Revocation, narrow Introspection, RP-Initiated Logout, and current-user Consent
revocation without weakening the phase-three Issuer, Redirect URI, PKCE, Client,
Session, JWT, privacy, and atomicity contracts.

The primary objective is to make every long-lived or explicitly retired authority
server-observable and race-safe. A copied Refresh Token must not create two durable
branches; a caller must not use Revocation or Introspection to enumerate another
Client's Tokens; and logout must not become a cross-site state change or open
redirect.

This phase is **not** a general resource-server authorization system. Access Tokens
remain audience-bound to OneIssuer UserInfo. It does not implement Front-/Back-
Channel Logout, DPoP, mTLS, Dynamic Registration, PAR/JAR/JARM, MFA, distributed
abuse prevention, automated key rotation, or a production-readiness claim.

## Assets

### Direct bearer authority

- clear Refresh Token and its newest usable family generation;
- clear JWT Access Token until expiry/revocation;
- browser Session cookie and CSRF value;
- Authorization Code, Client Secret, and existing phase-three credentials;
- logout transaction clear token (transient HttpOnly cookie only) and any submitted
  `id_token_hint`/`logout_hint`.

### Persistent authority and security evidence

- Refresh Token digest, family lineage, Scope, generation, expiry, use, and revoke
  state;
- Access Token `jti` digest, issuance source, family/Grant/Session linkage, expiry,
  and revoke state;
- Consent Grant Scope and revoke/reactivation state;
- current User/Client status and Client authentication material;
- login Session state, stable rotation binding, and its linkage to Token families;
- verified logout Client/URI plus opaque State bound only to that pair;
- append-only fixed Audit events and low-cardinality metrics;
- signing private key and public verification ring.

### Privacy-sensitive context

- stable OIDC `sub`, Client identity, Scope, issue/expiry times, and Token activity;
- the fact that a user approved offline access or revoked an application;
- Session-to-Token-family linkage and logout activity;
- post-logout `state`, registered URI, Refresh family and Token identifiers.

## Actors and trust boundaries

- **End user/browser:** holds Session/CSRF values and confirms logout or Grant
  revocation. Browser input is untrusted even when a valid cookie exists.
- **Public Client:** cannot keep a Client Secret. It holds bearer Refresh Tokens and
  identifies with public `client_id` only.
- **Confidential Client:** holds a Client Secret and may refresh, revoke, and
  introspect only its own authority.
- **Malicious or compromised Client:** may possess one valid Token, race requests,
  submit another Client ID, or attempt to turn endpoint behavior into an oracle.
- **External site:** may navigate a browser to logout, submit forms, frame pages, or
  attempt post-logout redirect abuse without reading same-origin responses.
- **OneIssuer HTTP process:** validates wire input and delegates authority changes;
  it is not the durable race arbiter.
- **PostgreSQL:** is the authority and concurrency boundary for family rotation,
  reuse, revoke cascades, and Audit commit.
- **Signing KeyStore:** signs Access/ID Tokens locally. It never receives Refresh
  Tokens and cannot decide lifecycle state.
- **Reverse proxy/operator:** owns TLS, edge limits, clock/storage monitoring,
  backup/key custody, and network policy.

## Fixed invariants

1. One canonical Issuer and no tenant/Realm/Organization dimension.
2. Exact registered Redirect and Logout URI comparison; no wildcard, prefix,
   decoding, or request-Host inference.
3. `offline_access` is never authority by itself. Current Client policy and a live
   explicit Consent Grant are required on initial issue and every refresh. Optional
   request Scope narrows only that Access Token; replacement Refresh Scope remains
   identical to the presented Refresh Token under RFC 6749 Section 6.
4. Clear Refresh Tokens are generated from a CSPRNG, sent only in their one successful
   Token response, and never persisted, logged, audited, metered, or returned by a
   management/current-user/read API.
5. A Refresh Token has at most one successful consumption. Every family has a
   single linear generation chain and an absolute expiry.
6. Before family absolute expiry, a consumed-token reuse revokes the whole family and
   linked active Access metadata before returning `invalid_grant`, even if that old
   generation's rolling expiry has passed.
7. A protocol response is written only after the transaction containing all state
   and required Audit events commits.
8. Revocation and Introspection never reveal whether a Token belongs to another
   Client. Public identity is not sufficient Introspection authentication.
9. Standard `GET` and `POST /oauth2/logout` requests never mutate authority. They
   issue a no-referrer 303 to a clean confirmation GET; the mutation requires the
   distinct hosted same-origin `/oauth2/logout/confirm` POST, exact bound Session,
   transaction-bound one-time CSRF, and the cookie-only server transaction.
10. A post-logout redirect is possible only for an ID-Token-identified Client, a
    Hint acceptable under the approved bounded time/key policy, and an exact
    registered Logout URI rechecked before redirect. Opaque `state` reaches only that
    verified URI after commit.
11. UserInfo and Introspection check current database lifecycle state; offline JWT
    verification remains bounded only by JWT expiry.
12. Cleanup never grants validity and never deletes a consumed Refresh digest
    before its family reuse-detection window is over.

## Threat and control matrix

| Threat | Primary controls | Required evidence |
| --- | --- | --- |
| Refresh Token database disclosure becomes direct bearer theft | versioned 256-bit opaque value; domain-separated SHA-256 digest only; no clear value in DB/Audit/read models | migration inspection, repository tests, sensitive-value scan |
| Stolen Refresh Token creates a durable sibling branch | mandatory rotation; conditional one-time consume; family generation uniqueness; whole-family revoke on consumed-token reuse | deterministic and real-PostgreSQL concurrent refresh tests |
| Old consumed generation stops detecting reuse after its rolling expiry | family-active/absolute check precedes generation expiry; consumed state wins and all digests remain indexed through the family evidence window | rolling-vs-absolute boundary and newest-descendant revocation tests |
| Benign retry after committed/lost response leaves attacker branch active | documented at-most-once delivery; retry is reuse and revokes every descendant; Client must reauthorize | fault-injected post-commit delivery test and example RP behavior |
| Attacker replays many consumed Tokens to amplify storage/Audit | fixed family/token lookup indexes; one bounded reuse event per target/family; no Audit for malformed/unknown traffic | unique-index test, repeated-replay row-count assertion |
| Refresh Scope escalation or accidental offline-authority change | request Scope is optional but exact/canonical, includes `openid` when present, and only narrows that Access Token within family/Grant/current Client policy; replacement Refresh Scope is identical; invalid Scope does not consume | scope/error/rotation identity matrix and property tests |
| `offline_access` obtained without explicit consent | Code Flow only; Client allowlist; first/expanded offline grant forces interaction; `prompt=none` fails without coverage | Authorize/Consent positive and negative browser tests |
| Disabled User/Client or revoked Grant continues refreshing | transaction locks/rechecks current User, Client, Grant and family before signing/insertion; fail closed | disable/revoke-versus-refresh race tests |
| Grant revoke then re-consent resurrects a pending Code | Code binds the issuance-time Grant version; revoke/reactivate increments version; exchange requires exact match | revoke/re-consent/old-Code test and interleaving test |
| Client removes and re-adds `offline_access`, reviving an old family | Scope removal atomically revokes existing Client families and linked Access metadata; re-add permits only new family issuance | Client-update/refresh race and non-resurrection test |
| Access Token remains usable at UserInfo after lifecycle revocation | Access metadata has explicit revoke state and family/Grant linkage; UserInfo checks it on every request | revoke/logout/grant-cascade UserInfo tests |
| JWT accepted by unrelated business API | fixed UserInfo `aud`; documentation; Introspection caller policy does not create resource audience | claim snapshots and cross-audience negative tests |
| Revocation endpoint is a Token-validity oracle | resolve the Client by its registered confidential-auth/public-identification method first; ownership-bound digest lookup; valid owning request always 200; unknown/wrong/expired states indistinguishable | byte/status/header comparison matrix |
| One Client revokes another Client's authority | Token-to-Client binding rechecked under transaction; wrong Client treated as unknown; for a Public Client, possession plus its public ID can only retire that possessed bearer value | cross-Client public/confidential tests |
| Revoking an old Refresh generation leaves its live descendants | any recognized owning generation, including consumed/rolling-expired, retires an otherwise-live family and linked Access; terminal family remains uniform no-op | old-generation/current-descendant Revocation matrix |
| Public Client impersonates protected Introspection caller | Introspection requires active Confidential Client and `client_secret_basic`; no public fallback or CORS credential shortcut | auth-method matrix and Discovery snapshot |
| Introspection leaks user/admin/internal data | minimal fixed response schema; inactive body exactly `{"active":false}`; no UUID, username, email, role, Session, digest, family, Audit, or arbitrary claim | response snapshots and forbidden-field scan |
| Introspection reports stale active state | current time, Token, family, User, Client, Grant and Scope policy checked in one consistent snapshot | state-transition matrix and repeatable-read integration test |
| Logout CSRF or RP POST/confirmation confusion | standard GET/POST request routes are zero-authority/read-only; only clean GET may bind; strict POST requires bound stage, exact Session/User, cookie-only transaction, transaction-bound one-time CSRF and same-origin Origin/Referer | real-browser method/form/cross-site, pre-confirm POST, duplicate-channel and missing/invalid CSRF tests |
| Standard RP logout is confused with existing local `/logout` | fixed disjoint routes and schemas; `/oauth2/logout` GET/POST is pre-confirm only; `/logout` accepts no RP fields and remains same-origin Session+CSRF mutation using the same atomic cascade | route/method/content-type/extra-field matrix and local-vs-RP cascade tests |
| Post-logout open redirect or ambiguous State append | verified signed `id_token_hint`; exact active Client lookup; byte-for-byte registered Logout URI before append; dedicated byte-preserving Location builder; a pre-existing decoded `state` query key makes a State-bearing request local-only | URI encoding/query/fragment/duplicate/state-key negative matrix and Fuzz |
| Client/Logout URI changes after GET | POST rechecks active Client and exact current registration; mismatch still permits local logout but suppresses external URI and State | disable/remove-URI between GET/POST tests |
| Logout hint swaps User or Client, or abuses stale signing keys | signature/Issuer/algorithm/claims validation; approved bounded stale-hint/clock/key-overlap policy; hint audience selects Client; current principal `sub` match; transaction stores verified IDs/URI plus only their bound opaque State, never raw Hint | mismatched `sub`/`aud`/`azp`/key/time tests |
| Cross-site Logout Request amplifies signature/transaction storage work | pre-verification global/per-IP limiter; global-rate × short-TTL live-row budget; per-Session cap at clean binding; bounded attempts and cleanup | cross-site burst, derived worst-case live rows, method, cap, limiter and cleanup tests |
| Original Logout Hint/State or transaction leaks through redirect Referer/URL/form | end-session response uses route-specific `Referrer-Policy: no-referrer`; 303 target is query-free; transaction exists only in a Path-scoped HttpOnly cookie; clean page has no external resource and uses `same-origin` only for its clean confirm form | Chromium GET/POST redirect request-header capture, Location/HTML scan, CSP/referrer snapshots |
| Required GET Logout Request exposes Hint/State in browser history or upstream access logs | support GET for standard compatibility but recommend form POST in Client/example docs; redact request target/query/body at OneIssuer and documented proxy; clean 303 prevents onward Referer propagation | GET/POST documentation snapshot, application/proxy-log canary and browser-history risk record |
| SameSite cookie omission on cross-site RP POST weakens or skips confirmation | initial POST is zero-authority/read-only; dedicated `SameSite=Lax` transaction cookie survives the proven 303 continuation; only clean GET binds the current main Session without weakening it to `SameSite=None` | Chromium cross-site form POST/continuation, cookie path/attribute and no-cookie negative tests |
| A later Logout Request overwrites the cookie and retargets an already rendered confirm form | POST accepts only bound-confirmable stage and exact Session/User; one-time CSRF proof is bound to transaction and stage, not merely the Session; POST never binds; overwritten/stale form fails locally | cookie-overwrite between render/submit, two-tab, pre-confirm POST and CSRF-rotation tests |
| Logout transaction replay, channel mixing, or form brute force | independent 256-bit lookup/CSRF values with domain-separated digest-only storage; lookup exclusively from transient cookie; form has only transaction-bound CSRF plus fixed decision; bounded attempts; one conditional consume; terminal/invalid/expired outcomes clear the cookie; no authority in browser-supplied URI/State | entropy/digest-domain, duplicate form/query transaction, cookie-loss, concurrent POST, terminal cleanup and attempt-cap tests |
| Login rotation disconnects authority or transfers a binding across accounts | stable binding is inherited only from an active Session for the same principal; account switch gets a new binding and fail-closed retirement of the old active binding; passive expiry does not cascade | same-user rotation, account-switch, expiry and real-PostgreSQL lineage races |
| Session revocation races Refresh | explicit cascade transaction; canonical lock order; refresh rechecks family; whichever commits last cannot leave active descendants | bidirectional concurrency and deadlock tests |
| Grant revocation races Code issue/Refresh | Grant locked before family mutation; Code/refresh revalidation; revoke/reactivate version state | issue/refresh/revoke interleaving tests |
| Current user enumerates or revokes another user's Grant | list derives principal from Session; its cursor contains only time + public `client_id`, never Grant UUID; revoke accepts only public `client_id` in strict JSON and resolves unique `(principal, client)` internally; cursor/input tampering remains owner-bound and unknown/wrong-owner is one 404 | cross-user/client/cursor matrix, response/schema forbidden-field scan and route-log test |
| User/Client administrative update creates partial revocation | status change, Session/family/Access retirement, and Audit commit atomically | injected Audit/Commit failure and rollback assertions |
| Refresh/Introspection RSA or DB resource exhaustion | 8 KiB forms, strict content type/duplicates, bounded auth headers/Token size, global and bounded per-IP/Client buckets before signing, operation deadlines | limiter/cap/refill tests and load budget record |
| Token-type confusion | distinct version prefixes and domain-separated digests; exact grant/parser branches; JWT Access structure still strict | cross-type Revocation/Introspection and parser Fuzz tests |
| Family cleanup erases replay evidence too early | retain every digest through absolute family expiry plus evidence window; reads enforce time before cleanup; FK-aware batches | retention-boundary and delayed-cleanup tests |
| Secret/Token leaks through errors, traces, logs, metrics or example RP | fixed error codes/labels; query/body/header redaction; transient transaction only in restricted HttpOnly cookie/memory; response allowlist only for opaque State bound to the verified post-logout URI; canary scan | HTTP/log/Audit/metric/Location/HTML/supply-chain exposure scan |
| Database/signing/Audit/commit partial failure | local signing callback inside bounded transaction; no response before commit; injected failures roll back consume/replacement/revoke | real PostgreSQL trigger and signer-fault tests |
| Discovery overclaims lifecycle support | typed capability model; fields/routes enabled together only after persistence and negative tests pass | metadata/route/live-behavior cross-test |

## Canonical lock and transaction rules

Presented Token digests may be resolved to candidate identifiers without a lock,
but all authority must be reloaded and validated after locks are acquired. New
family operations use the stable order:

```text
User → Client → Consent Grant → Refresh family → Refresh Token → Access metadata
```

Session/logout transactions lock the selected Session and stable binding before
applying their family cascade, but Refresh does not lock or require a live browser
Session: offline access survives passive Session expiry. Login/fixation rotation
copies the binding in its existing atomic login commit only when the old Session is
active and belongs to the same principal; account switching cannot cross-link Users
and retires the old active binding under the proposed fail-closed policy. Explicit
Session revocation and logout acquire the binding's families and retire them before
commit. Implementations must use set-based ordered updates and avoid per-row lock
order derived from attacker input.

Clean-bind and confirm first conditionally lock the presented logout transaction,
then the Session/binding and ordered family/Access rows. Ordinary Session revocation
never locks a logout transaction after the Session. A bind-time cap implementation
must reject the current transaction unless a replacement algorithm proves that it
cannot wait on another transaction while holding this order.

The legacy Code exchange may lock its unique Code first, then User, Client and
Grant. It never waits on an existing family before locking the Grant. If it creates
initial offline authority, family/Refresh/Access insertion occurs only after the
Grant lock, preserving the no-cycle relationship. Every cross-operation pair needs
a real PostgreSQL concurrency test and a bounded deadlock retry policy only for
classified serialization/deadlock errors; an application retry must never mint two
clear responses.

## Delivery and failure semantics

### Authorization Code exchange with offline access

Code consume, initial Access metadata, Refresh family, initial Refresh digest, and
Audit commit together. If the response is not delivered, the Code cannot be
retried. The Client starts a new Authorization Request.

### Refresh exchange

Presented-token consume, replacement digest, Access metadata, and Audit commit
together. A lost response followed by retry is indistinguishable from theft and
revokes the family. This behavior is intentionally fail-closed and must be stated in
Client and operations documentation.

### Revocation and logout

Revocation is idempotent at the wire layer. Internal database/Audit failure returns
a server error and leaves the prior authority unchanged. Logout does not clear the
browser cookie before the Session/token cascade commits and never redirects
externally before the applicable terminal transaction/cascade commit. Confirm,
cancel, invalid, expired, and already-terminal outcomes clear the transient lookup
cookie; a missing cookie produces only a fixed local result. Terminal delivery is
at most once: a lost confirmed Redirect/State is not replayed from a consumed
transaction, while a lost cancel response can never turn into confirm.

## Fixed privacy boundaries

The following values must never appear in general logs, arbitrary Audit values,
metric labels, ordinary API models, errors, or committed test output. They also must
not appear in URLs generated by OneIssuer, with one narrow protocol exception: the
exact post-logout `state` may be round-tripped only to the transaction's already
verified, still-registered byte-exact URI after the confirmed logout commit (never
after cancel):

- clear Refresh/Access/ID Token and all presented Token values;
- Refresh/Access digest, JWT `jti`, generation values, authority lookup result;
- Client Secret, Basic/Bearer/Cookie Header, CSRF and logout transaction value;
- raw `id_token_hint`/`logout_hint`, post-logout `state` outside the exception above,
  and any unverified URI;
- Session-to-family linkage and all family/Refresh/binding/logout-transaction IDs in
  protocol or new current-user output; internal User/Client/Session/Grant UUIDs never
  enter OAuth/OIDC protocol output;
- signing private key, database credentials, SQL parameters, or stack traces.

The existing restricted append-only Audit model may use a random internal Token,
family, Session, Grant, or logout-transaction UUID only in its fixed `target_id`
field. That exception does not permit a digest, clear value, generation, linkage,
URI/State, Client ID string, or copied identifier in Audit changed fields, logs, or
metric labels, and it never makes an internal UUID eligible for OAuth/OIDC or a new
phase-four current-user field. Existing owner/administrator-authorized phase-two
User/Client/Session resource-ID fields remain frozen compatibility surfaces; phase
four does not copy Audit targets into them or add family/binding/Token/Grant IDs.
The public protocol `client_id` is allowlisted only where a fixed OAuth/OIDC response
requires it and in the principal-owned Grant list/revoke input; that narrow allowance
does not expose the database Client UUID or permit arbitrary Client IDs elsewhere.

PostgreSQL necessarily stores a verified registered URI and its bound opaque State
for a short logout transaction, plus digest/lifecycle relationships for replay
detection. Access is repository-scoped, retention is bounded, and generic
admin/current-user reads do not expose these fields.

## Residual risks and deferred controls

- A copied newest Refresh Token can win the first race and receive one response;
  subsequent reuse revokes the family but cannot retract bytes already delivered.
- A Public Client cannot prove caller identity at Revocation; a holder of a valid
  bearer value can intentionally retire it. This is an availability property of
  RFC 7009 public-client use, not a Token-confidentiality oracle.
- JWT offline verifiers cannot observe Access metadata revocation before `exp`.
  Phase-four immediate revocation guarantees apply to UserInfo and Introspection.
- Bearer Refresh Tokens are not sender-constrained. DPoP/mTLS and hardware-backed
  Client keys remain future work.
- RP-Initiated Logout ends the selected OneIssuer Session but does not notify or
  destroy the RP's own Session. Front-/Back-Channel Logout is deferred.
- If confirmed logout commits but its Redirect response is lost, OneIssuer is logged
  out while the RP may retain its own Session; replay cannot recover the State/Location
  and the user or RP must begin a new flow.
- A later cross-site Logout Request can overwrite the browser's transient cookie and
  force an in-progress confirmation to fail/restart. Transaction-bound CSRF prevents
  retargeting, but this bounded availability nuisance remains subject to endpoint and
  edge rate limits.
- Because RP-Initiated Logout requires GET support, an RP choosing a query request can
  place Hint/State in browser history or infrastructure before OneIssuer receives it.
  OneIssuer recommends POST and redacts its own/proxy path, but cannot retract an
  upstream copy outside its trust boundary.
- Confidential self-introspection is not a resource-server registry and may be of
  limited utility until audiences/resources are designed.
- In-process endpoint limits do not coordinate replicas and do not replace edge
  rate limits, bot controls, or incident reputation systems.
- Long family retention increases database and backup exposure. PostgreSQL/backup
  compromise still exposes PII and digest metadata and may enable offline guessing
  only if Token entropy or CSPRNG assumptions fail.
- Restart-style RSA key rotation and operator cache overlap remain error-prone;
  remote KMS and automatic rotation are not addressed.
- Refresh does not mint a new ID Token, so an RP Session can outlive the default
  24-hour Hint/key-overlap window and lose post-logout redirection while local
  confirmed logout remains available. P4-00 freezes a configurable 5-minute through
  30-day bound and requires equal old-key overlap; the 90-day family remains longer.
- This remains a development release without OpenID Foundation certification or a
  production-readiness claim.

## Security review and evidence gate

ADR 0003, this model, and the P4-00 Spike were accepted on 2026-08-02. Residual
ownership is frozen as follows: OneIssuer maintainers own protocol, dependency,
Conformance, and browser-regression decisions; deployment operators own capacity,
clock, backup, edge limits, and verification-key overlap; RP integrators own local
Refresh replacement, at-most-once recovery, and RP Session destruction. Any change
to Refresh format/lifetime,
rotation/reuse, Scope narrowing, revoke cascade, Introspection caller/response,
logout hint/redirect/transaction-channel behavior, lock order, retention, or
metadata requires:

1. ADR and threat-model update before code merge;
2. positive, negative, concurrency, delivery-failure, and privacy tests;
3. migration/rollback/capacity and cleanup evidence;
4. Discovery, OpenAPI, Client, operations, and incident documentation updates;
5. race, Fuzz, vulnerability, SBOM, container, and sensitive-value gates;
6. applicable OIDC/OAuth Conformance rerun with secret-free evidence.

The accepted evidence and exact Hint/key, Session-lineage, SameSite, lock/retry,
schema, and capacity decisions are recorded in the
[phase-four dependency/concurrency Spike](./phase-4-dependency-concurrency-spike.md).
