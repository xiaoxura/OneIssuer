# ADR 0003: Phase-four token lifecycle and RP logout profile

- Status: Accepted
- Date: 2026-08-02
- Decision owners: OneIssuer maintainers
- Scope: `v0.1.0-dev.4`
- Extends: ADR 0001 and ADR 0002

## Context

Phase three deliberately issued only short-lived ID and Access Tokens. It has no
Refresh Token, Revocation, Introspection, RP-Initiated Logout, or user-facing
Consent revocation. That boundary made the first Authorization Code Flow small
enough to verify, but it also leaves four lifecycle gaps:

1. a Client cannot continue an explicitly approved offline session without
   starting a new Authorization Request;
2. a Client or user cannot explicitly retire a Token or Consent Grant;
3. a confidential caller cannot ask OneIssuer for the current server-authoritative
   state of a Token;
4. an RP cannot request a safe OneIssuer browser logout and return to a registered
   post-logout URI.

Adding these surfaces is not just endpoint work. Refresh rotation, replay handling,
Grant/Session cascades, and response delivery must share one PostgreSQL authority
model. Enabling Fosite's all-feature composition or adding placeholder rows would
break the phase-three atomicity and metadata-accuracy rules.

The existing Access Token remains an RFC 9068 JWT whose only supported audience is
OneIssuer UserInfo. Phase four does not yet have a resource-server registry or a
general business API authorization model, so Introspection needs a deliberately
narrow caller policy.

## Decision

### Offline access and Refresh Token issuance

- `offline_access` becomes a supported protocol Scope only with Authorization Code
  Flow. It is never accepted with another response/grant type.
- A Refresh Token is issued only when the verified request includes
  `offline_access`, current Client policy permits it, and a persistent Consent Grant
  covers it. First grant or expansion requires interactive consent;
  `prompt=none` returns `consent_required` when no covering grant exists.
- Public and Confidential Clients both receive rotating Refresh Tokens. Public
  Clients continue to identify themselves with exactly one `client_id` form field;
  Confidential Clients continue to use only `client_secret_basic`.
- Refresh Tokens are 256-bit, version-prefixed opaque values. PostgreSQL stores only
  a domain-separated SHA-256 digest and lifecycle metadata.
- Every successful refresh consumes the presented Token and returns exactly one
  replacement in the same family. Rotation is mandatory; there is no static-token
  compatibility flag or grace window.
- RFC 6749 Section 6 Scope semantics remain exact: optional request `scope` controls
  only the newly issued Access Token and can never exceed the Refresh family, live
  Grant, or current Client policy. If omitted, the Access Token receives the current
  effective family Scope; if explicit, it must include `openid`. Invalid Scope
  returns `invalid_scope` without consuming the Refresh Token.
- Every replacement Refresh Token retains Scope identical to the presented Refresh
  Token, as RFC 6749 Section 6 requires. Per-request Access narrowing is therefore
  not sticky and cannot silently reduce or terminate the offline family.
- The default rolling Refresh Token lifetime is 30 days and the default absolute
  family lifetime is 90 days. A replacement expires at the earlier of its rolling
  deadline and the family absolute deadline.
- A refresh response contains a new Access Token and replacement Refresh Token. It
  does not return a new ID Token in phase four.

### Replay and transaction semantics

- A second presentation of a consumed Refresh Token is reuse detection, including
  a concurrent duplicate after one request has committed. While the family remains
  inside its absolute lifetime, consumed status takes precedence over that old
  generation's rolling expiry so retained replay evidence still protects the newest
  descendant.
- Reuse atomically revokes the entire family and every still-live Access Token
  metadata row linked to it, then returns the same external `invalid_grant` used for
  other invalid Refresh Tokens.
- Reuse evidence is bounded to one fixed Audit event per consumed Token/family
  transition. Unknown or malformed Token traffic does not create unbounded Audit
  rows.
- Refresh consumption, replacement insertion, Access Token metadata insertion,
  family state, and success Audit commit in one PostgreSQL transaction before the
  response is written.
- Delivery remains at most once. If the commit succeeds but the response is lost,
  retrying the old Refresh Token triggers family revocation. OneIssuer does not
  introduce a non-standard idempotency key in this phase.

### Revocation

- Add `POST /oauth2/revoke` with RFC 7009 form and Client authentication rules.
- Revoking an Access Token marks only that Access Token metadata inactive.
- Revoking any recognized owning Refresh generation revokes its otherwise-live whole
  family and linked live Access Token metadata, even when that generation is already
  consumed or past its rolling expiry. An already revoked/absolute-expired family is
  a no-op. The clear Token is never retained or returned.
- A syntactically valid request from a Client resolved by its registered method
  returns `200` whether the Token is unknown, already inactive, expired, or newly
  revoked. A Public Client is identified, not secretly authenticated, by one
  `client_id`; possession of the bearer Token plus its owning public ID is sufficient
  to retire it. Another Client's Token is otherwise indistinguishable from unknown.
- Every such success/invalid-token response has the same zero-length body and
  no-store/no-cache headers; it does not invent a JSON status object.
- A recognized `token_type_hint` is only a lookup optimization; a miss still searches
  every supported Token type. An unknown hint is ignored and cannot alter the
  uniform response, as RFC 7009 Section 2.2 requires for an invalid hint value.
- Client Secret rotation does not silently revoke existing Token families. Client
  disable, explicit revocation, Grant revocation, User disable, and applicable
  Session/logout actions do.

### Introspection

- Add `POST /oauth2/introspect` with RFC 7662 form semantics.
- Only an active Confidential Client authenticated with `client_secret_basic` may
  call Introspection in phase four. It can receive `active=true` only for a Token
  issued to that same Client.
- Public Clients have no credential suitable for a protected Introspection
  endpoint and receive `invalid_client`; phase four does not invent a public-client
  secret or bearer management credential.
- Unknown, malformed, inactive, expired, revoked, wrong-Client, disabled-authority,
  or no-longer-consented Tokens return the exact minimal body `{"active":false}`
  after caller authentication succeeds.
- An active Access response exposes only `active`, `token_type="Bearer"`,
  `client_id`, effective canonical `scope`, `sub`, `iss`, `aud`, `iat`, and `exp`.
  An active Refresh response omits `token_type` and `aud`, and exposes only the
  remaining applicable fields. Both omit internal UUIDs, username, email, role,
  Session identifiers, digests, family identifiers, `jti`, and Audit data.
- This self-introspection profile does not turn the UserInfo Access Token into a
  general resource API Token. A future resource-server/audience registry requires
  another ADR.

### RP-Initiated Logout

- Add an `end_session_endpoint` at `/oauth2/logout` following RP-Initiated Logout
  1.0 within the phase-four profile.
- The advertised `/oauth2/logout` endpoint accepts both standard query `GET` and
  form `POST` Logout Requests as RP-Initiated Logout 1.0 requires. Both only validate
  input and create a short-lived server-side pre-confirm transaction; neither mutates
  Session or Token state. Both start at zero authority and do not bind a main Session
  cookie even when one happens to accompany the request.
- GET uses query only and no body; POST uses one bounded
  `application/x-www-form-urlencoded` body and no query. Duplicate, malformed, or
  cross-channel parameters fail before Hint verification. These standard requests do
  not require CSRF/same-origin because they cannot mutate authority.
- The clear transaction lookup value is carried only in a dedicated short-lived,
  `Secure`-in-production, HttpOnly, host-only, `SameSite=Lax` cookie whose Path is
  `/oauth2/logout/confirm`. End-session GET/POST returns a 303 with a route-specific
  `Referrer-Policy: no-referrer` to the query-free
  `GET /oauth2/logout/confirm`; neither the Location nor a form field carries the
  transaction, Hint, or State.
- The clean confirmation GET is the only operation allowed to bind an unbound
  pre-confirm transaction to the current browser Session. It rechecks the verified
  Hint Subject against that principal and suppresses external Redirect/State on a
  mismatch while still permitting a confirmed local logout. It then creates a
  one-time CSRF proof bound to that transaction, stage, and Session and renders a
  no-external-resource hosted page with `Referrer-Policy: same-origin`. A reload may
  re-render only for the exact bound Session/User and rotates the proof, invalidating
  older forms. GET does not consume the transaction or mutate Session/Token authority.
- A separate hosted `POST /oauth2/logout/confirm` performs confirm/cancel with the
  authenticated browser Session plus CSRF. It resolves the transaction exclusively
  from the HttpOnly cookie; the strict form contains only the transaction-bound CSRF
  proof and one fixed `confirm|cancel` decision. POST requires an already bound stage
  and exact current Session/User and never binds a pre-confirm transaction. Cookie
  overwrite therefore cannot retarget an already rendered form. Its route and form
  schema cannot be confused with the standard Logout Request.
- End-session GET/POST is rate-limited before Hint signature work and has a bounded
  zero-authority live-row budget derived from global rate, short TTL, and reviewed
  capacity; a separate per-Session cap is enforced when the clean GET binds. P4-00
  verified the 303 same-origin continuation in Chromium and Firefox for a cross-site
  RP POST when `SameSite=Lax` omits the main Session cookie, including transaction-
  cookie delivery/path/cleanup and absence of original Hint/State in the clean GET's
  Referer. OneIssuer does not weaken the main cookie to `SameSite=None` or mutate
  authority on that initial request. Cookie overwrite/stale-form rejection remains a
  required implementation test.
- A `post_logout_redirect_uri` is honored only after an `id_token_hint` identifies
  an active registered Client and the URI matches one of that Client's registered
  Logout URIs byte-for-byte. If `client_id` is also present it must match the Hint;
  a bare public `client_id` cannot authorize a redirect. `state` is returned only to
  that verified URI. Optional `logout_hint`/`ui_locales` are bounded but not used as
  authority in phase four.
- RP-Initiated Logout defines `client_id` as a common way to identify a registered
  redirect when no Hint is sent. Phase four intentionally adopts the narrower
  Hint-required redirect profile rather than treating a public identifier as enough;
  approval and the applicable Conformance result must record this interoperability
  tradeoff instead of calling it an unqualified full-profile implementation.
- URI registration matching happens before any response parameter is appended. The
  Location builder preserves the registered URI bytes and encodes only opaque
  `state`; if that URI already has a decoded query key named `state`, a State-bearing
  request becomes local-only rather than producing duplicate or ambiguous values.
- GET support is mandatory for the standard profile, but OneIssuer's Client/example
  guidance prefers form POST so Hint/State do not start in an RP-generated URL. Both
  methods are redacted from application/proxy access logs; the clean no-referrer 303
  cannot retract an upstream copy already created by an RP choosing GET.
- Hint signature, Issuer, Audience/authorized-party, Subject, issued-at, and expiry
  semantics are verified. A Hint is accepted through `exp + clock_skew`; after that,
  it is recently expired only while
  `now <= iat + logout_hint_max_age + clock_skew`. The maximum age defaults to 24
  hours and is configurable from 5 minutes through 30 days. Its encoded lifetime may
  not exceed 15 minutes, and an old public key remains in the verification ring for
  at least `logout_hint_max_age + clock_skew` after its last possible issuance.
  Failure downgrades to local logout without Redirect/State.
- The current authenticated browser cookie selects the exact Session to revoke.
  The hint's `sub` must match the current principal for RP Redirect/State authority;
  a mismatch downgrades the transaction to confirmed local logout only. Phase four
  does not expose an internal Session UUID as an OIDC `sid` claim and does not
  implement Front-/Back-Channel Logout.
- A missing/invalid hint or URI never causes an external redirect. The user can
  still perform a local, confirmed logout.
- Cancel consumes the transaction and renders a local not-logged-out result; it does
  not revoke, externally redirect, or return `state`, because post-logout redirect
  is only performed after a confirmed logout. Cancel, confirm, and every
  invalid/expired/terminal outcome clear the transient cookie using the same Path and
  attributes; cookie loss cannot authorize a mutation or redirect.
- Before any external redirect, `POST` rechecks that the Client remains active and
  the URI remains registered. A failed recheck suppresses Redirect/State but does
  not prevent the user from completing local logout.
- Confirmed RP logout revokes the current browser Session binding and Token families
  tied to it, marks linked Access metadata inactive, clears the main Session and
  transient cookies only after commit, and appends fixed Audit events atomically.
- Confirm/cancel terminal delivery is at most once. A lost confirmed Redirect/State
  is not replayed from a consumed transaction; the OP remains logged out and the RP/
  user starts a new flow. A lost cancel response can never be retried as confirm.
- The existing same-origin `POST /logout` remains a distinct Session+CSRF local
  mutation with no RP parameters, Redirect, or State. It and explicit current-user/
  administrator Session revocation reuse the same atomic binding/family/Access
  cascade; they never share the standard `/oauth2/logout` form schema.

### Consent and authority cascades

- Consent Grants gain an explicit revoked state rather than being physically
  deleted while dependent evidence exists.
- Current-user APIs may list and revoke only the principal's own Grants. The list does
  not expose an internal Grant UUID; `POST /api/v1/me/grants/revoke` accepts the
  already-public protocol `client_id` in a strict body and resolves the unique
  `(principal, client)` Grant internally. Revocation atomically retires and versions
  the Grant, invalidates unconsumed Codes issued against an older Grant version, and
  retires all Refresh families and related live Access metadata.
- A later interactive Consent can reactivate the same `(user, client)` Grant with
  the newly approved Scope set. Old revoked Scope is not silently unioned back in.
- User or Client disable continues to fail closed on every read and persists
  retirement of active families/Access metadata in the same administrative
  transaction; a partial status-only commit is not allowed.
- Removing `offline_access` from a Client permanently retires its existing families
  and linked live Access metadata. Re-adding the Scope can authorize a new family but
  never resurrects old bearer values.
- Passive browser Session expiry does not by itself cancel approved offline access.
  Explicit user/administrator Session revocation and logout do cascade to families
  linked to a stable internal Session binding. Login/fixation rotation transfers the
  binding only from an active Session to a replacement for the same principal;
  expired Sessions and account switches never transfer a binding across Users. The
  proposed account-switch default revokes the old active binding and its families.
  Cascade behavior uses a fixed revoke-reason allow-list; `rotation` and `expired`
  are explicitly non-cascading, while user/administrator/security revocations and
  `account_switch` cascade.
  This distinction must be visible in operations documentation.

### Metadata and compatibility

- Discovery advertises `refresh_token`, `offline_access`, `revocation_endpoint`,
  `introspection_endpoint`, and `end_session_endpoint` only after all corresponding
  routes and persistence rules are live.
- Authorization Code, PKCE, Redirect URI, Subject, Issuer, Client Secret, JWT
  algorithm, ID/Access Token claim, and UserInfo audience semantics stay compatible
  with ADR 0002.
- Existing phase-three Grants, Codes, and Access metadata are migrated without
  fabricating Refresh authority. Existing short-lived Access Tokens remain valid
  only under their original checks and expire naturally.
- The restart-style signing-key model remains. Phase four does not add hot reload,
  HSM/KMS, or remote signing.

## Alternatives rejected

- **Non-rotating Refresh Tokens:** fails current OAuth security guidance for public
  Clients and cannot detect copied-token reuse.
- **Rotation with a grace window:** reduces false positives after network loss but
  also permits bounded replay and creates ambiguous multi-winner state.
- **Process-local replay cache or mutex:** loses authority on restart and cannot
  coordinate replicas.
- **Store clear Refresh Tokens:** turns a database disclosure directly into usable
  bearer authority.
- **Revoke only the reused row:** leaves the attacker's winning descendant active.
- **Always revoke a family on Access Token revocation:** prevents a Client from
  retiring one leaked Access Token while retaining an otherwise trusted offline
  session.
- **Sticky narrowing of each replacement Refresh Token:** RFC 6749 Section 6 requires
  a newly issued Refresh Token to retain Scope identical to the presented one. A
  durable reduction instead uses Grant/Client policy plus Revocation and a new
  authorization; the request `scope` only narrows that response's Access Token.
- **Public unauthenticated Introspection:** creates a Token oracle. `client_id` alone
  is public identity, not endpoint authentication.
- **General resource-server Introspection now:** requires audience/resource policy,
  caller credentials, and authorization semantics outside the phase-four scope.
- **Logout by GET without confirmation:** allows logout CSRF and lets third-party
  pages mutate Session state through top-level navigation.
- **Arbitrary post-logout return URL:** recreates the open-redirect class already
  excluded from Authorization.
- **Delete Consent/Refresh rows immediately:** destroys replay evidence and conflicts
  with Access metadata foreign-key/history requirements.
- **Fosite ComposeAllEnabled:** expands the advertised and storage surface beyond
  the reviewed OneIssuer profile.

## Consequences

Positive:

- offline access has a bounded, replay-detecting lifecycle for both Client types;
- Session, Consent, Refresh family, and Access state have explicit revocation rules;
- Revocation and Introspection have non-enumerating ownership boundaries;
- RP logout cannot become an arbitrary redirect or cross-site mutation;
- all races remain PostgreSQL-authoritative and restart-safe.

Costs and limitations:

- refresh response loss can revoke the family on retry; Clients must start a new
  interactive authorization after `invalid_grant`;
- a 90-day absolute family requires longer retention and capacity planning than
  phase-three protocol artifacts;
- Introspection is useful only to the owning Confidential Client and OneIssuer's
  narrow Token profile; it is not yet a generic resource-server service;
- RP logout is local to the OneIssuer browser Session. Downstream RP Sessions are
  not notified by Front-/Back-Channel Logout;
- because refresh does not issue a new ID Token, RP Sessions can outlast the default
  24-hour logout-Hint/key-overlap window and then receive local logout without an RP
  redirect; increasing the window up to 30 days requires the same additional old-key
  overlap and still cannot cover a 90-day family by default;
- a lost post-commit logout Redirect leaves OneIssuer logged out but can leave the RP
  Session intact; consumed transaction/State delivery is not replayable;
- Public-Client Revocation cannot authenticate the caller beyond its public ID;
  anyone already holding that Client's bearer Token can retire it, which is an
  accepted availability tradeoff rather than a confidentiality boundary;
- JWT offline verifiers still cannot observe database revocation until expiration;
  only UserInfo and Introspection provide immediate server-authoritative state;
- schema and cross-table locking become substantially more complex and need
  explicit deadlock/concurrency evidence.

## Approval record

On 2026-08-02 the maintainers accepted the following as implementation input:

1. the 30-day rolling / 90-day absolute lifetime defaults;
2. no ID Token on refresh;
3. whole-family revocation on any consumed-token reuse, with no grace window;
4. RFC 6749 per-request Access Scope narrowing, replacement Refresh Scope identity,
   and `invalid_scope` behavior;
5. confidential-owning-Client-only Introspection and the per-Token response fields;
6. all Revocation/Introspection parameter and error snapshots, including ignored
   unknown `token_type_hint` behavior;
7. standard GET/POST Logout Requests, no-referrer 303 to a clean GET, cookie-only
   confirmed POST with transaction-bound one-time CSRF, bounded transactions,
   overwrite/stale-form rejection, State append rules, SameSite/cookie-cleanup
   behavior, and no `sid`/Front-/Back-Channel behavior;
8. the recently expired ID Token Hint age/clock/key-overlap policy;
9. stable Session binding across login rotation, explicit-revoke cascade, and
   passive-expiry non-cascade semantics;
10. current-user Grant selector/visibility, Grant-version invalidation, Client
    offline-Scope removal, and their cascades;
11. the migration/retention and at-most-once delivery costs.

See the [phase-four development plan](../phase-4-development-plan.md) and
[phase-four threat model](../phase-4-threat-model.md). The supporting dependency,
schema, lock-order, Session-lineage, Hint/key, browser, wire, RP-storage, capacity,
and Conformance findings are recorded in the accepted
[P4-00 Spike](../phase-4-dependency-concurrency-spike.md).
