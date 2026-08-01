# Phase-three protocol handoff

Status: accepted phase-two boundary freeze  
Input version: `v0.1.0-dev.2`  
Accepted against: [`phase-2-release-notes.md`](./phase-2-release-notes.md), verified 2026-08-01

Phase three may add Discovery, JWKS, Authorize, PKCE, Token, ID Token, Access
Token, and UserInfo only after phase-two acceptance is green. This document
states which phase-two semantics must be reused rather than reimplemented.

## Frozen domain contracts

### Identity

- `User.Subject` is the external stable `sub`; never derive it from ID, username,
  or email.
- Username/email normalization and uniqueness rules are compatibility-sensitive.
- Password verification goes through `identity.Service.VerifyLogin`, including
  dummy unknown-account work, disabled semantics, concurrency gate, and rehash.
- Protocol handlers never query/serialize a credential digest.
- Disabled users cannot authenticate and existing Sessions become invalid.

### Client

- Resolve Clients through the Client service/repository read model; no secret
  digest enters an HTTP response.
- Public means authentication method `none`; confidential means
  `client_secret_basic` in the current registry.
- Use `ValidateSecret` for confidential authentication and its generic failure.
- Use exact `RedirectURIMatches` after structural registration validation; do not
  introduce prefix, wildcard, decoding, case, or query normalization.
- Requested scopes must be a subset of the stored fixed allowed scopes and must
  include `openid` for OIDC.
- Any new auth method, response type, grant, URI rule, or scope needs a new ADR,
  migration/API change, and negative tests.

### Session and recent authentication

- Browser authority is a server-side Session cookie, not an OAuth token.
- Use `session.Service.Authenticate` on browser requests and retain CSRF for all
  OneIssuer state mutations.
- `Principal.AuthenticatedAt` is the source for `max_age`/recent-auth policy design;
  phase three must define protocol behavior without bypassing current admin rules.
- Successful reauthentication creates a fresh Session and revokes the old browser
  Session; protocol continuation is separate from Session authority.

### Authentication transaction

- The browser receives only the opaque transaction token.
- A protocol adapter must first validate Client status/type, exact Redirect URI,
  response/grant type, Scope, PKCE syntax/method, prompt/max_age, State, and Nonce
  bounds, then call `authflow.CreateVerified` with the minimal verified context.
- `authflow.Resolve` enforces digest lookup, TTL, and unconsumed state.
- Final success must consume transaction context exactly once in the same logical
  issuance operation; protocol handlers must not read/update its SQL tables
  directly.
- State, Nonce, PKCE challenge, and transaction clear token never enter logs,
  audit details, metrics labels, or error bodies.

### Audit, errors, and pagination

- Preserve current event/result/target names and value-free changed-field model.
  Add protocol events through the fixed whitelist, never arbitrary metadata.
- Preserve `X-Request-ID`, safe error envelope, privacy mappings, and bounded
  fixed labels. OIDC endpoints additionally require RFC-compliant errors and
  strict redirect/no-redirect rules.
- Preserve opaque cursor encoding and field visibility for management APIs.

### Storage and lifecycle

- Production migrations remain the schema source and are immutable after checksum
  approval. New tables start at migration 00006 or later.
- Keep explicit `migrate up`; `serve` only checks compatibility.
- Compose retains a one-shot migration service.
- New background jobs use the application Context, bounded database operations,
  and stop before pool closure.
- Keep one configured Issuer and no tenant/Realm/Organization fields.

## Required phase-three design work

Before implementation, submit protocol-specific ADR/threat analysis for:

1. canonical Discovery metadata and fixed Issuer URL behavior;
2. signing algorithm/key storage, JWK `kid`, public JWKS cache, rotation overlap,
   emergency revocation, and backup;
3. Authorize parameter parsing, duplicate parameter rejection, response mode,
   prompt/max_age, consent decision, and error redirect safety;
4. S256 PKCE requirements, verifier syntax, constant-time comparison, and public
   Client policy;
5. random digest-only single-use Authorization Code schema and atomic exchange;
6. Token endpoint Client authentication, content type, rate/size bounds, and
   uniform errors;
7. ID Token claims (`iss`, `sub`, `aud`, `azp`, `exp`, `iat`, `auth_time`,
   `nonce`) and clock skew;
8. Access Token format, audience/resource semantics, lifetime, revocation, and
   UserInfo authorization;
9. optional Refresh Token rotation/reuse detection (or explicit deferral);
10. protocol audit/privacy labels and conformance plan.

## Explicitly forbidden shortcuts

- returning a successful authorization response before code/token machinery exists;
- accepting a Redirect URI supplied by the browser after authentication;
- deriving Issuer from `Host` or forwarding headers;
- reading credential/secret/session SQL directly from a protocol Handler;
- placing User/Client ID, URI, Scope string, State, Nonce, Code, or Token in a
  metric label or general log;
- using a signed self-contained browser Session to bypass server revocation;
- adding placeholder token tables or fields without implemented lifecycle rules;
- treating the React mock state as an identity or consent source.

## Entry checklist

Phase three starts only when:

- phase-two migration checksum, generation, race, fuzz, vulnerability, OpenAPI,
  Web, image, and Compose gates pass;
- Bootstrap, login, rotation, revocation, restart persistence, exact Client URI,
  one-time Secret, and append-only Audit evidence is recorded;
- phase-two OpenAPI and error/visibility semantics are frozen;
- operators have Bootstrap/backup/restore/retention documentation;
- any unresolved phase-two security issue has an owner or blocks protocol work.
