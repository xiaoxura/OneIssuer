# OIDC Client integration guide

This guide describes the implemented OneIssuer `v0.1.0-dev.4` wire profile for a
server-side Relying Party (RP). The provider is single-Issuer and supports
Authorization Code Flow with mandatory S256 PKCE plus rotating Refresh Tokens,
restricted lifecycle endpoints, and RP-Initiated Logout.

The executable under `examples/oidc-client/` demonstrates the checks described
here, but it is an interoperability example, **not a production SDK**.

## 1. Discover the provider

Configure the Issuer as an exact canonical origin supplied out of band, for
example:

```text
https://id.example.invalid
```

Fetch:

```text
{issuer}/.well-known/openid-configuration
```

Require the returned `issuer` to equal the configured value byte-for-byte. Do not
derive trust from a request `Host` header, callback query, email domain, or an
endpoint URL alone. Cache Discovery/JWKS according to their headers, use HTTPS in
production, and reject metadata that moves an endpoint outside the trusted
Issuer origin.

The phase-four capability set is:

| Capability | Value |
| --- | --- |
| response type | `code` |
| response mode | `query` |
| grant type | `authorization_code` |
| refresh grant | `refresh_token`, single-use rotating family |
| subject type | `public` |
| ID Token signing | `RS256` |
| Client authentication | `none`, `client_secret_basic` |
| PKCE | `S256` only, required for every Client |
| scopes | `openid`, `profile`, `email`, `offline_access` |
| prompt values | `none`, `login`, `consent`, `create` |

Discovery advertises Revocation and an Introspection endpoint restricted to an
owning Confidential Client, plus the RP-Initiated Logout endpoint. Dynamic
Registration, `client_secret_post`, Request Objects, PAR, JARM, DPoP, and mTLS
remain outside this profile.

## 2. Provision a static Client

An authenticated, recently reauthenticated administrator creates the Client
through the management API documented in [`api/openapi.yaml`](../api/openapi.yaml).
There is no Dynamic Client Registration endpoint.

Required registration decisions:

- `client_type=public` produces auth method `none` and no Secret;
- `client_type=confidential` produces auth method `client_secret_basic` and a
  one-time clear Secret in the successful create response;
- register at least one exact Redirect URI;
- register the minimal Scope set needed by the RP;
- set Client `registration_enabled` only if this RP may use `prompt=create`.

Production Redirect URIs use HTTPS. Loopback HTTP is allowed only in an explicit
development environment. OneIssuer rejects fragments, wildcards, user info, and
unsafe URI forms, then compares the complete registered string byte-for-byte at
authorization and exchange. Preserve the exact scheme, host, port, path, and
query.

Store the generated Client ID as configuration. For a Confidential Client,
transfer the one-time Secret directly into a secret manager; it cannot be read
again. Never send the Secret to a browser, place it in a URL, use it as a Public
Client credential, or fall back to a form-body Secret.

## 3. Start an authorization

For every attempt, generate independent CSPRNG values and keep them in an
expiring server-side RP Session:

- at least 256 bits of unpredictable `state`;
- at least 256 bits of unpredictable `nonce`;
- a 43–128 character RFC 7636 unreserved ASCII `code_verifier`;
- `code_challenge = BASE64URL-NOPAD(SHA256(ASCII(code_verifier)))`.

Do not put the verifier, Token, or Client Secret in browser storage, a cookie,
query logging, distributed tracing, or a rendered page. Bind the pending attempt
to the browser Session, intended Issuer, Client ID, Redirect URI, Scope, creation
time, and single callback consumption.

Redirect the browser to the discovered authorization endpoint with exactly one
value for each security parameter:

```text
response_type=code
client_id=<registered-client-id>
redirect_uri=<exact-registered-redirect-uri>
scope=openid profile email
state=<per-attempt-state>
nonce=<per-attempt-nonce>
code_challenge=<derived-challenge>
code_challenge_method=S256
```

Use normal URL query encoding; do not pre-decode/re-encode a registered Redirect
URI inconsistently. `state` and `nonce` are 1–1024 bytes when present. OneIssuer
requires `openid`; Scope is limited to the Client's currently registered subset.

Optional interaction controls:

| Request | Behavior |
| --- | --- |
| no `prompt` | reuse an eligible Session and covering Grant, otherwise interact |
| `prompt=none` | never show UI; return an interaction error if login/Consent is needed |
| `prompt=login` | require fresh credentials and rotate the OneIssuer Session |
| `prompt=consent` | show Consent even when a Grant already covers the Scope |
| `prompt=create` | enter hosted registration only if global and Client policy allow it |
| `prompt=login consent` | fresh login followed by explicit Consent |
| `prompt=create consent` | hosted registration followed by explicit Consent |
| `max_age=<seconds>` | require authentication no older than this value; maximum 30 days |

`prompt=none` cannot be combined. `create` cannot be combined with `login`. An
already authenticated browser cannot use `create` as an account switch; it gets
`interaction_required` and must explicitly log out first.

The RP should set a short timeout on its pending attempt. If the user, browser,
or network abandons the flow, discard local state and start a new request.

## 4. Process the callback safely

The callback may contain either:

```text
code=<single-value>&state=<original-state>
```

or a standard error plus state. Before treating either outcome as belonging to
the browser:

1. require exactly one matching callback route and expected HTTP method;
2. enforce a small query-size limit and reject duplicate security parameters;
3. load one pending attempt from the server-side RP Session;
4. compare `state` in constant time before using the Code or error;
5. consume/retire the pending attempt so browser refresh cannot replay it;
6. never render or log the raw query, Code, state, or error context.

OneIssuer redirects only after it has trusted both Client and exact Redirect URI.
Initial Client/URI errors stay on a local provider error page and intentionally
do not reach the RP.

For `login_required`, `consent_required`, `interaction_required`,
`access_denied`, or another safe protocol error, display a generic RP message and
offer a new authorization. Do not retry an opaque provider transaction URL.

## 5. Exchange the Code once

Send an HTTPS `POST` to the discovered Token endpoint with content type exactly
`application/x-www-form-urlencoded`. The form is:

```text
grant_type=authorization_code
code=<callback-code>
redirect_uri=<exact-original-redirect-uri>
code_verifier=<original-verifier>
```

For a Public Client, add one form `client_id` and no Authorization header or
Secret. For a Confidential Client, send one RFC 6749 Basic Authorization header
and do not add `client_id`/`client_secret` credentials to the form. Build Basic
credentials with the OAuth form-encoding rules for Client ID and Secret before
base64 encoding; use a tested OAuth library rather than string concatenation.

Set a bounded connection/request timeout. A successful JSON response contains:

```text
access_token
token_type = Bearer
expires_in
id_token
scope
```

It never contains a Refresh Token. Require one JSON value, a small body, expected
types, `token_type=Bearer`, a positive bounded lifetime, and returned Scope no
broader than requested.

### At-most-once warning

Code consumption and Access metadata insertion commit atomically before the HTTP
response can be delivered. If the database commits and the connection then
fails, retrying the Code returns `invalid_grant`. The RP cannot determine from
that generic error whether an earlier response committed, and OneIssuer cannot
recreate the same signed Token Response.

**Do not retry the same Code. Start a new authorization request.** Never ask an
operator to reset Code state.

## 6. Validate the ID Token

Treat the compact ID Token as untrusted input until all checks succeed. A
production RP must:

1. parse exactly one compact JWS with a bounded size;
2. require exactly one signature;
3. require protected `alg=RS256`, `typ=JWT`, and a non-empty `kid`;
4. reject `none`, HMAC, algorithm confusion, embedded JWK, unexpected critical or
   duplicate headers, and malformed base64/JSON;
5. select exactly one public RSA signing key by `kid` from the discovered JWKS;
6. verify the RS256 signature with an algorithm allow-list;
7. require `iss` to equal the configured Discovery Issuer;
8. require `aud` to equal this Client ID and `azp` to equal this Client ID;
9. validate `exp` and `iat` with a small, reviewed clock-skew allowance;
10. require a sensible `auth_time`, and apply RP reauthentication policy;
11. compare `nonce` in constant time to the pending attempt when one was sent;
12. require a non-empty stable `sub`;
13. accept profile/email claims only as attributes covered by granted Scope, not
    as account-link authority.

OneIssuer's phase-four ID Token uses a single string Audience. Claims are:

| Claim | Rule |
| --- | --- |
| `iss`, `sub`, `aud`, `azp`, `exp`, `iat`, `auth_time` | always present |
| `nonce` | present when requested |
| `name`, `preferred_username` | present with `profile` |
| `email`, `email_verified` | present with `email` |

Use the verified tuple **`(iss, sub)`** as the local federated identity key. Never
link accounts by email, username, display name, or Client ID. `email_verified`
may be false; do not infer verification from the claim's presence.

## 7. Call UserInfo

Send the Access Token only to the discovered UserInfo endpoint using one Bearer
Authorization header. `GET` is preferred; OneIssuer also accepts an empty-body
`POST`. Do not place the Token in query/form input.

Require HTTPS, a small JSON body, and a successful status. Compare UserInfo `sub`
to the verified ID Token `sub` in constant time before accepting any attributes.
The response projection is:

| Scope | Claims |
| --- | --- |
| `openid` | `sub` |
| `profile` | `name`, `preferred_username` |
| `email` | `email`, `email_verified` |

The JWT Access Token has `typ=at+jwt`, RS256, Issuer `iss`, UserInfo URL `aud`,
User `sub`, `client_id`, canonical `scope`, `iat`, `exp`, and `jti`. These details
support OneIssuer's own validation but do **not** authorize another resource API
to accept it. UserInfo additionally requires committed unexpired metadata and
current Active User, Active Client, and covering Consent/Client Scope.

A `401 invalid_token` is terminal for that call. A Client holding
`offline_access` may perform one bounded Refresh exchange and must atomically
replace the old generation. `invalid_grant` is terminal for that family; clear
the local copy and start a new authorization. Introspection is available only
to the owning Confidential Client, and Revocation uses uniform success semantics
for unknown or already-inactive values.

## 8. Session, logout, and lifecycle expectations

The RP owns its own application Session and should rotate it after successful
callback validation. Keep Tokens server-side and render only minimal identity
attributes. Use Secure, HttpOnly, SameSite cookies, CSRF protection, short local
Sessions, and explicit local logout.

Use the discovered `end_session_endpoint` with a server-side, bounded ID Token
Hint and a fresh state. The example submits a form POST, keeps the RP Session
until the exact returned state is verified, then clears the local cookie and
redirects to a clean URL. The hosted provider confirmation is transaction-bound
and revokes the matching Session binding, Refresh families, and live Access
metadata atomically. Front-/back-channel logout is outside this profile.

Disabling a User/Client causes Code exchange and UserInfo to fail closed. Re-
enabling cannot restore an expired or consumed Code; only an unconsumed,
unexpired Code with all current bindings can proceed. UserInfo and Introspection
observe User/Client/Grant/Session/Refresh revocation immediately; external
resource servers validating JWTs directly still need their own bounded cache and
revocation policy.

## 9. Error and privacy handling

- treat `invalid_client` as a generic Client authentication/configuration failure;
- treat `invalid_grant` as a generic terminal Code failure and never distinguish
  unknown, expired, consumed, PKCE, URI, status, or delivery-race causes to users;
- handle `temporarily_unavailable`/`server_error` with a new user-initiated flow,
  not blind replay;
- never log raw authorization/callback URLs, Basic/Bearer headers, cookies,
  Secrets, state, nonce, challenge, verifier, Code, ID/Access Token, or decoded JWT
  claims containing PII;
- use a local correlation ID that does not embed any protocol value;
- cap retries, redirect depth, response sizes, header sizes, and network timeouts;
- keep Discovery/JWKS cache refresh errors separate from accepting an unknown
  key or algorithm.

## 10. Example and acceptance test

The repository example runs as Public Client A and Confidential Client B in the
`oidc-demo` Compose profile. The full disposable scenario is:

```bash
make phase-4-smoke
```

It is the recommended interoperability reference because it verifies state,
nonce, S256, signed ID Token claims, UserInfo Subject, separate Client Audience/
Consent, offline Consent, Refresh rotation/replay, lifecycle endpoints, logout,
Session reuse, and Secret handling. Copy concepts and tests—not the
in-memory Session store or development HTTP settings—into a production RP.
