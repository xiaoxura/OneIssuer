# OneIssuer OIDC interoperability example

This directory contains a deliberately small server-side Relying Party used by
the phase-three tests. It demonstrates OneIssuer's static Authorization Code +
S256 profile for both Public and Confidential Clients.

> [!CAUTION]
> This is an interoperability example, **not a production SDK or application
> template**. Its Sessions and JIT identities are in memory, local Compose uses
> HTTP, and it has no durable account/session/logout lifecycle. Do not deploy it
> publicly or copy its development settings into a production RP.

## What it verifies

- validates Discovery against the configured exact Issuer and fixed endpoint/
  capability profile;
- creates independent CSPRNG state, nonce, and PKCE verifier per attempt;
- stores those values in a server-side RP Session rather than browser storage;
- requires S256 for Public and Confidential flows;
- compares callback state before exchanging one Code;
- uses Public `none` or Confidential `client_secret_basic` as configured;
- fetches a public RSA JWKS and allows only RS256;
- verifies ID Token signature, `typ`, `kid`, Issuer, Audience, `azp`, expiry,
  issuance time, authentication time, nonce, and Scope/claim minimization;
- calls only the discovered UserInfo endpoint and compares `sub` to the ID Token;
- keys its mock JIT identity by the verified `(iss, sub)` pair;
- does not render or log Codes, Secrets, verifiers, or Tokens;
- sets bounded HTTP clients/servers, no-store/CSP headers, and HttpOnly RP cookies.

Provider/callback errors are intentionally generic so logs and pages cannot
become a protocol-secret oracle.

## Recommended run

Run the repository's complete disposable A/B scenario:

```bash
make phase-3-smoke
```

The script creates and cleans an empty database, private key, administrator,
Public Client A, Confidential Client B, and the B Secret file. It verifies the
example along with Consent, SSO, replay/concurrency, restart, privacy, and
container behavior. Runtime Secrets remain in a mode-restricted temporary
directory and are removed on exit.

Compose defines the two instances under profile `oidc-demo`:

| Service | Local URL | Client profile |
| --- | --- | --- |
| `client-a` | `http://127.0.0.1:8081` | Public / `none` |
| `client-b` | `http://127.0.0.1:8082` | Confidential / `client_secret_basic` |

Do not start the profile until the exact Redirect URIs are registered and the
generated Client IDs/Secret file are supplied.

## Configuration

The process reads environment variables directly and prints no rejected value:

| Variable | Required/default | Meaning |
| --- | --- | --- |
| `EXAMPLE_ISSUER` | required | exact canonical OneIssuer origin |
| `EXAMPLE_CLIENT_ID` | required | statically registered Client ID |
| `EXAMPLE_REDIRECT_URI` | required | exact registered callback URL |
| `EXAMPLE_HTTP_ADDR` | `:8080` | example listen address |
| `EXAMPLE_NAME` | `OneIssuer OIDC Example` | escaped display label |
| `EXAMPLE_SCOPES` | `openid profile email` | canonical supported Scope subset; must contain `openid` |
| `EXAMPLE_COOKIE_NAME` | `oneissuer_example` | RP Session cookie name |
| `EXAMPLE_COOKIE_SECURE` | `true` | use `false` only for explicit loopback HTTP |
| `EXAMPLE_PROVIDER_BACKCHANNEL` | empty | optional internal origin used only for transport after advertised-origin validation |
| `EXAMPLE_CLIENT_SECRET_FILE` | empty | recommended Confidential Secret file |
| `EXAMPLE_CLIENT_SECRET` | empty | alternative process environment input; do not use in Compose/production examples |

The two Secret inputs are mutually exclusive. The file must be non-empty,
bounded, readable by the process, and contain no newline. Mount it read-only from
a secret manager. The example does not print it, but an environment variable can
still be exposed by platform/process inspection and is retained only as a narrow
test configuration path.

`EXAMPLE_PROVIDER_BACKCHANNEL` exists for Compose, where the browser-visible
Issuer is loopback but the RP container reaches `http://oneissuer:8080`. The
example first verifies every advertised endpoint belongs to the exact Issuer,
then swaps only scheme/host for the internal transport. Do not use it to accept
arbitrary metadata origins.

## Native development

After OneIssuer is running and a matching static Client has been created:

```bash
export EXAMPLE_ISSUER=http://localhost:8080
export EXAMPLE_CLIENT_ID=<runtime-client-id>
export EXAMPLE_REDIRECT_URI=http://127.0.0.1:8081/callback
export EXAMPLE_HTTP_ADDR=:8081
export EXAMPLE_COOKIE_SECURE=false
go run ./examples/oidc-client
```

For a Confidential Client, set `EXAMPLE_CLIENT_SECRET_FILE` to a protected
runtime file rather than placing the clear value in the shell command. Open the
example home page and choose sign-in or account creation.

Run package tests with:

```bash
go test ./examples/oidc-client
go test -race ./examples/oidc-client
```

## Known non-production properties

- RP Sessions and linked identities disappear on restart and are not shared
  across replicas;
- no RP logout, Session revocation, CSRF token for application mutations, user
  database, authorization policy, refresh lifecycle, or account management;
- no persistent encrypted Token store; Tokens are used transiently during the
  callback and discarded;
- no distributed state/replay cache, HA routing, rate limit, telemetry backend,
  or operational administration;
- local HTTP and non-Secure cookies are accepted only for loopback development;
- provider metadata and claim expectations are intentionally OneIssuer-specific,
  not a generic OIDC library API.

For an actual RP, use a maintained OIDC library with strict algorithm and Issuer
configuration, durable encrypted server-side Sessions, production TLS/cookies,
CSRF and rate limits, monitored key caching, explicit local logout, account-link
review, and the at-most-once recovery behavior in
[`docs/oidc-client-integration.md`](../../docs/oidc-client-integration.md).
