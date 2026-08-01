# Configuration reference

OneIssuer `v0.1.0-dev.3` uses environment variables only:

```text
safe code defaults < environment variables < explicit test injection
```

The process never derives its Issuer from `Host`, forwarding headers, or request
data, and never automatically loads a working-directory `.env`. `oneissuer
config check` validates the complete service configuration and signing-key ring
before a listener opens. Its JSON output redacts the database credential and
reports only safe key metadata; it never prints a file path or private JWK.

## Service variables

| Variable | Default | Accepted range and behavior |
| --- | --- | --- |
| `ONEISSUER_ENV` | `development` | `development`, `test`, or `production` |
| `ONEISSUER_ISSUER` | `http://localhost:8080` | Canonical origin only: absolute HTTP(S), no user info/path/trailing slash/query/fragment; non-loopback HTTP is rejected; explicit HTTPS required in production |
| `ONEISSUER_HTTP_ADDR` | `:8080` | TCP listen address with port 1–65535 |
| `ONEISSUER_DATABASE_URL` | none | Required PostgreSQL URL with host/database; `sslmode=disable` rejected in production |
| `ONEISSUER_DATABASE_MAX_CONNS` | `10` | 1–100 |
| `ONEISSUER_SIGNING_KEY_FILE` | none | Required regular, non-symlink private RSA JWK file; must pass the key rules below |
| `ONEISSUER_VERIFICATION_KEYS_FILE` | empty | Optional regular, non-symlink, **public-only** JWKS for overlap during restart-style rotation |
| `ONEISSUER_AUTHORIZATION_CODE_TTL` | `1m` | 30 seconds–5 minutes |
| `ONEISSUER_ID_TOKEN_TTL` | `5m` | 1–15 minutes |
| `ONEISSUER_ACCESS_TOKEN_TTL` | `10m` | 1–30 minutes |
| `ONEISSUER_OIDC_CLOCK_SKEW` | `30s` | 0–2 minutes; JWT validation tolerance only |
| `ONEISSUER_LOG_LEVEL` | `info` | `debug`, `info`, `warn`, or `error` |
| `ONEISSUER_LOG_FORMAT` | `json` | `json` or `text` |
| `ONEISSUER_SHUTDOWN_TIMEOUT` | `15s` | Positive, at most 5 minutes |
| `ONEISSUER_HTTP_READ_HEADER_TIMEOUT` | `5s` | Positive, at most 10 minutes |
| `ONEISSUER_HTTP_READ_TIMEOUT` | `10s` | Positive, at most 10 minutes |
| `ONEISSUER_HTTP_WRITE_TIMEOUT` | `30s` | Positive, at most 10 minutes |
| `ONEISSUER_HTTP_IDLE_TIMEOUT` | `60s` | Positive, at most 10 minutes |
| `ONEISSUER_HTTP_MAX_HEADER_BYTES` | `1048576` | 1–16777216 bytes; Compose deliberately uses 65536 |
| `ONEISSUER_TRUSTED_PROXIES` | empty | Comma-separated CIDRs; empty ignores forwarded headers |
| `ONEISSUER_COOKIE_NAME` | `oneissuer_session` | Valid HTTP cookie token; production requires an `__Host-` prefix |
| `ONEISSUER_COOKIE_SECURE` | `false` | Production requires `true` |
| `ONEISSUER_SESSION_TTL` | `24h` | Positive, at most 30 days |
| `ONEISSUER_SESSION_IDLE_TIMEOUT` | `2h` | Positive, at most 30 days and no greater than the absolute Session TTL |
| `ONEISSUER_CSRF_TTL` | `15m` | Positive, at most 1 hour |
| `ONEISSUER_AUTH_TRANSACTION_TTL` | `10m` | Positive, at most 1 hour |
| `ONEISSUER_LOGIN_REAUTH_WINDOW` | `15m` | Positive, at most 24 hours; bounds sensitive administrator operations |
| `ONEISSUER_CLEANUP_INTERVAL` | `5m` | Positive, at most 1 hour |
| `ONEISSUER_REGISTRATION_ENABLED` | `false` | Deny by default; production requires an explicit value |
| `ONEISSUER_PASSWORD_MIN_LENGTH` | `15` | 15–128 Unicode code points |
| `ONEISSUER_PASSWORD_MAX_BYTES` | `1024` | 64–4096 UTF-8 bytes and at least the minimum-length setting |
| `ONEISSUER_ARGON2_MEMORY_KIB` | `65536` | 19456–1048576 KiB per hash |
| `ONEISSUER_ARGON2_TIME` | `3` | 2–10 Argon2id passes |
| `ONEISSUER_ARGON2_THREADS` | `2` | 1–16 lanes |
| `ONEISSUER_ARGON2_MAX_CONCURRENT` | `2` | 1–64 in-process concurrent hashes |

Compose-only interpolation values such as
`ONEISSUER_SIGNING_KEY_HOST_FILE`, `ONEISSUER_BUILD_GOPROXY`, port overrides,
and `EXAMPLE_CLIENT_*` are deployment inputs to `deploy/docker-compose.yml`, not
application environment variables. See [`.env.example`](../.env.example).

## Issuer invariants

The configured Issuer is a permanent protocol identifier and URL base. For
example, `https://id.example.com` is valid; all of the following are rejected:

```text
https://id.example.com/
https://id.example.com/tenant-a
https://user@id.example.com
https://id.example.com?region=a
http://id.example.com
```

Only an explicit loopback host (`localhost`, `127.0.0.1`, or another loopback IP)
may use HTTP, including in development. OneIssuer derives Discovery, Authorize,
Token, UserInfo, and JWKS URLs from this value. Changing it changes `iss`, breaks
existing validation, and creates a different security domain; do not use a load
balancer's internal URL or allow forwarding headers to rewrite it.

## Signing-key file invariants

The active file must contain exactly one RSA private JWK whose metadata is:

- `alg=RS256` and `use=sig`;
- at least 2048 RSA bits (`keys generate` creates 3072 bits);
- `kid` equal to the RFC 7638 SHA-256 thumbprint;
- no X.509 certificate fields;
- no duplicate `kid` in the optional verification set.

The loader rejects a directory, symlink, empty/oversized file, changed file while
opening, malformed JSON, a public-only active key, a non-RSA key, any active
algorithm other than RS256, and any private-key file with group or world mode
bits. Use a normal file with mode `0600`. It must be readable by the service
identity; the shipped container runs as UID/GID `65532`.

Do not place a private JWK in an environment variable, PostgreSQL, a container
image, source control, shell history, diagnostic bundle, log, or HTTP response.
Use a read-only secret mount backed by a reviewed secret-management system. The
optional verification file contains public keys only, but its integrity still
controls token verification and must be change-controlled.

Generate and inspect safe public material with:

```bash
oneissuer keys generate --alg RS256 --out /protected/path/signing-key.jwk
oneissuer keys public \
  --in /protected/path/signing-key.jwk \
  --out /controlled/path/signing-key-public.jwks
oneissuer config check
```

Both key commands refuse to overwrite an existing destination. See the
[key-rotation runbook](./key-rotation-runbook.md) before replacing an active key.

## OIDC lifetimes and clock skew

- Authorization Code expiry is checked during exchange and never depends on the
  cleanup loop.
- ID and Access Token expiry is encoded in the signed claims. UserInfo also
  requires a matching, committed, unexpired Access Token metadata row.
- `ONEISSUER_OIDC_CLOCK_SKEW` tolerates a bounded JWT verifier/clock difference;
  it does not extend Code, Session, authorization-transaction, Consent, or
  metadata authority.
- Code and Access metadata remain in PostgreSQL for 24 hours after expiry before
  cleanup eligibility. This retention is evidence, not continued validity.

The Access Token audience is OneIssuer's own UserInfo endpoint. A resource API
must not accept these tokens just because it can verify the RSA signature.

## Production invariants

With `ONEISSUER_ENV=production`, validation fails closed unless all of these are
true:

1. `ONEISSUER_ISSUER` is explicitly set and uses HTTPS;
2. the database URL does not disable TLS;
3. `ONEISSUER_COOKIE_SECURE=true`;
4. `ONEISSUER_COOKIE_NAME` begins with `__Host-`;
5. `ONEISSUER_REGISTRATION_ENABLED` is explicitly `true` or `false`;
6. an active RS256 signing key and optional public verification set load safely.

A `__Host-` cookie has no Domain attribute and uses `Path=/`. OneIssuer derives
matching pre-auth and CSRF names from the Session name. Session and pre-auth
cookies are HttpOnly; the CSRF cookie is intentionally browser-readable for the
double-submit design. SameSite and Origin/Referer validation remain enforced.

Do not enable registration merely to Bootstrap an administrator. Bootstrap is a
separate CLI operation and registration remains an independent policy decision.
Client-specific `registration_enabled` must also permit `prompt=create`.

## Password and Argon2 capacity

Passwords are exact UTF-8 input: OneIssuer does not trim, normalize, or impose
composition rules. It allows paste/password managers and stores Argon2id PHC
hashes. A valid older hash is transparently upgraded after successful login when
configured parameters increase.

Argon2 memory is per operation. A rough upper memory budget is:

```text
ONEISSUER_ARGON2_MEMORY_KIB × ONEISSUER_ARGON2_MAX_CONCURRENT
```

Benchmark on the actual CPU and memory limit. When the bounded worker budget is
full, the service returns `429 temporarily_unavailable`; do not remove the bound.

## Session and cleanup semantics

- absolute and idle Session expiry are server-authoritative;
- login rotates the Session and revokes an existing browser Session;
- every authenticated request checks current User status and revocation in
  PostgreSQL;
- CSRF digests rotate when the browser clear value is missing or expired;
- terminal authorization transactions are retained for 24 hours;
- retired login Sessions are retained for 30 days;
- Authorization Code and Access Token metadata are retained for 24 hours after
  expiry;
- Consent Grants persist until a future explicit grant-management lifecycle;
- Audit events are never deleted by the application cleanup loop.

Cleanup never grants validity: every read/exchange path enforces expiry before a
background deletion can occur.

## Command scopes

- `oneissuer version`, `help`, and `keys *` do not load service configuration;
- `oneissuer migrate *` requires only the database URL and pool limit;
- `oneissuer admin bootstrap` validates database, environment, PostgreSQL TLS,
  password policy, and Argon2 settings, but does not require a signing key;
- `oneissuer serve` and `oneissuer config check` validate every service setting
  and load the key ring;
- validation reports field/reason pairs without echoing rejected values.

Example:

```bash
set -a
. ./.env
set +a
oneissuer config check
```

Structured logging redacts password, authorization, cookie, token, secret,
credential, DSN, and database URL attributes. The service does not log request
bodies, authorization headers, cookies, raw panic values, SQL parameters,
account identifiers, full user agents, or full Client IPs.

## Trusted proxies

Forwarding headers take effect only when the direct TCP peer is in
`ONEISSUER_TRUSTED_PROXIES`. `X-Forwarded-For` is walked right-to-left across
trusted hops; malformed chains are ignored. Proxy host/scheme never changes the
Issuer. Configure only actual proxy CIDRs; never trust `0.0.0.0/0` or `::/0`.

## Production checklist

- inject database credentials and the private key from dedicated secret systems;
- terminate TLS at a trusted proxy and configure narrow proxy CIDRs;
- restrict `/metrics`, administrator routes, and PostgreSQL network access;
- run one explicit `migrate up` release job before application replicas;
- execute first-admin Bootstrap through a controlled TTY or secret pipe;
- prepublish and retain public keys according to the rotation runbook;
- back up PostgreSQL and signing material under separate access controls;
- monitor Audit, Session, Code, and Access metadata table growth;
- do not reuse `.env.example`, local credentials, or Compose as a production
  deployment manifest.

See [operations.md](./operations.md) and
[key-rotation-runbook.md](./key-rotation-runbook.md).
