# Configuration reference

OneIssuer uses an environment-only configuration model:

```text
safe code defaults < environment variables < explicit test injection
```

The application never derives its Issuer from `Host`, forwarding headers, or
other request data and never automatically loads a working-directory `.env`.
`oneissuer config check` validates the complete service configuration before any
listener opens and prints only a redacted JSON representation.

## Variables

| Variable | Default | Accepted range and behavior |
| --- | --- | --- |
| `ONEISSUER_ENV` | `development` | `development`, `test`, or `production` |
| `ONEISSUER_ISSUER` | `http://localhost:8080` | Absolute HTTP(S) URL; no user info, query, or fragment; explicit HTTPS value required in production |
| `ONEISSUER_HTTP_ADDR` | `:8080` | TCP listen address with port 1–65535 |
| `ONEISSUER_DATABASE_URL` | none | Required PostgreSQL URL with host/database; `sslmode=disable` rejected in production |
| `ONEISSUER_DATABASE_MAX_CONNS` | `10` | 1–100 |
| `ONEISSUER_LOG_LEVEL` | `info` | `debug`, `info`, `warn`, or `error` |
| `ONEISSUER_LOG_FORMAT` | `json` | `json` or `text` |
| `ONEISSUER_SHUTDOWN_TIMEOUT` | `15s` | Positive, at most 5 minutes |
| `ONEISSUER_HTTP_READ_HEADER_TIMEOUT` | `5s` | Positive, at most 10 minutes |
| `ONEISSUER_HTTP_READ_TIMEOUT` | `10s` | Positive, at most 10 minutes |
| `ONEISSUER_HTTP_WRITE_TIMEOUT` | `30s` | Positive, at most 10 minutes |
| `ONEISSUER_HTTP_IDLE_TIMEOUT` | `60s` | Positive, at most 10 minutes |
| `ONEISSUER_HTTP_MAX_HEADER_BYTES` | `1048576` | 1–16777216 bytes |
| `ONEISSUER_TRUSTED_PROXIES` | empty | Comma-separated CIDRs; empty ignores all forwarded headers |
| `ONEISSUER_COOKIE_NAME` | `oneissuer_session` | Valid HTTP cookie token; production requires an `__Host-` prefix |
| `ONEISSUER_COOKIE_SECURE` | `false` | Production requires `true` |
| `ONEISSUER_SESSION_TTL` | `24h` | Positive, at most 30 days |
| `ONEISSUER_SESSION_IDLE_TIMEOUT` | `2h` | Positive, at most 30 days and not greater than absolute Session TTL |
| `ONEISSUER_CSRF_TTL` | `15m` | Positive, at most 1 hour |
| `ONEISSUER_AUTH_TRANSACTION_TTL` | `10m` | Positive, at most 1 hour |
| `ONEISSUER_LOGIN_REAUTH_WINDOW` | `15m` | Positive, at most 24 hours; bounds sensitive administrator operations |
| `ONEISSUER_CLEANUP_INTERVAL` | `5m` | Positive, at most 1 hour |
| `ONEISSUER_REGISTRATION_ENABLED` | `false` | Deny by default; production requires this variable to be explicitly set |
| `ONEISSUER_PASSWORD_MIN_LENGTH` | `15` | 15–128 Unicode code points |
| `ONEISSUER_PASSWORD_MAX_BYTES` | `1024` | 64–4096 UTF-8 bytes and at least the minimum length setting |
| `ONEISSUER_ARGON2_MEMORY_KIB` | `65536` | 19456–1048576 KiB per hash |
| `ONEISSUER_ARGON2_TIME` | `3` | 2–10 Argon2id passes |
| `ONEISSUER_ARGON2_THREADS` | `2` | 1–16 lanes |
| `ONEISSUER_ARGON2_MAX_CONCURRENT` | `2` | 1–64 in-process concurrent hashes |

Session, CSRF, pre-auth, authorization-transaction, and Client Secret clear values
are generated at runtime and are **not configuration**. There is no default
administrator credential, signing-key configuration, tenant identifier, or
long-lived management token in phase two.

## Production invariants

With `ONEISSUER_ENV=production`, validation fails closed unless all of these are
true:

1. `ONEISSUER_ISSUER` is explicitly set and uses `https`;
2. the database URL does not disable TLS;
3. `ONEISSUER_COOKIE_SECURE=true`;
4. `ONEISSUER_COOKIE_NAME` begins with `__Host-`;
5. `ONEISSUER_REGISTRATION_ENABLED` is explicitly `true` or `false`.

A `__Host-` cookie has no Domain attribute and uses `Path=/`. OneIssuer derives
matching pre-auth and CSRF names from the configured session name. The session
and pre-auth cookies are HttpOnly; the CSRF cookie is intentionally readable for
double-submit use. SameSite and Origin/Referer validation remain enforced by the
server.

Do not enable registration merely to Bootstrap an administrator. Bootstrap is an
explicit CLI operation and registration remains an independent policy decision.

## Password and Argon2 capacity

Passwords are validated as exact UTF-8 input: OneIssuer does not trim, normalize,
or impose composition rules. It allows paste/password managers and hashes with
Argon2id in PHC format. Existing valid hashes are transparently replaced after a
successful login when configured parameters increase.

Argon2 memory is per operation. A rough upper memory budget is:

```text
ONEISSUER_ARGON2_MEMORY_KIB × ONEISSUER_ARGON2_MAX_CONCURRENT
```

Benchmark the defaults on the actual CPU and memory limit before production.
Increasing either value without adjusting container memory can cause avoidable
availability loss. When the bounded worker budget is full, the service returns a
stable `429 temporarily_unavailable` rather than starting unlimited hashes.

## Session and cleanup semantics

- absolute Session expiry and idle expiry are both server-authoritative;
- login creates a new Session ID and revokes an existing browser Session;
- every authenticated request checks current user status and revocation in
  PostgreSQL;
- CSRF digests rotate when the clear browser value is missing or expired;
- cleanup does not grant validity: an expired record is unusable before deletion;
- retired login sessions are retained for 30 days, terminal authorization
  transactions for 24 hours, and expired pre-auth state can be removed promptly;
- audit events are not deleted by the application cleanup loop.

## Command scopes

- `oneissuer version` and help do not read runtime configuration;
- `oneissuer migrate *` requires only database URL and pool limit;
- `oneissuer admin bootstrap` uses `ScopeBootstrap`: database, environment,
  PostgreSQL TLS rule, password policy, and Argon2 envelope;
- `oneissuer serve` and `oneissuer config check` validate every variable;
- validation reports all discoverable field/reason pairs without echoing rejected
  values.

Example:

```bash
set -a; . ./.env; set +a
oneissuer config check
```

The output masks database credentials and secret-looking URL query values.
Structured logging applies another redaction layer for password, authorization,
cookie, token, secret, credential, DSN, and database URL attributes. The service
does not log request bodies, authentication headers, cookies, raw panic values,
SQL parameters, account identifiers, full user agents, or full client IPs.

## Trusted proxies

Forwarding headers take effect only when the direct TCP peer is within
`ONEISSUER_TRUSTED_PROXIES`. `X-Forwarded-For` is walked right-to-left across
trusted hops; malformed chains are ignored. Proxy host/scheme never changes the
configured Issuer. Use only actual proxy CIDRs; do not trust `0.0.0.0/0` or
`::/0`.

## Production checklist

- inject the database URL from a secret manager rather than a command argument;
- terminate TLS at a trusted proxy and set narrow proxy CIDRs;
- restrict `/metrics` and PostgreSQL network access;
- run one explicit `migrate up` release job before application replicas;
- execute first-admin Bootstrap through a controlled TTY or secret pipe;
- back up PostgreSQL and monitor audit/session table growth;
- do not reuse `.env.example`, Compose credentials, or Compose itself as a
  production deployment manifest.

See [operations.md](./operations.md) for Bootstrap, backup, restore, and retention.
