# Signing-key generation and rotation runbook

OneIssuer `v0.1.0-dev.4` has one active file-backed RS256 private key and an
optional public-only verification JWKS. It loads an immutable ring at process
startup; there is no hot reload, online rotation, KMS/HSM adapter, or automatic
key lifecycle in phase four.

This runbook separates a planned overlap rotation from emergency compromise
response. Adapt paths and secret-mount mechanics to the deployment platform.
Never copy private JWK content into a command line, environment variable,
database, image, Git, log, ticket, or HTTP response.

## Security invariants

- the active key is RSA and `alg=RS256`, `use=sig`;
- `kid` is the RFC 7638 SHA-256 public-key thumbprint and is unique;
- generated keys use 3072 bits; imported RSA keys must be at least 2048 bits;
- the private JWK is a normal non-symlink file with no group/world bits, normally
  mode `0600`;
- the service identity must be able to read it; the shipped image runs as
  UID/GID `65532`;
- `ONEISSUER_VERIFICATION_KEYS_FILE` contains public JWKs only and must not
  duplicate the active `kid`;
- every replica for one Issuer publishes/verifies the complete intended overlap
  ring before any replica signs with a new key;
- every change requires a process restart and post-start Discovery/JWKS/Token
  verification;
- a failed key load, duplicate/malformed key, or failed startup Audit prevents
  the listener from opening.

The JWKS endpoint publishes only public members and uses a strong content ETag
plus `Cache-Control: public, max-age=300`.

## Roles and change record

Use two-person review where available. Record, without private material:

- change/incident identifier and operator/reviewer;
- canonical Issuer and environment;
- old/new public `kid` values and public JWKS SHA-256 digests;
- application/image version and migration version;
- generation/staging/restart/cache-wait/removal UTC times;
- effective ID Token TTL, Access Token TTL, clock skew, and five-minute JWKS
  cache window;
- verification results and rollback decision.

The `kid` and public key are not secrets, but avoid putting them in general
application labels or unbounded metric dimensions.

## Generate a new key

Create the file directly inside a protected secret-staging filesystem:

```bash
umask 077
oneissuer keys generate \
  --alg RS256 \
  --out /protected/staging/signing-key-b.jwk

oneissuer keys public \
  --in /protected/staging/signing-key-b.jwk \
  --out /controlled/staging/signing-key-b-public.jwks
```

Both commands use exclusive creation and refuse to overwrite an existing path.
The generation command prints only safe algorithm/count/`kid` metadata. Do not
redirect private content through a pipeline or inspect it with shell tracing.

Before deployment:

1. verify private-file owner, mode `0600`, regular-file type, size, and protected
   storage controls without printing content;
2. verify the public export contains one RS256 signing key and no private JWK
   members;
3. back up/escrow the private key according to the approved key policy, encrypted
   under a separate access domain from PostgreSQL backups;
4. stage the secret read-only for UID/GID `65532` (or the reviewed service
   identity);
5. run `oneissuer config check` inside the exact target identity/mount namespace.

For a Linux bind mount, do not make the key world-readable. A root-controlled
staging step can transfer ownership while preserving `0600`:

```bash
chown 65532:65532 /protected/staging/signing-key-b.jwk
chmod 0600 /protected/staging/signing-key-b.jwk
```

Use the platform's secret-volume ownership controls rather than host `chown` when
available.

## Planned A → B rotation

Assume A is active. The minimum safe procedure is a four-deployment overlap.

### 1. Prepare B without changing the active signer

Generate B and export B's public-only JWKS. Leave A's private file and deployment
unchanged. Securely stage B's private file for the later switch; do not mount it
as active yet.

### 2. Prepublish B while A remains active

Configure:

```text
ONEISSUER_SIGNING_KEY_FILE       -> private A
ONEISSUER_VERIFICATION_KEYS_FILE -> public B JWKS
```

Restart/roll every replica. Old and new replicas must all expose both public A
and B before continuing. Verify:

- startup/readiness succeeds and `signing_key_loaded` Audit is present;
- Discovery still declares RS256 and the same Issuer/endpoints;
- JWKS contains exactly the intended A/B public keys and no private fields;
- ETag changed from the A-only document;
- newly issued ID/Access Tokens are still signed by A and validate with the
  published ring.

Wait **at least the advertised JWKS cache lifetime (300 seconds)** after the last
replica/public edge has served A+B. Use a longer deployment-specific maximum if a
proxy/RP is configured to cache longer. Do not proceed based only on a direct
backend request.

### 3. Switch the active signer to B and keep A public

Export A's public-only JWKS into a separate controlled file if it was not already
retained. Configure the new replica set as:

```text
ONEISSUER_SIGNING_KEY_FILE       -> private B
ONEISSUER_VERIFICATION_KEYS_FILE -> public A JWKS
```

Do **not** include public B in the verification file: the active B public key is
added automatically, and duplicate `kid` values fail startup.

Restart/roll every replica. During a rolling transition, old A-active replicas
must still publish B and new B-active replicas must publish A, so either signer
is verifiable. Verify after completion:

- all replicas use the intended configuration and are Ready;
- JWKS remains A+B (ordering/ETag may be deterministic and unchanged if public
  content is identical);
- new ID/Access Tokens are signed by B;
- a still-live A-signed test Token continues to validate where applicable;
- Token/UserInfo and example RP flows succeed.

Record the time the **last A-signed Token could have been issued**.

### 4. Retain A for the complete validation window

Keep public A in every verification ring for at least:

```text
max(ONEISSUER_ID_TOKEN_TTL, ONEISSUER_ACCESS_TOKEN_TTL)
+ ONEISSUER_OIDC_CLOCK_SKEW
+ 5 minutes JWKS cache
```

Measure from the last possible A issuance, not the first B deployment. Add any
reviewed downstream cache/queue margin. With defaults, the formula is 10 minutes
+ 30 seconds + 5 minutes; operators may deliberately wait longer.

Do not confuse the 24-hour database metadata retention with Token validity: it
does not require keeping an old key for 24 hours, and it does not extend `exp`.

### 5. Remove A public

After the complete window, unset the overlap file or replace it with a reviewed
public set that excludes A and the active B. Restart/roll every replica:

```text
ONEISSUER_SIGNING_KEY_FILE       -> private B
ONEISSUER_VERIFICATION_KEYS_FILE -> empty (for a simple two-key rotation)
```

Verify JWKS contains B only, ETag changed, new Tokens validate, UserInfo works,
and no replica still serves A. Wait through edge/RP cache propagation before
declaring removal complete.

### 6. Retire private A

Follow the approved cryptographic retention policy:

- if recovery policy requires a bounded archive, encrypt it under separate key
  management with least privilege, an expiry, and access Audit;
- otherwise securely destroy every active/staging/backup copy after review;
- retain only public fingerprint/change evidence required by policy;
- never delete evidence needed for an active incident investigation.

## More than one overlap key

The `keys public` command exports one private key's public JWKS; it intentionally
does not merge arbitrary sets. If disaster recovery or a long rollout needs more
than one additional public key, build a public-only JWKS through reviewed tooling
that:

- reads public exports only, never private files;
- enforces RSA/RS256/`sig`, RFC 7638 `kid`, minimum size, no X.509 fields, and no
  duplicates;
- uses deterministic ordering and an atomic new-file replacement;
- is tested by `oneissuer config check` before deployment.

Keep the ring minimal. Remove retired keys as soon as their safe overlap window
ends.

## Rollback during planned rotation

- Before B signs: restore the prior A-only/A+B public deployment if needed; no
  B-signed Token exists yet.
- After B signs: a rollback to A **must continue publishing B** until all B-signed
  Tokens and JWKS caches have elapsed. Returning to A-only would invalidate live
  B Tokens.
- Never restore an old verification file without comparing the set of signers
  that may have issued Tokens.
- Never copy `consumed_at`/Token metadata or change the database to compensate for
  a key deployment error.

If the integrity of B is in doubt, use the emergency procedure rather than a
normal rollback.

## Emergency suspected-key compromise

Availability and overlap are secondary to stopping trust in a suspected private
key.

1. activate incident response and restrict access to the compromised key/source;
2. generate or select a known-good new RS256 private key through a trusted path;
3. prepare a verification ring that **excludes the suspected key**;
4. in one controlled deployment, switch every replica to the new active key and
   remove the suspected key from local verification/JWKS;
5. purge/reconfigure controlled reverse-proxy/CDN caches where possible;
6. verify fresh JWKS and new Tokens from multiple network paths;
7. disable affected Users/Clients or rotate Client Secrets if the incident scope
   requires additional fail-closed containment;
8. preserve forensic metadata and quarantine private material through the
   incident channel; do not paste it into tickets/logs;
9. assess all Tokens signed during the exposure window and notify relying parties.

Consequences must be explicit:

- old Tokens signed by the removed key stop working at OneIssuer UserInfo as soon
  as all new processes are active;
- external verifiers may continue trusting a cached old JWKS for up to roughly
  the advertised five-minute cache lifetime (or longer if they violate headers);
- live legitimate Tokens signed by the removed key are intentionally broken;
- JWTs presented to external resource servers cannot be globally invalidated
  instantly; OneIssuer UserInfo and restricted Introspection observe persisted
  Revocation and lifecycle state immediately.

Do not keep a suspected key in the overlap ring merely to avoid user disruption.

## Lost key and disaster recovery

If the active key is unavailable but not suspected compromised:

- do not generate a silent replacement under the same `kid`;
- recover the exact protected key only through the approved escrow process; or
- deploy a new key and treat existing signed Tokens as invalidated, documenting
  the break and expected five-minute downstream cache behavior.

Restoring PostgreSQL does not restore a private key. Restoring a private key does
not restore Session/Code/Access metadata. Disaster-recovery tests must verify both
domains while keeping their backups and access roles separate.

## Post-change checklist

- [ ] All replicas run the intended immutable image/configuration.
- [ ] Private key is a `0600` regular non-symlink file readable only by the
      service/authorized operators.
- [ ] `config check` and startup Audit succeed without private/path output.
- [ ] Discovery Issuer and RS256 declaration are unchanged.
- [ ] JWKS contains only intended public keys, has the expected ETag/cache header,
      and contains no private members.
- [ ] New ID Token has `alg=RS256`, `typ=JWT`, and the intended active `kid`.
- [ ] New Access Token has `alg=RS256`, `typ=at+jwt`, and the intended active
      `kid`; UserInfo succeeds.
- [ ] Planned old-token validation/removal behavior matches the timeline.
- [ ] No private JWK entered image layers, environment, Git, logs, Audit, metrics,
      HTTP output, CI artifacts, or support evidence.
- [ ] Change record, backup/retirement action, and next review date are complete.
