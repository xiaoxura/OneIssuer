# Phase-three OpenID Conformance record

Status: applicable non-certification subset passed
Target: OneIssuer `v0.1.0-dev.3`
Executed: 2026-08-01
Retest due on or before: 2026-11-01

## Scope and disclaimer

OneIssuer was exercised with the official OpenID Conformance Suite against the
phase-three static-registration Authorization Code profile. This record is
engineering interoperability evidence only.

**OneIssuer has not obtained OpenID Foundation certification, and this project
does not claim certification.** Passing selected applicable modules is not a
substitute for a certification plan, Foundation listing, production security
review, or support for features outside the frozen profile.

The machine-reviewed source of truth is:

- [`conformance/phase-3/matrix.json`](../conformance/phase-3/matrix.json);
- [`conformance/phase-3/results/2026-08-01.json`](../conformance/phase-3/results/2026-08-01.json);
- secret-free Public and Confidential configuration templates in the same
  directory;
- [`scripts/check-conformance-record.py`](../scripts/check-conformance-record.py).

## Pinned suite

| Item | Pin |
| --- | --- |
| release | `release-v5.2.1` |
| source commit | `932b46f1e507871eb0b34621aaef65ff04442e6f` |
| plan | `oidcc-test-plan` |
| plan class | comprehensive Authorization Server test, not part of the certification program |
| server image | `registry.gitlab.com/openid/conformance-suite@sha256:b1942bd82cd08bef7e81fb3370124141c044d913a096056a8d9b68f0b4fee720` |
| Nginx image | `registry.gitlab.com/openid/conformance-suite/nginx@sha256:496a11f6d11514945d5c90dc87aa7c04e223d915b2b4a53844d68d73440f926b` |
| Mongo image | `mongo@sha256:b415b12f638e2685d06c58ab7fb5943577c50fadec6d9340ef67d21aeac72070` |

The run used a temporary HTTPS reverse proxy, a non-production Issuer, static
throwaway Clients, and no production credentials.

## Passed applicable modules

Common variants were Discovery metadata, static Client registration,
`response_type=code`, and default/query response mode.

| Module | Client auth | Module ID | Result | Raw export SHA-256 |
| --- | --- | --- | --- | --- |
| `oidcc-discovery-endpoint-verification` | `none` | `xQE2fnqPaU7ymSS` | PASSED | `5072eeddbb1355601cab2fcedbbfd8a21a133308c3f5d33f9dd065cddc6134bc` |
| `oidcc-ensure-request-with-valid-pkce-succeeds` | `none` | `DfkEM7EHpMoKA1z` | PASSED | `c16152ee892a6d1cec4b8ce1e7feac813a01ba56afbd28c2788119d24f753ad2` |
| `oidcc-ensure-request-with-valid-pkce-succeeds` | `client_secret_basic` | `s87ygoiKOOu6JtQ` | PASSED | `6602485e17825b440cdbf2fc79ccb86aa4cfa8d1726531ed47e267ab20e1b09a` |

Together these runs covered accurate Discovery/JWKS, a Public static Client, a
Confidential static Client, Authorization Code Flow, mandatory S256, state,
nonce, RS256 ID Token processing, Bearer Access Token, and UserInfo in the suite's
applicable path.

Discovery initially produced an optional warning because `claims_supported` was
absent. OneIssuer was changed to declare the exact claims it can issue; the final
Discovery module passed. No unsupported endpoint, grant, Scope, algorithm, or
Client authentication method was added to make the test pass.

## Not-applicable and harness constraints

The frozen phase-three profile excludes:

- Refresh Token and online token/session lifecycle;
- Dynamic Client Registration;
- Request Object, Request URI, and JWT Client authentication;
- address/phone/locales/ACR/display/login-hint and other optional claims/hints;
- online signing-key rotation;
- Logout, Revocation, Introspection, PAR/JAR/JARM, DPoP, and mTLS.

The exact categories/modules/reasons are recorded in `matrix.json` rather than
being silently skipped.

Many older OIDCC Code Flow modules build their main authorization request without
`code_challenge` and later verifier. OneIssuer correctly rejects those requests
because S256 is mandatory for **both** Public and Confidential Clients. The
server was not weakened and Discovery was not expanded to make those upstream
modules runnable. Equivalent positive, negative, concurrency, replay, restart,
and privacy behavior is covered by first-party HTTP, PostgreSQL, Fuzz, race, and
Compose gates.

The suite's Basic Certification Plan is not applicable to this release because it
requires `client_secret_post` and other behavior outside phase three. OneIssuer
supports only `none` and `client_secret_basic`.

## Evidence handling

Raw exports are kept in the ignored, permission-restricted location referenced by
the result summary:

```text
.artifacts/conformance/2026-08-01/final/
```

The Confidential export may contain the throwaway runtime Client Secret. Raw
exports therefore must not be committed, uploaded as a public CI artifact,
attached to an issue, or copied into release notes. Keep them encrypted and
access-controlled for the evidence retention period, verify the recorded digest,
then securely destroy them according to policy.

Checked-in JSON contains only placeholders, module identifiers, public image/
source pins, result states, artifact paths, and SHA-256 digests. Validate it with:

```bash
./scripts/check-conformance-record.py
```

The script also enforces the non-certification plan and a false certification
claim flag.

## Rerun procedure

For a dependency, protocol, metadata, signing, or release change:

1. review/update the applicability matrix before executing;
2. pin the exact official release, source commit, and container digests;
3. create a temporary HTTPS Issuer and new static Public/Confidential Clients;
4. inject clear runtime Secrets only through restricted ephemeral files/memory;
5. run Discovery, Public S256, and Confidential S256 modules;
6. export results directly into a mode-restricted ignored artifact directory;
7. inspect exports for clear values before any transfer;
8. record IDs/results/digests in a new dated secret-free summary;
9. run the validator, full phase-three gates, and reviewer diff;
10. set a new retest date and remove runtime Clients/keys/environment.

Any applicable failure blocks release unless the implementation is fixed or a
reviewed, explicit known issue changes the release decision. It must not be hidden
by removing an accurate Discovery declaration or loosening mandatory S256.
