# Security policy

## Supported versions

OneIssuer is currently a pre-release engineering foundation. No version is
declared production-ready, but maintainers still accept and triage reports
affecting the current default branch and newest development release.

## Private vulnerability reporting

Please use this repository's **GitHub private vulnerability reporting** page
(`Security` → `Advisories` → `Report a vulnerability`). If that feature is not
available, contact the maintainers through a private channel listed on the
repository owner profile and ask for a secure reporting address before sending
sensitive details.

Do not open a public issue, discussion, pull request, or paste containing an
unfixed vulnerability, exploit, credential, database URL, token, private key,
or production log/data.

Include, where safely possible:

- affected commit/version and deployment model;
- impact and prerequisites;
- minimal reproduction without real secrets or personal data;
- suggested mitigation;
- whether the issue is already public or actively exploited.

Maintainers aim to acknowledge a report within 3 business days, provide an
initial assessment within 7 business days, coordinate remediation/disclosure,
and credit reporters who want attribution. Timelines can vary with severity and
maintainer availability.

## Scope notes

The current phase-two development release implements local identity,
password-based authentication, browser sessions, OIDC Client administration,
and related audit controls. It intentionally does **not** implement the OIDC
protocol endpoints (Discovery, Authorize, Token, UserInfo, and related token or
key handling); those routes must not be treated as available protocol surfaces.

Reports about authentication or authorization bypass, account/session
isolation, CSRF, password or Client Secret handling, sensitive-data exposure,
redirect validation, administration boundaries, audit integrity, migration
safety, container privilege, and supply-chain configuration are in scope.
Mock-only Web console behavior remains non-authoritative and must not be used as
evidence of a backend identity-state change.
