# OneIssuer Web Prototype

Clickable UI prototype for the OneIssuer hosted authentication experience and admin console.

## Run locally

```bash
npm install
npm run dev
```

Open the URL printed by Vite. The default entry redirects to the admin overview.

## Prototype routes

### Hosted authentication

```text
/login
/register
/consent
/complete
```

### Admin console

```text
/admin
/admin/users
/admin/applications
/admin/applications/new
/admin/sessions
/admin/audit
/admin/settings
```

## Scripts

```bash
npm run dev      # Start the Vite development server
npm run lint     # Run Oxlint
npm run build    # Type-check and build production assets
npm run check    # Run lint and build together
npm run preview  # Preview the production build
```

## Important

This is a front-end-only prototype. It uses mock identity data and does not perform real
authentication, issue tokens, persist settings, or contact a backend.

The design rationale, responsive rules, backend mapping, and security constraints are documented in
[`../docs/ui-design.md`](../docs/ui-design.md).
