# Audit Playbook

## Repository And Secrets

Inspect:

- Committed `.env`, `.pem`, `.key`, credential JSON, database dumps, cookies,
  session exports, provider tokens, SSH keys, and service-account files.
- Private secrets exposed through frontend prefixes such as `NEXT_PUBLIC_`,
  `VITE_`, `PUBLIC_`, or mobile bundle config.
- Docs, screenshots, fixture files, logs, and tests that include real tokens,
  internal URLs, customer data, reset links, or admin panels.
- CI workflows that echo secrets, run untrusted pull request code with secrets,
  use broad tokens, or fetch executable scripts without integrity checks.
- Missing ignore rules for local env, cache, build output, coverage, and
  generated credentials.

Do not treat every secret-like string as confirmed. Confirm whether it is real,
live, committed, reachable in a public artifact, or only a dummy fixture.

## Authentication And Sessions

Check:

- Protected routes, server actions, API handlers, and admin pages enforce auth
  server-side.
- Login, logout, session refresh, OAuth callback, magic link, password reset,
  and email verification paths handle replay, expiry, and redirects.
- Passwords use a reputable password hashing mechanism and are never logged or
  stored in plaintext.
- Session cookies in production are `HttpOnly`, `Secure`, `SameSite`, scoped
  narrowly, and expire reasonably.
- OAuth state/nonce, callback URL validation, and open-redirect controls exist
  where relevant.
- Password reset and magic-link tokens are single-use, short-lived, and never
  included in logs or analytics.

## Authorization And Multi-Tenancy

Look for:

- User, team, tenant, organization, role, or ownership filters on every
  protected read and write.
- Endpoints that accept `userId`, `tenantId`, `organizationId`, `role`,
  `isAdmin`, `plan`, or entitlement state from the client and trust it.
- Direct object reference issues where changing an ID exposes another user's
  resource.
- Admin or paid-plan gates enforced only through frontend navigation or hidden
  components.
- Database queries, storage reads, background jobs, and exports missing tenant
  or ownership scope.
- Service-role credentials used without explicit authorization before the data
  access.

When in doubt, trace one protected object from request to database and back.

## Input Validation And Injection

Check:

- Body, query, params, headers, uploaded metadata, and webhook payloads are
  validated at the boundary.
- SQL, NoSQL, shell, template, and path operations use structured APIs instead
  of string concatenation.
- User content rendered as HTML, markdown, SVG, or rich text is sanitized.
- Redirects and callback URLs are allowlisted or restricted to safe relative
  paths.
- Backend URL fetches cannot be turned into SSRF against internal services.
- Model output is treated as untrusted before executing tools, rendering markup,
  storing records, or building code.

## Files And Media

Check:

- Upload size, extension, MIME type, and content signature are validated.
- Filenames are normalized and cannot escape storage paths.
- Uploaded files are not stored in executable paths.
- Public URLs cannot expose private tenant data.
- SVG, HTML, office documents, archives, and image-processing paths are handled
  with explicit safety decisions.
- High-risk products have quarantine, malware scanning, or delayed publication.

## API, Browser, CORS, CSRF, And Headers

Inspect:

- Authenticated or cookie-based APIs do not use wildcard CORS.
- State-changing cookie-based requests have CSRF protection or a deliberate
  same-site design.
- Security headers fit the app: CSP, frame protections, HSTS, referrer policy,
  permissions policy, and content-type sniffing controls.
- Auth endpoints, public APIs, AI calls, scraping jobs, contact forms, and
  expensive compute paths have abuse limits.
- Production errors avoid stack traces, SQL messages, tokens, provider
  responses, internal paths, and customer data.

## Payments, Webhooks, And Entitlements

Check:

- Webhook signatures are verified with the provider SDK or documented algorithm.
- Test and live keys, webhook secrets, customer IDs, and account IDs are not
  mixed.
- Paid status, plan, quota, and entitlement changes come from trusted
  server-side events.
- Checkout success pages do not grant durable access before trusted
  confirmation unless the risk is intentionally accepted.
- Subscription, cancellation, refund, failed payment, and expired states are
  handled.
- Customer and subscription IDs are scoped to the authenticated user or tenant.

## Dependencies And Supply Chain

Check:

- Lockfiles exist when dependencies exist.
- Audit commands are available and were run for the stack when meaningful.
- Install, prepare, postinstall, CI, and release scripts do not fetch and run
  unverified remote code.
- GitHub Actions avoid untrusted PR secret exposure and use least-privilege
  permissions.
- Deprecated auth, crypto, serialization, templating, or request libraries are
  flagged for replacement.
- New dependencies have a clear reason, maintenance signal, license clarity, and
  no obvious supply-chain risk.

## Logging, Privacy, And Operations

Check:

- Logs and analytics do not include passwords, tokens, cookies, reset links,
  authorization headers, payment data, or sensitive personal data.
- Error monitoring redacts sensitive fields.
- Backups, exports, and generated reports are not public by default.
- Admin and support tools are authenticated, authorized, and auditable.
- Production config disables debug mode, local permissive settings, and verbose
  error output.
- User deletion and export requests have a plausible engineering path.

## Mobile And Client Apps

Assume anything bundled in a client app is public.

Check:

- Sensitive operations go through a server-controlled trusted boundary.
- Deep links validate destination and auth state.
- Local storage avoids long-lived high-privilege secrets.
- Backend APIs do not trust client app identity, build flags, or local role
  claims on their own.
- Certificate pinning, device attestation, and obfuscation are treated as
  defense-in-depth, not authorization.
