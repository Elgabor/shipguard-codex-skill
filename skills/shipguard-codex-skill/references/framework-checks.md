# Framework Checks

Load only the sections that match the repository.

## Next.js And React

- Confirm secrets are never exposed through `NEXT_PUBLIC_`, `VITE_`,
  `REACT_APP_`, or other client-bundle prefixes.
- Check route handlers, server actions, middleware, and API routes for
  server-side auth and authorization.
- Treat client components, hidden routes, and UI guards as non-security
  boundaries.
- Review `dangerouslySetInnerHTML`, markdown rendering, MDX, SVG handling, and
  user-generated rich text.
- Verify cookies are secure in production and session refresh cannot be replayed
  across users or tenants.
- Check image proxying, metadata routes, redirects, and backend fetches for SSRF
  or open redirect behavior.

## Node APIs, Express, Fastify, Nest

- Confirm route-level auth is not bypassed by alternate method/path variants.
- Validate request body, params, query, headers, and uploaded metadata at the
  boundary.
- Check CORS and CSRF together: wildcard CORS is not safe for credentialed APIs,
  and cookie-based state changes need CSRF defenses or a deliberate same-site
  design.
- Review middleware order, especially auth, body parsing for webhooks, rate
  limits, and error handlers.
- Check raw SQL, command execution, template rendering, path joins, and backend
  URL fetches that depend on request data.

## Python APIs, Django, Flask, FastAPI

- Confirm debug mode is disabled in production config.
- Check Django middleware, CSRF settings, `ALLOWED_HOSTS`, storage backends, and
  admin route exposure.
- Review FastAPI dependency injection for auth/role checks on every protected
  route.
- Validate Pydantic schemas and ensure validators match persistence constraints.
- Check ORM filters for user, tenant, organization, or role scope.
- Review `subprocess`, template rendering, deserialization, file path joins, and
  outbound URL fetches.

## Rails, Laravel, PHP Backends

- Confirm mass-assignment protections and request validation cover sensitive
  fields like role, owner, tenant, price, paid status, and entitlement.
- Review CSRF, session cookie, signed URL, queue, mailer, and storage settings.
- Check route middleware groups and policy/guard usage for protected actions.
- Review raw SQL, command execution, template escaping, uploads, and public
  storage links.

## Supabase, Firebase, Postgres, Prisma

- Confirm server-side code does not trust client-provided `userId`, `tenantId`,
  role, or plan fields.
- For Supabase/Postgres, review RLS policies, service-role usage, storage
  policies, SQL functions, and migrations touching sensitive data.
- For Firebase, review Firestore/Storage rules and custom-claim assumptions.
- For Prisma/ORM use, verify every protected query is scoped by owner, tenant,
  organization, or role where required.
- Check migrations for broad grants, public buckets, nullable ownership columns,
  and missing unique constraints on security-sensitive identifiers.

## Stripe, Lemon Squeezy, Paddle, Webhooks

- Verify webhook signatures before parsing trusted state changes.
- Ensure raw body handling matches the provider SDK requirements.
- Confirm checkout success pages do not grant durable access before trusted
  server-side confirmation unless explicitly risk-accepted.
- Scope customer, subscription, checkout session, and account IDs to the
  authenticated user or tenant.
- Check cancellation, refund, failed payment, expired subscription, trial, and
  plan downgrade behavior.

## GitHub Actions And Release Automation

- Prefer `pull_request` for untrusted PR code; treat `pull_request_target` as
  privileged.
- Use least-privilege `permissions`.
- Avoid checking out and executing untrusted code in privileged workflows.
- Pin important third-party actions to immutable SHAs when the workflow handles
  secrets, releases, packages, or deploys.
- Disable credential persistence unless later git pushes are intentionally
  required.
- Do not print secrets, tokens, cloud credentials, npm tokens, or signed URLs in
  logs.
