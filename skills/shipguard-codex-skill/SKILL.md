---
name: shipguard-codex-skill
description: Launch-readiness security audit workflow for Codex. Use when reviewing a local codebase, GitHub repository, pull request, SaaS app, API, web app, mobile app, CI pipeline, deployment config, or MVP before release for secrets, auth/session flaws, authorization and multi-tenant data leaks, injection, unsafe file uploads, payment/webhook mistakes, dependency and GitHub Actions supply-chain risk, insecure headers/CORS/CSRF, logging/privacy leaks, production misconfiguration, or when asked to produce or implement a prioritized security fix plan.
---

# ShipGuard

## Operating Model

Use this skill as a practical release gate. Prefer confirmed exploit paths,
reachable code, and concrete misconfiguration over generic checklist output.
Start from repository instructions (`AGENTS.md` or equivalent) when present, and
respect the project's existing test and review workflow.

Default to four modes:

1. **Triage**: quickly identify launch blockers and high-risk areas.
2. **Deep audit**: inspect trust boundaries, data flow, and security controls.
3. **Diff audit**: review changed files and adjacent call paths for regressions.
4. **Fix mode**: implement the smallest safe remediation and verify it.

## Scope Guardrails

Before reading files or running the scanner, establish the active repository
root. Run `pwd` and, when available, `git rev-parse --show-toplevel` from the
user's current project directory. Treat that Git top-level directory as "this
repo".

Never scan broad parent directories such as `~`, `~/code`, a workspace folder,
or any directory that contains multiple unrelated repositories. If the current
directory is not inside the intended repo, ask the user for the repo path or
tell them to reopen Codex from that project directory.

When local files are available, run the scanner only against the resolved repo
root, for example:

```bash
node scripts/shipguard-scan.js ci --path "$(git rev-parse --show-toplevel)"
```

or:

```bash
npx --yes shipguard-codex-skill@0.1.1 ci --path "$(git rev-parse --show-toplevel)"
```

Treat scanner output as leads until the code path is confirmed.

Use Plan mode or write a short plan before broad audits, multi-file fixes, or
launch decisions. A good plan names the files likely in scope, trust boundaries,
verification commands, and areas intentionally out of scope.

## Audit Workflow

1. Establish scope: stack, app type, deployment target, public/private status,
   auth provider, tenant model, sensitive data, payment/provider usage, and
   whether fixes are in scope.
2. Map entry points: routes, API handlers, server actions, middleware,
   background jobs, webhooks, file uploads, admin tools, database access,
   client/server boundaries, CI workflows, and deploy config.
3. Identify trust boundaries: user input, headers, cookies, query params, file
   content, third-party events, model output, environment variables, database
   rows, cache entries, and generated markup.
4. Run deterministic checks: bundled scanner, package audit when available,
   type/lint/test commands when relevant, and framework-native security checks.
5. Load `references/audit-playbook.md` for risk-category checks.
6. Load `references/framework-checks.md` only for stacks actually present in the
   repository.
7. Report only findings with evidence, plus suspicious leads that need manual
   verification.
8. If fixing, patch close to the boundary, preserve local architecture, add or
   update tests for the security behavior, and rerun focused verification.

## Diff Audit

For pull requests or uncommitted changes:

1. Identify the base and changed files with `git status --short`,
   `git diff --name-only`, or the PR base/head refs available in CI.
2. Inspect changed files first, then adjacent auth, data-access, validation,
   webhook, and configuration code that the changed path calls.
3. Treat new public endpoints, new dependency scripts, permission changes,
   workflow changes, and env-var changes as high-priority review areas.
4. Separate regressions introduced by the diff from pre-existing hardening
   issues.

## Threat Modeling Pass

Before a deep audit, write a compact model:

- Assets: secrets, user data, tenant data, payments, admin capabilities,
  generated content, source code, deploy credentials.
- Actors: anonymous user, authenticated user, tenant admin, platform admin,
  malicious dependency, compromised webhook sender, CI pull request author.
- Entry points: browser routes, API routes, uploads, webhooks, background jobs,
  scheduled tasks, CLI/admin tools, CI workflows, model/tool outputs.
- Trust boundaries: client/server, tenant boundary, provider webhook boundary,
  CI secret boundary, storage/public URL boundary, model-output boundary.

Use this model to prioritize review instead of walking checklists mechanically.

## Severity Rubric

- **Critical**: exposed live secret, auth bypass, cross-tenant data exposure,
  remote code execution, webhook/payment bypass, production takeover, or a
  realistic path to large-scale sensitive data loss.
- **High**: exploitable authorization, injection, upload, session, SSRF,
  dependency, CI secret exposure, or privacy bug under realistic conditions.
- **Medium**: meaningful hardening gap, missing validation, permissive CORS,
  weak rate limits, unsafe logging, production debug behavior, or brittle
  provider configuration.
- **Low**: defense-in-depth, documentation, observability, or hygiene issue that
  is unlikely to be directly exploitable on its own.

State confidence separately when useful:

- **Confirmed**: reachable code path or exact misconfiguration found.
- **Likely**: strong evidence, but one runtime condition is unverified.
- **Lead**: pattern requires manual confirmation before calling it a finding.

## Output Contract

Use this structure unless the user asks for code changes only:

```markdown
Security decision: Pass / Pass after fixes / Do not launch yet
Risk level: Low / Medium / High / Critical

Confirmed findings
- [Severity] Title
  Evidence: file/path:line or command summary
  Impact: concrete app-specific risk
  Fix: minimum viable remediation
  Verify: command or manual check

Needs verification
- Lead, why it matters, and how to confirm it.

Fastest safe fix plan
1. ...
2. ...

Verification
- Commands run:
- Files inspected:
- Not covered:
```

When no confirmed issue is found, still include the trust boundaries inspected
and the highest-risk areas not covered. Do not return a broad "secure" claim.

## Fix Rules

- Add validation where untrusted data enters.
- Add authorization close to data access or protected side effects.
- Keep service-role, admin, signing, and payment secrets server-only.
- Use framework or provider SDK verification for sessions, cookies, webhooks,
  password hashing, signatures, and cryptography.
- Do not silence a scanner finding by suppressing it unless the code path is
  proved unreachable or intentionally safe.
- Never print full secrets. Redact values and report path, line, key name, and
  risk.
- Add regression tests for auth, ownership, injection, upload, webhook, and
  payment behavior whenever feasible.
- If a fix changes CI, deployment, auth, payments, or data access, include the
  exact verification evidence needed before release.

## CI Use

For repositories using GitHub Actions, add a ShipGuard job from
`references/ci-github-actions.md`. The CI command is intentionally conservative:
it catches common secret and dangerous-code patterns, emits GitHub annotations,
and fails at the configured severity threshold. It is not a replacement for the
manual audit workflow above.

For AI-assisted pull request review in CI, use the optional Codex GitHub Action
pattern in `references/codex-action-ci.md`. It requires an OpenAI API key and
trusted workflow permissions, so keep it opt-in.

## Resources

- `references/audit-playbook.md`: Detailed checks by risk area.
- `references/framework-checks.md`: Stack-specific checks for common app
  frameworks and providers.
- `references/ci-github-actions.md`: GitHub Actions setup and threshold policy.
- `references/codex-action-ci.md`: Optional Codex Action prompt and workflow
  guidance for AI-assisted PR review.
- `scripts/shipguard-scan.js`: Dependency-free local scanner and CI reporter.
