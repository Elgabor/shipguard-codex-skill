# ShipGuard

[![npm version](https://img.shields.io/npm/v/shipguard-codex-skill.svg)](https://www.npmjs.com/package/shipguard-codex-skill)
[![GitHub](https://img.shields.io/badge/GitHub-Elgabor%2Fshipguard--codex--skill-black)](https://github.com/Elgabor/shipguard-codex-skill)

ShipGuard is a Codex skill plus a dependency-free CI scanner for practical
security launch reviews. It is built for codebases, SaaS apps, APIs, mobile
backends, GitHub Actions workflows, and MVPs that need a clear go/no-go security
pass before release.

Published package:

- npm: <https://www.npmjs.com/package/shipguard-codex-skill>
- GitHub: <https://github.com/Elgabor/shipguard-codex-skill>

## What It Does

ShipGuard helps Codex run a security review with a concrete workflow instead of
a generic checklist. It focuses on:

- exposed secrets and unsafe env files;
- auth, authorization, and tenant/data isolation mistakes;
- injection, unsafe uploads, SSRF, XSS, and dangerous code execution;
- payment, webhook, and entitlement trust boundaries;
- GitHub Actions, npm, and dependency supply-chain risk;
- deployment config, logs, privacy leaks, CORS, CSRF, and security headers.

The bundled scanner is deterministic and dependency-free. It is a first-pass
gate for common issues; Codex still performs the manual review and fix plan.

## Install In Codex

Install the published npm package:

```bash
npx --yes shipguard-codex-skill@0.1.0 install
```

Or install from the pinned GitHub release tag:

```bash
npx --yes github:Elgabor/shipguard-codex-skill#v0.1.0 install
```

For local development from this checkout:

```bash
node bin/shipguard.js install
```

The installer copies the skill to:

```text
the detected Codex skill root, usually ~/.codex/skills or ~/.agents/skills
```

Open a new Codex chat if skill autocomplete does not refresh immediately.

Use the skill in Codex:

```text
Use $shipguard-codex-skill to audit this repo before launch.
```

To force a specific target:

```bash
npx --yes shipguard-codex-skill@0.1.0 install --target codex-home
npx --yes shipguard-codex-skill@0.1.0 install --target agents-home
npx --yes shipguard-codex-skill@0.1.0 install --target-root /custom/skills
```

The installer replaces only a managed
`<target-root>/shipguard-codex-skill` directory. If that directory already
exists and was not created by ShipGuard, rerun with `--force` only after
checking its contents.

## Verify It Works

From any repository you want to scan:

```bash
npx --yes shipguard-codex-skill@0.1.0 --help
npx --yes shipguard-codex-skill@0.1.0 scan --path . --format json
npx --yes shipguard-codex-skill@0.1.0 ci --path . --fail-on high
```

Expected clean output for a repo with no built-in findings:

```json
{
  "findings": []
}
```

or:

```text
ShipGuard: no findings from built-in checks.
```

If you test `npx` from inside this package's own checkout, npm may prefer local
package resolution. For a clean smoke test, run the commands from another
directory or a temporary folder.

## Use With Codex

```text
Use $shipguard-codex-skill to audit this repo before launch.
Check secrets, auth, authorization, tenant isolation, input validation, uploads,
webhooks, payments, CORS, headers, logging, dependencies, GitHub Actions, and
deployment config. Give me confirmed findings and the fastest safe fix plan.
```

For fixes:

```text
Use $shipguard-codex-skill and implement the Critical and High fixes only.
Verify with the smallest meaningful tests.
```

ShipGuard asks Codex to return a structured result:

```text
Security decision: Pass / Pass after fixes / Do not launch yet
Risk level: Low / Medium / High / Critical

Confirmed findings
- Evidence
- Impact
- Fix
- Verify

Needs verification
Fastest safe fix plan
Verification
```

## Run The Scanner

```bash
npx --yes shipguard-codex-skill@0.1.0 scan --path .
npx --yes shipguard-codex-skill@0.1.0 scan --path . --format json
npx --yes shipguard-codex-skill@0.1.0 scan --path . --format sarif > shipguard.sarif
npx --yes shipguard-codex-skill@0.1.0 ci --path . --fail-on high
```

The built-in scanner is a first pass. It finds common exposed secret patterns,
client-exposed env names, dangerous code sinks, risky GitHub Actions patterns,
and obvious config hazards. It does not replace manual review of authorization,
tenant isolation, webhook trust, payment entitlements, or runtime behavior.

## GitHub Actions

Create `.github/workflows/shipguard.yml`:

```yaml
name: ShipGuard

on:
  pull_request:
  push:
    branches: [main]

permissions:
  contents: read

jobs:
  security-gate:
    runs-on: ubuntu-24.04
    steps:
      # actions/checkout v5
      - uses: actions/checkout@93cb6efe18208431cddfb8368fd83d5badbf9bfd
        with:
          persist-credentials: false
      # actions/setup-node v5
      - uses: actions/setup-node@a0853c24544627f65ddf259abe73b1d18a591444
        with:
          node-version: "22"
      - name: Run ShipGuard
        run: npx --yes shipguard-codex-skill@0.1.0 ci --fail-on high
```

For AI-assisted pull request review with the official Codex GitHub Action, use
the optional pattern in
`skills/shipguard-codex-skill/references/codex-action-ci.md`. That requires an
`OPENAI_API_KEY` GitHub secret and tighter workflow permissions.

Thresholds:

- `--fail-on critical`: only fail on launch-blocking leaks or takeover paths.
- `--fail-on high`: recommended default for pull requests.
- `--fail-on medium`: stricter mature-project gate.
- `--fail-on none`: report only.

## Development

```bash
npm test
npm run validate
npm run ci
npm run pack:check
node bin/shipguard.js ci --fail-on high
```
