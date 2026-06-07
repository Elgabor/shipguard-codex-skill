# ShipGuard

ShipGuard is a Codex skill plus a dependency-free CI scanner for practical
security launch reviews. It is built for codebases, SaaS apps, APIs, mobile
backends, GitHub Actions workflows, and MVPs that need a clear go/no-go security
pass before release.

## Install

As a local Codex skill through `npx` after npm publication:

```bash
npx --yes shipguard-codex-skill@0.1.0 install
```

From the first GitHub release tag:

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

As a Codex plugin marketplace source after the GitHub repo is public:

```bash
codex plugin marketplace add Elgabor/shipguard-codex-skill
```

For repeatable installs, prefer a published npm version or a pinned GitHub tag
after the first release:

```bash
npx --yes github:Elgabor/shipguard-codex-skill#v0.1.0 install
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

## Use In Codex

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

## Run Locally

```bash
node bin/shipguard.js scan --path .
node bin/shipguard.js scan --path . --format json
node bin/shipguard.js scan --path . --format sarif > shipguard.sarif
node bin/shipguard.js ci --path . --fail-on high
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

After npm publication, use:

```bash
npx --yes shipguard-codex-skill@0.1.0 ci --fail-on high
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
npm run pack:check
node bin/shipguard.js ci --fail-on high
```
