# GitHub Actions CI

## Minimal Workflow

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

For local development before npm publication, use the checked-out repository
directly or a pinned GitHub release tag:

```bash
npx --yes github:Elgabor/shipguard-codex-skill#v0.1.0 ci --fail-on high
```

## Thresholds

Use:

- `--fail-on critical` for early adoption when the repo has known issues.
- `--fail-on high` for normal pull request gating.
- `--fail-on medium` for mature projects that want stricter hardening.
- `--fail-on none` to report findings without failing.

## Output Formats

The default CI output emits GitHub annotations plus a readable summary.

For machine processing:

```bash
npx --yes shipguard-codex-skill@0.1.0 scan --format json --path .
npx --yes shipguard-codex-skill@0.1.0 scan --format sarif --path . > shipguard.sarif
```

Upload SARIF only after confirming your GitHub plan and repository settings
support code scanning uploads.

## Policy

Treat CI as a first-pass gate. It is useful for common exposed secret patterns
client-exposed env names, dangerous code patterns, and risky workflow patterns,
but it cannot prove authorization, tenant isolation, webhook trust, payment
entitlements, or full runtime behavior. Use the manual ShipGuard audit workflow
for release decisions.

For AI-assisted pull request review, use `references/codex-action-ci.md` in
addition to this deterministic scanner. Keep that workflow opt-in because it
requires an OpenAI API key and trusted GitHub Actions permissions.
