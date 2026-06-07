# Optional Codex Action CI

Use this only when a repository wants AI-assisted pull request security review
inside GitHub Actions. It requires an `OPENAI_API_KEY` secret and careful
workflow permissions.

## Security Notes

- Limit who can trigger the workflow.
- Keep `permissions` narrow.
- Use the Codex Action safety strategy defaults unless the repository has a
  deliberate reason to change them.
- Treat PR title, body, comments, commit messages, and changed files as
  untrusted prompt input.
- Do not pass production secrets or broad deploy credentials to the review job.

## Prompt File

Create `.github/codex/prompts/shipguard-review.md`:

```md
Use $shipguard-codex-skill to review this pull request as a security gate.

Focus on changed files and adjacent call paths. Prioritize:
- exposed secrets and public env leaks;
- auth/session regressions;
- authorization and tenant isolation;
- injection, unsafe uploads, SSRF, XSS, and unsafe redirects;
- payment, webhook, and entitlement trust;
- GitHub Actions and release secret exposure;
- logging/privacy leaks and production config.

Return only confirmed findings and high-confidence leads. Include file evidence,
impact, minimum fix, and verification. If there are no confirmed issues, state
the boundaries inspected and what was not covered.
```

## Workflow Sketch

```yaml
name: ShipGuard Codex Review

on:
  pull_request:
    types: [opened, synchronize, reopened]

permissions:
  contents: read
  pull-requests: write

jobs:
  codex-security-review:
    runs-on: ubuntu-24.04
    steps:
      # actions/checkout v5
      - uses: actions/checkout@93cb6efe18208431cddfb8368fd83d5badbf9bfd
        with:
          persist-credentials: false
      # openai/codex-action v1
      - uses: openai/codex-action@e0fdf01220eb9a88167c4898839d273e3f2609d1
        with:
          openai-api-key: ${{ secrets.OPENAI_API_KEY }}
          prompt-file: .github/codex/prompts/shipguard-review.md
          codex-args: '["--sandbox", "read-only"]'
```

This complements the deterministic `shipguard-codex-skill ci` scanner. Do not
use the AI review as the only release gate for high-risk systems.
