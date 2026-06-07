"use strict";

const assert = require("node:assert/strict");
const childProcess = require("node:child_process");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");

const { formatJson, formatSarif, formatText, scan, shouldFail } = require("../skills/shipguard-codex-skill/scripts/shipguard-scan");

function withTempRepo(callback) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "shipguard-"));
  try {
    return callback(root);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
}

function git(root, args) {
  const result = childProcess.spawnSync("git", args, {
    cwd: root,
    encoding: "utf8",
  });

  assert.equal(result.status, 0, result.stderr);
}

test("detects sensitive assignments without exposing full values", () => {
  withTempRepo((root) => {
    const content =
      "const api" + "Key = \"" + "prod-token-value-1234567890" + "\";\n";
    fs.writeFileSync(path.join(root, "app.js"), content);

    const findings = scan(root);
    const finding = findings.find((item) => item.ruleId === "secret.assigned-sensitive-value");

    assert.ok(finding);
    assert.equal(finding.severity, "high");
    assert.match(finding.snippet, /prod\.\.\.7890/);
    assert.doesNotMatch(finding.snippet, /prod-token-value-1234567890/);
    assert.equal(shouldFail(findings, "high"), true);
  });
});

test("redacts all secret values that appear on the same line", () => {
  withTempRepo((root) => {
    const githubToken = "ghp_" + "a".repeat(36);
    const openAiKey = "sk-proj-" + "b".repeat(32);
    fs.writeFileSync(path.join(root, "tokens.js"), `const tokens = "${githubToken} ${openAiKey}";\n`);

    const findings = scan(root);

    assert.ok(findings.length >= 2);
    for (const finding of findings) {
      assert.doesNotMatch(finding.snippet, new RegExp(githubToken));
      assert.doesNotMatch(finding.snippet, new RegExp(openAiKey));
    }
  });
});

test("does not flag obvious placeholder assignments", () => {
  withTempRepo((root) => {
    const content = "const api" + "Key = \"" + "placeholder-value-123456" + "\";\n";
    fs.writeFileSync(path.join(root, "example.js"), content);

    const findings = scan(root);

    assert.equal(findings.length, 0);
  });
});

test("flags environment files and private key filenames", () => {
  withTempRepo((root) => {
    fs.writeFileSync(path.join(root, ".env.local"), "SAFE_PLACEHOLDER=true\n");
    fs.writeFileSync(path.join(root, "deploy.pem"), "placeholder\n");

    const findings = scan(root);

    assert.ok(findings.some((item) => item.ruleId === "secret.env-file"));
    assert.ok(findings.some((item) => item.ruleId === "secret.key-file"));
    assert.equal(shouldFail(findings, "critical"), true);
  });
});

test("does not flag ignored untracked environment files in a git repository", () => {
  withTempRepo((root) => {
    git(root, ["init"]);
    fs.writeFileSync(path.join(root, ".gitignore"), ".env.*\n");
    fs.writeFileSync(path.join(root, ".env.local"), "SAFE_PLACEHOLDER=true\n");

    const findings = scan(root);

    assert.equal(findings.some((item) => item.ruleId === "secret.env-file"), false);
  });
});

test("flags environment files when gitignore does not cover them", () => {
  withTempRepo((root) => {
    git(root, ["init"]);
    fs.writeFileSync(path.join(root, ".env.local"), "SAFE_PLACEHOLDER=true\n");

    const findings = scan(root);

    assert.ok(findings.some((item) => item.ruleId === "secret.env-file"));
  });
});

test("default CLI scope resolves a subdirectory to the current git repository root", () => {
  withTempRepo((root) => {
    git(root, ["init"]);
    const appDir = path.join(root, "apps", "web");
    fs.mkdirSync(appDir, { recursive: true });
    fs.writeFileSync(path.join(root, ".env.local"), "SAFE_PLACEHOLDER=true\n");

    const findings = scan(appDir, { defaultToGitRoot: true });

    assert.ok(findings.some((item) => item.ruleId === "secret.env-file"));
  });
});

test("refuses to scan a non-repo parent directory that contains repositories", () => {
  withTempRepo((root) => {
    const firstRepo = path.join(root, "app-one");
    const secondRepo = path.join(root, "app-two");
    fs.mkdirSync(firstRepo);
    fs.mkdirSync(secondRepo);
    git(firstRepo, ["init"]);
    git(secondRepo, ["init"]);

    assert.throws(
      () => scan(root),
      /Refusing to scan .*contains nested repositories/,
    );
  });
});

test("formats json and sarif output", () => {
  withTempRepo((root) => {
    fs.writeFileSync(path.join(root, ".env"), "SAFE_PLACEHOLDER=true\n");
    const findings = scan(root);

    const json = JSON.parse(formatJson(findings));
    const sarif = JSON.parse(formatSarif(findings));

    assert.equal(json.findings.length, 1);
    assert.equal(sarif.version, "2.1.0");
    assert.equal(sarif.runs[0].results.length, 1);
  });
});

test("detects client-exposed sensitive environment names", () => {
  withTempRepo((root) => {
    const envName = "NEXT_PUBLIC_" + "STRIPE_" + "SECRET_KEY";
    fs.writeFileSync(path.join(root, "config.js"), `const exposed = process.env.${envName};\n`);

    const findings = scan(root);

    assert.ok(findings.some((item) => item.ruleId === "secret.public-env-sensitive-name"));
    assert.equal(shouldFail(findings, "high"), true);
  });
});

test("detects risky auth and sql patterns", () => {
  withTempRepo((root) => {
    const jwtDecode = "jwt." + "decode(token);";
    const rawSql = "db." + "que" + "ry(`SELECT * FROM users WHERE id = ${userId}`);";
    fs.writeFileSync(
      path.join(root, "api.js"),
      [
        jwtDecode,
        rawSql,
      ].join("\n"),
    );

    const findings = scan(root);

    assert.ok(findings.some((item) => item.ruleId === "auth.jwt-decode-without-verify"));
    assert.ok(findings.some((item) => item.ruleId === "sql.raw-template-interpolation"));
  });
});

test("detects privileged GitHub Actions patterns", () => {
  withTempRepo((root) => {
    const workflows = path.join(root, ".github", "workflows");
    fs.mkdirSync(workflows, { recursive: true });
    fs.writeFileSync(
      path.join(workflows, "danger.yml"),
      [
        "on:",
        "  pull_request_target:",
        "jobs:",
        "  test:",
        "    runs-on: ubuntu-latest",
        "    steps:",
        "      - uses: actions/checkout@main",
        "        with:",
        "          persist-credentials: true",
        "      - run: echo ${{ secrets.NPM_TOKEN }}",
      ].join("\n"),
    );

    const findings = scan(root);

    assert.ok(findings.some((item) => item.ruleId === "ci.pull-request-target-checkout"));
    assert.ok(findings.some((item) => item.ruleId === "ci.pull-request-target-secrets"));
    assert.ok(findings.some((item) => item.ruleId === "ci.mutable-action-ref"));
    assert.ok(findings.some((item) => item.ruleId === "ci.checkout-persists-credentials"));
  });
});

test("detects privileged GitHub Actions array events and named checkout steps", () => {
  withTempRepo((root) => {
    const workflows = path.join(root, ".github", "workflows");
    fs.mkdirSync(workflows, { recursive: true });
    fs.writeFileSync(
      path.join(workflows, "array.yml"),
      [
        "on: [pull_request_target]",
        "jobs:",
        "  test:",
        "    runs-on: ubuntu-latest",
        "    steps:",
        "      - name: Checkout",
        "        uses: actions/checkout@main",
        "      - run: echo ${{ secrets.NPM_TOKEN }}",
      ].join("\n"),
    );

    const findings = scan(root);

    assert.ok(findings.some((item) => item.ruleId === "ci.pull-request-target-checkout"));
    assert.ok(findings.some((item) => item.ruleId === "ci.pull-request-target-secrets"));
    assert.ok(findings.some((item) => item.ruleId === "ci.mutable-action-ref"));
  });
});

test("escapes control characters in text output file paths", () => {
  withTempRepo((root) => {
    fs.writeFileSync(path.join(root, ".env\n::warning file=x::name"), "SAFE_PLACEHOLDER=true\n");

    const findings = scan(root);
    const output = formatText(findings);

    assert.match(output, /\.env\\n::warning file=x::name/);
    assert.doesNotMatch(output, /\n\.env\n::warning file=x::name/);
  });
});
