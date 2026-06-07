#!/usr/bin/env node
"use strict";

const fs = require("fs");
const os = require("os");
const path = require("path");
const childProcess = require("child_process");

const DEFAULT_EXCLUDES = new Set([
  ".git",
  ".hg",
  ".svn",
  "node_modules",
  "vendor",
  "dist",
  "build",
  ".next",
  ".nuxt",
  ".svelte-kit",
  ".cache",
  "coverage",
  "__pycache__",
  ".pytest_cache",
  ".turbo",
  ".vercel",
]);

const SEVERITY_RANK = {
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
};

const TEXT_RULES = [
  {
    id: "secret.aws-access-key",
    severity: "critical",
    title: "AWS access key pattern",
    pattern: /\bAKIA[0-9A-Z]{16}\b/g,
    capture: 0,
  },
  {
    id: "secret.github-token",
    severity: "critical",
    title: "GitHub token pattern",
    pattern: /\bgh[pousr]_[A-Za-z0-9_]{30,}\b/g,
    capture: 0,
  },
  {
    id: "secret.openai-key",
    severity: "critical",
    title: "OpenAI API key pattern",
    pattern: /\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b/g,
    capture: 0,
  },
  {
    id: "secret.stripe-key",
    severity: "critical",
    title: "Stripe secret or restricted key pattern",
    pattern: /\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{20,}\b/g,
    capture: 0,
  },
  {
    id: "secret.slack-token",
    severity: "critical",
    title: "Slack token pattern",
    pattern: /\bxox[baprs]-[A-Za-z0-9-]{20,}\b/g,
    capture: 0,
  },
  {
    id: "secret.google-api-key",
    severity: "high",
    title: "Google API key pattern",
    pattern: /\bAIza[0-9A-Za-z_-]{35}\b/g,
    capture: 0,
  },
  {
    id: "secret.npm-token",
    severity: "critical",
    title: "npm token pattern",
    pattern: /\bnpm_[A-Za-z0-9]{30,}\b/g,
    capture: 0,
  },
  {
    id: "secret.npmrc-auth-token",
    severity: "critical",
    title: "npm auth token assigned",
    pattern: /_authToken\s*=\s*([A-Za-z0-9_./+=:@$%!-]{14,})/g,
    capture: 1,
  },
  {
    id: "secret.private-key",
    severity: "critical",
    title: "Private key block",
    pattern: /-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/g,
    capture: 0,
  },
  {
    id: "secret.assigned-sensitive-value",
    severity: "high",
    title: "Sensitive-looking value assigned in source",
    pattern:
      /\b(api[_-]?key|secret|token|password|passwd|pwd|client[_-]?secret|webhook[_-]?secret|service[_-]?role[_-]?key|signing[_-]?secret)\b\s*[:=]\s*['"]?([A-Za-z0-9_./+=:@$%!-]{14,})/gi,
    capture: 2,
  },
  {
    id: "secret.public-env-sensitive-name",
    severity: "high",
    title: "Sensitive env var appears client-exposed",
    pattern:
      /\b(?:NEXT_PUBLIC|VITE|REACT_APP|PUBLIC)_[A-Z0-9_]*(?:SECRET|TOKEN|PRIVATE|PASSWORD|SERVICE_ROLE|WEBHOOK|STRIPE_SECRET|OPENAI_API_KEY)[A-Z0-9_]*\b/g,
    capture: 0,
  },
  {
    id: "code.eval",
    severity: "high",
    title: "Dynamic code execution",
    pattern: /\beval\s*\(/g,
    capture: 0,
  },
  {
    id: "code.function-constructor",
    severity: "high",
    title: "Function constructor executes dynamic code",
    pattern: /\bnew\s+Function\s*\(/g,
    capture: 0,
  },
  {
    id: "auth.jwt-decode-without-verify",
    severity: "high",
    title: "JWT decoded without verification",
    pattern: /\bjwt\.decode\s*\(/g,
    capture: 0,
  },
  {
    id: "crypto.weak-random-token",
    severity: "medium",
    title: "Math.random used near security-sensitive naming",
    pattern: /(?=.*\bMath\.random\s*\()(?=.*\b(?:token|secret|password|session|nonce|reset)\b).*/gi,
    capture: 0,
  },
  {
    id: "crypto.weak-hash",
    severity: "medium",
    title: "Weak hash algorithm",
    pattern: /\bcreateHash\s*\(\s*['"](?:md5|sha1)['"]\s*\)/gi,
    capture: 0,
  },
  {
    id: "network.tls-disabled",
    severity: "high",
    title: "TLS certificate verification disabled",
    pattern: /\b(?:NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['"]?0|rejectUnauthorized\s*:\s*false)\b/g,
    capture: 0,
  },
  {
    id: "browser.unsafe-html",
    severity: "medium",
    title: "Unsafe HTML rendering sink",
    pattern: /\bdangerouslySetInnerHTML\b|\.innerHTML\s*=/g,
    capture: 0,
  },
  {
    id: "api.cors-wildcard",
    severity: "medium",
    title: "Wildcard CORS origin",
    pattern:
      /Access-Control-Allow-Origin['"]?\s*,?\s*['"]?\*|origin\s*:\s*['"]\*['"]/g,
    capture: 0,
  },
  {
    id: "api.csrf-disabled",
    severity: "medium",
    title: "CSRF protection appears disabled",
    pattern: /\bcsrf\s*:\s*false\b|\bcsrfProtection\s*:\s*false\b/gi,
    capture: 0,
  },
  {
    id: "cookie.insecure-session",
    severity: "medium",
    title: "Session cookie security option disabled",
    pattern: /\b(?:httpOnly|secure)\s*:\s*false\b/g,
    capture: 0,
  },
  {
    id: "sql.raw-template-interpolation",
    severity: "high",
    title: "SQL query template interpolates values",
    pattern:
      /\b(?:query|execute|raw|sql)\s*\(\s*`[^`]*(?:SELECT|INSERT|UPDATE|DELETE|UPSERT)[^`]*\$\{/gi,
    capture: 0,
  },
  {
    id: "ssrf.request-derived-fetch",
    severity: "medium",
    title: "Backend fetch appears request-derived",
    pattern: /\bfetch\s*\(\s*(?:req\.|request\.|ctx\.request|event\.url|urlParams|searchParams)/g,
    capture: 0,
  },
  {
    id: "shell.child-process-exec",
    severity: "medium",
    title: "Shell command execution sink",
    pattern: /\bchild_process\.exec\s*\(|\brequire\(['"](?:node:)?child_process['"]\)\.exec\s*\(/g,
    capture: 0,
  },
];

const PLACEHOLDER_VALUES = new Set([
  "example",
  "examplevalue",
  "example-value",
  "changeme",
  "change-me",
  "placeholder",
  "replace-me",
  "your-token",
  "your-secret",
  "not-a-secret",
  "dummy",
  "dummy-value",
]);

function parseArgs(argv) {
  const args = {
    command: "scan",
    path: ".",
    format: "text",
    failOn: "none",
    maxBytes: 1024 * 1024,
    githubAnnotations: false,
  };

  const tokens = [...argv];
  if (tokens[0] && !tokens[0].startsWith("-")) {
    args.command = tokens.shift();
  }

  if (args.command === "ci") {
    args.failOn = "high";
    args.githubAnnotations = true;
  }

  for (let index = 0; index < tokens.length; index += 1) {
    const token = tokens[index];
    const next = () => {
      index += 1;
      if (index >= tokens.length) {
        throw new Error(`Missing value for ${token}`);
      }
      return tokens[index];
    };

    if (token === "--path" || token === "-p") {
      args.path = next();
    } else if (token === "--format") {
      args.format = next();
    } else if (token === "--fail-on") {
      args.failOn = next().toLowerCase();
    } else if (token === "--max-bytes") {
      args.maxBytes = Number(next());
    } else if (token === "--github-annotations") {
      args.githubAnnotations = true;
    } else if (token === "--no-github-annotations") {
      args.githubAnnotations = false;
    } else if (token === "--help" || token === "-h") {
      args.command = "help";
    } else {
      throw new Error(`Unknown argument: ${token}`);
    }
  }

  if (!["scan", "ci", "help"].includes(args.command)) {
    throw new Error(`Unknown command: ${args.command}`);
  }
  if (!["text", "json", "sarif"].includes(args.format)) {
    throw new Error("--format must be text, json, or sarif");
  }
  if (args.failOn !== "none" && !Object.hasOwn(SEVERITY_RANK, args.failOn)) {
    throw new Error("--fail-on must be none, low, medium, high, or critical");
  }
  if (!Number.isFinite(args.maxBytes) || args.maxBytes <= 0) {
    throw new Error("--max-bytes must be a positive number");
  }

  return args;
}

function isBinary(filePath) {
  const buffer = Buffer.alloc(1024);
  let descriptor;
  try {
    descriptor = fs.openSync(filePath, "r");
    const bytesRead = fs.readSync(descriptor, buffer, 0, buffer.length, 0);
    return buffer.subarray(0, bytesRead).includes(0);
  } catch {
    return true;
  } finally {
    if (descriptor !== undefined) {
      fs.closeSync(descriptor);
    }
  }
}

function shouldSkip(entryPath, root) {
  const relative = path.relative(root, entryPath);
  if (!relative || relative.startsWith("..")) {
    return false;
  }
  return relative.split(path.sep).some((part) => DEFAULT_EXCLUDES.has(part));
}

function walkFiles(root) {
  const files = [];
  const stack = [root];

  while (stack.length > 0) {
    const current = stack.pop();
    let entries;
    try {
      entries = fs.readdirSync(current, { withFileTypes: true });
    } catch {
      continue;
    }

    for (const entry of entries) {
      const entryPath = path.join(current, entry.name);
      if (shouldSkip(entryPath, root)) {
        continue;
      }
      if (entry.isDirectory()) {
        stack.push(entryPath);
      } else if (entry.isFile()) {
        files.push(entryPath);
      }
    }
  }

  return files.sort();
}

function normalizeGitPath(filePath) {
  return filePath.split(path.sep).join("/");
}

function realPath(filePath) {
  try {
    return fs.realpathSync.native(filePath);
  } catch {
    return path.resolve(filePath);
  }
}

function splitNulOutput(output) {
  return String(output).split("\0").filter(Boolean);
}

function runGit(root, args, input) {
  return childProcess.spawnSync("git", ["-C", root, ...args], {
    encoding: "utf8",
    input,
    maxBuffer: 10 * 1024 * 1024,
  });
}

function chunkPaths(paths, maxItems = 500, maxBytes = 128 * 1024) {
  const chunks = [];
  let current = [];
  let currentBytes = 0;

  for (const item of paths) {
    const itemBytes = Buffer.byteLength(item) + 1;
    if (current.length > 0 && (current.length >= maxItems || currentBytes + itemBytes > maxBytes)) {
      chunks.push(current);
      current = [];
      currentBytes = 0;
    }
    current.push(item);
    currentBytes += itemBytes;
  }

  if (current.length > 0) {
    chunks.push(current);
  }
  return chunks;
}

function collectGitTracked(topLevel, repoRelativePaths) {
  const tracked = new Set();
  for (const chunk of chunkPaths(repoRelativePaths)) {
    const result = runGit(topLevel, ["ls-files", "-z", "--", ...chunk]);
    if (result.status !== 0) {
      continue;
    }
    for (const entry of splitNulOutput(result.stdout)) {
      tracked.add(entry);
    }
  }
  return tracked;
}

function collectGitIgnored(topLevel, repoRelativePaths) {
  const ignored = new Set();
  for (const chunk of chunkPaths(repoRelativePaths)) {
    const result = runGit(topLevel, ["check-ignore", "-z", "--stdin"], `${chunk.join("\0")}\0`);
    if (result.status !== 0 && result.status !== 1) {
      continue;
    }
    for (const entry of splitNulOutput(result.stdout)) {
      ignored.add(entry);
    }
  }
  return ignored;
}

function createGitContext(root, files) {
  const topLevelResult = runGit(root, ["rev-parse", "--show-toplevel"]);
  if (topLevelResult.status !== 0 || !topLevelResult.stdout.trim()) {
    return {
      available: false,
      ignored: new Set(),
      tracked: new Set(),
      toRepoRelative() {
        return null;
      },
    };
  }

  const topLevel = realPath(topLevelResult.stdout.trim());
  const repoRelativePaths = files
    .map((filePath) => normalizeGitPath(path.relative(topLevel, realPath(filePath))))
    .filter((relative) => relative && !relative.startsWith(".."));

  const tracked = collectGitTracked(topLevel, repoRelativePaths);
  const ignored = collectGitIgnored(topLevel, repoRelativePaths);

  return {
    available: true,
    ignored,
    tracked,
    toRepoRelative(filePath) {
      const relative = normalizeGitPath(path.relative(topLevel, realPath(filePath)));
      return relative && !relative.startsWith("..") ? relative : null;
    },
  };
}

function isPublishableSensitiveFile(filePath, gitContext) {
  if (!gitContext.available) {
    return true;
  }

  const repoRelative = gitContext.toRepoRelative(filePath);
  if (!repoRelative) {
    return true;
  }

  return gitContext.tracked.has(repoRelative) || !gitContext.ignored.has(repoRelative);
}

function isSecretValueRule(ruleId) {
  return ruleId.startsWith("secret.") && ruleId !== "secret.public-env-sensitive-name";
}

function redact(value) {
  const normalized = String(value).trim().replace(/^['"]|['"]$/g, "");
  if (normalized.length <= 8) {
    return "***";
  }
  return `${normalized.slice(0, 4)}...${normalized.slice(-4)}`;
}

function redactRanges(value, ranges) {
  const ordered = [...ranges]
    .filter((range) => range.end > range.start)
    .sort((left, right) => right.start - left.start);
  let output = value;
  for (const range of ordered) {
    output = `${output.slice(0, range.start)}${redact(output.slice(range.start, range.end))}${output.slice(range.end)}`;
  }
  return output;
}

function secretValueRanges(line) {
  const ranges = [];
  for (const rule of TEXT_RULES) {
    if (!isSecretValueRule(rule.id)) {
      continue;
    }
    const pattern = new RegExp(rule.pattern.source, rule.pattern.flags);
    let match;
    while ((match = pattern.exec(line)) !== null) {
      const matchValue = match[rule.capture] || match[0];
      if (rule.id === "secret.assigned-sensitive-value" && isPlaceholder(matchValue)) {
        continue;
      }
      const offsetInMatch = match[0].indexOf(matchValue);
      const start = match.index + Math.max(offsetInMatch, 0);
      ranges.push({ start, end: start + matchValue.length });
    }
  }
  return ranges;
}

function sanitizeSnippet(line) {
  let snippet = line.trim();
  snippet = redactRanges(snippet, secretValueRanges(snippet));
  if (snippet.length > 180) {
    snippet = `${snippet.slice(0, 177)}...`;
  }
  return snippet;
}

function isPlaceholder(value) {
  const normalized = String(value)
    .trim()
    .replace(/^['"]|['"]$/g, "")
    .toLowerCase();
  return (
    PLACEHOLDER_VALUES.has(normalized) ||
    normalized.includes("example") ||
    normalized.includes("placeholder") ||
    normalized.includes("changeme")
  );
}

function isDocumentationFile(filePath) {
  return [".md", ".mdx", ".markdown", ".rst", ".txt"].includes(path.extname(filePath).toLowerCase());
}

function createFinding({ rule, filePath, root, line, column, lineText, matchValue }) {
  return {
    ruleId: rule.id,
    severity: rule.severity,
    title: rule.title,
    file: path.relative(root, filePath) || path.basename(filePath),
    absoluteFile: filePath,
    line,
    column,
    snippet: sanitizeSnippet(lineText, matchValue),
  };
}

function scanTextFile(filePath, root) {
  const findings = [];
  let content;
  try {
    content = fs.readFileSync(filePath, "utf8");
  } catch {
    return findings;
  }

  const lines = content.split(/\r?\n/);
  const documentationFile = isDocumentationFile(filePath);
  lines.forEach((lineText, lineIndex) => {
    for (const rule of TEXT_RULES) {
      if (documentationFile && !rule.id.startsWith("secret.")) {
        continue;
      }
      rule.pattern.lastIndex = 0;
      let match;
      while ((match = rule.pattern.exec(lineText)) !== null) {
        const matchValue = match[rule.capture] || match[0];
        if (rule.id === "secret.assigned-sensitive-value" && isPlaceholder(matchValue)) {
          continue;
        }
        findings.push(
          createFinding({
            rule,
            filePath,
            root,
            line: lineIndex + 1,
            column: match.index + 1,
            lineText,
            matchValue,
          }),
        );
      }
    }
  });

  return findings;
}

function scanFileName(filePath, root, gitContext) {
  const findings = [];
  const basename = path.basename(filePath);
  const lower = basename.toLowerCase();
  const relative = path.relative(root, filePath);

  const envAllowed =
    lower.endsWith(".example") ||
    lower.endsWith(".sample") ||
    lower.endsWith(".template") ||
    lower === ".envrc";

  if (lower.startsWith(".env") && !envAllowed && isPublishableSensitiveFile(filePath, gitContext)) {
    findings.push({
      ruleId: "secret.env-file",
      severity: "high",
      title: "Environment file present in scanned tree",
      file: relative,
      absoluteFile: filePath,
      line: 1,
      column: 1,
      snippet: "Environment files often contain deploy secrets. Confirm this file is not committed or published.",
    });
  }

  if (
    lower === "id_rsa" ||
    lower === "id_ed25519" ||
    lower.endsWith(".pem") ||
    lower.endsWith(".p8") ||
    lower.endsWith(".p12") ||
    lower.endsWith(".pfx")
  ) {
    if (!isPublishableSensitiveFile(filePath, gitContext)) {
      return findings;
    }

    findings.push({
      ruleId: "secret.key-file",
      severity: "critical",
      title: "Private key file present in scanned tree",
      file: relative,
      absoluteFile: filePath,
      line: 1,
      column: 1,
      snippet: "Private key material should not be committed or published.",
    });
  }

  if (
    (lower.includes("service-account") && lower.endsWith(".json") ||
      lower.includes("service_account") && lower.endsWith(".json")) &&
    isPublishableSensitiveFile(filePath, gitContext)
  ) {
    findings.push({
      ruleId: "secret.service-account-file",
      severity: "high",
      title: "Service account file present in scanned tree",
      file: relative,
      absoluteFile: filePath,
      line: 1,
      column: 1,
      snippet: "Service account JSON files often contain deploy or cloud credentials.",
    });
  }

  return findings;
}

function scanPackageJson(filePath, root) {
  if (path.basename(filePath) !== "package.json") {
    return [];
  }

  let parsed;
  try {
    parsed = JSON.parse(fs.readFileSync(filePath, "utf8"));
  } catch {
    return [];
  }

  const findings = [];
  const scripts = parsed.scripts || {};
  for (const [scriptName, command] of Object.entries(scripts)) {
    if (
      /(?:^|\s)(curl|wget)\b.*(?:bash|sh|node|python|ruby)|https?:\/\/.*\|\s*(?:bash|sh)/i.test(
        String(command),
      )
    ) {
      findings.push({
        ruleId: "supply-chain.remote-install-script",
        severity: "high",
        title: "Package script executes remote code",
        file: path.relative(root, filePath),
        absoluteFile: filePath,
        line: 1,
        column: 1,
        snippet: `${scriptName}: ${sanitizeSnippet(String(command))}`,
      });
    }
  }

  return findings;
}

function scanGitHubWorkflow(filePath, root) {
  const relative = path.relative(root, filePath);
  if (!relative.startsWith(".github/workflows/") && !relative.startsWith(`.github${path.sep}workflows${path.sep}`)) {
    return [];
  }

  let content;
  try {
    content = fs.readFileSync(filePath, "utf8");
  } catch {
    return [];
  }

  const findings = [];
  const lines = content.split(/\r?\n/);
  const pullRequestTargetLine = lines.findIndex((lineText) => (
    /^\s*pull_request_target\s*:/i.test(lineText) ||
    /^\s*on\s*:\s*pull_request_target\s*(?:#.*)?$/i.test(lineText) ||
    /^\s*on\s*:\s*\[[^\]]*\bpull_request_target\b[^\]]*\]\s*(?:#.*)?$/i.test(lineText)
  ));
  const hasPullRequestTarget = pullRequestTargetLine !== -1;
  const checksOutCode = /^\s*(?:-\s*)?uses\s*:\s*['"]?actions\/checkout@/im.test(content);
  const referencesSecrets = /\bsecrets\.[A-Z0-9_]+\b/i.test(content);

  if (hasPullRequestTarget && checksOutCode) {
    findings.push({
      ruleId: "ci.pull-request-target-checkout",
      severity: "high",
      title: "pull_request_target workflow checks out repository code",
      file: relative,
      absoluteFile: filePath,
      line: pullRequestTargetLine + 1,
      column: 1,
      snippet: "Review whether untrusted pull request code can run with privileged token or secrets.",
    });
  }

  if (hasPullRequestTarget && referencesSecrets) {
    const line = lines.findIndex((value) => /\bsecrets\.[A-Z0-9_]+\b/i.test(value)) + 1;
    findings.push({
      ruleId: "ci.pull-request-target-secrets",
      severity: "high",
      title: "pull_request_target workflow references secrets",
      file: relative,
      absoluteFile: filePath,
      line: line || 1,
      column: 1,
      snippet: "Privileged PR workflows must not expose secrets to untrusted code paths.",
    });
  }

  lines.forEach((lineText, index) => {
    if (/^\s*permissions:\s*write-all\s*$/i.test(lineText)) {
      findings.push({
        ruleId: "ci.write-all-permissions",
        severity: "medium",
        title: "GitHub Actions grants write-all permissions",
        file: relative,
        absoluteFile: filePath,
        line: index + 1,
        column: 1,
        snippet: "Use least-privilege workflow permissions.",
      });
    }

    const action = lineText.match(/^\s*(?:-\s*)?uses\s*:\s*['"]?([^@'"\s]+)@([^'"\s#]+)['"]?\s*(?:#.*)?$/);
    if (action && /^(main|master|latest|dev|develop)$/i.test(action[2])) {
      findings.push({
        ruleId: "ci.mutable-action-ref",
        severity: "medium",
        title: "GitHub Action uses a mutable ref",
        file: relative,
        absoluteFile: filePath,
        line: index + 1,
        column: 1,
        snippet: "Pin sensitive workflows to version tags or immutable SHAs.",
      });
    }

    if (/^\s*persist-credentials:\s*true\s*$/i.test(lineText)) {
      findings.push({
        ruleId: "ci.checkout-persists-credentials",
        severity: "medium",
        title: "Checkout persists git credentials",
        file: relative,
        absoluteFile: filePath,
        line: index + 1,
        column: 1,
        snippet: "Set persist-credentials: false unless the job intentionally pushes with the token.",
      });
    }
  });

  return findings;
}

function scan(rootInput, options = {}) {
  const root = path.resolve(rootInput || ".");
  const maxBytes = options.maxBytes || 1024 * 1024;
  if (!fs.existsSync(root)) {
    throw new Error(`Path not found: ${root}`);
  }

  const findings = [];
  const files = walkFiles(root);
  const gitContext = createGitContext(root, files);

  for (const filePath of files) {
    findings.push(...scanFileName(filePath, root, gitContext));

    let stats;
    try {
      stats = fs.statSync(filePath);
    } catch {
      continue;
    }
    if (stats.size > maxBytes || isBinary(filePath)) {
      continue;
    }

    findings.push(...scanTextFile(filePath, root));
    findings.push(...scanPackageJson(filePath, root));
    findings.push(...scanGitHubWorkflow(filePath, root));
  }

  return findings.sort((left, right) => {
    const severityDelta = SEVERITY_RANK[right.severity] - SEVERITY_RANK[left.severity];
    if (severityDelta !== 0) {
      return severityDelta;
    }
    return `${left.file}:${left.line}:${left.ruleId}`.localeCompare(
      `${right.file}:${right.line}:${right.ruleId}`,
    );
  });
}

function shouldFail(findings, failOn) {
  if (failOn === "none") {
    return false;
  }
  const threshold = SEVERITY_RANK[failOn];
  return findings.some((finding) => SEVERITY_RANK[finding.severity] >= threshold);
}

function escapeTextField(value) {
  return String(value)
    .replace(/\r/g, "\\r")
    .replace(/\n/g, "\\n")
    .replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, (character) => {
      return `\\x${character.charCodeAt(0).toString(16).padStart(2, "0")}`;
    });
}

function formatText(findings) {
  if (findings.length === 0) {
    return "ShipGuard: no findings from built-in checks.";
  }

  const counts = findings.reduce((accumulator, finding) => {
    accumulator[finding.severity] = (accumulator[finding.severity] || 0) + 1;
    return accumulator;
  }, {});
  const summary = ["critical", "high", "medium", "low"]
    .filter((severity) => counts[severity])
    .map((severity) => `${severity}=${counts[severity]}`)
    .join(", ");

  const lines = [`ShipGuard: ${findings.length} finding(s) from built-in checks (${summary}).`];
  for (const finding of findings) {
    lines.push(
      `[${finding.severity.toUpperCase()}] ${finding.title} (${finding.ruleId})`,
      `  ${escapeTextField(finding.file)}:${finding.line}:${finding.column}`,
      `  ${escapeTextField(finding.snippet)}`,
    );
  }
  return lines.join(os.EOL);
}

function formatJson(findings) {
  return JSON.stringify({ findings }, null, 2);
}

function formatSarif(findings) {
  const rules = new Map();
  for (const finding of findings) {
    rules.set(finding.ruleId, {
      id: finding.ruleId,
      name: finding.title,
      shortDescription: { text: finding.title },
      properties: { severity: finding.severity },
    });
  }

  return JSON.stringify(
    {
      version: "2.1.0",
      $schema: "https://json.schemastore.org/sarif-2.1.0.json",
      runs: [
        {
          tool: {
            driver: {
              name: "ShipGuard",
              informationUri: "https://github.com/Elgabor/shipguard-codex-skill",
              rules: [...rules.values()],
            },
          },
          results: findings.map((finding) => ({
            ruleId: finding.ruleId,
            level: finding.severity === "critical" || finding.severity === "high" ? "error" : "warning",
            message: { text: `${finding.title}: ${finding.snippet}` },
            locations: [
              {
                physicalLocation: {
                  artifactLocation: { uri: finding.file },
                  region: { startLine: finding.line, startColumn: finding.column },
                },
              },
            ],
            properties: { severity: finding.severity },
          })),
        },
      ],
    },
    null,
    2,
  );
}

function escapeAnnotation(value) {
  return String(value)
    .replace(/%/g, "%25")
    .replace(/\r/g, "%0D")
    .replace(/\n/g, "%0A")
    .replace(/:/g, "%3A")
    .replace(/,/g, "%2C");
}

function printGitHubAnnotations(findings) {
  for (const finding of findings) {
    const level = SEVERITY_RANK[finding.severity] >= SEVERITY_RANK.high ? "error" : "warning";
    const message = `${finding.severity.toUpperCase()} ${finding.title} (${finding.ruleId}): ${finding.snippet}`;
    process.stdout.write(
      `::${level} file=${escapeAnnotation(finding.file)},line=${finding.line},col=${finding.column}::${escapeAnnotation(message)}${os.EOL}`,
    );
  }
}

function printHelp() {
  process.stdout.write(`ShipGuard scanner

Usage:
  shipguard-codex-skill scan [--path .] [--format text|json|sarif] [--fail-on none|low|medium|high|critical]
  shipguard-codex-skill ci [--path .] [--fail-on high]

Commands:
  scan  Run built-in checks. Does not fail by default.
  ci    Run built-in checks for CI. Emits GitHub annotations and fails on high by default.

Options:
  --path <dir>          Directory to scan. Default: .
  --format <format>     text, json, or sarif. Default: text.
  --fail-on <severity>  Exit 1 when findings meet threshold. Default: none for scan, high for ci.
  --max-bytes <number>  Skip text files larger than this size. Default: 1048576.
`);
}

function main(argv = process.argv.slice(2)) {
  let args;
  try {
    args = parseArgs(argv);
  } catch (error) {
    process.stderr.write(`ShipGuard: ${error.message}${os.EOL}`);
    process.stderr.write("Run with --help for usage.\n");
    return 2;
  }

  if (args.command === "help") {
    printHelp();
    return 0;
  }

  let findings;
  try {
    findings = scan(args.path, { maxBytes: args.maxBytes });
  } catch (error) {
    process.stderr.write(`ShipGuard: ${error.message}${os.EOL}`);
    return 2;
  }

  if (args.githubAnnotations) {
    printGitHubAnnotations(findings);
  }

  if (args.format === "json") {
    process.stdout.write(`${formatJson(findings)}${os.EOL}`);
  } else if (args.format === "sarif") {
    process.stdout.write(`${formatSarif(findings)}${os.EOL}`);
  } else {
    process.stdout.write(`${formatText(findings)}${os.EOL}`);
  }

  return shouldFail(findings, args.failOn) ? 1 : 0;
}

if (require.main === module) {
  process.exitCode = main();
}

module.exports = {
  parseArgs,
  scan,
  shouldFail,
  formatJson,
  formatSarif,
  formatText,
  main,
};
