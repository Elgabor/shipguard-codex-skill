#!/usr/bin/env node
"use strict";

const fs = require("fs");
const path = require("path");

const ROOT = path.resolve(__dirname, "..");
const SKILL_NAME = "shipguard-codex-skill";
const SKILL_ROOT = path.join(ROOT, "skills", SKILL_NAME);

function fail(message) {
  process.stderr.write(`validate-skill: ${message}\n`);
  process.exitCode = 1;
}

function read(relativePath) {
  return fs.readFileSync(path.join(ROOT, relativePath), "utf8");
}

function readSkill(relativePath) {
  return fs.readFileSync(path.join(SKILL_ROOT, relativePath), "utf8");
}

function parseFrontmatter(markdown) {
  const match = markdown.match(/^---\n([\s\S]*?)\n---\n/);
  if (!match) {
    return null;
  }

  const values = {};
  for (const line of match[1].split(/\r?\n/)) {
    const pair = line.match(/^([a-zA-Z_][a-zA-Z0-9_-]*):\s*(.*)$/);
    if (pair) {
      values[pair[1]] = pair[2].replace(/^['"]|['"]$/g, "");
    }
  }
  return values;
}

function assertExists(relativePath) {
  if (!fs.existsSync(path.join(ROOT, relativePath))) {
    fail(`missing ${relativePath}`);
  }
}

assertExists(".codex-plugin/plugin.json");
assertExists(`skills/${SKILL_NAME}/SKILL.md`);
assertExists(`skills/${SKILL_NAME}/agents/openai.yaml`);
assertExists(`skills/${SKILL_NAME}/references/audit-playbook.md`);
assertExists(`skills/${SKILL_NAME}/references/framework-checks.md`);
assertExists(`skills/${SKILL_NAME}/references/ci-github-actions.md`);
assertExists(`skills/${SKILL_NAME}/references/codex-action-ci.md`);
assertExists(`skills/${SKILL_NAME}/scripts/shipguard-scan.js`);
assertExists("bin/shipguard.js");

const plugin = JSON.parse(read(".codex-plugin/plugin.json"));
if (plugin.name !== SKILL_NAME) {
  fail("plugin name does not match package name");
}
if (plugin.skills !== "./skills/") {
  fail("plugin skills path should point at ./skills/");
}

const skill = readSkill("SKILL.md");
const frontmatter = parseFrontmatter(skill);

if (!frontmatter) {
  fail("SKILL.md must start with YAML frontmatter");
} else {
  if (frontmatter.name !== SKILL_NAME) {
    fail(`frontmatter name must be ${SKILL_NAME}`);
  }
  if (!frontmatter.description || frontmatter.description.length < 120) {
    fail("frontmatter description should be specific enough to trigger correctly");
  }
  if (Object.keys(frontmatter).some((key) => !["name", "description"].includes(key))) {
    fail("frontmatter should only contain name and description");
  }
}

if (skill.includes("TODO")) {
  fail("SKILL.md still contains TODO");
}

const openaiYaml = readSkill("agents/openai.yaml");
if (!openaiYaml.includes(`$${SKILL_NAME}`)) {
  fail("agents/openai.yaml default_prompt must mention the skill with $shipguard-codex-skill");
}

const packageJson = JSON.parse(read("package.json"));
if (packageJson.name !== SKILL_NAME) {
  fail("package.json name does not match skill name");
}
if (!packageJson.bin || !packageJson.bin[SKILL_NAME]) {
  fail("package.json must expose the shipguard-codex-skill binary");
}

if (!process.exitCode) {
  process.stdout.write("validate-skill: ok\n");
}
