"use strict";

const assert = require("node:assert/strict");
const childProcess = require("node:child_process");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");

const BIN = path.resolve(__dirname, "..", "bin", "shipguard.js");
const SKILL_NAME = "shipguard-codex-skill";

function withTempDir(callback) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "shipguard-install-"));
  try {
    return callback(root);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
}

function runInstall(args) {
  return childProcess.spawnSync(process.execPath, [BIN, "install", ...args], {
    encoding: "utf8",
  });
}

test("installer refuses to replace unmanaged target directory without force", () => {
  withTempDir((root) => {
    const target = path.join(root, SKILL_NAME);
    const sentinel = path.join(target, "sentinel.txt");
    fs.mkdirSync(target, { recursive: true });
    fs.writeFileSync(sentinel, "keep me\n");

    const refused = runInstall(["--target-root", root]);

    assert.equal(refused.status, 2);
    assert.match(refused.stderr, /refusing to replace unmanaged directory/);
    assert.equal(fs.readFileSync(sentinel, "utf8"), "keep me\n");

    const forced = runInstall(["--target-root", root, "--force"]);

    assert.equal(forced.status, 0, forced.stderr);
    assert.equal(fs.existsSync(sentinel), false);
    assert.equal(fs.existsSync(path.join(target, "SKILL.md")), true);
    assert.equal(fs.existsSync(path.join(target, ".shipguard-managed")), true);
  });
});
