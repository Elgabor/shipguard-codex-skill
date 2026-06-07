#!/usr/bin/env node
"use strict";

const fs = require("fs");
const os = require("os");
const path = require("path");
const scanner = require("../skills/shipguard-codex-skill/scripts/shipguard-scan");

const SKILL_NAME = "shipguard-codex-skill";
const PACKAGE_ROOT = path.resolve(__dirname, "..");
const SKILL_ROOT = path.join(PACKAGE_ROOT, "skills", SKILL_NAME);
const INSTALL_ENTRIES = ["SKILL.md", "agents", "references", "scripts"];
const MANAGED_MARKER = ".shipguard-managed";

function unique(values) {
  return [...new Set(values)];
}

function knownTargetRoots() {
  const home = os.homedir();
  const roots = [];
  if (process.env.CODEX_HOME) {
    roots.push(path.join(process.env.CODEX_HOME, "skills"));
  }

  const codexRoot = path.join(home, ".codex");
  const agentsRoot = path.join(home, ".agents");
  const codexSkills = path.join(codexRoot, "skills");
  const agentsSkills = path.join(agentsRoot, "skills");

  if (fs.existsSync(codexRoot) || fs.existsSync(codexSkills)) {
    roots.push(codexSkills);
  }
  if (fs.existsSync(agentsRoot) || fs.existsSync(agentsSkills)) {
    roots.push(agentsSkills);
  }

  if (roots.length === 0) {
    roots.push(agentsSkills);
  }

  return unique(roots.map((root) => path.resolve(root)));
}

function copyRecursive(source, target) {
  const stat = fs.statSync(source);

  if (stat.isDirectory()) {
    fs.mkdirSync(target, { recursive: true });
    for (const entry of fs.readdirSync(source)) {
      copyRecursive(path.join(source, entry), path.join(target, entry));
    }
    return;
  }

  fs.mkdirSync(path.dirname(target), { recursive: true });
  fs.copyFileSync(source, target);
  fs.chmodSync(target, stat.mode);
}

function parseInstallArgs(argv) {
  const args = {
    targetRoots: knownTargetRoots(),
    force: false,
  };

  for (let index = 0; index < argv.length; index += 1) {
    const token = argv[index];
    if (token === "--target-root") {
      index += 1;
      if (index >= argv.length) {
        throw new Error("Missing value for --target-root");
      }
      args.targetRoots = [path.resolve(argv[index].replace(/^~/, os.homedir()))];
    } else if (token === "--target") {
      index += 1;
      if (index >= argv.length) {
        throw new Error("Missing value for --target");
      }
      const target = argv[index];
      if (target === "codex-home") {
        args.targetRoots = [path.resolve(path.join(process.env.CODEX_HOME || path.join(os.homedir(), ".codex"), "skills"))];
      } else if (target === "agents-home") {
        args.targetRoots = [path.resolve(path.join(os.homedir(), ".agents", "skills"))];
      } else if (target === "all-known") {
        args.targetRoots = unique([
          path.resolve(path.join(process.env.CODEX_HOME || path.join(os.homedir(), ".codex"), "skills")),
          path.resolve(path.join(os.homedir(), ".agents", "skills")),
        ]);
      } else {
        throw new Error("--target must be codex-home, agents-home, or all-known");
      }
    } else if (token === "--help" || token === "-h") {
      args.help = true;
    } else if (token === "--force") {
      args.force = true;
    } else {
      throw new Error(`Unknown install argument: ${token}`);
    }
  }

  return args;
}

function printInstallHelp() {
  process.stdout.write(`ShipGuard installer

Usage:
  shipguard-codex-skill install [--target codex-home|agents-home|all-known]
  shipguard-codex-skill install [--target-root /custom/skills] [--force]
  shipguard-codex-skill scan --path .
  shipguard-codex-skill ci --path . --fail-on high

Running without a command installs the Codex skill into detected skill roots.
Install replaces only a managed <target-root>/${SKILL_NAME} directory.
`);
}

function isManagedInstall(targetDir) {
  return fs.existsSync(path.join(targetDir, MANAGED_MARKER));
}

function install(argv) {
  let args;
  try {
    args = parseInstallArgs(argv);
  } catch (error) {
    process.stderr.write(`ShipGuard: ${error.message}${os.EOL}`);
    return 2;
  }

  if (args.help) {
    printInstallHelp();
    return 0;
  }

  for (const targetRoot of args.targetRoots) {
    const targetDir = path.join(targetRoot, SKILL_NAME);
    fs.mkdirSync(targetRoot, { recursive: true });
    if (fs.existsSync(targetDir) && !args.force && !isManagedInstall(targetDir)) {
      process.stderr.write(
        `ShipGuard: refusing to replace unmanaged directory ${targetDir}. Re-run with --force if this is intentional.${os.EOL}`,
      );
      return 2;
    }
    fs.rmSync(targetDir, { recursive: true, force: true });

    for (const entry of INSTALL_ENTRIES) {
      copyRecursive(path.join(SKILL_ROOT, entry), path.join(targetDir, entry));
    }
    fs.writeFileSync(path.join(targetDir, MANAGED_MARKER), `${SKILL_NAME}\n`, "utf8");

    process.stdout.write(`Installed ${SKILL_NAME} to ${targetDir}${os.EOL}`);
  }

  process.stdout.write("Restart Codex or open a new chat if skill autocomplete does not refresh immediately.\n");
  process.stdout.write(`Use it with: $${SKILL_NAME}\n`);
  return 0;
}

function main(argv = process.argv.slice(2)) {
  const [command, ...rest] = argv;
  if (!command || command === "install") {
    return install(rest);
  }
  if (command === "scan" || command === "ci" || command === "help" || command === "--help" || command === "-h") {
    const scannerArgs = command === "--help" || command === "-h" ? ["help"] : [command, ...rest];
    return scanner.main(scannerArgs);
  }

  process.stderr.write(`ShipGuard: unknown command ${command}${os.EOL}`);
  printInstallHelp();
  return 2;
}

if (require.main === module) {
  process.exitCode = main();
}

module.exports = {
  install,
  knownTargetRoots,
  main,
};
