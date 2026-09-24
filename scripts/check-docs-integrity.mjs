#!/usr/bin/env node
/**
 * check-docs-integrity.mjs
 * Deterministic documentation integrity and drift detection gate.
 *
 * Verifies that documentation (README.md, README.zh-TW.md, SECURITY.md, CONTRIBUTING.md)
 * never drifts from actual repository baseline invariants:
 * 1. Package version agreement across all doc headers.
 * 2. Section 24 invariant count (121) accurately represented.
 * 3. Release specification count (62) and security invariants (40) accurately represented.
 * 4. Directory tree annotation version parity.
 * 5. Supported minor line accurately reflected in SECURITY.md table.
 * 6. Mandatory onboarding sections (Getting Started, Support Matrix, CONTRIBUTING.md) present.
 *
 * Zero external npm dependencies.
 */

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const REPO_ROOT = path.resolve(path.dirname(__filename), '..');

function fail(msg) {
  console.error(`❌ DOC_INTEGRITY_DRIFT: ${msg}`);
  process.exit(1);
}

function assert(condition, msg) {
  if (!condition) fail(msg);
}

const pkgPath = path.join(REPO_ROOT, 'package.json');
const pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf8'));
const currentVersion = pkg.version;
const minorLine = currentVersion.split('.').slice(0, 2).join('.') + '.x';

const EXPECTED_INVARIANTS = 121;
const EXPECTED_SPECS = 62;
const EXPECTED_SECURITY_INVARIANTS = 40;

console.log(`Checking documentation integrity for v${currentVersion} (minor line: ${minorLine})...`);

// 1. Check README.md
const readmePath = path.join(REPO_ROOT, 'README.md');
assert(fs.existsSync(readmePath), 'README.md must exist');
const readme = fs.readFileSync(readmePath, 'utf8');

assert(
  readme.includes(`# agy-security-audit (plugin ID: \`security-audit\`) v${currentVersion}`),
  `README.md header must match v${currentVersion}`
);
assert(
  readme.includes(`├── package.json                          # npm test, test:evals, test:semantic, test:discovery, test:stability, check:release (${currentVersion})`),
  `README.md directory tree package.json must match (${currentVersion})`
);
assert(
  readme.includes(`├── render-sarif.mjs          # SARIF 2.1.0 / Markdown rendering plus ${EXPECTED_INVARIANTS} invariant tests`),
  `README.md directory tree render-sarif.mjs must state ${EXPECTED_INVARIANTS} invariant tests`
);
assert(
  readme.includes(`└── check-release-invariants.mjs # Section 24 release-invariant gate (${EXPECTED_SPECS} specifications, ${EXPECTED_SECURITY_INVARIANTS} invariants)`),
  `README.md directory tree check-release-invariants.mjs must state ${EXPECTED_SPECS} specifications, ${EXPECTED_SECURITY_INVARIANTS} invariants`
);
assert(readme.includes('## Getting Started'), 'README.md must contain a "## Getting Started" section');
assert(readme.includes('### Prerequisites & Support Matrix'), 'README.md must contain "### Prerequisites & Support Matrix"');

// 2. Check README.zh-TW.md
const readmeZhPath = path.join(REPO_ROOT, 'README.zh-TW.md');
assert(fs.existsSync(readmeZhPath), 'README.zh-TW.md must exist');
const readmeZh = fs.readFileSync(readmeZhPath, 'utf8');

assert(
  readmeZh.includes(`# agy-security-audit (plugin ID: \`security-audit\`) v${currentVersion}`),
  `README.zh-TW.md header must match v${currentVersion}`
);
assert(
  readmeZh.includes(`├── package.json                          # npm test, test:evals, test:semantic, test:discovery, test:stability, check:release (${currentVersion})`),
  `README.zh-TW.md directory tree package.json must match (${currentVersion})`
);
assert(
  readmeZh.includes(`├── render-sarif.mjs          # SARIF 2.1.0 / Markdown 渲染與 ${EXPECTED_INVARIANTS} 項不變量測試`),
  `README.zh-TW.md directory tree render-sarif.mjs must state ${EXPECTED_INVARIANTS} 項不變量測試`
);
assert(
  readmeZh.includes(`└── check-release-invariants.mjs # Section 24 發行不變量閘門 (${EXPECTED_SPECS} 項規格，${EXPECTED_SECURITY_INVARIANTS} 項安全不變量)`),
  `README.zh-TW.md directory tree check-release-invariants.mjs must state ${EXPECTED_SPECS} 項規格，${EXPECTED_SECURITY_INVARIANTS} 項安全不變量`
);
assert(readmeZh.includes('## 快速上手 (Getting Started)'), 'README.zh-TW.md must contain "## 快速上手 (Getting Started)"');

// 3. Check SECURITY.md
const securityPath = path.join(REPO_ROOT, 'SECURITY.md');
assert(fs.existsSync(securityPath), 'SECURITY.md must exist');
const security = fs.readFileSync(securityPath, 'utf8');

assert(
  security.includes(`## 2. Hardening & Guardrails (v${currentVersion} / Production)`),
  `SECURITY.md Section 2 header must match v${currentVersion} / Production`
);
assert(
  new RegExp(`\\|\\s*${minorLine.replace('.', '\\.')}\\s*\\|\\s*:white_check_mark:\\s*\\|`).test(security),
  `SECURITY.md supported versions table must mark current minor line ${minorLine} as supported (:white_check_mark:)`
);

// 4. Check CONTRIBUTING.md
const contribPath = path.join(REPO_ROOT, 'CONTRIBUTING.md');
assert(fs.existsSync(contribPath), 'CONTRIBUTING.md must exist');
const contrib = fs.readFileSync(contribPath, 'utf8');
assert(contrib.includes('Default-Deny'), 'CONTRIBUTING.md must mention Default-Deny');
assert(contrib.includes(`${EXPECTED_INVARIANTS}`), `CONTRIBUTING.md must mention ${EXPECTED_INVARIANTS} Section 24 invariants`);
assert(contrib.includes('Patch Jail'), 'CONTRIBUTING.md must mention Patch Jail');
assert(contrib.includes('0 external npm dependencies') || contrib.includes('zero external npm dependencies'), 'CONTRIBUTING.md must mention 0 external npm dependencies');

console.log(`✔ Documentation integrity gate PASSED! All documentation matches v${currentVersion} and baseline invariants.`);
