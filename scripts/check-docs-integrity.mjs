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

// 5. Track D Doctor contract
assert(pkg.scripts?.doctor === 'node scripts/doctor.mjs', 'package.json must expose npm run doctor');
assert(pkg.scripts?.['test:doctor'] === 'node scripts/test-doctor.mjs', 'package.json must expose npm run test:doctor');
const doctorPath = path.join(REPO_ROOT, 'scripts', 'doctor.mjs');
const doctorTestPath = path.join(REPO_ROOT, 'scripts', 'test-doctor.mjs');
const doctorSchemaPath = path.join(REPO_ROOT, 'schemas', 'doctor-report.schema.json');
const reproductionReadmePath = path.join(REPO_ROOT, 'docs', 'reproduction', 'README.md');
assert(fs.existsSync(doctorPath), 'scripts/doctor.mjs must exist');
assert(fs.existsSync(doctorTestPath), 'scripts/test-doctor.mjs must exist');
assert(fs.existsSync(doctorSchemaPath), 'schemas/doctor-report.schema.json must exist');
assert(fs.existsSync(reproductionReadmePath), 'docs/reproduction/README.md must exist');
const doctorSchema = JSON.parse(fs.readFileSync(doctorSchemaPath, 'utf8'));
assert(
  doctorSchema.$id === 'https://antigravity.google/schemas/security-audit/doctor-report.schema.json',
  'doctor report schema $id must remain canonical'
);
const reproductionReadme = fs.readFileSync(reproductionReadmePath, 'utf8');
assert(reproductionReadme.includes('npm run doctor'), 'reproduction README must document npm run doctor');
assert(reproductionReadme.includes('npm run doctor -- --json'), 'reproduction README must document Doctor JSON mode');
assert(reproductionReadme.includes('UNVERIFIABLE'), 'reproduction README must preserve honest UNVERIFIABLE semantics');

// 6. Track D Tier 1 Reproduction contract
assert(pkg.scripts?.['check:reproducibility'] === 'node scripts/run-reproducibility-check.mjs', 'package.json must expose npm run check:reproducibility');
assert(pkg.scripts?.['test:reproducibility'] === 'node scripts/test-reproducibility.mjs', 'package.json must expose npm run test:reproducibility');
const reproScriptPath = path.join(REPO_ROOT, 'scripts', 'run-reproducibility-check.mjs');
const reproTestPath = path.join(REPO_ROOT, 'scripts', 'test-reproducibility.mjs');
const reproSchemaPath = path.join(REPO_ROOT, 'schemas', 'reproduction-record.schema.json');
assert(fs.existsSync(reproScriptPath), 'scripts/run-reproducibility-check.mjs must exist');
assert(fs.existsSync(reproTestPath), 'scripts/test-reproducibility.mjs must exist');
assert(fs.existsSync(reproSchemaPath), 'schemas/reproduction-record.schema.json must exist');
const reproSchema = JSON.parse(fs.readFileSync(reproSchemaPath, 'utf8'));
assert(
  reproSchema.$id === 'https://antigravity.google/schemas/security-audit/reproduction-record.schema.json',
  'reproduction record schema $id must remain canonical'
);
assert(reproductionReadme.includes('npm run check:reproducibility'), 'reproduction README must document npm run check:reproducibility');
assert(reproductionReadme.includes('npm run test:reproducibility'), 'reproduction README must document npm run test:reproducibility');
assert(reproductionReadme.includes('Maintainer Intervention Degradation Rule'), 'reproduction README must document maintainer intervention degradation');
assert(
  reproductionReadme.includes('> **Status**: REPRODUCIBILITY_READY / D-AC-10 OPEN'),
  'reproduction README status must be REPRODUCIBILITY_READY / D-AC-10 OPEN'
);
assert(
  new RegExp(`> \\*\\*Frozen Baseline\\*\\*: \`agy-security-audit v${currentVersion.replace(/\\./g, '\\\\.')}\``).test(reproductionReadme),
  `reproduction README frozen baseline must match current version v${currentVersion}`
);
assert(
  !reproductionReadme.includes('(14 tests)'),
  'reproduction README must not retain stale hardcoded (14 tests) count'
);

// 7. Track D Tier 2 Micro-Corpus contract
assert(pkg.scripts?.['check:micro-corpus'] === 'node scripts/run-micro-corpus.mjs', 'package.json must expose npm run check:micro-corpus');
assert(pkg.scripts?.['test:micro-corpus'] === 'node scripts/test-micro-corpus.mjs', 'package.json must expose npm run test:micro-corpus');
const microScriptPath = path.join(REPO_ROOT, 'scripts', 'run-micro-corpus.mjs');
const microTestPath = path.join(REPO_ROOT, 'scripts', 'test-micro-corpus.mjs');
const microGtPath = path.join(REPO_ROOT, 'evals', 'micro-corpus', 'ground-truth.json');
assert(fs.existsSync(microScriptPath), 'scripts/run-micro-corpus.mjs must exist');
assert(fs.existsSync(microTestPath), 'scripts/test-micro-corpus.mjs must exist');
assert(fs.existsSync(microGtPath), 'evals/micro-corpus/ground-truth.json must exist');
assert(fs.existsSync(path.join(REPO_ROOT, 'evals', 'micro-corpus', 'quickstart-vulnerable', 'index.js')), 'quickstart-vulnerable fixture must exist');
assert(fs.existsSync(path.join(REPO_ROOT, 'evals', 'micro-corpus', 'quickstart-safe', 'index.js')), 'quickstart-safe fixture must exist');
assert(fs.existsSync(path.join(REPO_ROOT, 'evals', 'micro-corpus', 'quickstart-disputed', 'index.js')), 'quickstart-disputed fixture must exist');
assert(reproductionReadme.includes('npm run check:micro-corpus'), 'reproduction README must document npm run check:micro-corpus');
assert(reproductionReadme.includes('npm run test:micro-corpus'), 'reproduction README must document npm run test:micro-corpus');
assert(reproductionReadme.includes('--tier2'), 'reproduction README must document --tier2 flag');

// 8. Track D Phase D3 Operator Metrics, Release Verification & Platform Compatibility contract
assert(pkg.scripts?.['test:operator-metrics'] === 'node scripts/test-operator-metrics.mjs', 'package.json must expose npm run test:operator-metrics');
const operatorScriptPath = path.join(REPO_ROOT, 'scripts', 'operator-metrics.mjs');
const operatorTestPath = path.join(REPO_ROOT, 'scripts', 'test-operator-metrics.mjs');
const operatorSchemaPath = path.join(REPO_ROOT, 'schemas', 'operator-metrics.schema.json');
const verifyReleasePath = path.join(REPO_ROOT, 'docs', 'verify-release.md');
const platformCompatPath = path.join(REPO_ROOT, 'docs', 'reproduction', 'platform-compatibility.md');

assert(fs.existsSync(operatorScriptPath), 'scripts/operator-metrics.mjs must exist');
assert(fs.existsSync(operatorTestPath), 'scripts/test-operator-metrics.mjs must exist');
assert(fs.existsSync(operatorSchemaPath), 'schemas/operator-metrics.schema.json must exist');
assert(fs.existsSync(verifyReleasePath), 'docs/verify-release.md must exist');
assert(fs.existsSync(platformCompatPath), 'docs/reproduction/platform-compatibility.md must exist');

const operatorSchema = JSON.parse(fs.readFileSync(operatorSchemaPath, 'utf8'));
assert(
  operatorSchema.$id === 'https://antigravity.google/schemas/security-audit/operator-metrics.schema.json',
  'operator metrics schema $id must remain canonical'
);

const verifyRelease = fs.readFileSync(verifyReleasePath, 'utf8');
assert(verifyRelease.includes('gh attestation verify'), 'verify-release.md must document gh attestation verify');
assert(verifyRelease.includes('SHA256SUMS.txt'), 'verify-release.md must document SHA256SUMS.txt');
assert(verifyRelease.includes('--deny-self-hosted-runners'), 'verify-release.md must document --deny-self-hosted-runners');

const platformCompat = fs.readFileSync(platformCompatPath, 'utf8');
assert(platformCompat.includes('LIVE_RUNTIME_VALIDATED'), 'platform-compatibility.md must document LIVE_RUNTIME_VALIDATED');
assert(platformCompat.includes('CI_TESTED'), 'platform-compatibility.md must document CI_TESTED');
assert(platformCompat.includes('DECLARED'), 'platform-compatibility.md must document DECLARED');
assert(platformCompat.includes('UNKNOWN'), 'platform-compatibility.md must document UNKNOWN');
assert(platformCompat.includes('UNSUPPORTED'), 'platform-compatibility.md must document UNSUPPORTED');

assert(reproductionReadme.includes('Phase D3: Operator Readiness & Friction Observability'), 'reproduction README must document Phase D3');
assert(reproductionReadme.includes('npm run test:operator-metrics'), 'reproduction README must document npm run test:operator-metrics');
assert(reproductionReadme.includes('platform-compatibility.md'), 'reproduction README must link platform-compatibility.md');
assert(reproductionReadme.includes('docs/verify-release.md'), 'reproduction README must link docs/verify-release.md');

console.log(`✔ Documentation integrity gate PASSED! All documentation matches v${currentVersion} and baseline invariants.`);

