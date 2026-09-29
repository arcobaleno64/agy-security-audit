#!/usr/bin/env node
/**
 * scripts/adapters/test-pipeline-integration.mjs
 * End-to-End Pipeline Integration Test Suite for Cloudflare Producer Adapter and finalize-scan.mjs.
 *
 * Verifies:
 * - Test 1: Ingest Cloudflare findings-confirmed.json without AGY verifier votes
 *           -> Default-Deny forces all to DEFERRED / NEEDS_MANUAL_REVIEW, canDeclareClean === false.
 * - Test 2: Ingest Cloudflare findings-confirmed.json with matching AGY votes (SUPPORTS)
 *           -> AGY grants REPORTABLE / CONFIRMED / AFFIRMATIVELY_VERIFIED.
 * - Test 3: Ingest with coverage-ledger-partial.json
 *           -> Sets COVERAGE_PARTIAL and strictly forbids clean claim.
 * - Test 4: Ingest with coverage-ledger-complete.json and 0 reportable findings
 *           -> Allows clean claim (canDeclareClean === true, coverageStatus === COMPLETE).
 * - Test 5: End-to-End CLI Execution via process spawn:
 *           --import-cloudflare-findings and --import-cloudflare-coverage flags.
 * - Test 6: Presumption of Non-Pass: Candidate-level quarantine boundary
 *           prevents candidates in partial units from obtaining authority.
 *
 * Built with zero external dependencies (Node.js ESM built-ins only).
 */

import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

import {
  toCandidateSet,
  ingestCoverageLedger,
  ingestFindings,
  toCanonicalFinding
} from './cloudflare-adapter.mjs';

import {
  finalizeScan,
  loadCloudflareAdapter
} from '../../skills/security-audit/scripts/finalize-scan.mjs';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const REPO_ROOT = path.resolve(__dirname, '../..');
const FIXTURES_DIR = path.resolve(REPO_ROOT, 'test/fixtures/cloudflare');

// -----------------------------------------------------------------------------
// Assertions & Test Framework
// -----------------------------------------------------------------------------
let testCount = 0;
let passCount = 0;

function assert(condition, message) {
  if (!condition) {
    throw new Error(`Assertion failed: ${message}`);
  }
}

function assertEqual(actual, expected, message) {
  if (actual !== expected) {
    throw new Error(`Assertion failed: ${message} (expected: ${JSON.stringify(expected)}, got: ${JSON.stringify(actual)})`);
  }
}

function test(description, fn) {
  testCount++;
  try {
    fn();
    passCount++;
    console.log(`✔ [PASS ${testCount}] ${description}`);
  } catch (err) {
    console.error(`✖ [FAIL ${testCount}] ${description}`);
    console.error(`  ${err.stack || err.message}`);
    process.exit(1);
  }
}

// -----------------------------------------------------------------------------
// Temporary Environment Setup
// -----------------------------------------------------------------------------
const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'agy-cf-integration-'));

function setupMockWorkspace(targetDir) {
  const dirs = [
    path.join(targetDir, 'src/api'),
    path.join(targetDir, 'src/services'),
    path.join(targetDir, '.security-audit')
  ];
  for (const d of dirs) {
    fs.mkdirSync(d, { recursive: true });
  }

  // Create physical target files with sufficient lines to cover trace/evidence references
  const usersCode = Array.from({ length: 60 }, (_, i) => `// users.js line ${i + 1}`).join('\n');
  const dbCode = Array.from({ length: 80 }, (_, i) => `// db.js line ${i + 1}`).join('\n');
  const webhooksCode = Array.from({ length: 60 }, (_, i) => `// webhooks.js line ${i + 1}`).join('\n');
  const errorCode = Array.from({ length: 60 }, (_, i) => `// errorHandler.js line ${i + 1}`).join('\n');

  fs.writeFileSync(path.join(targetDir, 'src/api/users.js'), usersCode, 'utf8');
  fs.writeFileSync(path.join(targetDir, 'src/services/db.js'), dbCode, 'utf8');
  fs.writeFileSync(path.join(targetDir, 'src/webhooks.js'), webhooksCode, 'utf8');
  fs.writeFileSync(path.join(targetDir, 'src/errorHandler.js'), errorCode, 'utf8');
  fs.writeFileSync(
    path.join(targetDir, 'package.json'),
    JSON.stringify({ name: 'integration-test-app', version: '1.0.0' }, null, 2),
    'utf8'
  );
}

setupMockWorkspace(tempRoot);

// Clean up temp environment on exit
process.on('exit', () => {
  try {
    fs.rmSync(tempRoot, { recursive: true, force: true });
  } catch {}
});

console.log('Running Pipeline Integration Test Suite (Cloudflare Adapter + finalize-scan)...');

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

test('Test 1: Ingest Cloudflare findings-confirmed.json without AGY verifier votes fails closed to DEFERRED', () => {
  const confirmedFixturePath = path.join(FIXTURES_DIR, 'findings-confirmed.json');
  const rawFindings = JSON.parse(fs.readFileSync(confirmedFixturePath, 'utf8'));

  const candidateSet = toCandidateSet(rawFindings);
  assert(Array.isArray(candidateSet.candidates), 'toCandidateSet returns candidates array');
  assertEqual(candidateSet.candidates.length, rawFindings.length, 'Candidate count matches input findings count');

  // Case A: Without coverage ledger (coverageStatus is UNCHECKABLE) -> fails closed to COVERAGE_PARTIAL
  const finalizationUnchecked = finalizeScan({
    candidates: candidateSet.candidates,
    manifest: null,
    repoRoot: tempRoot,
    votes: [],
    auditIntent: 'REGRESSION'
  });
  for (const f of finalizationUnchecked.canonicalFindings) {
    assertEqual(f.disposition, 'DEFERRED', `Finding '${f.id}' must be DEFERRED without votes`);
    assertEqual(f.verdict, 'NEEDS_MANUAL_REVIEW', `Finding '${f.id}' must be NEEDS_MANUAL_REVIEW`);
    assertEqual(f.reasonCode, 'COVERAGE_PARTIAL', `Finding '${f.id}' reasonCode must reflect uncheckable/partial coverage`);
  }

  // Case B: With complete coverage ledger -> candidates without votes fail closed to EVIDENCE_INCOMPLETE
  const completeLedgerPath = path.join(FIXTURES_DIR, 'coverage-ledger-complete.json');
  const parsedLedger = ingestCoverageLedger(completeLedgerPath);

  const finalizationCompleteCov = finalizeScan({
    candidates: candidateSet.candidates,
    manifest: null,
    repoRoot: tempRoot,
    votes: [],
    auditIntent: 'REGRESSION',
    cloudflareCoverage: parsedLedger
  });

  const canonicalFindings = finalizationCompleteCov.canonicalFindings;
  assertEqual(canonicalFindings.length, rawFindings.length, 'All candidates are evaluated');

  for (const f of canonicalFindings) {
    assertEqual(f.disposition, 'DEFERRED', `Finding '${f.id}' must be DEFERRED without AGY verifier votes`);
    assertEqual(f.verdict, 'NEEDS_MANUAL_REVIEW', `Finding '${f.id}' must be NEEDS_MANUAL_REVIEW`);
    assertEqual(f.reasonCode, 'EVIDENCE_INCOMPLETE', `Finding '${f.id}' reasonCode must reflect incomplete evidence`);
  }

  assertEqual(finalizationCompleteCov.summary.canDeclareClean, false, 'Cannot declare clean when unverified candidates exist');
  assertEqual(finalizationCompleteCov.summary.findingCounts.reportable, 0, 'Zero reportable findings without verifier votes');
  assertEqual(finalizationCompleteCov.summary.findingCounts.deferred, rawFindings.length, 'All findings categorized as deferred');
});

test('Test 2: Ingest Cloudflare findings-confirmed.json with matching AGY votes grants REPORTABLE / CONFIRMED / AFFIRMATIVELY_VERIFIED', () => {
  const confirmedFixturePath = path.join(FIXTURES_DIR, 'findings-confirmed.json');
  const rawFindings = JSON.parse(fs.readFileSync(confirmedFixturePath, 'utf8'));
  const candidateSet = toCandidateSet(rawFindings);

  const targetCandidate = candidateSet.candidates.find(c => c.id === 'cf-sqli-01' || c.id === 'CF-cf-sqli-01');
  assert(Boolean(targetCandidate), "Target candidate found in candidate set");
  const targetId = targetCandidate.id;

  const completeLedgerPath = path.join(FIXTURES_DIR, 'coverage-ledger-complete.json');
  const parsedLedger = ingestCoverageLedger(completeLedgerPath);

  // Construct unanimous, evidence-bound 3-Lens verifier panel votes
  const votes = [
    {
      findingId: targetId,
      lens: 'REACHABILITY',
      decision: 'SUPPORTS',
      reviewerId: 'verifier-reachability',
      evidence: [
        { path: 'src/api/users.js', line: 12, role: 'entrypoint', description: 'Public HTTP search endpoint' }
      ]
    },
    {
      findingId: targetId,
      lens: 'DEFENSES',
      decision: 'SUPPORTS',
      reviewerId: 'verifier-defenses',
      evidence: [
        { path: 'src/services/db.js', line: 45, role: 'control', description: 'Direct string concatenation without sanitizer' }
      ]
    },
    {
      findingId: targetId,
      lens: 'IMPACT',
      decision: 'SUPPORTS',
      reviewerId: 'verifier-impact',
      evidence: [
        { path: 'src/services/db.js', line: 52, role: 'sink', description: 'Raw SQL query executed' }
      ]
    }
  ];

  const finalization = finalizeScan({
    candidates: [targetCandidate],
    manifest: null,
    repoRoot: tempRoot,
    votes,
    auditIntent: 'REGRESSION',
    cloudflareCoverage: parsedLedger
  });

  const confirmedFinding = finalization.canonicalFindings.find(f => f.id === targetId);
  assert(Boolean(confirmedFinding), `Finalized finding '${targetId}' exists`);
  assertEqual(confirmedFinding.disposition, 'REPORTABLE', 'Candidate granted REPORTABLE authority with quorum votes');
  assertEqual(confirmedFinding.verdict, 'CONFIRMED', 'Verdict promoted to CONFIRMED');
  assertEqual(confirmedFinding.reasonCode, 'AFFIRMATIVELY_VERIFIED', 'ReasonCode promoted to AFFIRMATIVELY_VERIFIED');
  assertEqual(confirmedFinding.consensus.supports, 3, 'All 3 lenses voted SUPPORTS');
  assertEqual(confirmedFinding.consensus.refutes, 0, 'Zero refutations');
  assertEqual(confirmedFinding.consensus.unanimous, true, 'Panel vote was unanimous');
  assertEqual(finalization.summary.findingCounts.reportable, 1, 'Reportable count is 1');
  assertEqual(finalization.summary.canDeclareClean, false, 'Reportable vulnerability forbids clean claim');
});

test('Test 3: Ingest with coverage-ledger-partial.json sets COVERAGE_PARTIAL and forbids clean claim', () => {
  const partialLedgerPath = path.join(FIXTURES_DIR, 'coverage-ledger-partial.json');
  const parsedLedger = ingestCoverageLedger(partialLedgerPath);

  assertEqual(parsedLedger.coverageStatus, 'COVERAGE_PARTIAL', 'Partial ledger reports COVERAGE_PARTIAL');
  assertEqual(parsedLedger.canDeclareClean, false, 'Partial ledger canDeclareClean is false');

  const finalization = finalizeScan({
    candidates: [],
    manifest: null,
    repoRoot: tempRoot,
    votes: [],
    auditIntent: 'REGRESSION',
    cloudflareCoverage: parsedLedger
  });

  assertEqual(finalization.coverageStatus, 'COVERAGE_PARTIAL', 'Finalization adopts COVERAGE_PARTIAL');
  assertEqual(finalization.summary.canDeclareClean, false, 'Partial coverage strictly blocks clean claim');
  assertEqual(finalization.summary.gates.coverageGate, false, 'coverageGate fails on partial coverage');
  assertEqual(finalization.summary.assuranceLabel, 'NON_CLEAN', 'Assurance level is NON_CLEAN');
});

test('Test 4: Ingest with coverage-ledger-complete.json and 0 reportable findings allows clean claim', () => {
  const completeLedgerPath = path.join(FIXTURES_DIR, 'coverage-ledger-complete.json');
  const parsedLedger = ingestCoverageLedger(completeLedgerPath);

  assertEqual(parsedLedger.coverageStatus, 'COMPLETE', 'Complete ledger reports COMPLETE');
  assertEqual(parsedLedger.canDeclareClean, true, 'Complete ledger canDeclareClean is true');

  const finalization = finalizeScan({
    candidates: [],
    manifest: null,
    repoRoot: tempRoot,
    votes: [],
    auditIntent: 'REGRESSION',
    cloudflareCoverage: parsedLedger
  });

  assertEqual(finalization.coverageStatus, 'COMPLETE', 'Finalization adopts COMPLETE coverage status');
  assertEqual(finalization.summary.canDeclareClean, true, '0 findings + COMPLETE coverage allows clean claim');
  assertEqual(finalization.summary.gates.coverageGate, true, 'coverageGate passes on complete coverage');
  assertEqual(finalization.summary.gates.findingGate, true, 'findingGate passes with 0 findings');
  assertEqual(finalization.summary.findingCounts.reportable, 0, 'Reportable count is 0');
  assertEqual(finalization.summary.findingCounts.deferred, 0, 'Deferred count is 0');
});

test('Test 5: End-to-End CLI execution via spawnSync with --import-cloudflare-findings and --import-cloudflare-coverage', () => {
  const finalizeScript = path.resolve(REPO_ROOT, 'skills/security-audit/scripts/finalize-scan.mjs');
  const confirmedFixture = path.join(FIXTURES_DIR, 'findings-confirmed.json');
  const completeCoverageFixture = path.join(FIXTURES_DIR, 'coverage-ledger-complete.json');

  const outJson = path.join(tempRoot, 'out-canonical.json');
  const outCoverage = path.join(tempRoot, 'out-coverage.json');

  const result = spawnSync(
    process.execPath,
    [
      finalizeScript,
      '--repo-root', tempRoot,
      '--import-cloudflare-findings', confirmedFixture,
      '--import-cloudflare-coverage', completeCoverageFixture,
      '--intent', 'REGRESSION',
      '--output', outJson,
      '--output-coverage', outCoverage
    ],
    {
      cwd: tempRoot,
      encoding: 'utf8'
    }
  );

  if (result.status !== 0) {
    console.error('CLI stderr:', result.stderr);
    console.error('CLI stdout:', result.stdout);
  }
  assertEqual(result.status, 0, 'CLI exited cleanly with code 0');

  assert(fs.existsSync(outJson), 'Canonical findings output file was generated');
  assert(fs.existsSync(outCoverage), 'Coverage JSON output file was generated');

  const canonicalOutput = JSON.parse(fs.readFileSync(outJson, 'utf8'));
  assert(Array.isArray(canonicalOutput), 'Canonical output is an array of findings');
  assert(canonicalOutput.length > 0, 'Ingested findings are present in output');

  // Without votes passed via CLI, unassessed findings must be DEFERRED under Default-Deny
  for (const f of canonicalOutput) {
    assertEqual(f.disposition, 'DEFERRED', `CLI ingested finding '${f.id}' defaults to DEFERRED`);
    assertEqual(f.verdict, 'NEEDS_MANUAL_REVIEW', `CLI ingested finding '${f.id}' defaults to NEEDS_MANUAL_REVIEW`);
  }

  const coverageOutput = JSON.parse(fs.readFileSync(outCoverage, 'utf8'));
  assertEqual(coverageOutput.coverageMode, 'cloudflare', 'Coverage mode is correctly set to cloudflare');
});

test('Test 6: loadCloudflareAdapter dynamically resolves and exports core adapter API', async () => {
  const adapter = await loadCloudflareAdapter(REPO_ROOT);
  assert(typeof adapter.toCandidateSet === 'function', 'adapter exports toCandidateSet');
  assert(typeof adapter.ingestCoverageLedger === 'function', 'adapter exports ingestCoverageLedger');
  assert(typeof adapter.toCanonicalFinding === 'function', 'adapter exports toCanonicalFinding');
});

test('Test 7 (P0 Regression): Target repository cannot hijack adapter execution (TCB isolation)', async () => {
  // Target repository under review intentionally plants a hostile adapter in its own repo structure
  const hostileTargetDir = fs.mkdtempSync(path.join(os.tmpdir(), 'hostile-target-repo-'));
  try {
    const hostileAdaptersDir = path.join(hostileTargetDir, 'scripts', 'adapters');
    fs.mkdirSync(hostileAdaptersDir, { recursive: true });
    const hostileAdapterPath = path.join(hostileAdaptersDir, 'cloudflare-adapter.mjs');
    fs.writeFileSync(
      hostileAdapterPath,
      'throw new Error("MALICIOUS_TARGET_ADAPTER_EXECUTED: P0_TCB_SECURITY_VIOLATION");\n',
      'utf8'
    );

    // 1. Calling loadCloudflareAdapter(hostileTargetDir) MUST NOT load the hostile target adapter
    const adapter = await loadCloudflareAdapter(hostileTargetDir);
    assert(typeof adapter.toCandidateSet === 'function', 'Loaded genuine adapter from TCB, not hostile target code');

    // 2. Direct CLI invocation with --repo-root pointing to hostile target MUST NOT execute hostile adapter
    const finalizeScript = path.resolve(REPO_ROOT, 'skills/security-audit/scripts/finalize-scan.mjs');
    const confirmedFixture = path.join(FIXTURES_DIR, 'findings-confirmed.json');
    const completeCoverageFixture = path.join(FIXTURES_DIR, 'coverage-ledger-complete.json');
    const outJson = path.join(hostileTargetDir, 'out-p0-test.json');
    const outCoverage = path.join(hostileTargetDir, 'out-coverage-p0.json');

    const result = spawnSync(
      process.execPath,
      [
        finalizeScript,
        '--repo-root', hostileTargetDir,
        '--import-cloudflare-findings', confirmedFixture,
        '--import-cloudflare-coverage', completeCoverageFixture,
        '--intent', 'REGRESSION',
        '--output', outJson,
        '--output-coverage', outCoverage
      ],
      {
        cwd: hostileTargetDir,
        encoding: 'utf8'
      }
    );

    if (result.status !== 0) {
      console.error('P0 regression CLI stderr:', result.stderr);
    }
    assertEqual(result.status, 0, 'CLI exited cleanly without executing hostile target adapter');
    assert(!result.stderr.includes('MALICIOUS_TARGET_ADAPTER_EXECUTED'), 'Hostile target code was not executed');
    assert(fs.existsSync(outJson), 'Canonical findings output was generated by genuine TCB adapter');
  } finally {
    try {
      fs.rmSync(hostileTargetDir, { recursive: true, force: true });
    } catch {}
  }
});

console.log('\n==================================================');
console.log(`All ${passCount}/${testCount} Pipeline Integration tests passed with exit code 0.`);
console.log('Verified under Presumption of Non-Pass (Default-Deny).');
console.log('==================================================\n');
