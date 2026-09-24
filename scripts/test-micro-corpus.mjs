#!/usr/bin/env node
/**
 * test-micro-corpus.mjs
 * Deterministic policy and regression test suite for Track D Phase D2 (Tier 2 Micro-Corpus).
 *
 * Verifies:
 * - RFC 0002 §5.2, §6, and §8 micro-corpus ground truth contract.
 * - Tri-control fixture presence and physical evidence integrity:
 *   1. quickstart-vulnerable (CWE-22 path traversal)
 *   2. quickstart-safe (CWE-22 defense containment barrier)
 *   3. quickstart-disputed (CWE-918 loopback SSRF architectural boundary)
 * - Deterministic synthetic evaluation produces expected confirmation states.
 * - Stream digest integrity (64-char SHA-256).
 * - Zero external npm dependencies and zero network/telemetry dependencies.
 */

import fs from 'node:fs';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import {
  DEFAULT_REPO_ROOT,
  MICRO_CORPUS_GROUND_TRUTH,
  computeDigest,
  evaluateSyntheticMicroCorpus,
  executeTier2Reproduction
} from './run-micro-corpus.mjs';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const REPO_ROOT = path.resolve(__dirname, '..');

function assert(condition, message) {
  if (!condition) {
    throw new Error(`ASSERTION_FAILED: ${message}`);
  }
}

function assertEqual(actual, expected, message) {
  assert(
    actual === expected,
    `${message}: expected ${JSON.stringify(expected)}, got ${JSON.stringify(actual)}`
  );
}

let passed = 0;
function test(name, fn) {
  fn();
  passed++;
  console.log(`PASS ${passed}: ${name}`);
}

// Test 1: Ground truth manifest integrity
test('micro-corpus ground truth manifest conforms to schema and defines 3 controls', () => {
  const gtPath = path.join(REPO_ROOT, MICRO_CORPUS_GROUND_TRUTH);
  assert(fs.existsSync(gtPath), 'ground-truth.json must exist');
  const manifest = JSON.parse(fs.readFileSync(gtPath, 'utf8'));
  assert(Array.isArray(manifest) && manifest.length === 3, 'manifest must define exactly 3 controls');

  const ids = manifest.map(m => m.id);
  assert(ids.includes('MC-VULN'), 'must include MC-VULN');
  assert(ids.includes('MC-SAFE'), 'must include MC-SAFE');
  assert(ids.includes('MC-DISPUTE'), 'must include MC-DISPUTE');

  for (const item of manifest) {
    assert(typeof item.id === 'string' && item.id.length > 0, 'valid id');
    assert(typeof item.name === 'string' && item.name.length > 0, 'valid name');
    assert(typeof item.cwe === 'string' && item.cwe.startsWith('CWE-'), 'valid CWE');
    assert(typeof item.targetFile === 'string' && item.targetFile.length > 0, 'valid targetFile');
    assert(['VULNERABLE', 'SAFE', 'DISPUTED'].includes(item.expectedVerdict), 'valid expectedVerdict');
    assert(typeof item.controlType === 'string', 'valid controlType');
    assert(typeof item.expectedResultState === 'string', 'valid expectedResultState');
  }
});

// Test 2: Physical fixture presence & syntax integrity
test('all micro-corpus fixtures exist and pass Node.js syntax checks', () => {
  const fixtures = [
    'evals/micro-corpus/quickstart-vulnerable/index.js',
    'evals/micro-corpus/quickstart-safe/index.js',
    'evals/micro-corpus/quickstart-disputed/index.js'
  ];

  for (const f of fixtures) {
    const fullPath = path.join(REPO_ROOT, f);
    assert(fs.existsSync(fullPath), `fixture must exist: ${f}`);
    const check = spawnSync(process.execPath, ['--check', fullPath], { encoding: 'utf8' });
    assertEqual(check.status, 0, `Node syntax check for ${f}`);
  }
});

// Test 3: Vulnerable fixture contains documented CWE-22 flaw
test('quickstart-vulnerable contains unmitigated path traversal pattern', () => {
  const vulnPath = path.join(REPO_ROOT, 'evals/micro-corpus/quickstart-vulnerable/index.js');
  const code = fs.readFileSync(vulnPath, 'utf8');
  assert(/path\.join\s*\(\s*publicDir\s*,\s*userPath\s*\)/.test(code), 'must contain direct path.join');
  assert(/fs\.readFileSync/.test(code), 'must contain readFileSync sink');
  assert(!code.includes('path.relative'), 'must not contain containment check');
});

// Test 4: Safe fixture contains documented defense barrier
test('quickstart-safe contains path containment defense barrier', () => {
  const safePath = path.join(REPO_ROOT, 'evals/micro-corpus/quickstart-safe/index.js');
  const code = fs.readFileSync(safePath, 'utf8');
  assert(/path\.relative/.test(code), 'must contain path.relative boundary check');
  assert(/relative\.startsWith\s*\(\s*['"]\.\.['"]\s*\)/.test(code), 'must reject escape via ..');
  assert(code.includes('ACCESS_DENIED'), 'must throw access denied on violation');
});

// Test 5: Disputed fixture enforces loopback restriction
test('quickstart-disputed restricts destinations strictly to loopback addresses', () => {
  const dispPath = path.join(REPO_ROOT, 'evals/micro-corpus/quickstart-disputed/index.js');
  const code = fs.readFileSync(dispPath, 'utf8');
  assert(code.includes('ALLOWED_LOOPBACK_HOSTS'), 'must define loopback host set');
  assert(code.includes('127.0.0.1') && code.includes('localhost'), 'must include standard loopback hosts');
  assert(code.includes('SECURITY_VIOLATION'), 'must reject non-loopback destinations');
});

// Test 6: Deterministic synthetic evaluation produces expected confirmation states
test('evaluateSyntheticMicroCorpus succeeds with all 3 control states confirmed', () => {
  const result = evaluateSyntheticMicroCorpus(REPO_ROOT);
  assertEqual(result.status, 'PASS', 'synthetic status must be PASS');
  assertEqual(result.vulnerableControl, 'TRUE_POSITIVE_CONFIRMED', 'vulnerable control confirmation');
  assertEqual(result.safeControl, 'FALSE_POSITIVE_SUPPRESSED', 'safe control confirmation');
  assertEqual(result.disputeControl, 'ORACLE_DISPUTE_RECONCILED', 'dispute control confirmation');
  assert(/^[0-9a-f]{64}$/.test(result.streamDigest), 'streamDigest must be 64-character SHA-256 hex');
  assert(typeof result.rawStream === 'string' && result.rawStream.length > 0, 'rawStream must be captured');
});

// Test 7: CLI dry-run / mock integration
test('run-micro-corpus.mjs --mock --json outputs schema-compliant tier2Results', () => {
  const res = spawnSync(process.execPath, [
    path.join(REPO_ROOT, 'scripts', 'run-micro-corpus.mjs'),
    '--mock',
    '--json'
  ], {
    cwd: REPO_ROOT,
    encoding: 'utf8'
  });
  assertEqual(res.status, 0, 'CLI exit code must be 0');
  const parsed = JSON.parse(res.stdout);
  assertEqual(parsed.status, 'PASS', 'mock status must be PASS');
  assertEqual(parsed.vulnerableControl, 'TRUE_POSITIVE_CONFIRMED', 'vulnerable control');
  assertEqual(parsed.safeControl, 'FALSE_POSITIVE_SUPPRESSED', 'safe control');
  assertEqual(parsed.disputeControl, 'ORACLE_DISPUTE_RECONCILED', 'dispute control');
  assert(/^[0-9a-f]{64}$/.test(parsed.streamDigest), 'valid streamDigest');
});

// Test 8: Fail-honest behavior when AGY is not available
test('executeTier2Reproduction fail-honestly marks SKIPPED without claiming fake PASS when AGY missing', () => {
  const mockDoctorMissingAgy = {
    checks: [
      { id: 'agy', status: 'UNSUPPORTED' }
    ]
  };
  const result = executeTier2Reproduction({
    repoRoot: REPO_ROOT,
    doctorReport: mockDoctorMissingAgy
  });
  assertEqual(result.status, 'SKIPPED', 'missing AGY must yield SKIPPED tier2 status');
  assertEqual(result.vulnerableControl, null, 'skipped vulnerableControl must be null');
  assertEqual(result.safeControl, null, 'skipped safeControl must be null');
  assertEqual(result.disputeControl, null, 'skipped disputeControl must be null');
  assertEqual(result.streamDigest, null, 'skipped streamDigest must be null');
});

// Test 9: Zero external dependencies & zero network imports
test('run-micro-corpus.mjs contains no network or external telemetry imports', () => {
  const scriptPath = path.join(REPO_ROOT, 'scripts', 'run-micro-corpus.mjs');
  const content = fs.readFileSync(scriptPath, 'utf8');
  for (const forbidden of ['node:http', 'node:https', 'node:net', 'fetch(', 'curl ', 'wget ']) {
    assert(!content.includes(forbidden), `run-micro-corpus.mjs must not contain ${forbidden}`);
  }
});

// Test 10: Stream digest computation is deterministic
test('computeDigest is deterministic across calls', () => {
  const sample = '{"id":"MC-VULN","status":"PASS"}\n';
  const h1 = computeDigest(sample);
  const h2 = computeDigest(sample);
  assertEqual(h1, h2, 'computeDigest must be deterministic');
  assert(/^[0-9a-f]{64}$/.test(h1), 'computeDigest must produce 64-char hex');
});

console.log(`\nAll Micro-Corpus policy tests passed (${passed}/${passed}).`);
