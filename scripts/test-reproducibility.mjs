#!/usr/bin/env node
/**
 * test-reproducibility.mjs
 * Deterministic policy and adversarial test suite for Track D Phase D1.
 *
 * Verifies:
 * - RFC 0002 §8 and §9 reproduction record schema compliance.
 * - Maintainer Intervention Degradation Rule: maintainer assistance strictly
 *   prevents INDEPENDENT_OPERATOR_REPRODUCTION and EXTERNAL_SYSTEM_REPLICATION claims.
 * - Fail-honest defaults, chronological boundaries, duplicate check rejection.
 * - Zero network/telemetry dependencies.
 *
 * Zero external npm dependencies (pure Node.js built-ins).
 */

import fs from 'node:fs';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import {
  DEFAULT_REPO_ROOT,
  REPRODUCTION_SCHEMA_ID,
  REPRODUCTION_SCHEMA_VERSION,
  RELEASE_ASSET_DIGEST_SOURCES,
  buildReproductionRecord,
  resolveReleaseAssetBinding,
  validateReproductionRecordShape
} from './run-reproducibility-check.mjs';

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

function makeValidBaselineRecord() {
  return {
    $schema: REPRODUCTION_SCHEMA_ID,
    schemaVersion: '1.0.0',
    projectVersion: '1.8.1',
    sourceCommit: '8af4bca5cdfef89c93649c03a70d43767875ffb7',
    releaseTag: 'v1.8.1',
    releaseAssetName: 'agy-security-audit-v1.8.1.zip',
    releaseAssetDigest: '2a0ece157b0264fc2cfd2efc8d87de78696ffe3a3d79fd01bfa8f83153ee04da',
    releaseAssetDigestSource: 'LOCAL_MANIFEST',
    operatorClass: 'INDEPENDENT_OPERATOR',
    reproductionClassification: 'INDEPENDENT_OPERATOR_REPRODUCTION',
    maintainerAssistance: false,
    executionMode: 'SOURCE_CHECKOUT',
    environment: {
      os: 'linux',
      arch: 'x64',
      nodeVersion: '20.11.1',
      gitVersion: '2.50.1',
      agyVersion: null,
      ghVersion: '2.50.0'
    },
    tier1Results: {
      status: 'PASS',
      section24Invariants: '121/121',
      provenancePolicy: '19/19',
      docsIntegrity: 'PASS',
      releaseInvariants: '62_SPECS_40_INVARIANTS_0_DEPS',
      doctorStatus: 'READY',
      steps: [
        { id: 'doctor-preflight', name: 'Doctor Preflight', status: 'PASS', durationMs: 120, details: 'READY' },
        { id: 'sarif-suite', name: 'Section 24 Invariant Suite', status: 'PASS', durationMs: 5400, details: '121/121' }
      ]
    },
    tier2Results: null,
    startedAt: '2026-09-24T08:00:00.000Z',
    completedAt: '2026-09-24T08:01:00.000Z',
    overallVerdict: 'PASS',
    notes: ['Autonomous execution on clean Ubuntu container.']
  };
}

// Test 1: Baseline valid record
test('validateReproductionRecordShape accepts a valid baseline record', () => {
  const record = makeValidBaselineRecord();
  assert(validateReproductionRecordShape(record), 'valid record must pass validation');
});

// Test 2: Required top-level keys
test('validateReproductionRecordShape rejects missing required top-level keys', () => {
  const requiredKeys = [
    '$schema', 'schemaVersion', 'projectVersion', 'sourceCommit', 'releaseTag',
    'releaseAssetName', 'releaseAssetDigest', 'releaseAssetDigestSource',
    'operatorClass', 'reproductionClassification',
    'maintainerAssistance', 'executionMode', 'environment', 'tier1Results',
    'startedAt', 'completedAt', 'overallVerdict'
  ];
  for (const k of requiredKeys) {
    const record = makeValidBaselineRecord();
    delete record[k];
    assert(!validateReproductionRecordShape(record), `missing ${k} must fail validation`);
  }
});

// Test 3: Rejection of additional unknown properties
test('validateReproductionRecordShape enforces additionalProperties=false across all objects', () => {
  const rec1 = makeValidBaselineRecord();
  rec1.unknownTopProperty = true;
  assert(!validateReproductionRecordShape(rec1), 'unknown top-level property must fail');

  const rec2 = makeValidBaselineRecord();
  rec2.environment.unknownEnvProp = 'x';
  assert(!validateReproductionRecordShape(rec2), 'unknown environment property must fail');

  const rec3 = makeValidBaselineRecord();
  rec3.tier1Results.unknownTier1Prop = 'x';
  assert(!validateReproductionRecordShape(rec3), 'unknown tier1Results property must fail');

  const rec4 = makeValidBaselineRecord();
  rec4.tier1Results.steps[0].unknownStepProp = 123;
  assert(!validateReproductionRecordShape(rec4), 'unknown step property must fail');
});

// Test 4: Schema version and identifier validation
test('validateReproductionRecordShape validates schema, commit, and digest syntax', () => {
  const rec1 = makeValidBaselineRecord();
  rec1.$schema = 'https://malicious.example.com/schema.json';
  assert(!validateReproductionRecordShape(rec1), 'invalid $schema must fail');

  const rec2 = makeValidBaselineRecord();
  rec2.schemaVersion = '2.0.0';
  assert(!validateReproductionRecordShape(rec2), 'schemaVersion major 2 must fail for v1.x schema');

  const rec3 = makeValidBaselineRecord();
  rec3.sourceCommit = 'not-a-40-char-hex';
  assert(!validateReproductionRecordShape(rec3), 'malformed sourceCommit must fail');

  const rec4 = makeValidBaselineRecord();
  rec4.releaseTag = '1.8.1'; // missing 'v' prefix
  assert(!validateReproductionRecordShape(rec4), 'releaseTag without v prefix must fail');

  const rec5 = makeValidBaselineRecord();
  rec5.releaseAssetDigest = 'shortdigest';
  assert(!validateReproductionRecordShape(rec5), 'non-64-char releaseAssetDigest must fail');

  const rec6 = makeValidBaselineRecord();
  rec6.releaseAssetName = 'bad asset name with spaces.zip';
  assert(!validateReproductionRecordShape(rec6), 'invalid releaseAssetName must fail');

  const rec7 = makeValidBaselineRecord();
  rec7.releaseAssetDigest = 'UNVERIFIABLE';
  rec7.releaseAssetDigestSource = 'UNVERIFIABLE';
  assert(validateReproductionRecordShape(rec7), 'UNVERIFIABLE digest and source must be accepted');
});

// Test 5: Enum constraints
test('validateReproductionRecordShape rejects unsupported enums and mismatching digest sources', () => {
  const rec1 = makeValidBaselineRecord();
  rec1.operatorClass = 'UNKNOWN_OPERATOR';
  assert(!validateReproductionRecordShape(rec1), 'invalid operatorClass must fail');

  const rec2 = makeValidBaselineRecord();
  rec2.reproductionClassification = 'ARBITRARY_REPLAY';
  assert(!validateReproductionRecordShape(rec2), 'invalid reproductionClassification must fail');

  const rec3 = makeValidBaselineRecord();
  rec3.executionMode = 'CONTAINER_VOLUME';
  assert(!validateReproductionRecordShape(rec3), 'invalid executionMode must fail');

  const rec4 = makeValidBaselineRecord();
  rec4.overallVerdict = 'ALMOST_PASSED';
  assert(!validateReproductionRecordShape(rec4), 'invalid overallVerdict must fail');

  const rec5 = makeValidBaselineRecord();
  rec5.tier1Results.status = 'DEGRADED'; // tier1Results.status must be PASS/FAIL/UNVERIFIABLE
  assert(!validateReproductionRecordShape(rec5), 'invalid tier1Results.status must fail');

  const rec6 = makeValidBaselineRecord();
  rec6.tier1Results.steps[0].status = 'UNVERIFIABLE'; // step status must be PASS/FAIL/SKIPPED
  assert(!validateReproductionRecordShape(rec6), 'invalid step status must fail');

  const rec7 = makeValidBaselineRecord();
  rec7.releaseAssetDigestSource = 'UNKNOWN_SOURCE';
  assert(!validateReproductionRecordShape(rec7), 'invalid releaseAssetDigestSource must fail');

  const rec8 = makeValidBaselineRecord();
  rec8.releaseAssetDigest = 'UNVERIFIABLE';
  rec8.releaseAssetDigestSource = 'USER_VERIFIED';
  assert(!validateReproductionRecordShape(rec8), 'UNVERIFIABLE digest with non-UNVERIFIABLE source must fail');

  const rec9 = makeValidBaselineRecord();
  rec9.releaseAssetDigest = '2a0ece157b0264fc2cfd2efc8d87de78696ffe3a3d79fd01bfa8f83153ee04da';
  rec9.releaseAssetDigestSource = 'UNVERIFIABLE';
  assert(!validateReproductionRecordShape(rec9), 'hex digest with UNVERIFIABLE source must fail');
});

// Test 6: Maintainer Intervention Invariant (Validator Level)
test('Maintainer Intervention Invariant: assistance strictly prevents independent reproduction claims', () => {
  const rec1 = makeValidBaselineRecord();
  rec1.maintainerAssistance = true;
  rec1.reproductionClassification = 'INDEPENDENT_OPERATOR_REPRODUCTION';
  assert(!validateReproductionRecordShape(rec1), 'assisted run cannot claim INDEPENDENT_OPERATOR_REPRODUCTION');

  const rec2 = makeValidBaselineRecord();
  rec2.maintainerAssistance = true;
  rec2.reproductionClassification = 'EXTERNAL_SYSTEM_REPLICATION';
  assert(!validateReproductionRecordShape(rec2), 'assisted run cannot claim EXTERNAL_SYSTEM_REPLICATION');

  // But assisted run CAN claim INDEPENDENT_ENVIRONMENT_REPLAY or SELF_REPLAY
  const rec3 = makeValidBaselineRecord();
  rec3.maintainerAssistance = true;
  rec3.reproductionClassification = 'INDEPENDENT_ENVIRONMENT_REPLAY';
  assert(validateReproductionRecordShape(rec3), 'assisted run can claim INDEPENDENT_ENVIRONMENT_REPLAY');

  const rec4 = makeValidBaselineRecord();
  rec4.maintainerAssistance = true;
  rec4.reproductionClassification = 'SELF_REPLAY';
  assert(validateReproductionRecordShape(rec4), 'assisted run can claim SELF_REPLAY');
});

// Test 7: Maintainer Intervention Invariant (Builder Level Automatic Degradation)
test('buildReproductionRecord automatically degrades classification upon maintainer assistance', () => {
  const mockTier1 = {
    status: 'PASS',
    section24Invariants: '121/121',
    steps: [{ id: 'test', name: 'Test', status: 'PASS', durationMs: 10 }]
  };

  // Autonomous case
  const recordUnassisted = buildReproductionRecord(mockTier1, {
    operatorClass: 'INDEPENDENT_OPERATOR',
    maintainerAssistance: false
  });
  assertEqual(recordUnassisted.reproductionClassification, 'INDEPENDENT_OPERATOR_REPRODUCTION', 'unassisted classification');
  assertEqual(recordUnassisted.maintainerAssistance, false, 'unassisted flag');

  // Assisted case
  const recordAssisted = buildReproductionRecord(mockTier1, {
    operatorClass: 'INDEPENDENT_OPERATOR',
    maintainerAssistance: true
  });
  assertEqual(recordAssisted.reproductionClassification, 'INDEPENDENT_ENVIRONMENT_REPLAY', 'assisted must degrade to replay');
  assertEqual(recordAssisted.maintainerAssistance, true, 'assisted flag must be true');
  assert(
    recordAssisted.notes.some(n => n.includes('Maintainer assistance occurred')),
    'explanatory degradation note must be added'
  );
  assert(validateReproductionRecordShape(recordAssisted), 'built assisted record must satisfy shape validation');
});

// Test 8: Timestamp consistency
test('validateReproductionRecordShape rejects chronological violations', () => {
  const rec1 = makeValidBaselineRecord();
  rec1.startedAt = 'invalid-date';
  assert(!validateReproductionRecordShape(rec1), 'invalid startedAt must fail');

  const rec2 = makeValidBaselineRecord();
  rec2.completedAt = 'invalid-date';
  assert(!validateReproductionRecordShape(rec2), 'invalid completedAt must fail');

  const rec3 = makeValidBaselineRecord();
  rec3.startedAt = '2026-09-24T08:05:00.000Z';
  rec3.completedAt = '2026-09-24T08:00:00.000Z'; // completed before started!
  assert(!validateReproductionRecordShape(rec3), 'completedAt before startedAt must fail');
});

// Test 9: Step ID uniqueness and non-negative duration
test('validateReproductionRecordShape rejects negative durations and duplicate step IDs', () => {
  const rec1 = makeValidBaselineRecord();
  rec1.tier1Results.steps[0].durationMs = -5;
  assert(!validateReproductionRecordShape(rec1), 'negative duration must fail');

  const rec2 = makeValidBaselineRecord();
  rec2.tier1Results.steps.push({ ...rec2.tier1Results.steps[0] }); // duplicate id
  assert(!validateReproductionRecordShape(rec2), 'duplicate step ID must fail');
});

// Test 10: Optional tier2Results validation
test('validateReproductionRecordShape validates optional tier2Results', () => {
  const rec1 = makeValidBaselineRecord();
  rec1.tier2Results = {
    status: 'PASS',
    vulnerableControl: 'DETECTED',
    safeControl: 'REJECTED',
    disputeControl: 'FLAGGED',
    streamDigest: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
  };
  assert(validateReproductionRecordShape(rec1), 'valid tier2Results must pass');

  const rec2 = makeValidBaselineRecord();
  rec2.tier2Results = {
    status: 'READY' // invalid status for tier2Results (must be PASS/FAIL/SKIPPED/UNVERIFIABLE)
  };
  assert(!validateReproductionRecordShape(rec2), 'invalid tier2Results status must fail');

  const rec3 = makeValidBaselineRecord();
  rec3.tier2Results = {
    status: 'PASS',
    unexpectedField: 42
  };
  assert(!validateReproductionRecordShape(rec3), 'extra field in tier2Results must fail');
});

// Test 11: Schema JSON file consistency
test('reproduction record JSON schema matches canonical URI and definitions', () => {
  const schemaPath = path.join(REPO_ROOT, 'schemas', 'reproduction-record.schema.json');
  assert(fs.existsSync(schemaPath), 'reproduction-record.schema.json must exist');
  const schema = JSON.parse(fs.readFileSync(schemaPath, 'utf8'));

  assertEqual(schema.$id, REPRODUCTION_SCHEMA_ID, 'schema $id matches constant');
  assertEqual(schema.title, 'ReproductionRecord', 'schema title');
  assertEqual(schema.additionalProperties, false, 'root additionalProperties must be false');
  assert(schema.required.includes('maintainerAssistance'), 'maintainerAssistance must be required');
  assert(schema.required.includes('reproductionClassification'), 'reproductionClassification must be required');
});

// Test 12: Zero-dependency & hermetic execution invariant
test('reproduction harness has zero network or external telemetry dependencies', () => {
  const scriptPath = path.join(REPO_ROOT, 'scripts', 'run-reproducibility-check.mjs');
  const content = fs.readFileSync(scriptPath, 'utf8');
  for (const forbidden of ['node:http', 'node:https', 'node:net', 'fetch(', 'curl ', 'wget ']) {
    assert(!content.includes(forbidden), `run-reproducibility-check.mjs must not contain ${forbidden}`);
  }
});

// Test 13: CLI dry-run integration with JSON output
test('run-reproducibility-check.mjs --dry-run --json emits valid reproduction record', () => {
  const res = spawnSync(process.execPath, [
    path.join(REPO_ROOT, 'scripts', 'run-reproducibility-check.mjs'),
    '--dry-run',
    '--json'
  ], {
    cwd: REPO_ROOT,
    encoding: 'utf8'
  });
  assertEqual(res.status, 0, 'CLI exit code must be 0');
  const parsed = JSON.parse(res.stdout);
  assert(validateReproductionRecordShape(parsed), 'CLI emitted JSON must satisfy shape validation');
  assertEqual(parsed.overallVerdict, 'PASS', 'dry-run overall verdict');
});

// Test 14: CLI dry-run integration with --assisted
test('run-reproducibility-check.mjs --dry-run --json --assisted degrades classification', () => {
  const res = spawnSync(process.execPath, [
    path.join(REPO_ROOT, 'scripts', 'run-reproducibility-check.mjs'),
    '--dry-run',
    '--json',
    '--assisted'
  ], {
    cwd: REPO_ROOT,
    encoding: 'utf8'
  });
  assertEqual(res.status, 0, 'CLI exit code must be 0');
  const parsed = JSON.parse(res.stdout);
  assert(validateReproductionRecordShape(parsed), 'CLI emitted JSON must satisfy shape validation');
  assertEqual(parsed.maintainerAssistance, true, 'maintainerAssistance must be true');
  assertEqual(parsed.reproductionClassification, 'INDEPENDENT_ENVIRONMENT_REPLAY', 'reproductionClassification must be degraded');
});

// Test 15: Tier 2 integration via --tier2 and --mock
test('run-reproducibility-check.mjs --dry-run --tier2 --json produces valid record with tier2Results', () => {
  const res = spawnSync(process.execPath, [
    path.join(REPO_ROOT, 'scripts', 'run-reproducibility-check.mjs'),
    '--dry-run',
    '--tier2',
    '--json'
  ], {
    cwd: REPO_ROOT,
    encoding: 'utf8'
  });
  assertEqual(res.status, 0, 'CLI exit code must be 0');
  const parsed = JSON.parse(res.stdout);
  assert(validateReproductionRecordShape(parsed), 'CLI emitted JSON must satisfy shape validation');
  assert(parsed.tier2Results !== null, 'tier2Results must not be null');
  assertEqual(parsed.tier2Results.status, 'PASS', 'tier2 status must be PASS');
  assertEqual(parsed.tier2Results.vulnerableControl, 'TRUE_POSITIVE_CONFIRMED', 'tier2 vulnerableControl');
  assertEqual(parsed.tier2Results.safeControl, 'FALSE_POSITIVE_SUPPRESSED', 'tier2 safeControl');
  assertEqual(parsed.tier2Results.disputeControl, 'ORACLE_DISPUTE_RECONCILED', 'tier2 disputeControl');
  assert(/^[0-9a-f]{64}$/.test(parsed.tier2Results.streamDigest), 'valid streamDigest');
  assertEqual(parsed.overallVerdict, 'PASS', 'overall verdict with tier2');
});

// Test 16: Operator metrics integration in reproduction record
test('validateReproductionRecordShape accepts valid operatorMetrics attached', () => {
  const record = makeValidBaselineRecord();
  record.operatorMetrics = {
    $schema: 'https://antigravity.google/schemas/security-audit/operator-metrics.schema.json',
    timeToInstallSeconds: 45,
    timeToFirstSuccessfulAuditSeconds: 180,
    timeToFirstUnderstoodFindingSeconds: 120,
    manualFilesOpenedCount: 4,
    rerunsRequiredCount: 0,
    commandsRetriedCount: 0,
    helpRequestsCount: 0,
    misinterpretedStatusesCount: 0,
    findingAdjudicationSeconds: 150,
    evidenceFilesManuallyInspectedCount: 3,
    operatorFrictionNotes: ['Smooth execution.']
  };
  assert(validateReproductionRecordShape(record), 'record with valid operatorMetrics must pass');

  // Invalid metrics in record rejected
  record.operatorMetrics.manualFilesOpenedCount = -1;
  assert(!validateReproductionRecordShape(record), 'record with invalid operatorMetrics must fail');
});

// Test 17: CLI integration with --metrics flag
test('run-reproducibility-check.mjs --dry-run --json --metrics attaches valid operatorMetrics', () => {
  const tempDir = fs.mkdtempSync(path.join(REPO_ROOT, 'scratch', 'repro-metrics-test-'));
  const metricsFile = path.join(tempDir, 'metrics.json');
  try {
    fs.writeFileSync(metricsFile, JSON.stringify({
      $schema: 'https://antigravity.google/schemas/security-audit/operator-metrics.schema.json',
      timeToInstallSeconds: 30,
      timeToFirstSuccessfulAuditSeconds: 120,
      timeToFirstUnderstoodFindingSeconds: 90,
      manualFilesOpenedCount: 2,
      rerunsRequiredCount: 0,
      commandsRetriedCount: 0,
      helpRequestsCount: 0,
      misinterpretedStatusesCount: 0,
      findingAdjudicationSeconds: 60,
      evidenceFilesManuallyInspectedCount: 1,
      operatorFrictionNotes: ['CLI execution verified.']
    }, null, 2));

    const res = spawnSync(process.execPath, [
      path.join(REPO_ROOT, 'scripts', 'run-reproducibility-check.mjs'),
      '--dry-run',
      '--json',
      '--metrics', metricsFile
    ], {
      cwd: REPO_ROOT,
      encoding: 'utf8'
    });
    assertEqual(res.status, 0, 'CLI exit code must be 0');
    const parsed = JSON.parse(res.stdout);
    assert(validateReproductionRecordShape(parsed), 'CLI emitted JSON must satisfy shape validation');
    assert(parsed.operatorMetrics !== null, 'operatorMetrics must be present');
    assertEqual(parsed.operatorMetrics.timeToInstallSeconds, 30, 'timeToInstallSeconds must match');
  } finally {
    fs.rmSync(tempDir, { recursive: true, force: true });
  }
});

// Test 18: resolveReleaseAssetBinding Priority 1 (USER_VERIFIED)
test('resolveReleaseAssetBinding favors user-supplied digest as USER_VERIFIED', () => {
  const binding = resolveReleaseAssetBinding({
    releaseTag: 'v1.9.1',
    releaseAssetDigest: 'aa3cf9cc353b286f0533c2b05cdc5962c831760bbacd4ae5c1527acdb132fa64'
  });
  assertEqual(binding.releaseAssetName, 'agy-security-audit-v1.9.1.zip', 'asset name');
  assertEqual(binding.releaseAssetDigest, 'aa3cf9cc353b286f0533c2b05cdc5962c831760bbacd4ae5c1527acdb132fa64', 'digest');
  assertEqual(binding.releaseAssetDigestSource, 'USER_VERIFIED', 'source');

  const unverifiableBinding = resolveReleaseAssetBinding({
    releaseTag: 'v1.9.1',
    releaseAssetDigest: 'UNVERIFIABLE'
  });
  assertEqual(unverifiableBinding.releaseAssetDigest, 'UNVERIFIABLE', 'unverifiable digest');
  assertEqual(unverifiableBinding.releaseAssetDigestSource, 'UNVERIFIABLE', 'unverifiable source');
});

// Test 19: resolveReleaseAssetBinding Priority 2 (LOCAL_MANIFEST) and priority order
test('resolveReleaseAssetBinding resolves from local manifest and respects Priority 1 > Priority 2', () => {
  const tempDir = fs.mkdtempSync(path.join(REPO_ROOT, 'scratch', 'repro-manifest-test-'));
  const manifestFile = path.join(tempDir, 'SHA256SUMS.txt');
  try {
    fs.writeFileSync(manifestFile, '1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef  agy-security-audit-v1.9.99.zip\n');

    // Priority 2 resolution
    const bindingFromManifest = resolveReleaseAssetBinding({
      releaseTag: 'v1.9.99',
      manifestPath: manifestFile
    });
    assertEqual(bindingFromManifest.releaseAssetDigest, '1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef', 'manifest digest');
    assertEqual(bindingFromManifest.releaseAssetDigestSource, 'LOCAL_MANIFEST', 'manifest source');

    // Priority 1 overrides Priority 2
    const bindingUserOverride = resolveReleaseAssetBinding({
      releaseTag: 'v1.9.99',
      releaseAssetDigest: 'fedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321',
      manifestPath: manifestFile
    });
    assertEqual(bindingUserOverride.releaseAssetDigest, 'fedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321', 'user override digest');
    assertEqual(bindingUserOverride.releaseAssetDigestSource, 'USER_VERIFIED', 'user override source');
  } finally {
    fs.rmSync(tempDir, { recursive: true, force: true });
  }
});

// Test 20: resolveReleaseAssetBinding Priority 4 (UNVERIFIABLE fallback)
test('resolveReleaseAssetBinding falls back honestly to UNVERIFIABLE when missing metadata', () => {
  const binding = resolveReleaseAssetBinding({
    releaseTag: 'v0.0.0-nonexistent-unverifiable',
    repoRoot: path.join(REPO_ROOT, 'scratch', 'empty-repo-for-test')
  });
  assertEqual(binding.releaseAssetDigest, 'UNVERIFIABLE', 'unverifiable fallback digest');
  assertEqual(binding.releaseAssetDigestSource, 'UNVERIFIABLE', 'unverifiable fallback source');
});

// Test 21: Historical reproduction record v1.9.0 conformance
test('historical evals/reproduction-records/reproduction-record-v1.9.0.json conforms to schema', () => {
  const recPath = path.join(REPO_ROOT, 'evals', 'reproduction-records', 'reproduction-record-v1.9.0.json');
  assert(fs.existsSync(recPath), 'reproduction-record-v1.9.0.json must exist');
  const record = JSON.parse(fs.readFileSync(recPath, 'utf8'));
  assert(validateReproductionRecordShape(record), 'reproduction-record-v1.9.0.json must pass shape validation');
  assertEqual(record.releaseAssetName, 'agy-security-audit-v1.9.0.zip', 'v1.9.0 asset name');
  assertEqual(record.releaseAssetDigestSource, 'USER_VERIFIED', 'v1.9.0 digest source');
});

// Test 22: CLI flag --release-asset-digest integration
test('run-reproducibility-check.mjs --dry-run --json --release-asset-digest binds user digest', () => {
  const customDigest = '1111222233334444555566667777888899990000aaaabbbbccccddddeeeeffff';
  const res = spawnSync(process.execPath, [
    path.join(REPO_ROOT, 'scripts', 'run-reproducibility-check.mjs'),
    '--dry-run',
    '--json',
    '--release-asset-digest', customDigest
  ], {
    cwd: REPO_ROOT,
    encoding: 'utf8'
  });
  assertEqual(res.status, 0, 'CLI exit code must be 0');
  const parsed = JSON.parse(res.stdout);
  assert(validateReproductionRecordShape(parsed), 'CLI emitted JSON must satisfy shape validation');
  assertEqual(parsed.releaseAssetDigest, customDigest, 'custom digest bound');
  assertEqual(parsed.releaseAssetDigestSource, 'USER_VERIFIED', 'source must be USER_VERIFIED');
});

// Test 23: Dynamic release asset binding matches canonical naming and resolves published v1.9.1 asset
test('run-reproducibility-check.mjs --dry-run --json dynamically binds canonical asset', () => {
  const res = spawnSync(process.execPath, [
    path.join(REPO_ROOT, 'scripts', 'run-reproducibility-check.mjs'),
    '--dry-run',
    '--json'
  ], {
    cwd: REPO_ROOT,
    encoding: 'utf8'
  });
  assertEqual(res.status, 0, 'CLI exit code must be 0');
  const parsed = JSON.parse(res.stdout);
  assert(validateReproductionRecordShape(parsed), 'CLI emitted JSON must satisfy shape validation');
  assertEqual(parsed.releaseAssetName, `agy-security-audit-v${parsed.projectVersion}.zip`, 'canonical release asset name');

  // Verify published v1.9.1 immutable release resolution
  const publishedBinding = resolveReleaseAssetBinding({ releaseTag: 'v1.9.1' });
  assertEqual(publishedBinding.releaseAssetName, 'agy-security-audit-v1.9.1.zip', 'published asset name');
  if (publishedBinding.releaseAssetDigestSource === 'GITHUB_RELEASE_API') {
    assertEqual(
      publishedBinding.releaseAssetDigest,
      'aa3cf9cc353b286f0533c2b05cdc5962c831760bbacd4ae5c1527acdb132fa64',
      'v1.9.1 digest matches immutable GitHub release'
    );
  }
});

console.log(`\nAll Reproduction policy tests passed (${passed}/${passed}).`);

