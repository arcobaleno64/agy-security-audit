#!/usr/bin/env node
/**
 * test-operator-metrics.mjs
 * Deterministic test suite for Track D Phase D3 (RFC 0002 §7).
 *
 * Verifies:
 * - schemas/operator-metrics.schema.json structural validity and compliance.
 * - validateOperatorMetricsShape rejects missing keys, negative numbers, floats for counts.
 * - RFC 0002 §7.2 Interface Decision Gate priority logic.
 * - CLI invocations (--template, --check).
 *
 * Zero external npm dependencies (pure Node.js built-ins).
 */

import fs from 'node:fs';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import {
  OPERATOR_METRICS_SCHEMA_ID,
  validateOperatorMetricsShape,
  evaluateInterfaceRecommendation,
  formatOperatorMetricsSummary,
  createBlankMetricsTemplate
} from './operator-metrics.mjs';

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

function makeBaselineMetrics() {
  return {
    $schema: OPERATOR_METRICS_SCHEMA_ID,
    schemaVersion: '1.0.0',
    recordedAt: '2026-09-24T12:00:00.000Z',
    operatorClass: 'INDEPENDENT_OPERATOR',
    targetRepository: 'example/target-repo',
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
    operatorFrictionNotes: ['Smooth installation via npm link.']
  };
}

// Test 1: JSON Schema file exists and contains canonical $id
test('schemas/operator-metrics.schema.json exists and has valid $id', () => {
  const schemaPath = path.join(REPO_ROOT, 'schemas', 'operator-metrics.schema.json');
  assert(fs.existsSync(schemaPath), 'schema file must exist');
  const schema = JSON.parse(fs.readFileSync(schemaPath, 'utf8'));
  assertEqual(schema.$id, OPERATOR_METRICS_SCHEMA_ID, 'schema $id must match canonical URI');
  assert(Array.isArray(schema.required), 'schema must declare required fields');
  assert(schema.required.includes('timeToInstallSeconds'), 'must require timeToInstallSeconds');
});

// Test 2: Baseline valid metrics passes shape validation
test('validateOperatorMetricsShape accepts RFC 0002 §7.1 baseline metrics', () => {
  const metrics = makeBaselineMetrics();
  assert(validateOperatorMetricsShape(metrics), 'valid baseline metrics must pass shape validation');
});

// Test 3: Template generator emits valid metrics
test('createBlankMetricsTemplate generates schema-valid metrics template', () => {
  const template = createBlankMetricsTemplate();
  assert(validateOperatorMetricsShape(template), 'template must pass shape validation');
});

// Test 4: Rejects missing required properties
test('validateOperatorMetricsShape rejects missing required properties', () => {
  const requiredKeys = [
    '$schema',
    'timeToInstallSeconds',
    'timeToFirstSuccessfulAuditSeconds',
    'timeToFirstUnderstoodFindingSeconds',
    'manualFilesOpenedCount',
    'rerunsRequiredCount',
    'commandsRetriedCount',
    'helpRequestsCount',
    'misinterpretedStatusesCount',
    'findingAdjudicationSeconds',
    'evidenceFilesManuallyInspectedCount',
    'operatorFrictionNotes'
  ];

  for (const key of requiredKeys) {
    const metrics = makeBaselineMetrics();
    delete metrics[key];
    assert(!validateOperatorMetricsShape(metrics), `must reject metrics missing required key: ${key}`);
  }
});

// Test 5: Rejects unknown properties (additionalProperties: false)
test('validateOperatorMetricsShape rejects extra unknown properties', () => {
  const metrics = makeBaselineMetrics();
  metrics.unexpectedExtraKey = true;
  assert(!validateOperatorMetricsShape(metrics), 'must reject unknown properties');
});

// Test 6: Rejects negative numbers and non-integers for counts
test('validateOperatorMetricsShape rejects negative values and invalid number types', () => {
  const negativeSecs = makeBaselineMetrics();
  negativeSecs.timeToInstallSeconds = -1;
  assert(!validateOperatorMetricsShape(negativeSecs), 'must reject negative seconds');

  const negativeCount = makeBaselineMetrics();
  negativeCount.manualFilesOpenedCount = -5;
  assert(!validateOperatorMetricsShape(negativeCount), 'must reject negative count');

  const floatCount = makeBaselineMetrics();
  floatCount.rerunsRequiredCount = 2.5;
  assert(!validateOperatorMetricsShape(floatCount), 'must reject floating point counts');

  const stringTime = makeBaselineMetrics();
  stringTime.findingAdjudicationSeconds = '150s';
  assert(!validateOperatorMetricsShape(stringTime), 'must reject string seconds');
});

// Test 7: Rejects invalid friction notes
test('validateOperatorMetricsShape rejects invalid notes types', () => {
  const notArray = makeBaselineMetrics();
  notArray.operatorFrictionNotes = 'not an array';
  assert(!validateOperatorMetricsShape(notArray), 'must reject non-array notes');

  const nonStringNote = makeBaselineMetrics();
  nonStringNote.operatorFrictionNotes = [123];
  assert(!validateOperatorMetricsShape(nonStringNote), 'must reject non-string note items');
});

// Test 8: Interface Decision Gate evaluates CLI_SUFFICIENT when friction is low
test('evaluateInterfaceRecommendation emits CLI_SUFFICIENT for low friction', () => {
  const metrics = makeBaselineMetrics();
  const rec = evaluateInterfaceRecommendation(metrics);
  assertEqual(rec, 'CLI_SUFFICIENT', 'low friction metrics must recommend CLI_SUFFICIENT');
});

// Test 9: Interface Decision Gate evaluates STATUS_VOCABULARY_CLARIFICATION_RECOMMENDED
test('evaluateInterfaceRecommendation prioritizes status vocabulary clarification', () => {
  const metrics = makeBaselineMetrics();
  metrics.misinterpretedStatusesCount = 1;
  metrics.manualFilesOpenedCount = 8; // High, but status ambiguity is higher priority
  const rec = evaluateInterfaceRecommendation(metrics);
  assertEqual(rec, 'STATUS_VOCABULARY_CLARIFICATION_RECOMMENDED', 'status ambiguity must take priority');
});

// Test 10: Interface Decision Gate evaluates TUI_RECOMMENDED on high navigation friction
test('evaluateInterfaceRecommendation emits TUI_RECOMMENDED on high manual navigation', () => {
  const metrics = makeBaselineMetrics();
  metrics.manualFilesOpenedCount = 9;
  metrics.findingAdjudicationSeconds = 450;
  const rec = evaluateInterfaceRecommendation(metrics);
  assertEqual(rec, 'TUI_RECOMMENDED', 'heavy raw SARIF inspection must recommend TUI_RECOMMENDED');
});

// Test 11: Interface Decision Gate evaluates CLI_WORKFLOW_IMPROVEMENT_RECOMMENDED on invocation friction
test('evaluateInterfaceRecommendation emits CLI_WORKFLOW_IMPROVEMENT_RECOMMENDED on command retries', () => {
  const metrics = makeBaselineMetrics();
  metrics.commandsRetriedCount = 3;
  metrics.rerunsRequiredCount = 2;
  const rec = evaluateInterfaceRecommendation(metrics);
  assertEqual(rec, 'CLI_WORKFLOW_IMPROVEMENT_RECOMMENDED', 'repeated command failure must recommend CLI workflow improvement');
});

// Test 12: Terminal summary formatting contains expected sections
test('formatOperatorMetricsSummary generates comprehensive textual representation', () => {
  const metrics = makeBaselineMetrics();
  const output = formatOperatorMetricsSummary(metrics);
  assert(output.includes('OPERATOR READINESS & FRICTION OBSERVABILITY'), 'must include title');
  assert(output.includes('Interface Recommendation:            CLI_SUFFICIENT'), 'must include recommendation');
  assert(output.includes('Smooth installation via npm link.'), 'must include friction notes');
});

// Test 13: CLI execution for --template and --check
test('CLI flags --template and --check operate deterministically', () => {
  const scriptPath = path.join(REPO_ROOT, 'scripts', 'operator-metrics.mjs');
  
  // --template
  const templateRun = spawnSync(process.execPath, [scriptPath, '--template'], { encoding: 'utf8' });
  assertEqual(templateRun.status, 0, '--template must exit 0');
  const parsed = JSON.parse(templateRun.stdout);
  assert(validateOperatorMetricsShape(parsed), 'template CLI output must be schema-valid');

  // --check with temp file
  const tempDir = fs.mkdtempSync(path.join(REPO_ROOT, 'scratch', 'metrics-test-'));
  const tempFile = path.join(tempDir, 'test-metrics.json');
  try {
    fs.writeFileSync(tempFile, JSON.stringify(makeBaselineMetrics(), null, 2));
    const checkRun = spawnSync(process.execPath, [scriptPath, '--check', tempFile], { encoding: 'utf8' });
    assertEqual(checkRun.status, 0, '--check on valid file must exit 0');

    // Invalid file check
    fs.writeFileSync(tempFile, JSON.stringify({ invalid: true }, null, 2));
    const failRun = spawnSync(process.execPath, [scriptPath, '--check', tempFile], { encoding: 'utf8' });
    assert(failRun.status !== 0, '--check on invalid file must exit non-zero');
  } finally {
    fs.rmSync(tempDir, { recursive: true, force: true });
  }
});

console.log(`\n✔ ALL ${passed}/13 OPERATOR METRICS TESTS PASSED CLEANLY.`);
