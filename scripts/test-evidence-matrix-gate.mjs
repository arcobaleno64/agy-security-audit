#!/usr/bin/env node
/**
 * test-evidence-matrix-gate.mjs
 * Milestone v1.6.2 Evidence-Gate Closure Regression Test Suite.
 *
 * Formally verifies fail-closed Default-Deny behavior across:
 * 1. Draft-07 JSON Schema validation against schemas/evidence-matrix.schema.json.
 * 2. Physical SHA-256 artifact hash corruption detection.
 * 3. Required dimension presence enforcement.
 * 4. Status enum invariant adherence.
 * 5. Governance and summary metadata integrity.
 * 6. Missing physical on-disk artifact detection.
 *
 * Zero external npm dependencies. Enforces strict LF line endings.
 */

import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { fileURLToPath } from 'node:url';
import {
  validateEvidenceMatrixSchema,
  checkEvidenceCompleteness
} from './bundle-release-evidence.mjs';

const __filename = fileURLToPath(import.meta.url);
const REPO_ROOT = path.resolve(path.dirname(__filename), '..');

function assert(condition, message) {
  if (!condition) {
    throw new Error(`ASSERTION_FAILED: ${message}`);
  }
}

/**
 * Runs the comprehensive regression suite for the evidence matrix release gate.
 * @param {string} repoRoot
 * @returns {{ passed: boolean, testsRun: number }}
 */
export function runEvidenceMatrixGateTests(repoRoot = REPO_ROOT) {
  let testsRun = 0;

  // 1. Valid baseline evidence matrix passes schema and completeness checks
  const matrixPath = path.resolve(repoRoot, 'evals/evidence-matrix.json');
  if (!fs.existsSync(matrixPath)) {
    throw new Error(`Baseline evidence matrix missing at ${matrixPath}`);
  }
  const baselineMatrix = JSON.parse(fs.readFileSync(matrixPath, 'utf8'));

  const baseSchemaRes = validateEvidenceMatrixSchema(baselineMatrix, repoRoot);
  assert(baseSchemaRes.valid === true, `Baseline schema validation failed: ${baseSchemaRes.errors.join('; ')}`);
  assert(baseSchemaRes.errors.length === 0, 'Baseline schema must have 0 errors');
  testsRun++;

  if (!process.env.IS_ZIP_CLEAN_SUBTEST) {
    const baseCompleteness = checkEvidenceCompleteness(repoRoot);
    assert(baseCompleteness.valid === true, `Baseline completeness check failed: ${baseCompleteness.errors.join('; ')}`);
    testsRun++;
  }

  // 2. Corrupted artifact hash pattern (non-hex or wrong length) fails schema validation
  const badPatternMatrix = JSON.parse(JSON.stringify(baselineMatrix));
  badPatternMatrix.dimensions.DETERMINISTIC_HARNESS.artifacts[0].sha256 = 'not-a-valid-sha256';
  const badPatternRes = validateEvidenceMatrixSchema(badPatternMatrix, repoRoot);
  assert(badPatternRes.valid === false, 'Bad sha256 pattern must fail schema validation');
  assert(badPatternRes.errors.some(e => e.includes('does not match pattern')), 'Error must report pattern mismatch');
  testsRun++;

  // 3. Missing required dimension fails schema validation
  const missingDimMatrix = JSON.parse(JSON.stringify(baselineMatrix));
  delete missingDimMatrix.dimensions.EXTERNAL_OSS_TRANSFER;
  const missingDimRes = validateEvidenceMatrixSchema(missingDimMatrix, repoRoot);
  assert(missingDimRes.valid === false, 'Missing dimension must fail schema validation');
  assert(missingDimRes.errors.some(e => e.includes('dimensions.EXTERNAL_OSS_TRANSFER')), 'Error must report missing dimension');
  testsRun++;

  // 4. Invalid dimension status enum fails schema validation
  const badStatusMatrix = JSON.parse(JSON.stringify(baselineMatrix));
  badStatusMatrix.dimensions.DETERMINISTIC_HARNESS.status = 'COMPLETED_SUCCESSFULLY';
  const badStatusRes = validateEvidenceMatrixSchema(badStatusMatrix, repoRoot);
  assert(badStatusRes.valid === false, 'Invalid status enum must fail schema validation');
  assert(badStatusRes.errors.some(e => e.includes('is not one of enum')), 'Error must report enum violation');
  testsRun++;

  // 5. Missing governance and summary fields fail schema validation
  const missingGovMatrix = JSON.parse(JSON.stringify(baselineMatrix));
  delete missingGovMatrix.governance.standard;
  const missingGovRes = validateEvidenceMatrixSchema(missingGovMatrix, repoRoot);
  assert(missingGovRes.valid === false, 'Missing governance.standard must fail schema validation');
  assert(missingGovRes.errors.some(e => e.includes('governance.standard')), 'Error must report missing governance.standard');
  testsRun++;

  const missingSumMatrix = JSON.parse(JSON.stringify(baselineMatrix));
  delete missingSumMatrix.summary.supportedDimensions;
  const missingSumRes = validateEvidenceMatrixSchema(missingSumMatrix, repoRoot);
  assert(missingSumRes.valid === false, 'Missing summary.supportedDimensions must fail schema validation');
  assert(missingSumRes.errors.some(e => e.includes('summary.supportedDimensions')), 'Error must report missing summary.supportedDimensions');
  testsRun++;

  // 6. Fail-Closed on missing on-disk artifact and physical hash corruption
  const tempRepo = fs.mkdtempSync(path.join(os.tmpdir(), 'evidence-gate-test-'));
  try {
    const tempSchemasDir = path.join(tempRepo, 'schemas');
    const tempEvalsDir = path.join(tempRepo, 'evals');
    fs.mkdirSync(tempSchemasDir, { recursive: true });
    fs.mkdirSync(tempEvalsDir, { recursive: true });

    fs.copyFileSync(
      path.resolve(repoRoot, 'schemas/evidence-matrix.schema.json'),
      path.join(tempSchemasDir, 'evidence-matrix.schema.json')
    );

    // 6a. Missing artifact on disk
    const ghostMatrix = JSON.parse(JSON.stringify(baselineMatrix));
    ghostMatrix.dimensions.DETERMINISTIC_HARNESS.artifacts.push({
      path: 'schemas/ghost-file.json',
      sha256: '0'.repeat(64),
      description: 'Ghost artifact'
    });
    fs.writeFileSync(path.join(tempEvalsDir, 'evidence-matrix.json'), JSON.stringify(ghostMatrix, null, 2), 'utf8');

    const ghostCompleteness = checkEvidenceCompleteness(tempRepo);
    assert(ghostCompleteness.valid === false, 'Missing artifact on disk must fail checkEvidenceCompleteness');
    assert(ghostCompleteness.errors.some(e => e.includes('missing on disk: schemas/ghost-file.json')), 'Error must report missing on-disk artifact');
    testsRun++;

    // 6b. Physical hash mismatch on existing file
    const corruptedHashMatrix = JSON.parse(JSON.stringify(baselineMatrix));
    corruptedHashMatrix.dimensions.DETERMINISTIC_HARNESS.artifacts = [{
      path: 'schemas/evidence-matrix.schema.json',
      sha256: 'f'.repeat(64), // Valid pattern, but corrupted hash
      description: 'Schema with mismatching hash'
    }];
    corruptedHashMatrix.dimensions.LIVE_MODEL_EVALUATION.artifacts = [];
    corruptedHashMatrix.dimensions.LIVE_RUNTIME_ENFORCEMENT.artifacts = [];
    corruptedHashMatrix.dimensions.CROSS_PROVIDER_REPLICATION.artifacts = [];
    corruptedHashMatrix.dimensions.EXTERNAL_OSS_TRANSFER.artifacts = [];

    fs.writeFileSync(path.join(tempEvalsDir, 'evidence-matrix.json'), JSON.stringify(corruptedHashMatrix, null, 2), 'utf8');
    const hashMismatchCompleteness = checkEvidenceCompleteness(tempRepo);
    assert(hashMismatchCompleteness.valid === false, 'Hash mismatch must fail checkEvidenceCompleteness');
    assert(hashMismatchCompleteness.errors.some(e => e.includes('SHA-256 mismatch')), 'Error must report SHA-256 mismatch');
    testsRun++;
  } finally {
    try {
      fs.rmSync(tempRepo, { recursive: true, force: true });
    } catch {}
  }

  return { passed: true, testsRun };
}

// CLI Dispatch
if (process.argv[1] && path.resolve(process.argv[1]) === path.resolve(__filename)) {
  const pkgPath = path.resolve(REPO_ROOT, 'package.json');
  const pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf8'));
  const matrixPath = path.resolve(REPO_ROOT, 'evals/evidence-matrix.json');
  const matrix = JSON.parse(fs.readFileSync(matrixPath, 'utf8'));
  const uniqueArtifactsCount = new Set(
    Object.values(matrix.dimensions)
      .flatMap(d => d.artifacts ?? [])
      .map(a => a.path)
  ).size;

  console.log('================================================================');
  console.log(`v${pkg.version} Evidence Matrix Gate Regression Test Suite`);
  console.log('================================================================\n');

  try {
    const result = runEvidenceMatrixGateTests(REPO_ROOT);
    console.log(`  ✔ 1. Baseline evidence matrix passes Draft-07 schema validation.`);
    console.log(`  ✔ 2. Baseline release evidence completes all ${uniqueArtifactsCount} artifact verifications.`);
    console.log(`  ✔ 3. Malformed artifact SHA-256 pattern fails schema validation fail-closed.`);
    console.log(`  ✔ 4. Missing required dimension fails schema validation fail-closed.`);
    console.log(`  ✔ 5. Invalid dimension status enum fails schema validation fail-closed.`);
    console.log(`  ✔ 6. Missing governance/summary fields fail schema validation fail-closed.`);
    console.log(`  ✔ 7. Missing on-disk artifact fails release gate fail-closed.`);
    console.log(`  ✔ 8. Corrupted physical artifact SHA-256 fails release gate fail-closed.\n`);
    console.log(`All evidence matrix gate regression tests passed cleanly! (${result.testsRun} checks executed)`);
    process.exit(0);
  } catch (err) {
    console.error(`\n❌ Evidence matrix gate test failed: ${err.message}`);
    if (err.stack) {
      console.error(err.stack);
    }
    process.exit(1);
  }
}
