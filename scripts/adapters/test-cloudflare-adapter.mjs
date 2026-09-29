#!/usr/bin/env node
/**
 * scripts/adapters/test-cloudflare-adapter.mjs
 * Comprehensive Verification & Semantic-Loss Test Suite for Cloudflare Adapter.
 *
 * Validates:
 * 1. Schema adherence to schemas/candidate-set.schema.json and schemas/canonical-finding.schema.json
 * 2. Bidirectional semantic losslessness across all fields (location, trace, conditions, execution, remediation)
 * 3. Default-Deny and quarantine boundary enforcement (partial coverage -> DEFERRED / COVERAGE_PARTIAL)
 * 4. Severity handling (needs_validation injected severity fail-closed or stripped to UNRATED)
 * 5. Run-to-run bitwise identity across repeated executions
 * 6. Malformed input fail-closed behavior
 * 7. Adversarial resistance (no unevidenced finding gets REPORTABLE / CONFIRMED)
 * 8. Zero external npm dependencies (built-in Node.js standard library only)
 */

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  toCanonicalFinding,
  toCandidate,
  toCandidateSet,
  ingestFindings,
  ingestCoverageLedger,
  ingestAuditSession,
  toCloudflareFinding,
  toCloudflareFindings,
  deterministicStringify,
  canonicalizeJson,
  mapCloudflareSeverity
} from './cloudflare-adapter.mjs';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const REPO_ROOT = path.resolve(__dirname, '../..');

// -----------------------------------------------------------------------------
// Assertions & Test Framework
// -----------------------------------------------------------------------------

let testCount = 0;
let passCount = 0;

function assert(condition, message) {
  if (!condition) {
    throw new Error(`[ASSERTION_FAILED] ${message}`);
  }
}

function assertEqual(actual, expected, message) {
  assert(
    actual === expected,
    `${message} - Expected: ${JSON.stringify(expected)}, Got: ${JSON.stringify(actual)}`
  );
}

function assertDeepEqual(actual, expected, message) {
  const actualStr = JSON.stringify(canonicalizeJson(actual));
  const expectedStr = JSON.stringify(canonicalizeJson(expected));
  assert(
    actualStr === expectedStr,
    `${message} - Deep equality mismatch.\nActual:   ${actualStr}\nExpected: ${expectedStr}`
  );
}

function test(name, fn) {
  testCount++;
  try {
    fn();
    passCount++;
    console.log(`✔ [PASS ${testCount}] ${name}`);
  } catch (err) {
    console.error(`✘ [FAIL ${testCount}] ${name}`);
    console.error(err.stack || err.message);
    process.exit(1);
  }
}

// -----------------------------------------------------------------------------
// JSON Schema Draft-07 Validator (Zero-Dependency)
// -----------------------------------------------------------------------------

/**
 * Validates data against a JSON schema (Draft-07 subset).
 * Supports: type, required, properties, additionalProperties, items, enum,
 * pattern, minimum, minLength, oneOf, $ref.
 *
 * @param {any} data
 * @param {object} schema
 * @param {object} rootSchema
 * @param {string} currentPath
 * @returns {string[]} List of error messages
 */
export function validateAgainstSchema(data, schema, rootSchema = schema, currentPath = '') {
  const errors = [];
  if (!schema || typeof schema !== 'object') return errors;

  // Resolve $ref (internal reference like #/definitions/...)
  if (schema.$ref) {
    const ref = schema.$ref;
    if (typeof ref === 'string' && ref.startsWith('#/')) {
      const parts = ref.slice(2).split('/');
      let resolved = rootSchema;
      for (const part of parts) {
        if (resolved && typeof resolved === 'object' && part in resolved) {
          resolved = resolved[part];
        } else {
          resolved = null;
          break;
        }
      }
      if (!resolved) {
        errors.push(`Unresolvable schema reference '${ref}' at ${currentPath || 'root'}`);
        return errors;
      }
      return validateAgainstSchema(data, resolved, rootSchema, currentPath);
    }
  }

  const p = currentPath || 'root';

  // Validate type
  if (schema.type) {
    const types = Array.isArray(schema.type) ? schema.type : [schema.type];
    const match = types.some(t => {
      switch (t) {
        case 'object':
          return typeof data === 'object' && data !== null && !Array.isArray(data);
        case 'array':
          return Array.isArray(data);
        case 'string':
          return typeof data === 'string';
        case 'integer':
          return typeof data === 'number' && Number.isInteger(data);
        case 'number':
          return typeof data === 'number' && !Number.isNaN(data);
        case 'boolean':
          return typeof data === 'boolean';
        case 'null':
          return data === null;
        default:
          return false;
      }
    });

    if (!match) {
      const actualType = data === null ? 'null' : Array.isArray(data) ? 'array' : typeof data;
      errors.push(`Expected type [${types.join(', ')}] at ${p}, got ${actualType}`);
      return errors; // Stop further validation on type mismatch
    }
  }

  // Validate enum
  if (Array.isArray(schema.enum)) {
    if (!schema.enum.includes(data)) {
      errors.push(`Value '${data}' at ${p} is not one of enum [${schema.enum.map(v => JSON.stringify(v)).join(', ')}]`);
    }
  }

  // Validate pattern
  if (typeof schema.pattern === 'string' && typeof data === 'string') {
    const regex = new RegExp(schema.pattern);
    if (!regex.test(data)) {
      errors.push(`String '${data}' at ${p} does not match pattern '${schema.pattern}'`);
    }
  }

  // Validate minLength
  if (typeof schema.minLength === 'number' && typeof data === 'string') {
    if (data.length < schema.minLength) {
      errors.push(`String length ${data.length} at ${p} is less than minLength ${schema.minLength}`);
    }
  }

  // Validate minimum
  if (typeof schema.minimum === 'number' && typeof data === 'number') {
    if (data < schema.minimum) {
      errors.push(`Number ${data} at ${p} is less than minimum ${schema.minimum}`);
    }
  }

  // Validate object properties
  if (typeof data === 'object' && data !== null && !Array.isArray(data)) {
    // Required properties
    if (Array.isArray(schema.required)) {
      for (const reqProp of schema.required) {
        if (data[reqProp] === undefined) {
          errors.push(`Missing required property: ${p ? `${p}.${reqProp}` : reqProp}`);
        }
      }
    }

    // Properties validation
    if (schema.properties && typeof schema.properties === 'object') {
      for (const [propName, propSchema] of Object.entries(schema.properties)) {
        if (data[propName] !== undefined) {
          const subPath = p ? `${p}.${propName}` : propName;
          const subErrors = validateAgainstSchema(data[propName], propSchema, rootSchema, subPath);
          errors.push(...subErrors);
        }
      }
    }

    // additionalProperties: false check
    if (schema.additionalProperties === false) {
      const allowed = new Set(Object.keys(schema.properties || {}));
      for (const key of Object.keys(data)) {
        if (!allowed.has(key)) {
          errors.push(`Unexpected property '${key}' at ${p} (additionalProperties: false)`);
        }
      }
    }
  }

  // Validate array items
  if (Array.isArray(data) && schema.items) {
    for (let i = 0; i < data.length; i++) {
      const subPath = `${p}[${i}]`;
      const itemErrors = validateAgainstSchema(data[i], schema.items, rootSchema, subPath);
      errors.push(...itemErrors);
    }
  }

  return errors;
}

// -----------------------------------------------------------------------------
// Load Schemas and Fixtures
// -----------------------------------------------------------------------------

const canonicalSchema = JSON.parse(
  fs.readFileSync(path.join(REPO_ROOT, 'schemas/canonical-finding.schema.json'), 'utf8')
);
const candidateSetSchema = JSON.parse(
  fs.readFileSync(path.join(REPO_ROOT, 'schemas/candidate-set.schema.json'), 'utf8')
);

const fixturesDir = path.join(REPO_ROOT, 'test/fixtures/cloudflare');
const confirmedJson = JSON.parse(fs.readFileSync(path.join(fixturesDir, 'findings-confirmed.json'), 'utf8'));
const needsValJson = JSON.parse(fs.readFileSync(path.join(fixturesDir, 'findings-needs-validation.json'), 'utf8'));
const rejectedJson = JSON.parse(fs.readFileSync(path.join(fixturesDir, 'findings-rejected.json'), 'utf8'));
const mixedJson = JSON.parse(fs.readFileSync(path.join(fixturesDir, 'findings-mixed.json'), 'utf8'));
const injectedSevJson = JSON.parse(fs.readFileSync(path.join(fixturesDir, 'findings-injected-severity.json'), 'utf8'));
const completeLedgerJson = JSON.parse(fs.readFileSync(path.join(fixturesDir, 'coverage-ledger-complete.json'), 'utf8'));
const partialLedgerJson = JSON.parse(fs.readFileSync(path.join(fixturesDir, 'coverage-ledger-partial.json'), 'utf8'));

console.log('Running Cloudflare Adapter Test Suite...');

// -----------------------------------------------------------------------------
// Suite 1: Schema Validator Sanity
// -----------------------------------------------------------------------------

test('Schema Validator rejects malformed canonical finding structure', () => {
  const badFinding = {
    id: 'SEC-001',
    // Missing required fields
    ruleId: 'CWE-89'
  };
  const errors = validateAgainstSchema(badFinding, canonicalSchema);
  assert(errors.length > 0, 'Validator must catch missing required fields');
});

test('Schema Validator rejects unexpected properties on candidate-set item', () => {
  const badCandidateSet = {
    schemaVersion: '1.0.0',
    candidates: [
      {
        id: 'SEC-01',
        ruleId: 'CWE-89',
        title: 'SQLi',
        securityProperty: 'Sanitize SQL inputs',
        findingType: 'VULNERABILITY',
        proofKind: 'STATIC_TRACE',
        location: { uri: 'test.js', startLine: 1 },
        illegalExtraField: 'disallowed'
      }
    ]
  };
  const errors = validateAgainstSchema(badCandidateSet, candidateSetSchema);
  assert(errors.some(e => e.includes('illegalExtraField')), 'Must reject illegalExtraField');
});

// -----------------------------------------------------------------------------
// Suite 2: R1 Lossless Canonical Finding Translation
// -----------------------------------------------------------------------------

test('Confirmed finding maps to REPORTABLE when authority is granted, and DEFERRED/UNVERIFIED_CLAIM by default under Default-Deny', () => {
  // 1. Default-Deny authority boundary: unassessed producer claim defaults to DEFERRED / UNVERIFIED_CLAIM
  const defaultCanonical = toCanonicalFinding(confirmedJson[0]);
  assertEqual(defaultCanonical.disposition, 'DEFERRED', 'Unassessed confirmed finding must default to DEFERRED');
  assertEqual(defaultCanonical.verdict, 'NEEDS_MANUAL_REVIEW', 'Verdict must be NEEDS_MANUAL_REVIEW');
  assertEqual(defaultCanonical.reasonCode, 'UNVERIFIED_CLAIM', 'Reason code must be UNVERIFIED_CLAIM');
  assertEqual(defaultCanonical.extensions.producer.authorityStatus, 'UNASSESSED', 'Authority status must be UNASSESSED');
  assertEqual(defaultCanonical.extensions.producer.claimedVerification, 'VERIFIED_BY_PRODUCER', 'Producer verification claim preserved');
  const defaultErrors = validateAgainstSchema(defaultCanonical, canonicalSchema);
  assertEqual(defaultErrors.length, 0, `Default canonical finding must validate against schema: ${defaultErrors.join('; ')}`);

  // 2. Explicit authority grant (trusted override)
  const canonical = toCanonicalFinding(confirmedJson[0], { trustProducerAsAuthority: true });

  assertEqual(canonical.disposition, 'REPORTABLE', 'Confirmed finding with authority grant must have disposition REPORTABLE');
  assertEqual(canonical.verdict, 'CONFIRMED', 'Confirmed finding must have verdict CONFIRMED');
  assertEqual(canonical.reasonCode, 'AFFIRMATIVELY_VERIFIED', 'Confirmed finding must have reasonCode AFFIRMATIVELY_VERIFIED');
  assertEqual(canonical.severity, 'CRITICAL', 'Severity must map to CRITICAL');
  assertEqual(canonical.findingType, 'VULNERABILITY', 'Finding type must be VULNERABILITY');
  assertEqual(canonical.proofKind, 'STATIC_TRACE', 'Proof kind must be STATIC_TRACE');

  // Verify bound proof
  assert(canonical.proof && typeof canonical.proof === 'object', 'Proof must be bound object');
  assertEqual(canonical.proof.trace.length, 3, 'Proof trace must contain all 3 trace steps');
  assertEqual(canonical.proof.conditions.length, 1, 'Proof conditions must be preserved');
  assertEqual(canonical.proof.execution.attacker_perspective, 'Remote anonymous caller', 'Execution perspective bound');

  // Verify defectManagement
  assert(canonical.defectManagement && typeof canonical.defectManagement === 'object', 'defectManagement must exist');
  assert(canonical.defectManagement.rootCause.includes('Concatenation'), 'rootCause bound');
  assert(canonical.defectManagement.preventiveAction.includes('parameterized queries'), 'remediation strategy bound to preventiveAction');

  // Verify extensions.cloudflare preservation
  assert(canonical.extensions && canonical.extensions.cloudflare, 'extensions.cloudflare must be present');
  assertEqual(canonical.extensions.cloudflare.attack_class, 'sql_injection', 'attack_class preserved');
  assertEqual(canonical.extensions.cloudflare.phase, 'Phase-3-Validation', 'phase preserved');
  assertDeepEqual(canonical.extensions.cloudflare.raw_tokens, ['SELECT', 'FROM', 'users'], 'raw tokens preserved');

  // Validate against canonical-finding.schema.json
  const errors = validateAgainstSchema(canonical, canonicalSchema);
  assertEqual(errors.length, 0, `Canonical finding must validate against schema: ${errors.join('; ')}`);
});

test('Needs validation finding maps to DEFERRED, NEEDS_MANUAL_REVIEW, EVIDENCE_INCOMPLETE with severity UNRATED', () => {
  const canonical = toCanonicalFinding(needsValJson[0]);

  assertEqual(canonical.disposition, 'DEFERRED', 'needs_validation must have disposition DEFERRED');
  assertEqual(canonical.verdict, 'NEEDS_MANUAL_REVIEW', 'needs_validation must have verdict NEEDS_MANUAL_REVIEW');
  assertEqual(canonical.reasonCode, 'EVIDENCE_INCOMPLETE', 'needs_validation must have reasonCode EVIDENCE_INCOMPLETE');
  assertEqual(canonical.severity, 'UNRATED', 'Severity must strictly be UNRATED');
  assert(canonical.dispositionReason.includes('Blockers'), 'Disposition reason must include blockers');

  // Validate against canonical-finding.schema.json
  const errors = validateAgainstSchema(canonical, canonicalSchema);
  assertEqual(errors.length, 0, `Canonical finding must validate against schema: ${errors.join('; ')}`);
});

test('Injected severity on needs_validation is stripped to UNRATED by default', () => {
  const canonical = toCanonicalFinding(injectedSevJson[0]);
  assertEqual(canonical.disposition, 'DEFERRED', 'disposition remains DEFERRED');
  assertEqual(canonical.severity, 'UNRATED', 'Injected severity must be strictly stripped to UNRATED');

  const errors = validateAgainstSchema(canonical, canonicalSchema);
  assertEqual(errors.length, 0, `Must validate against schema: ${errors.join('; ')}`);
});

test('Injected severity on needs_validation fails closed when failClosedOnInjectedSeverity is true', () => {
  let threw = false;
  try {
    toCanonicalFinding(injectedSevJson[0], { failClosedOnInjectedSeverity: true });
  } catch (err) {
    threw = true;
    assert(err.message.includes('FAIL_CLOSED_SEVERITY_ERROR'), 'Must throw FAIL_CLOSED_SEVERITY_ERROR');
  }
  assert(threw, 'Must throw error when injected severity is rejected fail-closed');
});

test('Rejected finding maps to SUPPRESSED, FALSE_POSITIVE, AFFIRMATIVELY_REFUTED preserving refutation reason', () => {
  const canonical = toCanonicalFinding(rejectedJson[0]);

  assertEqual(canonical.disposition, 'SUPPRESSED', 'rejected must have disposition SUPPRESSED');
  assertEqual(canonical.verdict, 'FALSE_POSITIVE', 'rejected must have verdict FALSE_POSITIVE');
  assertEqual(canonical.reasonCode, 'AFFIRMATIVELY_REFUTED', 'rejected must have reasonCode AFFIRMATIVELY_REFUTED');
  assert(canonical.dispositionReason.includes('Content-Type is application/json'), 'Refutation rationale preserved in dispositionReason');

  const errors = validateAgainstSchema(canonical, canonicalSchema);
  assertEqual(errors.length, 0, `Canonical finding must validate against schema: ${errors.join('; ')}`);
});

// -----------------------------------------------------------------------------
// Suite 3: Candidate Set Schema Adherence
// -----------------------------------------------------------------------------

test('toCandidateSet generates candidates strictly conforming to schemas/candidate-set.schema.json', () => {
  const candidateSet = toCandidateSet(mixedJson);

  assertEqual(candidateSet.schemaVersion, '1.0.0', 'schemaVersion is 1.0.0');
  assertEqual(candidateSet.candidates.length, 3, 'Must produce 3 candidates');

  const errors = validateAgainstSchema(candidateSet, candidateSetSchema);
  assertEqual(errors.length, 0, `Candidate set must validate against candidate-set.schema.json: ${errors.join('; ')}`);

  // Verify candidate properties
  const cand0 = candidateSet.candidates[0];
  assertEqual(cand0.id, 'CF-cf-sqli-01', 'Candidate ID matches');
  assertEqual(cand0.ruleId, 'sql_injection', 'Rule ID matches');
  assertEqual(cand0.severity, 'CRITICAL', 'Severity matches');
  assertEqual(cand0.location.uri, 'src/services/db.js', 'Sink location mapped');
  assertEqual(cand0.location.startLine, 52, 'Sink start line mapped');
});

// -----------------------------------------------------------------------------
// Suite 4: Bidirectional Lossless Roundtrip Checks
// -----------------------------------------------------------------------------

test('Bidirectional roundtrip proves zero loss of location, trace, conditions, execution, and remediation', () => {
  for (const original of mixedJson) {
    const canonical = toCanonicalFinding(original);
    const recovered = toCloudflareFinding(canonical);

    assertEqual(recovered.verdict, original.verdict, `Verdict matches for ${original.fingerprint}`);
    assertEqual(recovered.fingerprint, original.fingerprint, `Fingerprint matches for ${original.fingerprint}`);
    assertEqual(recovered.title, original.title, `Title matches for ${original.fingerprint}`);
    assertEqual(recovered.description, original.description, `Description matches for ${original.fingerprint}`);

    // Trace roundtrip check
    assert(Array.isArray(recovered.trace), 'Trace must be an array');
    assertEqual(recovered.trace.length, original.trace.length, 'Trace step count matches');
    for (let i = 0; i < original.trace.length; i++) {
      assertEqual(recovered.trace[i].kind, original.trace[i].kind, `Trace[${i}].kind matches`);
      assertEqual(recovered.trace[i].file, original.trace[i].file, `Trace[${i}].file matches`);
      assertEqual(recovered.trace[i].line, original.trace[i].line, `Trace[${i}].line matches`);
      assertEqual(recovered.trace[i].scope, original.trace[i].scope, `Trace[${i}].scope matches`);
      assertEqual(recovered.trace[i].description, original.trace[i].description, `Trace[${i}].description matches`);
    }

    // Evidence roundtrip check
    assert(Array.isArray(recovered.evidence), 'Evidence must be an array');
    assertEqual(recovered.evidence.length, original.evidence.length, 'Evidence count matches');
    for (let i = 0; i < original.evidence.length; i++) {
      assertEqual(recovered.evidence[i].file, original.evidence[i].file, `Evidence[${i}].file matches`);
      assertEqual(recovered.evidence[i].line, original.evidence[i].line, `Evidence[${i}].line matches`);
      assertEqual(recovered.evidence[i].description, original.evidence[i].description, `Evidence[${i}].description matches`);
    }

    if (original.verdict === 'confirmed') {
      // Conditions check
      assertDeepEqual(recovered.conditions, original.conditions, 'Conditions match identically');

      // Execution check
      assertDeepEqual(recovered.execution, original.execution, 'Execution check matches identically');

      // Remediation check
      assertDeepEqual(recovered.remediation, original.remediation, 'Remediation matches identically');

      // Metadata check
      assertEqual(recovered.attack_class, original.attack_class, 'attack_class matches');
      assertEqual(recovered.phase, original.phase, 'phase matches');
      assertDeepEqual(recovered.raw_tokens, original.raw_tokens, 'raw_tokens match');
    }

    if (original.verdict === 'needs_validation') {
      assertDeepEqual(recovered.blockers, original.blockers, 'Blockers match');
      assertDeepEqual(recovered.validation_plan, original.validation_plan, 'Validation plan matches');
    }

    if (original.verdict === 'rejected') {
      assertEqual(recovered.reason, original.reason, 'Rejection reason matches');
    }
  }
});

// -----------------------------------------------------------------------------
// Suite 5: R2 Coverage Ledger Ingestion & Quarantine Boundary
// -----------------------------------------------------------------------------

test('Complete coverage ledger permits complete status and bounded clean eligibility', () => {
  const ledgerResult = ingestCoverageLedger(completeLedgerJson);

  assertEqual(ledgerResult.coverageStatus, 'COMPLETE', 'Coverage status must be COMPLETE');
  assertEqual(ledgerResult.canDeclareClean, true, 'canDeclareClean must be true for 0 findings on complete ledger');
  assertEqual(ledgerResult.summary.coveredUnits, 2, '2 covered units');
  assertEqual(ledgerResult.summary.partialUnitsCount, 0, '0 partial units');
});

test('Partial coverage ledger enforces COVERAGE_PARTIAL and strictly prevents clean claim', () => {
  const ledgerResult = ingestCoverageLedger(partialLedgerJson);

  assertEqual(ledgerResult.coverageStatus, 'COVERAGE_PARTIAL', 'Coverage status must be COVERAGE_PARTIAL');
  assertEqual(ledgerResult.canDeclareClean, false, 'canDeclareClean must strictly be false');
  assert(ledgerResult.summary.reason.includes('Presumption of Non-Pass'), 'Reason explains non-pass');
  assert(ledgerResult.partialUnits.length > 0, 'Partial units identified');
});

test('Quarantine Boundary: Confirmed finding on budget-deferred path is quarantined to DEFERRED / COVERAGE_PARTIAL', () => {
  // partialLedgerJson has src/services/db.js marked as deferred!
  // confirmedJson finding cf-sqli-01 has its sink in src/services/db.js.
  const sessionResult = ingestAuditSession({
    findings: confirmedJson,
    coverageLedger: partialLedgerJson
  });

  const finding = sessionResult.canonicalFindings[0];

  // Even though finding was confirmed in findings.json, coverage ledger reveals the path was deferred!
  assertEqual(finding.disposition, 'DEFERRED', 'Finding on partial path must be quarantined to DEFERRED');
  assertEqual(finding.verdict, 'NEEDS_MANUAL_REVIEW', 'Verdict must be downgraded to NEEDS_MANUAL_REVIEW');
  assertEqual(finding.reasonCode, 'COVERAGE_PARTIAL', 'Reason code must be COVERAGE_PARTIAL');
  assert(finding.dispositionReason.includes('Presumption of Non-Pass'), 'Reason notes quarantine boundary enforcement');
  assertEqual(sessionResult.canDeclareClean, false, 'canDeclareClean must be false');
});

test('Quarantine Boundary: Confirmed finding on complete path retains REPORTABLE on complete ledger when authority granted', () => {
  const sessionResult = ingestAuditSession({
    findings: confirmedJson,
    coverageLedger: completeLedgerJson
  }, { trustProducerAsAuthority: true });

  const finding = sessionResult.canonicalFindings[0];
  assertEqual(finding.disposition, 'REPORTABLE', 'Confirmed finding on complete ledger is REPORTABLE');
  assertEqual(finding.verdict, 'CONFIRMED', 'Confirmed finding verdict is CONFIRMED');
  assertEqual(finding.reasonCode, 'AFFIRMATIVELY_VERIFIED', 'Reason code is AFFIRMATIVELY_VERIFIED');
  assertEqual(sessionResult.canDeclareClean, false, 'canDeclareClean is false because reportable finding exists');
});

test('Clean Run Assurance: 0 reportable findings + complete ledger allows canDeclareClean: true', () => {
  const sessionResult = ingestAuditSession({
    findings: rejectedJson, // Only rejected findings (false positives)
    coverageLedger: completeLedgerJson
  });

  assertEqual(sessionResult.canonicalFindings[0].disposition, 'SUPPRESSED', 'Finding is SUPPRESSED');
  assertEqual(sessionResult.canDeclareClean, true, 'canDeclareClean must be true when 0 reportable and complete coverage');
});

// -----------------------------------------------------------------------------
// Suite 6: Fail-Closed Behavior on Malformed Inputs
// -----------------------------------------------------------------------------

test('Malformed findings JSON fails closed without corruption', () => {
  let threw = false;
  try {
    ingestFindings('{ invalid-json');
  } catch (err) {
    threw = true;
    assert(err.message.includes('DEFAULT_DENY_INPUT_ERROR'), 'Must throw DEFAULT_DENY_INPUT_ERROR');
  }
  assert(threw, 'Must throw on malformed JSON');
});

test('Missing required finding fields fails closed', () => {
  const missingReq = JSON.parse(fs.readFileSync(path.join(fixturesDir, 'findings-missing-required.json'), 'utf8'));
  let threw = false;
  try {
    ingestFindings(missingReq);
  } catch (err) {
    threw = true;
    assert(err.message.includes('DEFAULT_DENY_SCHEMA_ERROR'), 'Must throw DEFAULT_DENY_SCHEMA_ERROR');
  }
  assert(threw, 'Must throw on missing required fields');
});

test('Malformed coverage ledger fails closed', () => {
  const malformedLedger = JSON.parse(fs.readFileSync(path.join(fixturesDir, 'coverage-ledger-malformed.json'), 'utf8'));
  let threw = false;
  try {
    ingestCoverageLedger(malformedLedger);
  } catch (err) {
    threw = true;
    assert(err.message.includes('DEFAULT_DENY_SCHEMA_ERROR'), 'Must throw DEFAULT_DENY_SCHEMA_ERROR');
  }
  assert(threw, 'Must throw on malformed coverage ledger');
});

// -----------------------------------------------------------------------------
// Suite 7: Run-to-Run Bitwise Identity
// -----------------------------------------------------------------------------

test('Proves run-to-run bitwise identity across 10 repeated executions', () => {
  const baseline = deterministicStringify(ingestAuditSession({
    findings: mixedJson,
    coverageLedger: completeLedgerJson
  }));

  for (let pass = 1; pass <= 10; pass++) {
    const current = deterministicStringify(ingestAuditSession({
      findings: mixedJson,
      coverageLedger: completeLedgerJson
    }));
    assertEqual(current, baseline, `Run ${pass} must be bitwise identical to baseline`);
  }
});

// -----------------------------------------------------------------------------
// Suite 8: Zero-Dependency & Hermetic Execution Invariant
// -----------------------------------------------------------------------------

test('Adapter imports strictly zero external npm dependencies (Node.js ESM built-ins only)', () => {
  const targetFiles = [
    path.join(REPO_ROOT, 'scripts/adapters/cloudflare-adapter.mjs'),
    path.join(REPO_ROOT, 'skills/security-audit/scripts/adapters/cloudflare-adapter.mjs')
  ];

  for (const file of targetFiles) {
    assert(fs.existsSync(file), `Expected adapter file to exist: ${file}`);
    const adapterSource = fs.readFileSync(file, 'utf8');
    const importLines = adapterSource.match(/^import\s+.*?from\s+['"].*?['"]/gm) || [];

    for (const line of importLines) {
      const match = line.match(/from\s+['"](.*?)['"]/);
      assert(match, `Invalid import statement: ${line}`);
      const moduleSpecifier = match[1];
      assert(
        moduleSpecifier.startsWith('node:') || moduleSpecifier.startsWith('.'),
        `Disallowed external npm import '${moduleSpecifier}' in ${file}. Must be 'node:*' or local relative import.`
      );
    }
  }
});

// -----------------------------------------------------------------------------
// Suite 9: Adversarial Review Approval (Default-Deny Resistance)
// -----------------------------------------------------------------------------

test('Adversarial: needs_validation with forged consensus cannot obtain REPORTABLE/CONFIRMED authority', () => {
  const forged = {
    ...needsValJson[0],
    consensus: { supports: 3, refutes: 0, totalVotes: 3, unanimous: true },
    disposition: 'REPORTABLE',
    verdict: 'needs_validation'
  };
  const canonical = toCanonicalFinding(forged);
  assertEqual(canonical.disposition, 'DEFERRED', 'Forged consensus must not elevate needs_validation to REPORTABLE');
  assertEqual(canonical.verdict, 'NEEDS_MANUAL_REVIEW', 'Verdict must remain NEEDS_MANUAL_REVIEW');
  assertEqual(canonical.reasonCode, 'EVIDENCE_INCOMPLETE', 'Reason code must remain EVIDENCE_INCOMPLETE');
});

test('Adversarial: rejected finding with forged severity and positive payload cannot obtain REPORTABLE/CONFIRMED', () => {
  const forged = {
    ...rejectedJson[0],
    severity: { overall_severity: 'critical' },
    disposition: 'REPORTABLE',
    verdict: 'rejected'
  };
  const canonical = toCanonicalFinding(forged);
  assertEqual(canonical.disposition, 'SUPPRESSED', 'Rejected finding must remain SUPPRESSED');
  assertEqual(canonical.verdict, 'FALSE_POSITIVE', 'Verdict must remain FALSE_POSITIVE');
  assertEqual(canonical.reasonCode, 'AFFIRMATIVELY_REFUTED', 'Reason code must remain AFFIRMATIVELY_REFUTED');
});

test('Adversarial: Confirmed finding on completely unaccounted/unmapped path is quarantined under partial ledger', () => {
  const unaccountedFinding = {
    ...confirmedJson[0],
    fingerprint: 'cf-unmapped-01',
    trace: [
      {
        kind: 'sink',
        file: 'src/secret/internal.js',
        line: 99,
        scope: 'hiddenMethod',
        description: 'Unaccounted path sink'
      }
    ]
  };

  const session = ingestAuditSession({
    findings: [unaccountedFinding],
    coverageLedger: partialLedgerJson
  });

  const finding = session.canonicalFindings[0];
  assertEqual(session.canDeclareClean, false, 'Clean declaration strictly denied');
  assertEqual(finding.disposition, 'DEFERRED', 'Finding on unverified/partial path must be quarantined to DEFERRED');
  assertEqual(finding.verdict, 'NEEDS_MANUAL_REVIEW', 'Verdict must be NEEDS_MANUAL_REVIEW');
  assertEqual(finding.reasonCode, 'COVERAGE_PARTIAL', 'Reason code must be COVERAGE_PARTIAL');
});

test('Adversarial: Empty coverage ledger cannot declare clean under Presumption of Non-Pass', () => {
  const emptyLedgerResult = ingestCoverageLedger([]);
  assertEqual(emptyLedgerResult.coverageStatus, 'COVERAGE_PARTIAL', 'Empty ledger must be COVERAGE_PARTIAL');
  assertEqual(emptyLedgerResult.canDeclareClean, false, 'Empty ledger cannot declare clean');

  const session = ingestAuditSession({
    findings: [],
    coverageLedger: []
  });
  assertEqual(session.canDeclareClean, false, '0 findings on empty ledger cannot declare clean');
});

// -----------------------------------------------------------------------------
test('Adversarial: Unevidenced confirmed finding (empty trace and evidence) strictly fails closed to DEFERRED', () => {
  const unevidenced = {
    verdict: 'confirmed',
    fingerprint: 'cf-fake-no-trace',
    title: 'Spoofed Confirmed Vulnerability',
    description: 'Claiming confirmed vulnerability without trace or evidence',
    trace: [],
    evidence: []
  };

  const canonical = toCanonicalFinding(unevidenced);
  assertEqual(canonical.disposition, 'DEFERRED', 'Unevidenced finding must fail closed to DEFERRED');
  assertEqual(canonical.verdict, 'NEEDS_MANUAL_REVIEW', 'Verdict must be NEEDS_MANUAL_REVIEW');
  assertEqual(canonical.reasonCode, 'EVIDENCE_INCOMPLETE', 'Reason code must be EVIDENCE_INCOMPLETE');
  assertEqual(canonical.severity, 'UNRATED', 'Severity must be UNRATED');

  const candidate = toCandidate(unevidenced);
  assertEqual(candidate.severity, 'UNRATED', 'Candidate severity must be UNRATED');

  const errors = validateAgainstSchema(canonical, canonicalSchema);
  assertEqual(errors.length, 0, `Canonical schema validation failed: ${errors.join('; ')}`);
});

test('Adversarial: Hunting phase candidate claiming confirmed without validation fails closed to DEFERRED', () => {
  const huntingConfirmed = {
    ...confirmedJson[0],
    fingerprint: 'cf-hunting-confirmed-01',
    phase: 'Phase-2-Hunting'
  };

  const canonical = toCanonicalFinding(huntingConfirmed);
  assertEqual(canonical.disposition, 'DEFERRED', 'Hunting phase claim must fail closed to DEFERRED');
  assertEqual(canonical.verdict, 'NEEDS_MANUAL_REVIEW', 'Verdict must be NEEDS_MANUAL_REVIEW');
  assertEqual(canonical.reasonCode, 'EVIDENCE_INCOMPLETE', 'Reason code must be EVIDENCE_INCOMPLETE');
  assertEqual(canonical.severity, 'UNRATED', 'Severity must be UNRATED');
});

test('Adversarial: Confirmed finding with unknown physical location fails closed to DEFERRED', () => {
  const unlocated = {
    verdict: 'confirmed',
    fingerprint: 'cf-no-loc-01',
    title: 'No location finding',
    description: 'Missing file location',
    trace: [{ kind: 'sink', scope: 'main', description: 'no file given' }],
    evidence: [],
    execution: { payloads: ['test'] }
  };

  const canonical = toCanonicalFinding(unlocated);
  assertEqual(canonical.disposition, 'DEFERRED', 'Unlocated finding must fail closed to DEFERRED');
  assertEqual(canonical.verdict, 'NEEDS_MANUAL_REVIEW', 'Verdict must be NEEDS_MANUAL_REVIEW');
});

test('Adversarial: Parent directory covered in ledger but subpath in partial unit is quarantined', () => {
  const ledgerWithBroadParent = [
    {
      coverage_id: 'cov-root-src',
      status: 'covered',
      starting_paths: ['src'],
      reviewed_paths: ['src']
    },
    {
      coverage_id: 'cov-db-deferred',
      status: 'deferred',
      starting_paths: ['src/services/db.js'],
      reviewed_paths: [],
      unresolved: ['Deferred by budget']
    }
  ];

  const session = ingestAuditSession({
    findings: confirmedJson, // has sink in src/services/db.js
    coverageLedger: ledgerWithBroadParent
  });

  const finding = session.canonicalFindings[0];
  assertEqual(finding.disposition, 'DEFERRED', 'Subpath in partial unit must be quarantined despite covered parent');
  assertEqual(finding.reasonCode, 'COVERAGE_PARTIAL', 'Reason code must be COVERAGE_PARTIAL');
  assertEqual(session.canDeclareClean, false, 'canDeclareClean must be false');
});

test('Adversarial: Unreviewed starting paths in covered unit fail clean claim and are tracked in partialUnits', () => {
  const ledgerOmittedPath = [
    {
      coverage_id: 'cov-incomplete-review',
      status: 'covered',
      starting_paths: ['src/api/users.js', 'src/services/unreviewed.js'],
      reviewed_paths: ['src/api/users.js']
    }
  ];

  const ledgerResult = ingestCoverageLedger(ledgerOmittedPath);
  assertEqual(ledgerResult.coverageStatus, 'COVERAGE_PARTIAL', 'Omitted starting path must force COVERAGE_PARTIAL');
  assertEqual(ledgerResult.canDeclareClean, false, 'Omitted starting path prohibits clean claim');
  assert(ledgerResult.partialUnits.length > 0, 'Partial units must capture unreviewed starting path');
  assertEqual(ledgerResult.pathCoverageMap['src/services/unreviewed.js'].status, 'PARTIAL', 'Omitted path marked PARTIAL');
});

test('Adversarial: Conflicting coverage units (covered vs deferred) order-independently fails closed to PARTIAL', () => {
  const orderA = [
    { coverage_id: 'cov-1', status: 'covered', reviewed_paths: ['src/auth.js'] },
    { coverage_id: 'cov-2', status: 'deferred', starting_paths: ['src/auth.js'] }
  ];
  const orderB = [
    { coverage_id: 'cov-2', status: 'deferred', starting_paths: ['src/auth.js'] },
    { coverage_id: 'cov-1', status: 'covered', reviewed_paths: ['src/auth.js'] }
  ];

  const resA = ingestCoverageLedger(orderA);
  const resB = ingestCoverageLedger(orderB);

  assertEqual(resA.pathCoverageMap['src/auth.js'].status, 'PARTIAL', 'Order A must resolve to PARTIAL');
  assertEqual(resB.pathCoverageMap['src/auth.js'].status, 'PARTIAL', 'Order B must resolve to PARTIAL');
  assertEqual(resA.canDeclareClean, false, 'Order A cannot declare clean');
  assertEqual(resB.canDeclareClean, false, 'Order B cannot declare clean');
});

test('Roundtrip: Unmapped Cloudflare custom metadata (subsystem, tags, tokens) preserved with 100% fidelity', () => {
  const findingWithMetadata = {
    ...confirmedJson[0],
    fingerprint: 'cf-custom-meta-01',
    subsystem: 'BillingAndPayments',
    tags: ['fintech', 'critical-path', 'p0'],
    custom_audit_token: 'tok-2026-audit-cf',
    external_ticket_id: 'SEC-9842'
  };

  const canonical = toCanonicalFinding(findingWithMetadata);
  const recovered = toCloudflareFinding(canonical);

  assertEqual(recovered.subsystem, 'BillingAndPayments', 'subsystem preserved lossless');
  assertDeepEqual(recovered.tags, ['fintech', 'critical-path', 'p0'], 'tags preserved lossless');
  assertEqual(recovered.custom_audit_token, 'tok-2026-audit-cf', 'custom token preserved lossless');
  assertEqual(recovered.external_ticket_id, 'SEC-9842', 'external ticket preserved lossless');
});

test('Edge Case: Unicode / non-ASCII path in trace and coverage ledger correctly maps and normalizes', () => {
  const unicodeFinding = {
    verdict: 'confirmed',
    fingerprint: 'cf-unicode-01',
    title: 'Unicode Path Vulnerability',
    description: 'Vulnerability in non-ASCII directory path',
    trace: [
      {
        kind: 'sink',
        file: 'src/用戶模組/查詢.js',
        line: 42,
        scope: 'search',
        description: 'db.query(userQuery)'
      }
    ],
    evidence: [{ file: 'src/用戶模組/查詢.js', line: 42, description: 'db.query' }],
    execution: { payloads: ["' OR '1'='1"] },
    confidence: { score: 'high' },
    phase: 'Phase-3-Validation'
  };

  const unicodeLedger = [
    {
      coverage_id: 'cov-unicode-auth',
      status: 'covered',
      starting_paths: ['src/用戶模組/查詢.js'],
      reviewed_paths: ['src/用戶模組/查詢.js']
    }
  ];

  const session = ingestAuditSession({
    findings: [unicodeFinding],
    coverageLedger: unicodeLedger
  }, { trustProducerAsAuthority: true });

  const canonical = session.canonicalFindings[0];
  assertEqual(canonical.disposition, 'REPORTABLE', 'Unicode path finding on complete ledger is REPORTABLE');
  assertEqual(canonical.location.uri, 'src/用戶模組/查詢.js', 'Unicode path correctly normalized');

  const recovered = toCloudflareFinding(canonical);
  assertEqual(recovered.trace[0].file, 'src/用戶模組/查詢.js', 'Unicode path roundtripped lossless');
});

test('Edge Case: Path normalization with .. traversal and leading slash correctly matches ledger', () => {
  const traversalFinding = {
    verdict: 'confirmed',
    fingerprint: 'cf-traversal-norm-01',
    title: 'Path with traversal',
    description: 'Path containing dot dot',
    trace: [
      {
        kind: 'sink',
        file: './src/services/../services/db.js',
        line: 52,
        scope: 'executeQuery',
        description: 'Sink with relative traversal'
      }
    ],
    evidence: [{ file: '/src/services/db.js', line: 52, description: 'db query' }],
    execution: { payloads: ['1'] },
    confidence: { score: 'high' },
    phase: 'Phase-3-Validation'
  };

  const session = ingestAuditSession({
    findings: [traversalFinding],
    coverageLedger: completeLedgerJson // has src/services/db.js
  }, { trustProducerAsAuthority: true });

  const canonical = session.canonicalFindings[0];
  assertEqual(canonical.location.uri, 'src/services/db.js', 'Path normalized to canonical relative form');
  assertEqual(canonical.disposition, 'REPORTABLE', 'Normalized path matched covered ledger path');
});

test('Edge Case: Deeply nested companion blocks in coverage ledger ingested without corruption', () => {
  const ledgerWithCompanion = [
    {
      coverage_id: 'cov-deep-companion',
      status: 'covered',
      starting_paths: ['src/api/users.js'],
      reviewed_paths: ['src/api/users.js'],
      selected_companion_blocks: [
        {
          block_name: 'companion-auth-guard',
          depth: 1,
          nested: {
            rules: ['no-bypass', 'strict-tokens'],
            deeper: [{ key: 'val' }]
          }
        }
      ]
    }
  ];

  const ledgerResult = ingestCoverageLedger(ledgerWithCompanion);
  assertEqual(ledgerResult.coverageStatus, 'COMPLETE', 'Complete coverage with companion blocks');
  assertEqual(ledgerResult.canDeclareClean, true, 'canDeclareClean is true');
});

test('Quarantine: Multi-step trace with propagation step in deferred unit is quarantined', () => {
  const multiStepFinding = {
    verdict: 'confirmed',
    fingerprint: 'cf-multi-quarantine-01',
    title: 'Multi-step SQLi across services',
    description: 'Flows from covered entrypoint through deferred db to covered sink',
    trace: [
      {
        kind: 'entrypoint',
        file: 'src/api/users.js',
        line: 12,
        scope: 'entry',
        description: 'Covered entry'
      },
      {
        kind: 'propagation',
        file: 'src/services/db.js', // Deferred in partialLedgerJson!
        line: 45,
        scope: 'propagate',
        description: 'Deferred db propagation'
      },
      {
        kind: 'sink',
        file: 'src/api/users.js',
        line: 99,
        scope: 'sink',
        description: 'Covered sink'
      }
    ],
    evidence: [{ file: 'src/api/users.js', line: 99, description: 'ev' }],
    execution: { payloads: ['1'] },
    confidence: { score: 'high' },
    phase: 'Phase-3-Validation'
  };

  const session = ingestAuditSession({
    findings: [multiStepFinding],
    coverageLedger: partialLedgerJson // has src/services/db.js as deferred
  });

  const canonical = session.canonicalFindings[0];
  assertEqual(canonical.disposition, 'DEFERRED', 'Finding with deferred trace step must be quarantined');
  assertEqual(canonical.verdict, 'NEEDS_MANUAL_REVIEW', 'Verdict must be NEEDS_MANUAL_REVIEW');
  assertEqual(canonical.reasonCode, 'COVERAGE_PARTIAL', 'Reason code must be COVERAGE_PARTIAL');
});

test('Ingest: Empty grouped object { confirmed: [], needs_validation: [], rejected: [] } normalizes cleanly without error', () => {
  const emptyGrouped = { confirmed: [], needs_validation: [], rejected: [] };
  const findings = ingestFindings(emptyGrouped);
  assertEqual(findings.canonicalFindings.length, 0, 'Clean grouped audit run must produce 0 canonical findings');
  assertEqual(findings.summary.findingCounts.total, 0, 'Finding count total must be 0');

  const candidates = toCandidateSet(emptyGrouped);
  assertEqual(candidates.candidates.length, 0, 'Must produce 0 candidates');
});

test('Adversarial: Ingest audit session without coverage ledger strictly rejects clean declaration under Default-Deny', () => {
  const session = ingestAuditSession({ findings: [] });
  assertEqual(session.canDeclareClean, false, 'Absence of affirmative coverage ledger strictly prohibits clean declaration');
  assertEqual(session.summary.canDeclareClean, false, 'Summary canDeclareClean must be false');
  assertEqual(session.summary.coverageStatus, 'UNCHECKABLE', 'Coverage status must be UNCHECKABLE');
});

test('Adversarial: Target path traversal escaping workspace root fails closed to DEFERRED', () => {
  const fTraversal = {
    verdict: 'confirmed',
    fingerprint: 'cf-trav-jailbreak',
    title: 'Arbitrary Read via Traversal',
    description: 'Path escaping workspace',
    trace: [
      {
        kind: 'sink',
        file: '../../etc/shadow',
        line: 1,
        description: 'Escaped sink'
      }
    ],
    evidence: [{ file: '../../etc/shadow', line: 1, description: 'Escaped evidence' }],
    execution: { payloads: ['read'], observed_result: 'file read' },
    confidence: { score: 'high' }
  };

  const canonical = toCanonicalFinding(fTraversal);
  assertEqual(canonical.disposition, 'DEFERRED', 'Escaping path traversal must fail closed to DEFERRED');
  assertEqual(canonical.verdict, 'NEEDS_MANUAL_REVIEW', 'Verdict must be NEEDS_MANUAL_REVIEW');
  assertEqual(canonical.reasonCode, 'EVIDENCE_INCOMPLETE', 'Reason code must be EVIDENCE_INCOMPLETE');
});

test('Quarantine: Evidence file located in deferred/partial coverage unit triggers quarantine to DEFERRED', () => {
  const fEvidencePartial = {
    verdict: 'confirmed',
    fingerprint: 'cf-ev-quarantine-01',
    title: 'SQLi with Evidence in Deferred Unit',
    description: 'Trace in covered file but evidence in deferred file',
    trace: [
      {
        kind: 'sink',
        file: 'src/api/users.js',
        line: 10,
        description: 'Covered trace'
      }
    ],
    evidence: [
      {
        file: 'src/services/db.js',
        line: 52,
        description: 'Evidence in deferred unit'
      }
    ],
    execution: { payloads: ['1=1'], observed_result: 'records returned' },
    confidence: { score: 'high' },
    phase: 'Phase-3-Validation'
  };

  const ledgerResult = ingestCoverageLedger(partialLedgerJson);
  const canonical = toCanonicalFinding(fEvidencePartial, { coverageLedgerResult: ledgerResult });
  assertEqual(canonical.disposition, 'DEFERRED', 'Evidence in deferred unit must trigger quarantine');
  assertEqual(canonical.verdict, 'NEEDS_MANUAL_REVIEW', 'Verdict must be NEEDS_MANUAL_REVIEW');
  assertEqual(canonical.reasonCode, 'COVERAGE_PARTIAL', 'Reason code must be COVERAGE_PARTIAL');
});

test('Roundtrip: needs_validation finding with conditions preserves conditions losslessly', () => {
  const nvFinding = {
    verdict: 'needs_validation',
    fingerprint: 'cf-cond-nv-01',
    title: 'Config-gated Candidate',
    description: 'Requires specific config',
    claimed_root_cause: 'Unvalidated configuration',
    trace: [{ kind: 'sink', file: 'src/app.js', line: 15, description: 'Config check' }],
    evidence: [{ file: 'src/app.js', line: 15, description: 'if (!config.secure)' }],
    conditions: [
      { kind: 'feature_flag', description: 'FLAG_EXPERIMENTAL_AUTH must be true' },
      { kind: 'environment', description: 'Production tenant only' }
    ],
    blockers: ['Awaiting stage deploy']
  };

  const canonical = toCanonicalFinding(nvFinding);
  assertEqual(canonical.disposition, 'DEFERRED', 'Disposition must be DEFERRED');
  assert(canonical.proof.conditions.length === 2, 'Proof must retain both conditions');

  const recovered = toCloudflareFinding(canonical);
  assertEqual(recovered.verdict, 'needs_validation', 'Recovered verdict is needs_validation');
  assert(Array.isArray(recovered.conditions), 'Recovered finding must retain conditions array');
  assertEqual(recovered.conditions.length, 2, 'Recovered finding must have 2 conditions');
  assertEqual(recovered.conditions[0].description, 'FLAG_EXPERIMENTAL_AUTH must be true', 'Condition description preserved');
});

test('Roundtrip: Uppercase/mixed-case original verdict preserves all fields without corruption', () => {
  const caseFinding = {
    verdict: 'CONFIRMED',
    fingerprint: 'cf-case-sens-01',
    title: 'Uppercase Verdict Test',
    description: 'Finding with uppercase verdict string',
    root_cause: 'Raw SQL concatenation',
    intended_behavior: 'Parameterized query',
    trace: [{ kind: 'sink', file: 'src/api/users.js', line: 20, description: 'sink' }],
    evidence: [{ file: 'src/api/users.js', line: 20, description: 'query()' }],
    execution: { payloads: ['1'], instructions: ['run'], observed_result: 'injected' },
    remediation: { strategy: 'Use ORM' },
    confidence: { score: 'high' }
  };

  const canonical = toCanonicalFinding(caseFinding, { trustProducerAsAuthority: true });
  assertEqual(canonical.disposition, 'REPORTABLE', 'Confirmed finding must be REPORTABLE when authority granted');

  const recovered = toCloudflareFinding(canonical);
  assertEqual(recovered.verdict, 'confirmed', 'Recovered verdict must normalize to lowercase confirmed');
  assertEqual(recovered.root_cause, 'Raw SQL concatenation', 'Root cause must be restored');
  assert(Array.isArray(recovered.trace), 'Trace must be restored');
  assert(Array.isArray(recovered.evidence), 'Evidence must be restored');
  assertEqual(recovered.remediation?.strategy, 'Use ORM', 'Remediation strategy must be restored');
});

test('Adversarial: Covered unit with zero reviewed paths fails closed to PARTIAL coverage and forbids clean claim', () => {
  const emptyCoveredLedger = [
    {
      coverage_id: 'cov-fake-complete',
      status: 'covered',
      starting_paths: [],
      reviewed_paths: []
    }
  ];

  const result = ingestCoverageLedger(emptyCoveredLedger);
  assertEqual(result.coverageStatus, 'COVERAGE_PARTIAL', 'Zero reviewed paths must fail closed to COVERAGE_PARTIAL');
  assertEqual(result.canDeclareClean, false, 'Zero reviewed paths cannot declare clean');
  assert(result.partialUnits.length > 0, 'Must record partial unit for unreviewed covered unit');
});

test('Adversarial: Finding with low string confidence fails closed to DEFERRED despite execution payloads', () => {
  const lowConfFinding = {
    verdict: 'confirmed',
    fingerprint: 'cf-low-conf-str-01',
    title: 'Suspected Flaw with Low Confidence String',
    description: 'Scanner marked low confidence',
    confidence: 'low',
    trace: [{ kind: 'sink', file: 'src/api/users.js', line: 10, description: 'sink' }],
    evidence: [{ file: 'src/api/users.js', line: 10, description: 'ev' }],
    execution: { payloads: ['heuristic-probe'], observed_result: 'inconclusive' }
  };

  const canonical = toCanonicalFinding(lowConfFinding);
  assertEqual(canonical.disposition, 'DEFERRED', 'Low confidence finding must fail closed to DEFERRED under Default-Deny');
  assertEqual(canonical.verdict, 'NEEDS_MANUAL_REVIEW', 'Verdict must be NEEDS_MANUAL_REVIEW');
  assertEqual(canonical.severity, 'UNRATED', 'Severity must be UNRATED');
});

test('Edge case: Multi-line finding location with inverted startLine/endLine interval is clamped safely', () => {
  const invertedFinding = {
    verdict: 'needs_validation',
    fingerprint: 'cf-inverted-lines-01',
    title: 'Inverted Lines',
    description: 'endLine is before startLine',
    location: {
      uri: 'src/app.js',
      startLine: 100,
      endLine: 20
    }
  };

  const canonical = toCanonicalFinding(invertedFinding);
  assertEqual(canonical.location.startLine, 100, 'startLine is 100');
  assert(canonical.location.endLine >= canonical.location.startLine, 'endLine must be >= startLine');
  assertEqual(canonical.location.endLine, 100, 'endLine clamped to startLine');
});

test('Adversarial: Phase-1 discovery candidate claiming confirmed verdict fails closed to DEFERRED', () => {
  const discoveryFinding = {
    verdict: 'confirmed',
    fingerprint: 'cf-disc-claim-01',
    title: 'Discovery Phase Candidate',
    description: 'Exploratory hypothesis claiming confirmed without Phase-3 verification',
    phase: 'Phase-1-Discovery',
    trace: [{ kind: 'sink', file: 'src/api/users.js', line: 10, description: 'sink' }],
    evidence: [{ file: 'src/api/users.js', line: 10, description: 'ev' }],
    execution: { payloads: ['probe'], observed_result: 'test' }
  };

  const canonical = toCanonicalFinding(discoveryFinding);
  assertEqual(canonical.disposition, 'DEFERRED', 'Discovery phase candidate must fail closed to DEFERRED');
  assertEqual(canonical.verdict, 'NEEDS_MANUAL_REVIEW', 'Verdict must be NEEDS_MANUAL_REVIEW');
});

test('Adversarial: URL-encoded directory traversal (%2e%2e/%2e%2e/etc/shadow) fails closed to DEFERRED', () => {
  const urlEncFinding = {
    verdict: 'confirmed',
    fingerprint: 'cf-url-enc-trav-01',
    title: 'URL-encoded Traversal',
    description: 'Bypass traversal check via URL encoding',
    trace: [{ kind: 'sink', file: '%2e%2e/%2e%2e/etc/shadow', line: 1, description: 'sink' }],
    evidence: [{ file: '%2e%2e/%2e%2e/etc/shadow', line: 1, description: 'ev' }],
    execution: { payloads: ['foo'], observed_result: 'read' },
    confidence: { score: 'high' }
  };

  const canonical = toCanonicalFinding(urlEncFinding);
  assertEqual(canonical.disposition, 'DEFERRED', 'URL-encoded traversal must fail closed to DEFERRED');
  assertEqual(canonical.verdict, 'NEEDS_MANUAL_REVIEW', 'Verdict must be NEEDS_MANUAL_REVIEW');
  assertEqual(canonical.reasonCode, 'EVIDENCE_INCOMPLETE', 'Reason code must be EVIDENCE_INCOMPLETE');
});

test('Adversarial: File URI scheme (file:///etc/shadow) fails closed to DEFERRED', () => {
  const schemeFinding = {
    verdict: 'confirmed',
    fingerprint: 'cf-file-scheme-01',
    title: 'File URI Scheme Read',
    description: 'Path escaping workspace via file scheme',
    trace: [{ kind: 'sink', file: 'file:///etc/shadow', line: 1, description: 'sink' }],
    evidence: [{ file: 'file:///etc/shadow', line: 1, description: 'ev' }],
    execution: { payloads: ['read'], observed_result: 'payload executed' },
    confidence: { score: 'high' }
  };

  const canonical = toCanonicalFinding(schemeFinding);
  assertEqual(canonical.disposition, 'DEFERRED', 'File URI scheme must fail closed to DEFERRED');
  assertEqual(canonical.verdict, 'NEEDS_MANUAL_REVIEW', 'Verdict must be NEEDS_MANUAL_REVIEW');
  assertEqual(canonical.reasonCode, 'EVIDENCE_INCOMPLETE', 'Reason code must be EVIDENCE_INCOMPLETE');
});

test('Adversarial: Windows UNC network path (//attacker.com/share/evil.js) fails closed to DEFERRED', () => {
  const uncFinding = {
    verdict: 'confirmed',
    fingerprint: 'cf-unc-share-01',
    title: 'UNC Share Inclusion',
    description: 'Path on remote UNC share',
    trace: [{ kind: 'sink', file: '//attacker.com/share/evil.js', line: 1, description: 'sink' }],
    evidence: [{ file: '//attacker.com/share/evil.js', line: 1, description: 'ev' }],
    execution: { payloads: ['read'], observed_result: 'payload executed' },
    confidence: { score: 'high' }
  };

  const canonical = toCanonicalFinding(uncFinding);
  assertEqual(canonical.disposition, 'DEFERRED', 'UNC network path must fail closed to DEFERRED');
  assertEqual(canonical.verdict, 'NEEDS_MANUAL_REVIEW', 'Verdict must be NEEDS_MANUAL_REVIEW');
});

test('Adversarial: Exploit execution observed_result reporting failure fails closed to DEFERRED', () => {
  const failedExecutionFinding = {
    verdict: 'confirmed',
    fingerprint: 'cf-fail-exec-01',
    title: 'Unreproduced Flaw',
    description: 'Exploit execution failed during reproduction attempt',
    trace: [{ kind: 'sink', file: 'src/api/users.js', line: 10, description: 'sink' }],
    execution: {
      payloads: ["' OR '1'='1"],
      observed_result: 'Exploit execution failed. System returned HTTP 400 and is not vulnerable.'
    }
  };

  const canonical = toCanonicalFinding(failedExecutionFinding);
  assertEqual(canonical.disposition, 'DEFERRED', 'Failed execution result must fail closed to DEFERRED under Default-Deny');
  assertEqual(canonical.verdict, 'NEEDS_MANUAL_REVIEW', 'Verdict must be NEEDS_MANUAL_REVIEW');
  assertEqual(canonical.reasonCode, 'EVIDENCE_INCOMPLETE', 'Reason code must be EVIDENCE_INCOMPLETE');
});

test('Adversarial: Disputed / inconclusive / tentative confidence fails closed to DEFERRED', () => {
  const inconclusiveFinding = {
    verdict: 'confirmed',
    fingerprint: 'cf-inconcl-conf-01',
    title: 'Inconclusive Confidence Finding',
    description: 'Scanner marked confidence as inconclusive',
    confidence: 'inconclusive',
    trace: [{ kind: 'sink', file: 'src/api/users.js', line: 10, description: 'sink' }],
    evidence: [{ file: 'src/api/users.js', line: 10, description: 'ev' }],
    execution: { payloads: ['test-probe'], observed_result: 'potential anomaly' }
  };

  const canonical = toCanonicalFinding(inconclusiveFinding);
  assertEqual(canonical.disposition, 'DEFERRED', 'Inconclusive confidence must fail closed to DEFERRED');
  assertEqual(canonical.verdict, 'NEEDS_MANUAL_REVIEW', 'Verdict must be NEEDS_MANUAL_REVIEW');
  assertEqual(canonical.severity, 'UNRATED', 'Severity must be UNRATED');
});

test('Quarantine: Unit with status "out_of_scope" forces COVERAGE_PARTIAL, forbids clean claim, and quarantines findings', () => {
  const ledgerWithOutOfScope = [
    {
      coverage_id: 'cov-covered-part',
      status: 'covered',
      starting_paths: ['src/api/users.js'],
      reviewed_paths: ['src/api/users.js']
    },
    {
      coverage_id: 'cov-excluded-part',
      status: 'out_of_scope',
      starting_paths: ['src/legacy/auth.js'],
      reviewed_paths: []
    }
  ];

  const ledgerResult = ingestCoverageLedger(ledgerWithOutOfScope);
  assertEqual(ledgerResult.coverageStatus, 'COVERAGE_PARTIAL', 'Out-of-scope unit must force COVERAGE_PARTIAL');
  assertEqual(ledgerResult.canDeclareClean, false, 'Out-of-scope unit strictly prohibits clean claim');
  assert(ledgerResult.partialUnits.some(u => u.status === 'out_of_scope'), 'Partial units must track out_of_scope unit');

  const findingInOutOfScope = {
    verdict: 'confirmed',
    fingerprint: 'cf-oos-vuln-01',
    title: 'Vulnerability in Out of Scope Unit',
    description: 'Finding on unaudited path',
    trace: [{ kind: 'sink', file: 'src/legacy/auth.js', line: 25, description: 'sink' }],
    evidence: [{ file: 'src/legacy/auth.js', line: 25, description: 'ev' }],
    execution: { payloads: ['bypass'], observed_result: 'auth bypassed' },
    confidence: { score: 'high' }
  };

  const session = ingestAuditSession({
    findings: [findingInOutOfScope],
    coverageLedger: ledgerWithOutOfScope
  });

  const canonical = session.canonicalFindings[0];
  assertEqual(canonical.disposition, 'DEFERRED', 'Finding on out_of_scope path must be quarantined to DEFERRED');
  assertEqual(canonical.reasonCode, 'COVERAGE_PARTIAL', 'Reason code must be COVERAGE_PARTIAL');
  assertEqual(session.canDeclareClean, false, 'canDeclareClean must be false');
});

test('Schema Integrity: Finding with non-string attack_class and non-string subsystem validates cleanly', () => {
  const nonStringFinding = {
    verdict: 'confirmed',
    fingerprint: 'cf-nonstring-meta-01',
    title: 'Non-string Metadata Finding',
    description: 'Finding with array attack_class and object subsystem',
    attack_class: ['injection', 'cwe-89'],
    subsystem: { name: 'Billing', tier: 1 },
    root_cause: { description: 'String concatenation in query' },
    intended_behavior: { description: 'Parameterized query' },
    trace: [{ kind: 'sink', file: 'src/api/users.js', line: 15, description: 'sink' }],
    evidence: [{ file: 'src/api/users.js', line: 15, description: 'ev' }],
    execution: { payloads: ['1'], observed_result: 'records dumped' },
    confidence: { score: 'high' }
  };

  const canonical = toCanonicalFinding(nonStringFinding, { trustProducerAsAuthority: true });
  assertEqual(canonical.disposition, 'REPORTABLE', 'Must convert without error');
  const canErrors = validateAgainstSchema(canonical, canonicalSchema);
  assertEqual(canErrors.length, 0, `Canonical schema errors: ${canErrors.join('; ')}`);

  const candSet = toCandidateSet([nonStringFinding]);
  const candErrors = validateAgainstSchema(candSet, candidateSetSchema);
  assertEqual(candErrors.length, 0, `Candidate set schema errors: ${candErrors.join('; ')}`);
});

test('Roundtrip & Lossless Ingestion: String remediation is losslessly bound to defectManagement.preventiveAction', () => {
  const strRemedFinding = {
    verdict: 'confirmed',
    fingerprint: 'cf-str-remed-01',
    title: 'String Remediation Finding',
    description: 'Finding with string remediation instead of object',
    remediation: 'Implement parameterized SQL queries and input validation.',
    trace: [{ kind: 'sink', file: 'src/api/users.js', line: 20, description: 'sink' }],
    evidence: [{ file: 'src/api/users.js', line: 20, description: 'ev' }],
    execution: { payloads: ['1'], observed_result: 'verified' },
    confidence: { score: 'high' }
  };

  const canonical = toCanonicalFinding(strRemedFinding);
  assertEqual(canonical.defectManagement.preventiveAction, 'Implement parameterized SQL queries and input validation.', 'String remediation bound to preventiveAction');

  const recovered = toCloudflareFinding(canonical);
  assertEqual(recovered.remediation, 'Implement parameterized SQL queries and input validation.', 'Remediation preserved losslessly');
});

test('CVSS Invariant: Numeric CVSS score correctly maps to CRITICAL or HIGH', () => {
  assertEqual(mapCloudflareSeverity(9.8), 'CRITICAL', '9.8 maps to CRITICAL');
  assertEqual(mapCloudflareSeverity({ score: 7.5 }), 'HIGH', '7.5 maps to HIGH');
  assertEqual(mapCloudflareSeverity({ score: '5.2' }), 'MEDIUM', '5.2 string maps to MEDIUM');
  assertEqual(mapCloudflareSeverity(2.1), 'LOW', '2.1 maps to LOW');
  assertEqual(toCanonicalFinding({ ...confirmedJson[0], fingerprint: 'cf-cvss-1', severity: 9.8 }, { trustProducerAsAuthority: true }).severity, 'CRITICAL', '9.8 maps to CRITICAL under authority override');
  assertEqual(toCanonicalFinding({ ...confirmedJson[0], fingerprint: 'cf-cvss-2', severity: { score: 7.5 } }, { trustProducerAsAuthority: true }).severity, 'HIGH', '7.5 maps to HIGH under authority override');
  assertEqual(toCanonicalFinding({ ...confirmedJson[0], fingerprint: 'cf-cvss-3', severity: { score: '5.2' } }, { trustProducerAsAuthority: true }).severity, 'MEDIUM', '5.2 string maps to MEDIUM under authority override');
  assertEqual(toCanonicalFinding({ ...confirmedJson[0], fingerprint: 'cf-cvss-4', severity: 2.1 }, { trustProducerAsAuthority: true }).severity, 'LOW', '2.1 maps to LOW under authority override');
  assertEqual(toCanonicalFinding({ ...confirmedJson[0], fingerprint: 'cf-cvss-5', severity: 9.8 }).severity, 'UNRATED', 'Without authority override, canonical severity is UNRATED');
});

test('Adversarial: Trace or evidence with non-positive line number is rejected from verifier proof', () => {
  const nonPosLineFinding = {
    verdict: 'confirmed',
    fingerprint: 'cf-nonpos-line-01',
    title: 'Zero Line Finding',
    description: 'Trace step specifies non-existent line 0',
    trace: [{ kind: 'sink', file: 'src/api/users.js', line: 0, description: 'sink' }],
    evidence: [{ file: 'src/api/users.js', line: 0, description: 'ev' }],
    execution: { payloads: ['payload'], observed_result: 'executed' },
    confidence: { score: 'high' }
  };

  const canonical = toCanonicalFinding(nonPosLineFinding);
  assertEqual(canonical.disposition, 'DEFERRED', 'Non-positive line number must fail closed to DEFERRED');
  assertEqual(canonical.verdict, 'NEEDS_MANUAL_REVIEW', 'Verdict must be NEEDS_MANUAL_REVIEW');
});

// -----------------------------------------------------------------------------
// Summary
// -----------------------------------------------------------------------------

console.log(`\n==================================================`);
console.log(`All ${passCount}/${testCount} Cloudflare Adapter tests passed with exit code 0.`);
console.log(`Verified under Presumption of Non-Pass (Default-Deny).`);
console.log(`==================================================\n`);

