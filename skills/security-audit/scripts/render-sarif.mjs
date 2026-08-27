#!/usr/bin/env node
/**
 * render-sarif.mjs
 * Generates SARIF 2.1.0 and Markdown reports for the AGY Security Audit Skill.
 * Implements objective mathematical rigor calculation, CVSS v4.0 verification,
 * Git provenance hashing, and double-blind swarm consensus summaries.
 */

import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { getHardenedGitProvenance } from './safe-git.mjs';
import {
  CVSS_V4_REGEX,
  normalizeUri,
  calculateRigor,
  validateDirectoryManifest,
  computeLineHash,
  mapSeverityToSarif,
  stripControlAndBidi,
  sanitizeInlineText,
  sanitizeTableCell,
  sanitizeBlockText,
  sanitizeCodeSnippet,
  redactSecrets,
  validateCvssV4,
  deriveFinalDisposition,
  clampConfidence,
  finalizeScan,
  renderSarifFromCanonical,
  renderMarkdownFromCanonical
} from './finalize-scan.mjs';

export {
  CVSS_V4_REGEX,
  normalizeUri,
  calculateRigor,
  validateDirectoryManifest,
  computeLineHash,
  mapSeverityToSarif,
  stripControlAndBidi,
  sanitizeInlineText,
  sanitizeTableCell,
  sanitizeBlockText,
  sanitizeCodeSnippet,
  redactSecrets,
  validateCvssV4,
  deriveFinalDisposition,
  clampConfidence,
  finalizeScan,
  renderSarifFromCanonical,
  renderMarkdownFromCanonical
};

/**
 * Escapes characters that could trigger markdown/HTML injection in reports.
 * Maintained for backward compatibility; delegates to sanitizeInlineText.
 */
export function escapeMarkdown(str) {
  return sanitizeInlineText(str);
}

/**
 * Extracts Git VCS Provenance using safe hardened environment.
 */
export function getGitProvenance(repoRoot) {
  return getHardenedGitProvenance(repoRoot);
}



/**
 * Builds standard SARIF 2.1.0 document.
 * Centralized through finalizeScan to enforce default-deny and canonical contract.
 */
export function renderSarif({ findings = [], manifest = null, provenance = null, repoRoot = process.cwd(), votes = [] }) {
  const finalization = finalizeScan({
    candidates: findings,
    manifest,
    repoRoot,
    provenance,
    votes
  });
  return renderSarifFromCanonical({
    canonicalFindings: finalization.canonicalFindings,
    manifest: finalization.manifest,
    coverageStatus: finalization.coverageStatus,
    provenance: finalization.provenance,
    repoRoot
  });
}

/**
 * Builds Human-Readable Markdown Audit Report with strict entity escaping and default-deny.
 * Centralized through finalizeScan to guarantee 100% parity with SARIF and JSON.
 */
export function renderMarkdown({ findings = [], manifest = null, provenance = null, repoRoot = process.cwd(), votes = [] }) {
  const finalization = finalizeScan({
    candidates: findings,
    manifest,
    repoRoot,
    provenance,
    votes
  });
  return renderMarkdownFromCanonical({
    canonicalFindings: finalization.canonicalFindings,
    manifest: finalization.manifest,
    coverageStatus: finalization.coverageStatus,
    provenance: finalization.provenance
  });
}


// -----------------------------------------------------------------------------
// Self-Contained Automated Test Suite (--test)
// -----------------------------------------------------------------------------
export function runTests() {
  console.log('Running test suite for render-sarif.mjs and finalize-scan.mjs (P0 Hardening)...');

  // 1. Rigor calculation test
  const fullMetrics = {
    sinkVerified: true,
    sourceVerified: true,
    dataflowVerifiedSteps: 4,
    dataflowTotalSteps: 4,
    pocSyntacticDemonstrated: true,
    mitigationInspected: true
  };
  const r1 = calculateRigor(fullMetrics);
  if (r1.score !== 1.0 || r1.assuranceLevel !== 'HIGH_RIGOR') {
    throw new Error(`Rigor test failed for full metrics: ${JSON.stringify(r1)}`);
  }

  const zeroMetrics = {};
  const r0 = calculateRigor(zeroMetrics);
  if (r0.score !== 0.0 || r0.assuranceLevel !== 'LOW_RIGOR') {
    throw new Error(`Rigor test failed for zero metrics: ${JSON.stringify(r0)}`);
  }
  console.log('✔ 1. Mathematical Rigor calculation tests passed.');

  // 2. CVSS v4 vector validation test
  const validVector = 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N';
  if (!CVSS_V4_REGEX.test(validVector)) {
    throw new Error(`Valid CVSS v4 vector rejected: ${validVector}`);
  }
  const invalidVector = 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H';
  if (CVSS_V4_REGEX.test(invalidVector)) {
    throw new Error(`Invalid CVSS v4 vector accepted: ${invalidVector}`);
  }
  const cvssRes = validateCvssV4({ vector: invalidVector, score: 9.0 });
  if (cvssRes.valid || cvssRes.vector !== null) {
    throw new Error('Invalid CVSS v4 vector was not rejected fail-closed');
  }
  console.log('✔ 2. CVSS v4.0 vector validation and fail-closed rejection tests passed.');

  // 3. Path normalization & RFC 3986 test
  const winPath = 'src\\controllers\\auth [admin].ts';
  const uri = normalizeUri('C:\\project', 'C:\\project\\' + winPath);
  if (uri.includes('\\') || !uri.includes('auth%20%5Badmin%5D.ts')) {
    throw new Error(`Path normalization failed: ${uri}`);
  }
  console.log('✔ 3. RFC 3986 URI & backslash normalization tests passed.');

  // 4. Directory manifest validation
  const validManifest = {
    entries: [
      { path: 'src/', status: 'SCANNED', fileCount: 10, reason: 'Source code' },
      { path: 'dist/', status: 'EXCLUDED_GENERATED', fileCount: 5, reason: 'Build output' }
    ]
  };
  const mv = validateDirectoryManifest(validManifest);
  if (!mv.valid) {
    throw new Error(`Valid manifest rejected: ${mv.error}`);
  }

  const invalidManifest = {
    entries: [
      { path: 'legacy/', status: 'UNKNOWN_FOLDER', fileCount: 1 }
    ]
  };
  const miv = validateDirectoryManifest(invalidManifest);
  if (miv.valid || !miv.error.includes('UNACCOUNTED_DIRECTORY_ERROR')) {
    throw new Error(`Unaccounted directory not flagged: ${JSON.stringify(miv)}`);
  }
  console.log('✔ 4. Directory Accounting reconciliation manifest tests passed.');

  // 5. Empty manifest rejection test
  const emptyManifest = { entries: [] };
  const emTest = validateDirectoryManifest(emptyManifest);
  if (emTest.valid || !emTest.error.includes('UNACCOUNTED_DIRECTORY_ERROR')) {
    throw new Error('Empty manifest was not rejected!');
  }
  console.log('✔ 5. Empty manifest rejection test passed.');

  // 6. Confirmed SARIF Generation with validated consensus
  const confirmedFindings = [
    {
      id: 'SEC-001',
      ruleId: 'CWE-89',
      title: 'SQL Injection in Auth',
      severity: 'CRITICAL',
      cvssV4: {
        vector: validVector,
        score: 9.3,
        severity: 'CRITICAL'
      },
      location: {
        uri: 'src/auth.ts',
        startLine: 42,
        endLine: 44,
        lineSnippet: 'const query = `SELECT * FROM users WHERE name = "${input}"`;'
      },
      rigorMetrics: fullMetrics,
      consensus: {
        totalVotes: 3,
        unanimous: true
      }
    }
  ];

  const sarif = renderSarif({ findings: confirmedFindings, manifest: validManifest });
  if (sarif.version !== '2.1.0') throw new Error('SARIF version must be 2.1.0');
  if (sarif.runs[0].tool.driver.rules.length !== 1) throw new Error('Rule was not registered in driver.rules');
  if (sarif.runs[0].results[0].level !== 'error') throw new Error('Critical confirmed finding must map to level error');
  if (sarif.runs[0].results[0].properties.disposition !== 'REPORTABLE') throw new Error('Finding should be REPORTABLE');
  console.log('✔ 6. SARIF 2.1.0 schema compliance and level mapping tests passed.');

  // 7. P0 Invariant: Anti-Self-Assertion (0 votes cannot be CONFIRMED)
  const zeroVotesFinding = [
    {
      id: 'SEC-002',
      ruleId: 'CWE-89',
      title: 'Self-Asserted SQLi',
      severity: 'CRITICAL',
      location: { uri: 'src/auth.ts', startLine: 10 },
      verdict: 'CONFIRMED' // Attempt to self-assert CONFIRMED with 0 votes
    }
  ];
  const zeroVotesSarif = renderSarif({ findings: zeroVotesFinding, manifest: validManifest });
  const zeroResult = zeroVotesSarif.runs[0].results[0];
  if (zeroResult.properties.disposition === 'REPORTABLE' || zeroResult.properties.verdict === 'CONFIRMED') {
    throw new Error('P0 VIOLATION: Finding with 0 votes was accepted as CONFIRMED / REPORTABLE!');
  }
  if (zeroResult.properties.disposition !== 'DEFERRED' || zeroResult.properties.verdict !== 'NEEDS_MANUAL_REVIEW') {
    throw new Error('Finding with 0 votes was not downgraded to DEFERRED / NEEDS_MANUAL_REVIEW');
  }
  console.log('✔ 7. P0 Invariant: 0 votes != CONFIRMED (Self-asserted finding downgraded to DEFERRED).');

  // 8. P0 Invariant: Quorum rule (1 vote alone cannot confirm)
  const singleVoteFinding = {
    id: 'SEC-003',
    ruleId: 'CWE-79',
    title: 'XSS Candidate',
    location: { uri: 'src/view.ts', startLine: 20 },
    rigorMetrics: fullMetrics
  };
  const singleVote = [
    { findingId: 'SEC-003', reviewerId: 'rev-1', decision: 'CONFIRMED' }
  ];
  const quorumTest = deriveFinalDisposition(singleVoteFinding, singleVote, calculateRigor(fullMetrics));
  if (quorumTest.disposition === 'REPORTABLE') {
    throw new Error('P0 VIOLATION: Single vote satisfied quorum!');
  }
  console.log('✔ 8. P0 Invariant: Quorum requires at least 2 independent votes.');

  // 9. P0 Invariant: Vote deduplication (same reviewer/persona cannot vote twice)
  const duplicateVotes = [
    { findingId: 'SEC-003', reviewerId: 'rev-1', persona: 'ExploitHacker', decision: 'CONFIRMED' },
    { findingId: 'SEC-003', reviewerId: 'rev-1', persona: 'ExploitHacker', decision: 'CONFIRMED' }
  ];
  const dedupTest = deriveFinalDisposition(singleVoteFinding, duplicateVotes, calculateRigor(fullMetrics));
  if (dedupTest.disposition === 'REPORTABLE') {
    throw new Error('P0 VIOLATION: Duplicate votes by same reviewer satisfied quorum!');
  }
  console.log('✔ 9. P0 Invariant: Duplicate votes from same reviewer/persona are deduplicated.');

  // 10. P0 Invariant: Decisive counterevidence refutation
  const counterevidenceVotes = [
    { findingId: 'SEC-003', reviewerId: 'rev-1', decision: 'CONFIRMED' },
    {
      findingId: 'SEC-003',
      reviewerId: 'rev-2',
      decision: 'FALSE_POSITIVE',
      mitigationProofLine: 18,
      mitigationReason: 'DOMPurify.sanitize neutralizes untrusted payload'
    },
    {
      findingId: 'SEC-003',
      reviewerId: 'rev-3',
      decision: 'FALSE_POSITIVE',
      mitigationProofLine: 18,
      mitigationReason: 'DOMPurify.sanitize neutralizes untrusted payload'
    }
  ];
  const refutedTest = deriveFinalDisposition(singleVoteFinding, counterevidenceVotes, calculateRigor(fullMetrics));
  if (refutedTest.disposition !== 'SUPPRESSED' || refutedTest.mappedVerdict !== 'FALSE_POSITIVE') {
    throw new Error('P0 VIOLATION: Decisive counterevidence was not honored as SUPPRESSED / FALSE_POSITIVE');
  }
  console.log('✔ 10. P0 Invariant: Decisive counterevidence suppresses finding to FALSE_POSITIVE.');

  // 11. P0 Invariant: Confidence clamping
  const clamp2of3 = clampConfidence('REPORTABLE', { total: 3, unanimous: false });
  if (clamp2of3.score > 0.70 || clamp2of3.level !== 'medium') {
    throw new Error(`P0 VIOLATION: Non-unanimous panel confidence not clamped to medium: ${JSON.stringify(clamp2of3)}`);
  }
  const clamp3of3 = clampConfidence('REPORTABLE', { total: 3, unanimous: true });
  if (clamp3of3.level !== 'high') {
    throw new Error(`P0 VIOLATION: Unanimous panel confidence should be high: ${JSON.stringify(clamp3of3)}`);
  }
  console.log('✔ 11. P0 Invariant: Confidence clamping (2/3 -> medium, 3/3 -> high).');

  // 12. P0 Invariant: Deterministic Secret Redaction
  const leakText = 'Found AWS key AKIAIOSFODNN7EXAMPLE and bearer eyJhbGciOiJIUzI1NiJ9.test and password: "SecretPassword123!"';
  const redacted = redactSecrets(leakText);
  if (redacted.includes('AKIAIOSFODNN7EXAMPLE') || redacted.includes('SecretPassword123!')) {
    throw new Error(`P0 VIOLATION: Raw secrets not redacted: ${redacted}`);
  }
  if (!redacted.includes('[REDACTED_AWS_ACCESS_KEY') || !redacted.includes('[REDACTED_GENERIC_SECRET_KV')) {
    throw new Error(`P0 VIOLATION: Redaction fingerprint markers missing: ${redacted}`);
  }
  console.log('✔ 12. P0 Invariant: Deterministic secret redaction masks credentials with fingerprints.');

  // 13. P0 Invariant: Credential finding lineSnippet complete suppression
  const credentialFinding = [
    {
      id: 'SEC-004',
      ruleId: 'CWE-798',
      title: 'Hardcoded API Secret',
      location: {
        uri: 'config/keys.ts',
        startLine: 5,
        lineSnippet: 'export const apiKey = "AIzaSyD-Secret123456789";'
      },
      consensus: { totalVotes: 3, unanimous: true },
      sourceVerified: true
    }
  ];
  const credSarif = renderSarif({ findings: credentialFinding, manifest: validManifest });
  const credSnippet = credSarif.runs[0].results[0].properties?.location?.lineSnippet ||
    credSarif.runs[0].results[0].locations[0].physicalLocation.artifactLocation.uri;
  const credMd = renderMarkdown({ findings: credentialFinding, manifest: validManifest });
  if (credMd.includes('AIzaSyD-Secret123456789')) {
    throw new Error('P0 VIOLATION: Credential finding leaked raw secret in report!');
  }
  if (!credMd.includes('Line snippet suppressed for credential finding')) {
    throw new Error('P0 VIOLATION: Credential snippet suppression marker not emitted');
  }
  console.log('✔ 13. P0 Invariant: Credential findings suppress raw line snippet completely.');

  // 14. P0 Invariant: Markdown & Terminal Output Injection Hardening
  const injectedFinding = [
    {
      id: 'SEC-005',
      ruleId: 'CWE-79',
      title: 'XSS <script>alert(1)</script> \x1B[31mRedText\x1B[0m \u202Ereversed',
      description: 'Breakout ```\n# Injected Heading\n| Pipe | Table | Injection |',
      location: { uri: 'src/main.ts', startLine: 1 },
      consensus: { totalVotes: 3, unanimous: true },
      sourceVerified: true
    }
  ];
  const injectedMd = renderMarkdown({ findings: injectedFinding, manifest: validManifest });
  if (injectedMd.includes('<script>') || injectedMd.includes('\x1B[31m') || injectedMd.includes('\u202E')) {
    throw new Error('P0 VIOLATION: Control characters or scripts leaked into markdown!');
  }
  if (injectedMd.includes('\n# Injected Heading')) {
    throw new Error('P0 VIOLATION: Markdown heading injection not escaped!');
  }
  console.log('✔ 14. P0 Invariant: ANSI escapes, Bidi overrides, and Markdown injections neutralized.');

  // 15. P0 Invariant: Target Path Traversal Containment
  const traversalFinding = [
    {
      id: 'SEC-006',
      ruleId: 'CWE-22',
      title: 'Path Traversal finding',
      location: { uri: '../../etc/shadow', startLine: 1 },
      consensus: { totalVotes: 3, unanimous: true },
      sourceVerified: true
    }
  ];
  const traversalSarif = renderSarif({ findings: traversalFinding, manifest: validManifest, repoRoot: process.cwd() });
  const traversalResult = traversalSarif.runs[0].results[0];
  if (traversalResult.properties.disposition === 'REPORTABLE') {
    throw new Error('P0 VIOLATION: Path traversal finding escaped repoRoot and was accepted as REPORTABLE!');
  }
  console.log('✔ 15. P0 Invariant: Target path traversal outside repo root is rejected.');

  // 16. P0 Invariant: Default-Deny Clean Claim Fail-Closed
  const emptyFindingsNoManifest = [];
  const partialMd = renderMarkdown({ findings: emptyFindingsNoManifest, manifest: null });
  if (partialMd.includes('No confirmed vulnerabilities found matching default-deny verification criteria in fully reconciled coverage')) {
    throw new Error('P0 VIOLATION: Stated repository was clean when coverage was UNCHECKABLE!');
  }
  if (!partialMd.includes('cannot be certified clean under default-deny')) {
    throw new Error('P0 VIOLATION: Missing explicit unverified coverage disclaimer under default-deny');
  }
  console.log('✔ 16. P0 Invariant: Incomplete coverage cannot declare repository clean (Fail-Closed).');

  // 17. P0 Invariant: 100% Canonical Parity between SARIF and Markdown
  const finalization = finalizeScan({
    candidates: confirmedFindings,
    manifest: validManifest,
    repoRoot: process.cwd()
  });
  const canonicalSarif = renderSarifFromCanonical({
    canonicalFindings: finalization.canonicalFindings,
    manifest: finalization.manifest,
    coverageStatus: finalization.coverageStatus
  });
  const canonicalMd = renderMarkdownFromCanonical({
    canonicalFindings: finalization.canonicalFindings,
    manifest: finalization.manifest,
    coverageStatus: finalization.coverageStatus
  });

  if (canonicalSarif.runs[0].results.length !== 1 || !canonicalMd.includes('SQL Injection in Auth')) {
    throw new Error('P0 VIOLATION: Inconsistency between canonical SARIF and Markdown outputs!');
  }
  console.log('✔ 17. P0 Invariant: 100% Canonical Parity between SARIF and Markdown.');

  console.log('\nAll render-sarif.mjs automated verification tests passed successfully (17/17).');
}


// -----------------------------------------------------------------------------
// CLI Dispatch
// -----------------------------------------------------------------------------
if (process.argv.includes('--test')) {
  try {
    runTests();
    process.exit(0);
  } catch (err) {
    console.error('❌ Test failure:', err.message);
    process.exit(1);
  }
}

// If invoked with parameters:
const args = process.argv.slice(2);
function getArg(name) {
  const idx = args.indexOf(name);
  if (idx !== -1 && idx + 1 < args.length) {
    return args[idx + 1];
  }
  return null;
}

const inputPath = getArg('--input');
const outputSarifPath = getArg('--output-sarif');
const outputMdPath = getArg('--output-md');
const manifestPath = getArg('--manifest');

if (inputPath) {
  try {
    const rawData = fs.readFileSync(inputPath, 'utf8');
    const findings = JSON.parse(rawData);

    let manifest = null;
    if (manifestPath && fs.existsSync(manifestPath)) {
      manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
    }

    const repoRoot = process.cwd();
    const provenance = getGitProvenance(repoRoot);

    if (outputSarifPath) {
      const sarif = renderSarif({ findings, manifest, provenance, repoRoot });
      fs.mkdirSync(path.dirname(outputSarifPath), { recursive: true });
      fs.writeFileSync(outputSarifPath, JSON.stringify(sarif, null, 2), 'utf8');
      console.log(`✔ Generated SARIF report: ${outputSarifPath}`);
    }

    if (outputMdPath) {
      const md = renderMarkdown({ findings, manifest, provenance });
      fs.mkdirSync(path.dirname(outputMdPath), { recursive: true });
      fs.writeFileSync(outputMdPath, md, 'utf8');
      console.log(`✔ Generated Markdown report: ${outputMdPath}`);
    }
  } catch (err) {
    console.error('Error processing audit reports:', err.message);
    process.exit(1);
  }
}
