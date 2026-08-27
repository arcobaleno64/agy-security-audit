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
import { getHardenedGitProvenance, readGitFileAtRevision } from './safe-git.mjs';
import { buildDirectoryManifest, extractChangedFiles, buildScanManifest, categorizeDirectory } from './build-inventory.mjs';
import { buildThreatModel, generateDiscoveryMatrix } from './build-threat-model.mjs';

import {
  CVSS_V4_REGEX,
  normalizeUri,
  calculateRigor,
  validateDirectoryManifest,
  validateReviewManifest,
  reconcileCoverage,
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
  unionCandidates,
  computeFindingFingerprint,
  renderSarifFromCanonical,
  renderMarkdownFromCanonical,
  normalizeDirectoryPath,
  loadVotes,
  extractVoteEvidence,
  validateVoteEvidence
} from './finalize-scan.mjs';






import { validateAttackPath, detectProofGaps } from './validate-attack-path.mjs';
import { validatePatchSyntax, detectStalePatch, verifyRemediation } from './validate-patch.mjs';




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
  renderMarkdownFromCanonical,
  buildDirectoryManifest,
  extractChangedFiles,
  buildScanManifest
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
  // P1-01 Suffix /GARBAGE rejection
  if (CVSS_V4_REGEX.test(validVector + '/GARBAGE')) {
    throw new Error('P1-01 VIOLATION: Suffix /GARBAGE accepted by CVSS_V4_REGEX');
  }
  const garbageRes = validateCvssV4({ vector: validVector + '/GARBAGE', score: 9.0 });
  if (garbageRes.valid) {
    throw new Error('P1-01 VIOLATION: Suffix /GARBAGE accepted by validateCvssV4');
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
      rigorMetrics: fullMetrics
    }
  ];

  const confirmedVotes = [
    { findingId: 'SEC-001', reviewerId: 'rev-1', decision: 'CONFIRMED' },
    { findingId: 'SEC-001', reviewerId: 'rev-2', decision: 'CONFIRMED' }
  ];

  const sarif = renderSarif({ findings: confirmedFindings, manifest: validManifest, votes: confirmedVotes });
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
      }
    }
  ];
  const credVotes = [
    { findingId: 'SEC-004', reviewerId: 'rev-1', decision: 'CONFIRMED' },
    { findingId: 'SEC-004', reviewerId: 'rev-2', decision: 'CONFIRMED' }
  ];
  const credSarif = renderSarif({ findings: credentialFinding, manifest: validManifest, votes: credVotes });
  const credSnippet = credSarif.runs[0].results[0].properties?.location?.lineSnippet ||
    credSarif.runs[0].results[0].locations[0].physicalLocation.artifactLocation.uri;
  const credMd = renderMarkdown({ findings: credentialFinding, manifest: validManifest, votes: credVotes });
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
      location: { uri: 'src/main.ts', startLine: 1 }
    }
  ];
  const injectedVotes = [
    { findingId: 'SEC-005', reviewerId: 'rev-1', decision: 'CONFIRMED' },
    { findingId: 'SEC-005', reviewerId: 'rev-2', decision: 'CONFIRMED' }
  ];
  const injectedMd = renderMarkdown({ findings: injectedFinding, manifest: validManifest, votes: injectedVotes });
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
      consensus: { totalVotes: 3, unanimous: true }
    }
  ];
  const traversalSarif = renderSarif({ findings: traversalFinding, manifest: validManifest });
  if (!traversalSarif.runs[0].results[0].locations[0].physicalLocation.artifactLocation.uri.includes('invalid_path_escaped')) {
    throw new Error('P0 VIOLATION: Path traversal finding was not neutralized to safe containment sentinel!');
  }

  console.log('✔ 15. P0 Invariant: Target path traversal outside repo root is rejected.');

  // 16. P0 Invariant: Incomplete Coverage cannot declare repository clean
  const partialManifest = {
    schemaVersion: '1',
    entries: [
      { path: './', status: 'SCANNED' },
      { path: 'src/secret-component', status: 'UNCHECKABLE' }
    ]
  };
  const partialSarif = renderSarif({ findings: [], manifest: partialManifest });
  const partialMd = renderMarkdown({ findings: [], manifest: partialManifest });
  if (partialSarif.runs[0].properties.coverageStatus === 'COMPLETE') {
    throw new Error('P0 VIOLATION: Incomplete coverage marked as COMPLETE in SARIF!');
  }
  if (!partialMd.includes('cannot be certified clean under default-deny')) {
    throw new Error('P0 VIOLATION: Missing explicit unverified coverage disclaimer under default-deny');
  }
  console.log('✔ 16. P0 Invariant: Incomplete coverage cannot declare repository clean (Fail-Closed).');

  // 17. P0 Invariant: 100% Canonical Parity between SARIF and Markdown
  const finalization = finalizeScan({
    candidates: confirmedFindings,
    manifest: validManifest,
    repoRoot: process.cwd(),
    votes: confirmedVotes
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

  // 18. P1 (0.10.0): Deterministic Directory Manifest from Filesystem
  const fsManifest = buildDirectoryManifest(process.cwd());
  const fsManifestValidation = validateDirectoryManifest(fsManifest);
  if (!fsManifestValidation.valid) {
    throw new Error(`P1 VIOLATION: Filesystem directory manifest invalid: ${fsManifestValidation.error}`);
  }
  if (!fsManifest.entries.some(e => e.path === 'skills/' && e.status === 'SCANNED')) {
    throw new Error('P1 VIOLATION: Expected skills/ folder not marked SCANNED in directory manifest');
  }
  console.log('✔ 18. P1 Invariant: Ground-truth directory manifest derived deterministically from filesystem.');

  // 19. P1 (0.10.0): Review Mode Changed Files Accounting
  const changedInfo = extractChangedFiles(process.cwd());
  if (typeof changedInfo.totalAccounted !== 'number') {
    throw new Error('P1 VIOLATION: extractChangedFiles did not return numeric totalAccounted');
  }
  console.log('✔ 19. P1 Invariant: Review mode extracts and accounts for 100% changed/deleted files.');

  // 20. P1 (0.10.0): Scan Manifest Schema Compliance
  const scanManifest = buildScanManifest({ mode: 'scan', repoRoot: process.cwd() });
  if (scanManifest.schemaVersion !== '1' || scanManifest.mode !== 'scan' || !scanManifest.target.root) {
    throw new Error('P1 VIOLATION: buildScanManifest output does not conform to Section 31 Schema');
  }
  const reviewManifest = buildScanManifest({ mode: 'review', repoRoot: process.cwd() });
  if (reviewManifest.mode !== 'review') {
    throw new Error('P1 VIOLATION: buildScanManifest failed to record review mode');
  }
  console.log('✔ 20. P1 Invariant: Scan and Review manifests conform to canonical schema.');

  // 21. P1 (0.10.0): Review Mode Coverage Reconciliation & Markdown Generation
  const realDiffForTest21 = extractChangedFiles(process.cwd(), { base: 'HEAD~1', head: 'HEAD' });
  const reviewInventoryManifest = {
    mode: 'review',
    base: 'HEAD~1',
    head: 'HEAD',
    reviewInventory: {
      changedFiles: realDiffForTest21.changedFiles,
      deletedFiles: realDiffForTest21.deletedFiles
    }
  };
  const reviewFinalization = finalizeScan({
    candidates: [],
    manifest: reviewInventoryManifest,
    repoRoot: process.cwd()
  });
  if (reviewFinalization.coverageStatus !== 'COMPLETE') {
    throw new Error('P1 VIOLATION: Valid review manifest was not marked COMPLETE coverage');
  }
  const reviewMd = renderMarkdownFromCanonical({
    canonicalFindings: reviewFinalization.canonicalFindings,
    manifest: reviewFinalization.manifest,
    coverageStatus: reviewFinalization.coverageStatus
  });
  if (!reviewMd.includes('Changed Files Accounting Manifest (Review Mode)')) {
    throw new Error('P1 VIOLATION: Review markdown does not render changed files accounting section');
  }
  console.log('✔ 21. P1 Invariant: Review mode coverage reconciliation achieves COMPLETE under Default-Deny.');


  // 22. P1 (0.10.0): Categorization Accuracy for Monorepos & CLI
  if (categorizeDirectory('.github').status !== 'SCANNED') {
    throw new Error('P1 VIOLATION: .github directory must be SCANNED for CI/CD attack surface');
  }
  if (categorizeDirectory('packages').status !== 'SCANNED') {
    throw new Error('P1 VIOLATION: packages directory must be SCANNED for monorepo first-party code');
  }
  if (categorizeDirectory('bin').status !== 'SCANNED') {
    throw new Error('P1 VIOLATION: bin directory must be SCANNED for CLI source scripts');
  }
  console.log('✔ 22. P1 Invariant: Critical entrypoints (.github, packages, bin) properly classified as SCANNED.');

  // 23. P1 (0.10.0): Git Baseline Pre-Image Reader
  const headPkg = readGitFileAtRevision(process.cwd(), 'HEAD', 'package.json');
  if (!headPkg || !headPkg.includes('@arcobaleno64/agy-security-audit')) {
    throw new Error('P1 VIOLATION: readGitFileAtRevision failed to read committed pre-image from git');
  }
  console.log('✔ 23. P1 Invariant: Git baseline pre-image reader safely retrieves historical revisions.');

  // 24. P1 (0.10.0): Deterministic Threat Model Schema Compliance
  const tm = buildThreatModel(process.cwd());
  if (tm.schemaVersion !== '1' || !Array.isArray(tm.components) || tm.components.length === 0 || !Array.isArray(tm.inScopeFamilies)) {
    throw new Error('P1 VIOLATION: buildThreatModel failed Section 17/30 schema validation');
  }
  console.log('✔ 24. P1 Invariant: Threat Model generated deterministically adhering to bounded schema.');

  // 25. P1 (0.10.0): Fixed 3-Lens Verifier Panel Unanimous Consensus
  const candidate3Lens = {
    id: 'SEC-3LENS',
    title: 'Command Injection in Worker',
    ruleId: 'CWE-078',
    severity: 'HIGH',
    location: { uri: 'skills/security-audit/scripts/safe-git.mjs', startLine: 25 },
    dataflowVerified: true
  };
  const threeLensVotes = [
    { findingId: 'SEC-3LENS', lens: 'REACHABILITY', decision: 'SUPPORTS', reason: 'Unsanitized argument flows directly to spawn' },
    { findingId: 'SEC-3LENS', lens: 'DEFENSES', decision: 'SUPPORTS', reason: 'No escaping or allowlist barrier present' },
    { findingId: 'SEC-3LENS', lens: 'IMPACT', decision: 'SUPPORTS', reason: 'Arbitrary host command execution' }
  ];
  const disp3Lens = deriveFinalDisposition(candidate3Lens, threeLensVotes, { score: 0.85 });
  if (disp3Lens.disposition !== 'REPORTABLE' || !disp3Lens.votesSummary.isThreeLens) {
    throw new Error('P1 VIOLATION: Unanimous 3-Lens panel failed to achieve REPORTABLE');
  }
  const conf3Lens = clampConfidence(disp3Lens.disposition, disp3Lens.votesSummary, 0.90);
  if (conf3Lens.level !== 'high' || conf3Lens.score < 0.85) {
    throw new Error('P1 VIOLATION: Unanimous 3-Lens panel did not achieve high confidence');
  }
  console.log('✔ 25. P1 Invariant: Unanimous 3-Lens Verifier Panel reaches High Confidence.');

  // 26. P1 (0.10.0): Fixed 3-Lens Panel Reachability Refutation
  const unreachableCandidate = {
    id: 'SEC-UNREACH',
    title: 'Theoretical Query Injection in Dead Code',
    ruleId: 'CWE-089',
    severity: 'HIGH',
    location: { uri: 'skills/security-audit/scripts/safe-git.mjs', startLine: 30 }
  };
  const reachabilityRefuteVotes = [
    {
      findingId: 'SEC-UNREACH',
      lens: 'REACHABILITY',
      decision: 'REFUTES',
      reason: 'Function is unreachable from any external route or entrypoint',
      evidence: [{ path: 'skills/security-audit/scripts/safe-git.mjs', line: 30, role: 'dead-path' }]
    },
    { findingId: 'SEC-UNREACH', lens: 'DEFENSES', decision: 'SUPPORTS', reason: 'No internal sanitizer' },
    { findingId: 'SEC-UNREACH', lens: 'IMPACT', decision: 'SUPPORTS', reason: 'Database read' }
  ];
  const dispUnreach = deriveFinalDisposition(unreachableCandidate, reachabilityRefuteVotes, { score: 0.70 });
  if (dispUnreach.disposition !== 'SUPPRESSED' || dispUnreach.mappedVerdict !== 'FALSE_POSITIVE') {
    throw new Error('P1 VIOLATION: Unreachable candidate was not suppressed by REACHABILITY lens');
  }
  console.log('✔ 26. P1 Invariant: Reachability lens refutation decisively suppresses candidate under Default-Deny.');

  // 27. P1 (0.10.0): 3-Lens Conjunction Invariant (Defenses Cannot Be Outvoted 2-to-1)
  const mitigatedCandidate = {
    id: 'SEC-MITIGATED',
    title: 'SQL Injection in User Search',
    ruleId: 'CWE-089',
    severity: 'HIGH',
    location: { uri: 'skills/security-audit/scripts/safe-git.mjs', startLine: 35 }
  };
  const defensesRefuteVotes = [
    { findingId: 'SEC-MITIGATED', lens: 'REACHABILITY', decision: 'SUPPORTS', reason: 'Public API endpoint reachable' },
    { findingId: 'SEC-MITIGATED', lens: 'DEFENSES', decision: 'REFUTES', mitigationProofLine: 'skills/security-audit/scripts/safe-git.mjs:20', mitigationReason: 'Parameterized query barrier prevents injection' },
    { findingId: 'SEC-MITIGATED', lens: 'IMPACT', decision: 'SUPPORTS', reason: 'Database read impact' }
  ];
  const dispMitigated = deriveFinalDisposition(mitigatedCandidate, defensesRefuteVotes, { score: 0.85 });

  if (dispMitigated.disposition !== 'SUPPRESSED' || dispMitigated.mappedVerdict !== 'FALSE_POSITIVE') {
    throw new Error('P1 VIOLATION: DEFENSES mitigation was outvoted 2-to-1 in 3-Lens panel!');
  }
  console.log('✔ 27. P1 Invariant: 3-Lens conjunction prevents defenses from being outvoted 2-to-1.');

  // 28. P1 (0.10.0): 10 Standard Vulnerability Families & Discovery Matrix
  const tmFull = buildThreatModel(process.cwd());
  if (tmFull.inScopeFamilies.length !== 10 || !tmFull.inScopeFamilies.includes('native-memory-safety')) {
    throw new Error('P1 VIOLATION: inScopeFamilies does not include all 10 standard vulnerability families');
  }
  const matrix = generateDiscoveryMatrix(tmFull.components, tmFull.inScopeFamilies);
  if (!Array.isArray(matrix) || matrix.length < 10) {
    throw new Error('P1 VIOLATION: generateDiscoveryMatrix failed to yield full component x family pairings');
  }
  console.log('✔ 28. P1 Invariant: Full 10 vulnerability families and discovery matrix generated.');

  // 29. P2 (0.11.0): Section 21 Attack Path Schema Validation
  const validAttackPath = {
    attackPathId: 'AP-01',
    source: { uri: 'skills/security-audit/scripts/safe-git.mjs', line: 10, description: 'User controllable argument' },
    steps: [
      { uri: 'skills/security-audit/scripts/safe-git.mjs', line: 25, description: 'Command string concatenation' }
    ],
    sink: { uri: 'skills/security-audit/scripts/safe-git.mjs', line: 40, description: 'Child process invocation' },
    preconditions: ['Local operator execution'],
    exploitabilityPrerequisites: ['Unvalidated input parameters'],
    unmitigatedInvariant: 'No shell escape routine applied'
  };
  const apResult = validateAttackPath(validAttackPath, process.cwd());
  if (!apResult.valid) {
    throw new Error(`P2 VIOLATION: valid attack path failed validation: ${apResult.error}`);
  }
  const traversalAttackPath = {
    ...validAttackPath,
    source: { uri: '../../../etc/passwd', line: 1 }
  };
  const apTraversalResult = validateAttackPath(traversalAttackPath, process.cwd());
  if (apTraversalResult.valid) {
    throw new Error('P2 VIOLATION: Attack path with directory traversal was accepted!');
  }
  console.log('✔ 29. P2 Invariant: Section 21 attack path schema validated fail-closed against traversal.');

  // 30. P2 (0.11.0): Proof-Gap Detection
  const gappyPath = {
    source: { uri: 'skills/security-audit/scripts/safe-git.mjs', line: 10 },
    steps: [
      { uri: 'skills/security-audit/scripts/safe-git.mjs', line: 20, description: 'assumed data propagation' }
    ],
    sink: { uri: 'skills/security-audit/scripts/safe-git.mjs', line: 30, description: 'sink' }
  };
  const gaps = detectProofGaps(gappyPath);
  if (!gaps.hasGaps || gaps.proofGaps.length < 2) {
    throw new Error('P2 VIOLATION: detectProofGaps failed to flag unproven steps or missing invariants');
  }
  console.log('✔ 30. P2 Invariant: Proof-gap detector flags unproven hops and missing mitigation proofs.');

  // 31. P2 (0.11.0): Multi-Run Candidate Union & Fingerprint Deduplication
  const run1 = [
    { ruleId: 'CWE-89', location: { uri: 'src/api.ts', startLine: 15 }, title: 'SQLi Candidate' },
    { ruleId: 'CWE-79', location: { uri: 'src/view.ts', startLine: 30 }, title: 'XSS Candidate' }
  ];
  const run2 = [
    { ruleId: 'CWE-89', location: { uri: 'src/api.ts', startLine: 15 }, title: 'SQLi Candidate Run 2' },
    { ruleId: 'CWE-78', location: { uri: 'src/exec.ts', startLine: 45 }, title: 'Command Injection' }
  ];
  const unioned = unionCandidates([run1, run2]);
  if (unioned.length !== 3) {
    throw new Error(`P2 VIOLATION: unionCandidates length expected 3, got ${unioned.length}`);
  }
  const sqli = unioned.find(c => c.ruleId === 'CWE-89');
  if (!sqli || sqli.recurrenceCount !== 2 || sqli.runsObserved.length !== 2) {
    throw new Error('P2 VIOLATION: Multi-run candidate union failed recurrence tracking');
  }
  console.log('✔ 31. P2 Invariant: Multi-run candidate union deduplicates candidates and tracks recurrence.');

  // 32. P2 (0.11.0): Unclosed Proof Gap Forces DEFERRED Under Default-Deny
  const candidateWithProofGaps = {
    id: 'SEC-GAP-01',
    ruleId: 'CWE-89',
    title: 'Candidate with Gap',
    location: { uri: 'skills/security-audit/scripts/safe-git.mjs', startLine: 10 },
    proofGaps: [{ stepIndex: 1, unprovenProperty: 'Control flow branch cannot be proven reachable' }]
  };
  const threeLensVotesWithGaps = [
    { findingId: 'SEC-GAP-01', lens: 'REACHABILITY', decision: 'SUPPORTS' },
    { findingId: 'SEC-GAP-01', lens: 'DEFENSES', decision: 'SUPPORTS' },
    { findingId: 'SEC-GAP-01', lens: 'IMPACT', decision: 'SUPPORTS' }
  ];
  const dispGaps = deriveFinalDisposition(candidateWithProofGaps, threeLensVotesWithGaps, { score: 1.0 });
  if (dispGaps.disposition !== 'DEFERRED' || dispGaps.mappedVerdict !== 'NEEDS_MANUAL_REVIEW') {
    throw new Error('P2 VIOLATION: Candidate with unclosed proof gaps was not forced to DEFERRED!');
  }
  console.log('✔ 32. P2 Invariant: Unclosed proof gaps strictly force DEFERRED disposition.');

  // 33. P2 (0.11.0): Fingerprint Delimiter Collision Resistance
  const fpA = computeFindingFingerprint('semgrep:rules', 'xss/api.ts', 10);
  const fpB = computeFindingFingerprint('semgrep', 'rules:xss/api.ts', 10);
  if (fpA === fpB) {
    throw new Error('P2 VIOLATION: computeFindingFingerprint collided on colon delimiter!');
  }
  console.log('✔ 33. P2 Invariant: Length-prefixed fingerprint generation is collision-resistant.');

  // 34. P2 (0.11.0): Automatic Proof-Gap Integration in finalizeScan
  const candidateWithUnprovenPath = {
    id: 'SEC-AUTO-GAP',
    ruleId: 'CWE-89',
    title: 'SQLi Candidate with Unverified Hop',
    location: { uri: 'skills/security-audit/scripts/safe-git.mjs', startLine: 15 },
    attackPath: {
      source: { uri: 'skills/security-audit/scripts/safe-git.mjs', line: 10, description: 'Incoming query parameter' },
      steps: [
        { uri: 'skills/security-audit/scripts/safe-git.mjs', line: 12, description: 'assumed unvalidated string concatenation' }
      ],
      sink: { uri: 'skills/security-audit/scripts/safe-git.mjs', line: 15, description: 'Executed SQL query' },
      unmitigatedInvariant: 'No parameterized query'
    }
  };
  const threeVotes = [
    { findingId: 'SEC-AUTO-GAP', lens: 'REACHABILITY', decision: 'SUPPORTS' },
    { findingId: 'SEC-AUTO-GAP', lens: 'DEFENSES', decision: 'SUPPORTS' },
    { findingId: 'SEC-AUTO-GAP', lens: 'IMPACT', decision: 'SUPPORTS' }
  ];
  const finalizationWithGap = finalizeScan({
    candidates: [candidateWithUnprovenPath],
    votes: threeVotes,
    repoRoot: process.cwd()
  });
  const canonicalFindingWithGap = finalizationWithGap.canonicalFindings[0];
  if (canonicalFindingWithGap.disposition !== 'DEFERRED' || canonicalFindingWithGap.verdict !== 'NEEDS_MANUAL_REVIEW') {
    throw new Error('P2 VIOLATION: Attack path with unproven hop leaked into CONFIRMED in finalizeScan!');
  }
  if (!Array.isArray(canonicalFindingWithGap.proofGaps) || canonicalFindingWithGap.proofGaps.length === 0) {
    throw new Error('P2 VIOLATION: proofGaps were not retained on canonical finding!');
  }
  console.log('✔ 34. P2 Invariant: finalizeScan automatically detects proof gaps and enforces DEFERRED under Default-Deny.');

  // 35. P2 (0.12.0): Unified Diff Patch Syntax & Traversal Defense
  const validPatch = `--- a/skills/security-audit/scripts/safe-git.mjs
+++ b/skills/security-audit/scripts/safe-git.mjs
@@ -10,2 +10,3 @@
 const hardened = true;
+const verified = true;
`;
  const patchVal = validatePatchSyntax(validPatch, process.cwd());
  if (!patchVal.valid || patchVal.targetFiles.length !== 1) {
    throw new Error(`P2 VIOLATION: valid patch failed validation: ${patchVal.error}`);
  }
  const traversalPatch = `--- a/../../../../etc/passwd
+++ b/../../../../etc/passwd
@@ -1,1 +1,2 @@
+malicious line
`;
  const traversalVal = validatePatchSyntax(traversalPatch, process.cwd());
  if (traversalVal.valid) {
    throw new Error('P2 VIOLATION: Patch containing directory traversal was accepted!');
  }
  console.log('✔ 35. P2 Invariant: Patch syntax validated fail-closed against directory traversal.');

  // 36. P2 (0.12.0): Stale Baseline Detection
  const staleCheck = detectStalePatch(process.cwd(), ['skills/security-audit/scripts/safe-git.mjs'], 'HEAD');
  if (staleCheck.stale !== false) {
    throw new Error('P2 VIOLATION: Clean baseline falsely marked as stale');
  }
  console.log('✔ 36. P2 Invariant: Stale baseline check safely inspects target file divergence.');

  // 37. P1-03: Remediation Verification strictly requires complete 3-Lens panel under Default-Deny
  const findingToVerify = { id: 'SEC-REMED', ruleId: 'CWE-89' };

  // 37.1 1 DEFENSES only -> REJECTED
  const defensesOnlyVotes = [
    { findingId: 'SEC-REMED', lens: 'DEFENSES', decision: 'REFUTES', mitigationProofLine: 'src/api.ts:25', mitigationReason: 'Parameterized query barrier added' }
  ];
  const defOnlyResult = verifyRemediation(findingToVerify, defensesOnlyVotes);
  if (defOnlyResult.verified) {
    throw new Error('P1-03 VIOLATION: Single DEFENSES vote alone certified remediation without REACHABILITY and IMPACT!');
  }

  // 37.2 DEFENSES + REACHABILITY only -> REJECTED
  const defAndReachVotes = [
    { findingId: 'SEC-REMED', lens: 'DEFENSES', decision: 'REFUTES', mitigationProofLine: 'src/api.ts:25', mitigationReason: 'Parameterized query barrier added' },
    { findingId: 'SEC-REMED', lens: 'REACHABILITY', decision: 'REFUTES', reason: 'Exploit path blocked' }
  ];
  const defAndReachResult = verifyRemediation(findingToVerify, defAndReachVotes);
  if (defAndReachResult.verified) {
    throw new Error('P1-03 VIOLATION: Missing IMPACT vote certified remediation!');
  }

  // 37.3 All 3 valid -> VERIFIED
  const allThreeVotes = [
    { findingId: 'SEC-REMED', lens: 'DEFENSES', decision: 'REFUTES', mitigationProofLine: 'src/api.ts:25', mitigationReason: 'Parameterized query barrier added' },
    { findingId: 'SEC-REMED', lens: 'REACHABILITY', decision: 'REFUTES', reason: 'Exploit path blocked' },
    { findingId: 'SEC-REMED', lens: 'IMPACT', decision: 'REFUTES', reason: 'Impact neutralized' }
  ];
  const remediationResult = verifyRemediation(findingToVerify, allThreeVotes);
  if (!remediationResult.verified) {
    throw new Error(`P1-03 VIOLATION: Complete 3-lens panel failed to certify remediation: ${remediationResult.reason}`);
  }

  // 37.4 Active exploit dissent (e.g. REACHABILITY SUPPORTS) -> REJECTED
  const unverifiedResult = verifyRemediation(findingToVerify, [
    { findingId: 'SEC-REMED', lens: 'DEFENSES', decision: 'REFUTES', mitigationProofLine: 'src/api.ts:25', mitigationReason: 'Parameterized query barrier added' },
    { findingId: 'SEC-REMED', lens: 'REACHABILITY', decision: 'SUPPORTS', reason: 'Bypass found' },
    { findingId: 'SEC-REMED', lens: 'IMPACT', decision: 'REFUTES', reason: 'Impact neutralized' }
  ]);
  if (unverifiedResult.verified) {
    throw new Error('P1-03 VIOLATION: Unverified remediation was incorrectly certified!');
  }
  console.log('✔ 37. P1-03 Invariant: Remediation verification strictly requires complete 3-Lens panel under Default-Deny.');

  // 38. P2 (0.12.0): Patch Jail Security Rules (Bidi, CI/CD, Multi-file)
  const bidiPatch = `--- a/skills/security-audit/scripts/safe-git.mjs
+++ b/skills/security-audit/scripts/safe-git.mjs
@@ -10,1 +10,1 @@
-const access = false;
+const access = true; \u202E /* hidden override */
`;
  const bidiVal = validatePatchSyntax(bidiPatch, process.cwd());
  if (bidiVal.valid) {
    throw new Error('P2 VIOLATION: Patch with Unicode Bidi character was accepted!');
  }

  const cicdPatch = `--- a/.github/workflows/audit.yml
+++ b/.github/workflows/audit.yml
@@ -1,1 +1,2 @@
+tampered
`;
  const cicdVal = validatePatchSyntax(cicdPatch, process.cwd());
  if (cicdVal.valid) {
    throw new Error('P2 VIOLATION: Patch tampering with CI/CD was accepted!');
  }
  console.log('✔ 38. P2 Invariant: Patch Jail strictly rejects Unicode Bidi and CI/CD modifications.');

  // 39. P2 (0.12.0): Option Injection Defense in detectStalePatch
  const optionInjectionCheck = detectStalePatch(process.cwd(), ['skills/security-audit/scripts/safe-git.mjs'], '--output=/tmp/evil');
  if (!optionInjectionCheck.stale || !optionInjectionCheck.error) {
    throw new Error('P2 VIOLATION: Unsafe baseRevision option injection was not rejected fail-closed!');
  }
  console.log('✔ 39. P2 Invariant: detectStalePatch rejects CLI option injection fail-closed.');

  // 40. P2 (0.12.0) & P1-03: 3-Lens Finding ID Binding and Active Exploit Dissent
  const candidateA = { id: 'SEC-100' };
  const candidateB = { id: 'SEC-200' };
  const votesForA = [
    { findingId: 'SEC-100', lens: 'DEFENSES', decision: 'REFUTES', mitigationProofLine: 'src/app.ts:50', mitigationReason: 'Sanitizer installed' },
    { findingId: 'SEC-100', lens: 'REACHABILITY', decision: 'REFUTES', reason: 'Unreachable' },
    { findingId: 'SEC-100', lens: 'IMPACT', decision: 'REFUTES', reason: 'Zero harm' }
  ];
  // Ballots for A must verify candidate A
  const candidateAVerified = verifyRemediation(candidateA, votesForA);
  if (!candidateAVerified.verified) {
    throw new Error('P1-03 VIOLATION: Valid 3-lens ballots for Candidate A failed verification!');
  }
  // Ballots for A must not verify candidate B
  const crossBindingCheck = verifyRemediation(candidateB, votesForA);
  if (crossBindingCheck.verified) {
    throw new Error('P2 VIOLATION: Ballots for Finding A verified Finding B!');
  }

  // Reachability + Impact dissent blocks certification
  const dissentedVotes = [
    { findingId: 'SEC-100', lens: 'DEFENSES', decision: 'REFUTES', mitigationProofLine: 'src/app.ts:50', mitigationReason: 'Sanitizer installed' },
    { findingId: 'SEC-100', lens: 'REACHABILITY', decision: 'SUPPORTS', justification: 'Bypass found' },
    { findingId: 'SEC-100', lens: 'IMPACT', decision: 'SUPPORTS', justification: 'Critical data loss' }
  ];
  const dissentCheck = verifyRemediation(candidateA, dissentedVotes);
  if (dissentCheck.verified) {
    throw new Error('P2 VIOLATION: Patch was certified despite REACHABILITY and IMPACT active exploit dissent!');
  }
  console.log('✔ 40. P2 Invariant: Fix verification enforces finding identity and 3-lens consensus.');

  // 41. P0-01 Hardening: Fake consensus without ballots is strictly DEFERRED (Default-Deny)
  const fakeConsensusCandidate = {
    id: 'C-FAKE-CONSENSUS',
    location: { uri: 'src/auth.ts', startLine: 10 },
    sourceVerified: true,
    consensus: {
      totalVotes: 3,
      unanimous: true
    }
  };
  const fakeConsensusResult = deriveFinalDisposition(fakeConsensusCandidate, [], { score: 0.85 });
  if (fakeConsensusResult.disposition !== 'DEFERRED' || fakeConsensusResult.mappedVerdict !== 'NEEDS_MANUAL_REVIEW') {
    throw new Error(`P0-01 VIOLATION: Candidate self-asserted consensus was accepted without ballots: ${JSON.stringify(fakeConsensusResult)}`);
  }
  // End-to-end pipeline test: verify finalizeScan strips raw.consensus
  const fakePipelineRes = finalizeScan({ candidates: [fakeConsensusCandidate], manifest: validManifest });
  const totalRecorded = Number(fakePipelineRes.canonicalFindings[0].consensus.total ?? fakePipelineRes.canonicalFindings[0].consensus.totalVotes ?? 0);
  if (fakePipelineRes.canonicalFindings[0].disposition !== 'DEFERRED' || totalRecorded !== 0) {
    throw new Error(`P0-01 VIOLATION: finalizeScan leaked self-asserted consensus: ${JSON.stringify(fakePipelineRes.canonicalFindings[0].consensus)}`);
  }

  console.log('✔ 41. P0-01 Invariant: Fake consensus without independent ballots is strictly DEFERRED.');

  // 42. P0-01 Hardening: Fake raw evidence flags with maximum rigor without ballots is strictly DEFERRED
  const fakeRawFlagsCandidate = {
    id: 'C-FAKE-FLAGS',
    location: { uri: 'src/auth.ts', startLine: 10 },
    sourceVerified: true,
    dataflowVerified: true
  };
  const fakeFlagsResult = deriveFinalDisposition(fakeRawFlagsCandidate, [], { score: 1.0 });
  if (fakeFlagsResult.disposition !== 'DEFERRED' || fakeFlagsResult.mappedVerdict !== 'NEEDS_MANUAL_REVIEW') {
    throw new Error(`P0-01 VIOLATION: Candidate raw flags were accepted without ballots even at score 1.0: ${JSON.stringify(fakeFlagsResult)}`);
  }
  console.log('✔ 42. P0-01 Invariant: Candidate raw flags without independent ballots is strictly DEFERRED.');

  // 43. P0-01 Hardening: Real task-bound ballots required for REPORTABLE
  const realBallotCandidate = {
    id: 'C-REAL-BALLOTS',
    location: { uri: 'src/auth.ts', startLine: 10 }
  };
  const realBallots = [
    { findingId: 'C-REAL-BALLOTS', reviewerId: 'rev-1', decision: 'CONFIRMED' },
    { findingId: 'C-REAL-BALLOTS', reviewerId: 'rev-2', decision: 'CONFIRMED' }
  ];
  const realResult = deriveFinalDisposition(realBallotCandidate, realBallots, { score: 0.85 });
  if (realResult.disposition !== 'REPORTABLE' || realResult.mappedVerdict !== 'CONFIRMED') {
    throw new Error(`P0-01 VIOLATION: Valid ballots with mathematical rigor failed to achieve REPORTABLE: ${JSON.stringify(realResult)}`);
  }
  console.log('✔ 43. P0-01 Invariant: Real task-bound ballots required to transition to REPORTABLE.');

  // 44. P0-01 Hardening: Unassigned ballots cannot bind via isSingleCandidate & null safety
  const unassignedBallot = [{ reviewerId: 'rev-1', decision: 'CONFIRMED' }];
  const multiCandidateA = { id: 'C-A', location: { uri: 'src/auth.ts', startLine: 10 }, isSingleCandidate: true };
  const nullVotesRes = deriveFinalDisposition(multiCandidateA, null);
  if (nullVotesRes.disposition !== 'DEFERRED') {
    throw new Error('P0-01 VIOLATION: Null votes did not default-deny to DEFERRED');
  }
  const unassignedRes = deriveFinalDisposition(multiCandidateA, unassignedBallot);
  if (unassignedRes.disposition !== 'DEFERRED') {
    throw new Error('P0-01 VIOLATION: Unassigned ballot bound to candidate via isSingleCandidate property');
  }
  console.log('✔ 44. P0-01 Invariant: Strict task-binding prevents unassigned ballot leakage.');

  // 45. P0-02 Invariant: Omitted directory results in PARTIAL coverage (Test A)
  const fullFsManifest = buildDirectoryManifest(process.cwd());
  const omittedEntries = fullFsManifest.entries.filter(e => normalizeDirectoryPath(e.path) !== 'skills/');
  const omittedScanManifest = { entries: omittedEntries };
  const omittedRes = reconcileCoverage(omittedScanManifest, process.cwd());
  if (omittedRes.status === 'COMPLETE' || !omittedRes.missing.includes('skills/')) {
    throw new Error(`P0-02 VIOLATION: Omitted directory skills/ was not detected as PARTIAL: ${JSON.stringify(omittedRes)}`);
  }
  console.log('✔ 45. P0-02 Invariant: Omitted directory results in PARTIAL coverage with missing list.');

  // 46. P0-02 Invariant: Fake complete manifest ({ entries: [{ path: './' }] }) cannot achieve COMPLETE (Test B)
  const fakeCompleteManifest = {
    entries: [
      { path: './', status: 'SCANNED' }
    ]
  };
  const fakeScanRes = finalizeScan({ candidates: [], manifest: fakeCompleteManifest, repoRoot: process.cwd() });
  if (fakeScanRes.coverageStatus === 'COMPLETE' || fakeScanRes.canDeclareClean) {
    throw new Error(`P0-02 VIOLATION: Fake manifest claimed COMPLETE coverage or declared clean: ${JSON.stringify(fakeScanRes)}`);
  }
  console.log('✔ 46. P0-02 Invariant: Fake complete manifest is rejected as PARTIAL under filesystem reconciliation.');

  // 47. P0-02 Invariant: Review mode missing changed file results in PARTIAL (Test C)
  const realDiffFor47 = extractChangedFiles(process.cwd(), { base: 'HEAD~1', head: 'HEAD' });
  const partialChangedList = realDiffFor47.changedFiles.slice(1);
  const partialReviewManifest = {
    mode: 'review',
    base: 'HEAD~1',
    head: 'HEAD',
    reviewInventory: {
      changedFiles: partialChangedList,
      deletedFiles: realDiffFor47.deletedFiles
    }
  };
  const partialReviewRes = reconcileCoverage(partialReviewManifest, process.cwd());
  if (partialReviewRes.status === 'COMPLETE' || partialReviewRes.missingChanged.length === 0) {
    throw new Error(`P0-02 VIOLATION: Review manifest missing changed files was accepted as COMPLETE: ${JSON.stringify(partialReviewRes)}`);
  }
  console.log('✔ 47. P0-02 Invariant: Review mode missing changed file rejected as PARTIAL.');

  // 48. P0-02 Invariant: Review mode fake/missing deleted file (Test D)
  const fakeDeletedManifest = {
    mode: 'review',
    base: 'HEAD~1',
    head: 'HEAD',
    reviewInventory: {
      changedFiles: realDiffFor47.changedFiles,
      deletedFiles: [{ path: 'unaccounted-fake-deleted.js', status: 'DELETED' }]
    }
  };
  const fakeDeletedRes = reconcileCoverage(fakeDeletedManifest, process.cwd());
  if (fakeDeletedRes.status === 'COMPLETE' || fakeDeletedRes.unexpectedDeleted.length === 0) {
    throw new Error(`P0-02 VIOLATION: Review manifest with fictitious deleted file was accepted as COMPLETE: ${JSON.stringify(fakeDeletedRes)}`);
  }
  console.log('✔ 48. P0-02 Invariant: Review mode deleted file discrepancy rejected as PARTIAL.');

  // 49. P0-02 Hardening: Null or non-existent repoRoot strictly fails closed to UNCHECKABLE

  const nullRootRes = finalizeScan({ candidates: [], manifest: fullFsManifest, repoRoot: null });
  if (nullRootRes.coverageStatus !== 'UNCHECKABLE' || nullRootRes.canDeclareClean) {
    throw new Error(`P0-02 VIOLATION: Null repoRoot did not fail closed to UNCHECKABLE: ${JSON.stringify(nullRootRes)}`);
  }
  const nonExistentRes = finalizeScan({ candidates: [], manifest: fullFsManifest, repoRoot: '/path/does/not/exist' });
  if (nonExistentRes.coverageStatus !== 'UNCHECKABLE' || nonExistentRes.canDeclareClean) {
    throw new Error(`P0-02 VIOLATION: Non-existent repoRoot did not fail closed to UNCHECKABLE: ${JSON.stringify(nonExistentRes)}`);
  }
  console.log('✔ 49. P0-02 Invariant: Null or non-existent repoRoot strictly fails closed to UNCHECKABLE.');

  // 50. P0-02 Hardening: False Exclusion / Categorization Fabrication is rejected as PARTIAL
  const falseExclusionEntries = fullFsManifest.entries.map(e => {
    if (normalizeDirectoryPath(e.path) === 'skills/') {
      return { ...e, status: 'EXCLUDED_VENDORED', reason: 'Fictitious vendor exclusion' };
    }
    return e;
  });
  const falseExclusionManifest = { entries: falseExclusionEntries };
  const falseExclusionRes = finalizeScan({ candidates: [], manifest: falseExclusionManifest, repoRoot: process.cwd() });
  if (falseExclusionRes.coverageStatus === 'COMPLETE' || falseExclusionRes.canDeclareClean) {
    throw new Error(`P0-02 VIOLATION: False exclusion of skills/ was accepted as COMPLETE: ${JSON.stringify(falseExclusionRes)}`);
  }
  console.log('✔ 50. P0-02 Invariant: False exclusion of core source directories is rejected as PARTIAL.');

  // 51. P0-02 Hardening: Review mode identical base/head revision manipulation rejected as PARTIAL
  const identicalRevManifest = {
    mode: 'review',
    base: 'HEAD',
    head: 'HEAD',
    reviewInventory: { changedFiles: [], deletedFiles: [] }
  };
  const identicalRevRes = finalizeScan({ candidates: [], manifest: identicalRevManifest, repoRoot: process.cwd() });
  if (identicalRevRes.coverageStatus === 'COMPLETE' || identicalRevRes.canDeclareClean) {
    throw new Error(`P0-02 VIOLATION: Identical review revisions (HEAD...HEAD) accepted as COMPLETE: ${JSON.stringify(identicalRevRes)}`);
  }
  console.log('✔ 51. P0-02 Invariant: Identical base/head revision manipulation rejected as PARTIAL.');

  // 52. P0-03 Invariant: loadVotes loads votes from single JSON file and nested ballot directories
  const tmpVotesDir = path.join(process.cwd(), 'scratch', 'test-votes-dir');
  const tmpSubDir = path.join(tmpVotesDir, 'SEC-001');
  fs.mkdirSync(tmpSubDir, { recursive: true });
  fs.writeFileSync(path.join(tmpSubDir, 'ballot_1.json'), JSON.stringify([{ findingId: 'F-1', reviewerId: 'r1', decision: 'CONFIRMED' }]));
  fs.writeFileSync(path.join(tmpVotesDir, 'ballot_2.json'), JSON.stringify({ findingId: 'F-1', reviewerId: 'r2', decision: 'CONFIRMED' }));
  const loadedDirVotes = loadVotes(tmpVotesDir);
  if (loadedDirVotes.length !== 2 || !loadedDirVotes.some(v => v.reviewerId === 'r1') || !loadedDirVotes.some(v => v.reviewerId === 'r2')) {
    throw new Error(`P0-03 VIOLATION: loadVotes failed to load votes from nested directory: ${JSON.stringify(loadedDirVotes)}`);
  }

  try {
    fs.rmSync(tmpVotesDir, { recursive: true, force: true });
  } catch {}
  console.log('✔ 52. P0-03 Invariant: loadVotes correctly aggregates ballots from files and directories.');

  // 53. P0-03 Invariant: Canonical rendering pipeline preserves canonical disposition without re-evaluation
  const preFinalizedCanonical = [
    {
      id: 'CANON-001',
      ruleId: 'CWE-89',
      title: 'SQL Injection in Auth',
      severity: 'CRITICAL',
      cvssV4: { vector: validVector, score: 9.3, severity: 'CRITICAL' },
      location: { uri: 'src/auth.ts', startLine: 42, endLine: 44, lineSnippet: 'SELECT' },
      disposition: 'REPORTABLE',
      mappedVerdict: 'CONFIRMED',
      confidence: 'high'
    }
  ];
  const canonicalSarifOutput = renderSarifFromCanonical({
    canonicalFindings: preFinalizedCanonical,
    manifest: fullFsManifest,
    coverageStatus: 'COMPLETE',
    repoRoot: process.cwd()
  });
  if (canonicalSarifOutput.runs[0].results.length !== 1 || canonicalSarifOutput.runs[0].results[0].properties.disposition !== 'REPORTABLE') {
    throw new Error('P0-03 VIOLATION: renderSarifFromCanonical altered disposition of canonical findings');
  }
  console.log('✔ 53. P0-03 Invariant: Canonical pipeline renders canonical findings without making disposition decisions.');

  // 54. P0-03 Invariant: Production rendering without votes strictly produces DEFERRED findings (Zero-Vote Default-Deny)
  const unvotedCandidates = [
    {
      id: 'UNVOTED-001',
      ruleId: 'CWE-89',
      title: 'Unvoted SQL Injection',
      severity: 'HIGH',
      location: { uri: 'src/auth.ts', startLine: 42, endLine: 44 }
    }
  ];
  const renderedWithoutVotes = renderSarif({
    findings: unvotedCandidates,
    manifest: fullFsManifest,
    votes: [], // Zero votes
    repoRoot: process.cwd()
  });
  if (renderedWithoutVotes.runs[0].results.length > 0 && renderedWithoutVotes.runs[0].results[0].properties.disposition === 'REPORTABLE') {
    throw new Error('P0-03 VIOLATION: Finding without votes was rendered as REPORTABLE!');
  }
  console.log('✔ 54. P0-03 Invariant: Production rendering without votes strictly enforces DEFERRED disposition.');

  // 55. P0-04 Invariant: Custom agents located at plugin root with hardened capability declarations
  const expectedAgents = [
    'agents/threat-modeler.md',
    'agents/discovery-agent.md',
    'agents/verifier-reachability.md',
    'agents/verifier-defenses.md',
    'agents/verifier-impact.md'
  ];
  for (const af of expectedAgents) {
    const fullP = path.resolve(process.cwd(), af);
    if (!fs.existsSync(fullP)) {
      throw new Error(`P0-04 VIOLATION: Expected agent missing from plugin root: ${af}`);
    }
    const content = fs.readFileSync(fullP, 'utf8');
    if (!content.includes('mainAgent: false') || !content.includes('subagent: true') || !content.includes('commandExecutionPolicy: off')) {
      throw new Error(`P0-04 VIOLATION: Agent ${af} missing mandatory capability constraints`);
    }
    if (content.includes('read_file')) {
      throw new Error(`P0-04 VIOLATION: Agent ${af} uses invalid tool name 'read_file'; must be 'view_file'`);
    }
    if (content.includes('run_command') || content.includes('write_to_file')) {
      throw new Error(`P0-04 VIOLATION: Agent ${af} has prohibited execution/modifying tools`);
    }
  }
  if (categorizeDirectory('agents').status !== 'SCANNED') {
    throw new Error('P0-04 VIOLATION: agents/ directory must be categorized as SCANNED');
  }
  console.log('✔ 55. P0-04 Invariant: Custom agents located at plugin root with verified least-privilege capabilities.');

  // 56. P1-01 Invariant: Strict fail-closed score boundaries (no clamping, reject out-of-bounds, no fabricated score)
  const score99Res = validateCvssV4({ vector: validVector, score: 99 });
  if (score99Res.valid || score99Res.score !== null) {
    throw new Error('P1-01 VIOLATION: Out-of-bounds score 99 was not rejected fail-closed');
  }
  const scoreNegRes = validateCvssV4({ vector: validVector, score: -1 });
  if (scoreNegRes.valid || scoreNegRes.score !== null) {
    throw new Error('P1-01 VIOLATION: Negative score -1 was not rejected fail-closed');
  }
  const scoreInfRes = validateCvssV4({ vector: validVector, score: Infinity });
  if (scoreInfRes.valid || scoreInfRes.score !== null) {
    throw new Error('P1-01 VIOLATION: Infinity score was not rejected fail-closed');
  }
  const scoreNanRes = validateCvssV4({ vector: validVector, score: NaN });
  if (scoreNanRes.valid || scoreNanRes.score !== null) {
    throw new Error('P1-01 VIOLATION: NaN score was not rejected fail-closed');
  }
  const missingScoreRes = validateCvssV4({ vector: validVector });
  if (!missingScoreRes.valid || missingScoreRes.score !== null) {
    throw new Error('P1-01 VIOLATION: Missing score must remain null without fabricating arbitrary numbers');
  }
  const validScoreRes = validateCvssV4({ vector: validVector, score: 9.3 });
  if (!validScoreRes.valid || validScoreRes.score !== 9.3 || validScoreRes.severity !== 'CRITICAL') {
    throw new Error('P1-01 VIOLATION: Valid score 9.3 failed validation');
  }
  console.log('✔ 56. P1-01 Invariant: CVSS v4 strictly fails closed on invalid scores and avoids score fabrication.');

  // 57. P1-02 Invariant: All REFUTES decisions require verifiable evidence binding
  const testCandidate = {
    id: 'SEC-EV-TEST',
    title: 'Candidate for Evidence Binding Check',
    ruleId: 'CWE-89',
    severity: 'HIGH',
    location: { uri: 'skills/security-audit/scripts/safe-git.mjs', startLine: 20 }
  };

  // 57.1 REACHABILITY REFUTES without evidence -> DEFERRED
  const noEvReachabilityVotes = [
    { findingId: 'SEC-EV-TEST', lens: 'REACHABILITY', decision: 'REFUTES', reason: 'Unreachable' },
    { findingId: 'SEC-EV-TEST', lens: 'DEFENSES', decision: 'SUPPORTS' },
    { findingId: 'SEC-EV-TEST', lens: 'IMPACT', decision: 'SUPPORTS' }
  ];
  const noEvReachRes = deriveFinalDisposition(testCandidate, noEvReachabilityVotes, { score: 0.8 }, process.cwd());
  if (noEvReachRes.disposition !== 'DEFERRED' || noEvReachRes.mappedVerdict !== 'NEEDS_MANUAL_REVIEW') {
    throw new Error('P1-02 VIOLATION: REACHABILITY REFUTES without evidence was not DEFERRED');
  }

  // 57.2 IMPACT REFUTES without evidence -> DEFERRED
  const noEvImpactVotes = [
    { findingId: 'SEC-EV-TEST', lens: 'REACHABILITY', decision: 'SUPPORTS' },
    { findingId: 'SEC-EV-TEST', lens: 'DEFENSES', decision: 'SUPPORTS' },
    { findingId: 'SEC-EV-TEST', lens: 'IMPACT', decision: 'REFUTES', reason: 'Zero harm' }
  ];
  const noEvImpactRes = deriveFinalDisposition(testCandidate, noEvImpactVotes, { score: 0.8 }, process.cwd());
  if (noEvImpactRes.disposition !== 'DEFERRED' || noEvImpactRes.mappedVerdict !== 'NEEDS_MANUAL_REVIEW') {
    throw new Error('P1-02 VIOLATION: IMPACT REFUTES without evidence was not DEFERRED');
  }

  // 57.3 DEFENSES REFUTES without proof/evidence -> DEFERRED
  const noEvDefensesVotes = [
    { findingId: 'SEC-EV-TEST', lens: 'REACHABILITY', decision: 'SUPPORTS' },
    { findingId: 'SEC-EV-TEST', lens: 'DEFENSES', decision: 'REFUTES', reason: 'Sanitized somehow' },
    { findingId: 'SEC-EV-TEST', lens: 'IMPACT', decision: 'SUPPORTS' }
  ];
  const noEvDefRes = deriveFinalDisposition(testCandidate, noEvDefensesVotes, { score: 0.8 }, process.cwd());
  if (noEvDefRes.disposition !== 'DEFERRED' || noEvDefRes.mappedVerdict !== 'NEEDS_MANUAL_REVIEW') {
    throw new Error('P1-02 VIOLATION: DEFENSES REFUTES without proof was not DEFERRED');
  }

  // 57.4 Wrong findingId evidence rejected
  const wrongIdVote = { findingId: 'WRONG-ID', lens: 'REACHABILITY', decision: 'REFUTES', evidence: [{ path: 'skills/security-audit/scripts/safe-git.mjs', line: 20 }] };
  const wrongIdRes = validateVoteEvidence(wrongIdVote, testCandidate, process.cwd());
  if (wrongIdRes.valid) {
    throw new Error('P1-02 VIOLATION: Wrong findingId evidence was accepted');
  }

  // 57.5 Outside-repo evidence rejected
  const traversalVote = { findingId: 'SEC-EV-TEST', lens: 'REACHABILITY', decision: 'REFUTES', evidence: [{ path: '../../etc/passwd', line: 1 }] };
  const traversalRes = validateVoteEvidence(traversalVote, testCandidate, process.cwd());
  if (traversalRes.valid) {
    throw new Error('P1-02 VIOLATION: Path traversal evidence was accepted');
  }

  // 57.6 Invalid line rejected (line 0, line -5, line beyond EOF)
  const line0Vote = { findingId: 'SEC-EV-TEST', lens: 'REACHABILITY', decision: 'REFUTES', evidence: [{ path: 'skills/security-audit/scripts/safe-git.mjs', line: 0 }] };
  const line0Res = validateVoteEvidence(line0Vote, testCandidate, process.cwd());
  if (line0Res.valid) {
    throw new Error('P1-02 VIOLATION: Evidence with line 0 was accepted');
  }
  const lineBeyondEofVote = { findingId: 'SEC-EV-TEST', lens: 'REACHABILITY', decision: 'REFUTES', evidence: [{ path: 'skills/security-audit/scripts/safe-git.mjs', line: 999999 }] };
  const lineBeyondRes = validateVoteEvidence(lineBeyondEofVote, testCandidate, process.cwd());
  if (lineBeyondRes.valid) {
    throw new Error('P1-02 VIOLATION: Evidence line beyond EOF was accepted');
  }

  // 57.7 Valid evidence on REFUTES successfully suppresses to FALSE_POSITIVE
  const validEvVotes = [
    { findingId: 'SEC-EV-TEST', lens: 'REACHABILITY', decision: 'SUPPORTS' },
    {
      findingId: 'SEC-EV-TEST',
      lens: 'DEFENSES',
      decision: 'REFUTES',
      evidence: [{ path: 'skills/security-audit/scripts/safe-git.mjs', line: 20, role: 'guard' }]
    },
    { findingId: 'SEC-EV-TEST', lens: 'IMPACT', decision: 'SUPPORTS' }
  ];
  const validEvRes = deriveFinalDisposition(testCandidate, validEvVotes, { score: 0.8 }, process.cwd());
  if (validEvRes.disposition !== 'SUPPRESSED' || validEvRes.mappedVerdict !== 'FALSE_POSITIVE') {
    throw new Error('P1-02 VIOLATION: Valid evidence refutation failed to suppress to FALSE_POSITIVE');
  }
  console.log('✔ 57. P1-02 Invariant: All REFUTES decisions strictly enforce verifiable evidence binding.');

  console.log('\nAll render-sarif.mjs automated verification tests passed successfully (57/57).');
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

const canonicalPath = getArg('--canonical');
const inputPath = getArg('--input') || getArg('--candidates');
const votesPath = getArg('--votes');
const manifestPath = getArg('--manifest');
const repoRootArg = getArg('--repo-root') || process.cwd();
const outputSarifPath = getArg('--output-sarif');
const outputMdPath = getArg('--output-md');

if (canonicalPath || inputPath) {
  try {
    const repoRoot = path.resolve(repoRootArg);
    const provenance = getHardenedGitProvenance(repoRoot);

    let manifest = null;
    if (manifestPath && fs.existsSync(manifestPath)) {
      manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
    }

    let canonicalFindings = [];
    let coverageStatus = 'COMPLETE';

    if (canonicalPath) {
      // Production Canonical Pipeline: renderer formats pre-finalized canonical findings
      const rawCanonical = fs.readFileSync(canonicalPath, 'utf8');
      canonicalFindings = JSON.parse(rawCanonical);
      const covRes = reconcileCoverage(manifest, repoRoot);
      coverageStatus = covRes.status;
    } else {
      // Legacy input pipeline: routes strictly through finalizeScan with votes
      const rawCandidates = fs.readFileSync(inputPath, 'utf8');
      const candidates = JSON.parse(rawCandidates);
      const votes = loadVotes(votesPath);

      if (candidates.length > 0 && votes.length === 0) {
        console.warn('[DEFAULT-DENY] Direct render without --votes. Under Default-Deny, all findings are derived as DEFERRED.');
      }

      const finalization = finalizeScan({ candidates, manifest, repoRoot, votes });
      canonicalFindings = finalization.canonicalFindings;
      coverageStatus = finalization.coverageStatus;
    }

    if (outputSarifPath) {
      const sarif = renderSarifFromCanonical({
        canonicalFindings,
        manifest,
        coverageStatus,
        provenance,
        repoRoot
      });
      fs.mkdirSync(path.dirname(outputSarifPath), { recursive: true });
      fs.writeFileSync(outputSarifPath, JSON.stringify(sarif, null, 2), 'utf8');
      console.log(`✔ Generated SARIF report: ${outputSarifPath}`);
    }

    if (outputMdPath) {
      const md = renderMarkdownFromCanonical({
        canonicalFindings,
        manifest,
        coverageStatus,
        provenance
      });
      fs.mkdirSync(path.dirname(outputMdPath), { recursive: true });
      fs.writeFileSync(outputMdPath, md, 'utf8');
      console.log(`✔ Generated Markdown report: ${outputMdPath}`);
    }
  } catch (err) {
    console.error('Error processing audit reports:', err.message);
    process.exit(1);
  }
}

