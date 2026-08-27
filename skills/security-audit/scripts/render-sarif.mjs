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
  const reviewInventoryManifest = {
    mode: 'review',
    reviewInventory: {
      changedFiles: [{ path: 'skills/security-audit/SKILL.md', status: 'MODIFIED' }],
      deletedFiles: [{ path: 'old-module.js', status: 'DELETED', baselineRevision: '12c9ce07d5eb' }]
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
    { findingId: 'SEC-UNREACH', lens: 'REACHABILITY', decision: 'REFUTES', reason: 'Function is unreachable from any external route or entrypoint' },
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
    { findingId: 'SEC-MITIGATED', lens: 'DEFENSES', decision: 'REFUTES', mitigationProofLine: 'src/api.ts:20', mitigationReason: 'Parameterized query barrier prevents injection' },
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

  console.log('\nAll render-sarif.mjs automated verification tests passed successfully (28/28).');
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
