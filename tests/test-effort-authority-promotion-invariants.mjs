#!/usr/bin/env node
/**
 * test-effort-authority-promotion-invariants.mjs
 * Verification suite for Authority Promotion and Effort Router Invariants (Gate 0 M54-P1-F03 / RFC 0003).
 *
 * Enforces the non-negotiable invariant:
 * EXECUTION_COMPLETE != FINDING_VERIFIED != RELEASE_AUTHORIZED
 *
 * Verifies that regardless of model effort (Low, Medium, High), NO raw candidate finding
 * can bypass the 3-Lens verification panel or transition directly from UNVERIFIED to REPORTABLE.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { deriveFinalDisposition, finalizeScan } from '../skills/security-audit/scripts/finalize-scan.mjs';

const EFFORT_TIERS = ['low', 'medium', 'high'];

for (const effort of EFFORT_TIERS) {
  test(`Authority Invariant [${effort}]: raw discovery candidate with zero verifier votes strictly defaults to DEFERRED`, () => {
    const candidate = {
      id: `SEC-RAW-${effort.toUpperCase()}-01`,
      ruleId: 'CWE-89',
      location: { uri: 'src/db.js', startLine: 10, endLine: 12 },
      modelEffort: effort
    };

    const disposition = deriveFinalDisposition(candidate, []);
    assert.notEqual(disposition.disposition, 'REPORTABLE', `Effort ${effort} candidate must not be promoted without verifier ballots`);
    assert.equal(disposition.disposition, 'DEFERRED');
    assert.equal(disposition.mappedVerdict, 'NEEDS_MANUAL_REVIEW');
  });

  test(`Authority Invariant [${effort}]: self-asserted CONFIRMED or REPORTABLE status is strictly rejected fail-closed`, () => {
    const candidate = {
      id: `SEC-SPOOF-${effort.toUpperCase()}-02`,
      ruleId: 'CWE-79',
      location: { uri: 'src/render.js', startLine: 20, endLine: 25 },
      modelEffort: effort,
      consensus: { verdict: 'CONFIRMED' },
      disposition: 'REPORTABLE'
    };

    // Even if candidate metadata claims CONFIRMED/REPORTABLE, deriveFinalDisposition with 0 ballots must reject it
    const disposition = deriveFinalDisposition(candidate, []);
    assert.equal(disposition.disposition, 'DEFERRED');
    assert.notEqual(disposition.mappedVerdict, 'CONFIRMED');
    assert.equal(disposition.mappedVerdict, 'NEEDS_MANUAL_REVIEW');
  });

  test(`Authority Invariant [${effort}]: 3 SUPPORTS with missing physical evidence binding cannot transition to REPORTABLE`, () => {
    const candidate = {
      id: `SEC-NOEV-${effort.toUpperCase()}-03`,
      ruleId: 'CWE-94',
      location: { uri: 'src/eval.js', startLine: 15, endLine: 18 },
      modelEffort: effort
    };

    const votesWithoutEvidence = [
      { findingId: candidate.id, lens: 'REACHABILITY', decision: 'SUPPORTS', evidence: [] },
      { findingId: candidate.id, lens: 'DEFENSES', decision: 'SUPPORTS', evidence: [] },
      { findingId: candidate.id, lens: 'IMPACT', decision: 'SUPPORTS', evidence: [] }
    ];

    const disposition = deriveFinalDisposition(candidate, votesWithoutEvidence, { score: 0.9 });
    assert.equal(disposition.disposition, 'DEFERRED', `Effort ${effort} with zero evidence binding must be DEFERRED`);
    assert.equal(disposition.mappedVerdict, 'NEEDS_MANUAL_REVIEW');
  });

  test(`Authority Invariant [${effort}]: partial lens panel (2/3 supports) cannot transition to REPORTABLE`, () => {
    const candidate = {
      id: `SEC-PARTIAL-${effort.toUpperCase()}-04`,
      ruleId: 'CWE-22',
      location: { uri: 'src/fs.js', startLine: 30, endLine: 32 },
      modelEffort: effort
    };

    const partialVotes = [
      { findingId: candidate.id, lens: 'REACHABILITY', decision: 'SUPPORTS', evidence: [{ path: 'src/fs.js', line: 30, role: 'sink' }] },
      { findingId: candidate.id, lens: 'DEFENSES', decision: 'SUPPORTS', evidence: [{ path: 'src/fs.js', line: 31, role: 'source' }] }
      // IMPACT lens missing!
    ];

    const disposition = deriveFinalDisposition(candidate, partialVotes, { score: 0.85 });
    assert.equal(disposition.disposition, 'DEFERRED');
    assert.notEqual(disposition.disposition, 'REPORTABLE');
  });

  test(`Authority Invariant [${effort}]: non-lens ballots (legacy 2/3 supports) strictly cannot bypass 3-Lens panel to reach REPORTABLE (F03 closure)`, () => {
    const candidate = {
      id: `SEC-NONLENS-${effort.toUpperCase()}-05`,
      ruleId: 'CWE-89',
      location: { uri: 'skills/security-audit/scripts/safe-git.mjs', startLine: 10, endLine: 25 },
      modelEffort: effort
    };

    // 2/3 votes without lens attribute, even with valid evidence and high rigor
    const nonLensVotes = [
      {
        findingId: candidate.id,
        reviewerId: 'rev-general-1',
        decision: 'CONFIRMED',
        evidence: [
          { path: 'skills/security-audit/scripts/safe-git.mjs', line: 10, role: 'source' },
          { path: 'skills/security-audit/scripts/safe-git.mjs', line: 25, role: 'sink' }
        ]
      },
      {
        findingId: candidate.id,
        reviewerId: 'rev-general-2',
        decision: 'CONFIRMED',
        evidence: [{ path: 'skills/security-audit/scripts/safe-git.mjs', line: 15, role: 'control' }]
      }
    ];

    const disposition = deriveFinalDisposition(candidate, nonLensVotes, { score: 0.95 }, process.cwd());
    assert.notEqual(disposition.disposition, 'REPORTABLE', `Effort ${effort} candidate must NEVER reach REPORTABLE via non-lens legacy voting`);
    assert.equal(disposition.disposition, 'DEFERRED');
    assert.equal(disposition.mappedVerdict, 'NEEDS_MANUAL_REVIEW');
  });

  test(`Authority Invariant [${effort}]: 3/3 non-lens supports strictly cannot transition to REPORTABLE`, () => {
    const candidate = {
      id: `SEC-NONLENS3-${effort.toUpperCase()}-06`,
      ruleId: 'CWE-79',
      location: { uri: 'skills/security-audit/scripts/safe-git.mjs', startLine: 10, endLine: 25 },
      modelEffort: effort
    };

    const nonLensVotes = [
      { findingId: candidate.id, reviewerId: 'rev-1', decision: 'CONFIRMED', evidence: [{ path: 'skills/security-audit/scripts/safe-git.mjs', line: 10, role: 'source' }] },
      { findingId: candidate.id, reviewerId: 'rev-2', decision: 'CONFIRMED', evidence: [{ path: 'skills/security-audit/scripts/safe-git.mjs', line: 25, role: 'sink' }] },
      { findingId: candidate.id, reviewerId: 'rev-3', decision: 'CONFIRMED', evidence: [{ path: 'skills/security-audit/scripts/safe-git.mjs', line: 15, role: 'control' }] }
    ];

    const disposition = deriveFinalDisposition(candidate, nonLensVotes, { score: 0.95 }, process.cwd());
    assert.notEqual(disposition.disposition, 'REPORTABLE');
    assert.equal(disposition.disposition, 'DEFERRED');
  });
}

test('Authority Promotion Gate: EXECUTION_COMPLETE != FINDING_VERIFIED != RELEASE_AUTHORIZED', () => {
  // A scan with complete findings but incomplete coverage or failed TCB integrity strictly cannot authorize release
  const partialCoverageScan = finalizeScan({
    candidates: [],
    manifest: {
      complete: false,
      coverageStatus: 'PARTIAL',
      files: []
    },
    repoRoot: process.cwd()
  });

  assert.equal(partialCoverageScan.summary.canDeclareClean, false, 'Incomplete manifest cannot authorize clean release');
  assert.notEqual(partialCoverageScan.summary.execution?.verdict, 'COMPLETE_VERIFIED');
});

test('Authority Promotion Gate: REPORTABLE Finding Strictly Separated from Release Authority (RFC 0003 Section 3)', () => {
  // RFC 0003 Section 3: Internal Advisory (REPORTABLE) != Release Authority
  // Even if a finding is confirmed REPORTABLE by unanimous 3-Lens panel, it can NEVER grant Release Authority (canDeclareClean must be false)
  const reportableCandidate = {
    id: 'SEC-REPORTABLE-01',
    ruleId: 'CWE-89',
    title: 'SQL Injection in SafeGit',
    location: { uri: 'skills/security-audit/scripts/safe-git.mjs', startLine: 10, endLine: 25 },
    modelEffort: 'high',
    disposition: 'REPORTABLE'
  };

  const unanimousVotes = [
    { findingId: 'SEC-REPORTABLE-01', lens: 'REACHABILITY', decision: 'SUPPORTS', evidence: [{ path: 'skills/security-audit/scripts/safe-git.mjs', line: 10, role: 'source' }] },
    { findingId: 'SEC-REPORTABLE-01', lens: 'DEFENSES', decision: 'SUPPORTS', evidence: [{ path: 'skills/security-audit/scripts/safe-git.mjs', line: 15, role: 'control' }] },
    { findingId: 'SEC-REPORTABLE-01', lens: 'IMPACT', decision: 'SUPPORTS', evidence: [{ path: 'skills/security-audit/scripts/safe-git.mjs', line: 25, role: 'sink' }] }
  ];

  const disposition = deriveFinalDisposition(reportableCandidate, unanimousVotes, { score: 0.95 }, process.cwd());
  assert.equal(disposition.disposition, 'REPORTABLE', 'Unanimous 3-Lens panel with evidence achieves REPORTABLE');

  const scanWithReportable = finalizeScan({
    candidates: [reportableCandidate],
    votes: unanimousVotes,
    manifest: { complete: true, coverageStatus: 'COMPLETE', files: ['skills/security-audit/scripts/safe-git.mjs'] },
    repoRoot: process.cwd(),
    allowSelfAudit: true
  });

  // Release authority MUST be denied when any REPORTABLE finding exists
  assert.equal(scanWithReportable.summary.canDeclareClean, false, 'Scan with REPORTABLE findings strictly cannot declare clean');
  assert.equal(scanWithReportable.summary.assuranceLabel, 'NON_CLEAN');
});

test('Authority Promotion Gate: 3-Lens Duplicate/Split Ballot Counterexample F03 (Fail-Closed to DEFERRED)', () => {
  // Counterexample identified by ChatGPT R4:
  // 4 votes: rev-1 (REACHABILITY: SUPPORTS), rev-2 (DEFENSES: SUPPORTS), rev-3 (DEFENSES: SUPPORTS), rev-4 (IMPACT: DEFERRED)
  // Even with valid source and sink evidence and high rigor, non-unanimous / duplicate-lens / incomplete IMPACT must strictly evaluate to DEFERRED!
  const candidate = {
    id: 'SEC-F03-COUNTEREXAMPLE-01',
    ruleId: 'CWE-89',
    title: 'SQL Injection Candidate with Split Lens Ballots',
    location: { uri: 'skills/security-audit/scripts/safe-git.mjs', startLine: 10, endLine: 25 },
    modelEffort: 'high'
  };

  const splitBallots = [
    {
      findingId: candidate.id,
      reviewerId: 'rev-1',
      lens: 'REACHABILITY',
      decision: 'SUPPORTS',
      evidence: [{ path: 'skills/security-audit/scripts/safe-git.mjs', line: 10, role: 'source' }]
    },
    {
      findingId: candidate.id,
      reviewerId: 'rev-2',
      lens: 'DEFENSES',
      decision: 'SUPPORTS',
      evidence: [{ path: 'skills/security-audit/scripts/safe-git.mjs', line: 15, role: 'control' }]
    },
    {
      findingId: candidate.id,
      reviewerId: 'rev-3',
      lens: 'DEFENSES',
      decision: 'SUPPORTS',
      evidence: [{ path: 'skills/security-audit/scripts/safe-git.mjs', line: 25, role: 'sink' }]
    },
    {
      findingId: candidate.id,
      reviewerId: 'rev-4',
      lens: 'IMPACT',
      decision: 'DEFERRED'
    }
  ];

  const disposition = deriveFinalDisposition(candidate, splitBallots, { score: 0.95 }, process.cwd());
  assert.equal(disposition.disposition, 'DEFERRED', 'Split ballots with duplicate DEFENSES and deferred IMPACT must be DEFERRED');
  assert.notEqual(disposition.disposition, 'REPORTABLE', 'Must strictly not achieve REPORTABLE');
  assert.equal(disposition.mappedVerdict, 'NEEDS_MANUAL_REVIEW');
});
