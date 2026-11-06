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
import { renderSarif, renderMarkdown } from '../skills/security-audit/scripts/render-sarif.mjs';

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
  const testNonce = 'NONCE-AUTH-001';
  const reportableCandidate = {
    id: 'SEC-REPORTABLE-01',
    ruleId: 'CWE-89',
    title: 'SQL Injection in SafeGit',
    location: { uri: 'skills/security-audit/scripts/safe-git.mjs', startLine: 10, endLine: 25 },
    modelEffort: 'high',
    disposition: 'REPORTABLE',
    nonce: testNonce
  };

  const unanimousVotes = [
    { findingId: 'SEC-REPORTABLE-01', lens: 'REACHABILITY', decision: 'SUPPORTS', nonce: testNonce, evidence: [{ path: 'skills/security-audit/scripts/safe-git.mjs', line: 10, role: 'source' }] },
    { findingId: 'SEC-REPORTABLE-01', lens: 'DEFENSES', decision: 'SUPPORTS', nonce: testNonce, evidence: [{ path: 'skills/security-audit/scripts/safe-git.mjs', line: 15, role: 'control' }] },
    { findingId: 'SEC-REPORTABLE-01', lens: 'IMPACT', decision: 'SUPPORTS', nonce: testNonce, evidence: [{ path: 'skills/security-audit/scripts/safe-git.mjs', line: 25, role: 'sink' }] }
  ];

  const disposition = deriveFinalDisposition(reportableCandidate, unanimousVotes, { score: 0.95 }, process.cwd(), { nonce: testNonce, expectedNonce: testNonce });
  assert.equal(disposition.disposition, 'REPORTABLE', 'Unanimous 3-Lens panel with evidence achieves REPORTABLE');

  const scanWithReportable = finalizeScan({
    candidates: [reportableCandidate],
    votes: unanimousVotes,
    nonce: testNonce,
    manifest: { complete: false, coverageStatus: 'COMPLETE', files: ['skills/security-audit/scripts/safe-git.mjs'] },
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

test('Authority Promotion Gate: Conflicting Duplicate Reviewer Counterexample R5-F03-01 (Fail-Closed to DEFERRED)', () => {
  // Counterexample identified by ChatGPT R5 (R5-F03-01):
  // 4 votes:
  // rev-1: REACHABILITY -> SUPPORTS
  // rev-2: DEFENSES -> SUPPORTS
  // rev-3: IMPACT -> SUPPORTS
  // rev-2: DEFENSES -> DEFERRED (conflicting duplicate from same reviewer rev-2)
  const candidate = {
    id: 'SEC-R5-F03-COUNTEREXAMPLE-REV2-CONFLICT',
    ruleId: 'CWE-89',
    title: 'SQL Injection Candidate with Conflicting Reviewer Ballots',
    location: { uri: 'skills/security-audit/scripts/safe-git.mjs', startLine: 10, endLine: 25 },
    modelEffort: 'high'
  };

  const conflictingBallots = [
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
      lens: 'IMPACT',
      decision: 'SUPPORTS',
      evidence: [{ path: 'skills/security-audit/scripts/safe-git.mjs', line: 25, role: 'sink' }]
    },
    {
      findingId: candidate.id,
      reviewerId: 'rev-2',
      lens: 'DEFENSES',
      decision: 'DEFERRED'
    }
  ];

  const disposition = deriveFinalDisposition(candidate, conflictingBallots, { score: 0.95 }, process.cwd());
  assert.equal(disposition.disposition, 'DEFERRED', 'Conflicting ballot from same reviewer rev-2 must fail-closed to DEFERRED');
  assert.notEqual(disposition.disposition, 'REPORTABLE', 'Must strictly not achieve REPORTABLE');
  assert.equal(disposition.mappedVerdict, 'NEEDS_MANUAL_REVIEW');
});

test('Authority Promotion Gate: Missing Effort Metadata Cannot Bypass 3-Lens Requirement (R5-F03-02)', () => {
  // Counterexample identified by ChatGPT R5 (R5-F03-02):
  // Candidate lacking modelEffort/effort/reasoningProfile/tier fields.
  // In an execution context requiring 3-lens (e.g. options.enforceThreeLens: true),
  // non-lens ballots (legacy 2/3 confirmation) strictly cannot bypass 3-lens verification to achieve REPORTABLE!
  const candidateNoEffort = {
    id: 'SEC-R5-F03-NO-EFFORT-METADATA',
    ruleId: 'CWE-89',
    title: 'Candidate without explicit effort metadata',
    location: { uri: 'skills/security-audit/scripts/safe-git.mjs', startLine: 10, endLine: 25 }
  };

  const twoNonLensSupports = [
    {
      findingId: candidateNoEffort.id,
      reviewerId: 'rev-1',
      decision: 'CONFIRMED',
      evidence: [{ path: 'skills/security-audit/scripts/safe-git.mjs', line: 10, role: 'source' }]
    },
    {
      findingId: candidateNoEffort.id,
      reviewerId: 'rev-2',
      decision: 'CONFIRMED',
      evidence: [{ path: 'skills/security-audit/scripts/safe-git.mjs', line: 25, role: 'sink' }]
    }
  ];

  const disposition = deriveFinalDisposition(candidateNoEffort, twoNonLensSupports, { score: 0.95 }, process.cwd(), { enforceThreeLens: true });
  assert.equal(disposition.disposition, 'DEFERRED', 'Enforced 3-lens context must reject legacy 2/3 confirmation');
  assert.notEqual(disposition.disposition, 'REPORTABLE', 'Must strictly not achieve REPORTABLE');
  assert.equal(disposition.mappedVerdict, 'NEEDS_MANUAL_REVIEW');
});

test('Authority Promotion Gate: Execution Nonce Replay Prevention Counterexample R6-F03-03 (Fail-Closed to DEFERRED)', () => {
  // Counterexample identified by ChatGPT R6 (R6-F03-03):
  // When finalizeScan is invoked with execution nonce 'RUN-B',
  // ballots from a previous run without nonce (or with old nonce)
  // must NOT bind to the candidate and must strictly fail closed to DEFERRED!
  const candidate = {
    id: 'SEC-REPLAY-NONCE-01',
    ruleId: 'CWE-89',
    title: 'SQL Injection Candidate with Replayed Ballots',
    location: { uri: 'skills/security-audit/scripts/safe-git.mjs', startLine: 10, endLine: 25 },
    modelEffort: 'high'
  };

  const oldVotesWithoutNonce = [
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
      lens: 'IMPACT',
      decision: 'SUPPORTS',
      evidence: [{ path: 'skills/security-audit/scripts/safe-git.mjs', line: 25, role: 'sink' }]
    }
  ];

  const scanResult = finalizeScan({
    candidates: [candidate],
    votes: oldVotesWithoutNonce,
    nonce: 'RUN-B',
    repoRoot: process.cwd(),
    allowSelfAudit: true
  });

  const resFinding = scanResult.canonicalFindings[0];
  assert.equal(resFinding.disposition, 'DEFERRED', 'Old ballots missing execution nonce must fail closed to DEFERRED');
  assert.notEqual(resFinding.disposition, 'REPORTABLE', 'Must strictly not achieve REPORTABLE');
});

test('Authority Promotion Gate: Old Manifest Nonce Replay Prevention Counterexample R7-F03-02 (Fail-Closed to DEFERRED)', () => {
  // Counterexample identified by ChatGPT R7 (R7-F03-02):
  // When finalizeScan is invoked with a new execution run (scanRunId: 'RUN-B')
  // but receives an old manifest with nonce 'RUN-A' (e.g. from a prior completed run)
  // and 3 ballots from the previous run with nonce 'RUN-A',
  // the new scan run MUST NOT inherit the old manifest's nonce to replay old ballots!
  // It must strictly fail closed to DEFERRED.
  const candidate = {
    id: 'SEC-REPLAY-MANIFEST-01',
    ruleId: 'CWE-89',
    title: 'SQL Injection Candidate with Replayed Manifest Nonce',
    location: { uri: 'skills/security-audit/scripts/safe-git.mjs', startLine: 10, endLine: 25 },
    modelEffort: 'high'
  };

  const oldManifest = {
    scanRunId: 'RUN-A',
    nonce: 'NONCE-RUN-A',
    taskCorrelationNonce: 'NONCE-RUN-A',
    complete: true,
    entries: [{ path: 'skills/security-audit/scripts/safe-git.mjs', status: 'SCANNED' }]
  };

  const oldVotesWithOldNonce = [
    {
      findingId: candidate.id,
      reviewerId: 'rev-1',
      lens: 'REACHABILITY',
      decision: 'SUPPORTS',
      nonce: 'NONCE-RUN-A',
      evidence: [{ path: 'skills/security-audit/scripts/safe-git.mjs', line: 10, role: 'source' }]
    },
    {
      findingId: candidate.id,
      reviewerId: 'rev-2',
      lens: 'DEFENSES',
      decision: 'SUPPORTS',
      nonce: 'NONCE-RUN-A',
      evidence: [{ path: 'skills/security-audit/scripts/safe-git.mjs', line: 15, role: 'control' }]
    },
    {
      findingId: candidate.id,
      reviewerId: 'rev-3',
      lens: 'IMPACT',
      decision: 'SUPPORTS',
      nonce: 'NONCE-RUN-A',
      evidence: [{ path: 'skills/security-audit/scripts/safe-git.mjs', line: 25, role: 'sink' }]
    }
  ];

  const scanResult = finalizeScan({
    candidates: [candidate],
    manifest: oldManifest,
    scanRunId: 'RUN-B',
    // Caller does not specify nonce, attempting to piggyback on oldManifest.nonce
    votes: oldVotesWithOldNonce,
    repoRoot: process.cwd(),
    allowSelfAudit: true
  });

  const resFinding = scanResult.canonicalFindings[0];
  assert.equal(resFinding.disposition, 'DEFERRED', 'Old manifest nonce replayed under new scanRunId must fail closed to DEFERRED');
  assert.notEqual(resFinding.disposition, 'REPORTABLE', 'Must strictly not achieve REPORTABLE');
});

test('Authority Promotion Gate: Missing Execution Nonce Fail-Closed Counterexample R7-F03-01 (Fail-Closed to DEFERRED)', () => {
  // Counterexample identified by ChatGPT R7 (R7-F03-01):
  // Under Default-Deny on Authority Claims (RFC 0003 Section 3),
  // candidate promotion to REPORTABLE strictly requires a verifiable execution nonce.
  // When neither caller, manifest, nor candidate provides an execution nonce,
  // ballots cannot be verified as belonging to this execution run,
  // and candidate must strictly fail closed to DEFERRED!
  const candidate = {
    id: 'SEC-NO-NONCE-01',
    ruleId: 'CWE-89',
    title: 'SQL Injection Candidate without Execution Nonce',
    location: { uri: 'skills/security-audit/scripts/safe-git.mjs', startLine: 10, endLine: 25 },
    modelEffort: 'high'
  };

  const votesWithoutNonce = [
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
      lens: 'IMPACT',
      decision: 'SUPPORTS',
      evidence: [{ path: 'skills/security-audit/scripts/safe-git.mjs', line: 25, role: 'sink' }]
    }
  ];

  const disposition = deriveFinalDisposition(candidate, votesWithoutNonce, { score: 0.95 }, process.cwd());
  assert.equal(disposition.disposition, 'DEFERRED', 'Missing execution nonce must fail closed to DEFERRED');
  assert.notEqual(disposition.disposition, 'REPORTABLE', 'Must strictly not achieve REPORTABLE');
});

test('Authority Promotion Gate: Candidate Nonce Cannot Bypass Stale Manifest Defense Counterexample R8-F03-01 (Fail-Closed to DEFERRED)', () => {
  // Counterexample identified by ChatGPT R8 (R8-F03-01):
  // When finalizeScan is invoked with a new execution run (scanRunId: 'RUN-B')
  // and receives a completed old manifest (scanRunId: 'RUN-A') without a fresh nonce,
  // effectiveNonce correctly evaluates to null.
  // HOWEVER, if the untrusted candidate ingress itself self-asserts nonce: 'NONCE-RUN-A',
  // and 3 ballots from the previous run carry nonce: 'NONCE-RUN-A',
  // finalizeScan MUST NOT allow candidate.nonce to become the expectedNonce authority!
  // It must strictly fail closed to DEFERRED.
  const candidateWithOldNonce = {
    id: 'SEC-CANDIDATE-NONCE-BYPASS-01',
    ruleId: 'CWE-89',
    title: 'SQL Injection Candidate Self-Asserting Stale Nonce',
    location: { uri: 'skills/security-audit/scripts/safe-git.mjs', startLine: 10, endLine: 25 },
    modelEffort: 'high',
    nonce: 'NONCE-RUN-A' // Untrusted candidate self-asserts old nonce
  };

  const oldManifest = {
    scanRunId: 'RUN-A',
    nonce: 'NONCE-RUN-A',
    taskCorrelationNonce: 'NONCE-RUN-A',
    complete: true,
    entries: [{ path: 'skills/security-audit/scripts/safe-git.mjs', status: 'SCANNED' }]
  };

  const oldVotesWithOldNonce = [
    {
      findingId: candidateWithOldNonce.id,
      reviewerId: 'rev-1',
      lens: 'REACHABILITY',
      decision: 'SUPPORTS',
      nonce: 'NONCE-RUN-A',
      evidence: [{ path: 'skills/security-audit/scripts/safe-git.mjs', line: 10, role: 'source' }]
    },
    {
      findingId: candidateWithOldNonce.id,
      reviewerId: 'rev-2',
      lens: 'DEFENSES',
      decision: 'SUPPORTS',
      nonce: 'NONCE-RUN-A',
      evidence: [{ path: 'skills/security-audit/scripts/safe-git.mjs', line: 15, role: 'control' }]
    },
    {
      findingId: candidateWithOldNonce.id,
      reviewerId: 'rev-3',
      lens: 'IMPACT',
      decision: 'SUPPORTS',
      nonce: 'NONCE-RUN-A',
      evidence: [{ path: 'skills/security-audit/scripts/safe-git.mjs', line: 25, role: 'sink' }]
    }
  ];

  const scanResult = finalizeScan({
    candidates: [candidateWithOldNonce],
    manifest: oldManifest,
    scanRunId: 'RUN-B',
    // Caller does not specify fresh nonce
    votes: oldVotesWithOldNonce,
    repoRoot: process.cwd(),
    allowSelfAudit: true
  });

  const resFinding = scanResult.canonicalFindings[0];
  assert.equal(resFinding.disposition, 'DEFERRED', 'Candidate self-asserted nonce under stale manifest must fail closed to DEFERRED');
  assert.notEqual(resFinding.disposition, 'REPORTABLE', 'Must strictly not achieve REPORTABLE');
});

test('Authority Promotion Gate: Missing Execution Nonce Cannot Suppress Finding Counterexample R8-F03-02 (Fail-Closed to DEFERRED)', () => {
  // Counterexample identified by ChatGPT R8 (R8-F03-02):
  // Under Default-Deny on Authority Claims (RFC 0003 Section 3),
  // candidate disposition mutation (both REPORTABLE and SUPPRESSED) strictly requires a verified execution nonce.
  // When an effort candidate lacks an execution nonce, ballots voting REFUTES with verified mitigation
  // MUST NOT suppress the finding to SUPPRESSED / FALSE_POSITIVE!
  // It must strictly fail closed to DEFERRED.
  const candidate = {
    id: 'SEC-EFFORT-NO-NONCE-REFUTE-01',
    ruleId: 'CWE-89',
    title: 'SQL Injection Candidate without Nonce Facing Refutation',
    location: { uri: 'skills/security-audit/scripts/safe-git.mjs', startLine: 10, endLine: 25 },
    modelEffort: 'high'
  };

  const refutingVotesWithoutNonce = [
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
      decision: 'REFUTES',
      evidence: [{ path: 'skills/security-audit/scripts/safe-git.mjs', line: 15, role: 'control' }]
    },
    {
      findingId: candidate.id,
      reviewerId: 'rev-3',
      lens: 'IMPACT',
      decision: 'SUPPORTS',
      evidence: [{ path: 'skills/security-audit/scripts/safe-git.mjs', line: 25, role: 'sink' }]
    }
  ];

  const disposition = deriveFinalDisposition(candidate, refutingVotesWithoutNonce, { score: 0.95 }, process.cwd());
  assert.equal(disposition.disposition, 'DEFERRED', 'Missing execution nonce on refutation must fail closed to DEFERRED');
  assert.notEqual(disposition.disposition, 'SUPPRESSED', 'Must strictly not achieve SUPPRESSED without verified nonce');
});

test('Authority Promotion Gate: Missing Manifest ScanRunId Cannot Inherit Nonce Counterexample R9-F03-01 (Fail-Closed to DEFERRED)', () => {
  // Counterexample identified by ChatGPT R9 (R9-F03-01):
  // When finalizeScan is invoked with a new execution run (scanRunId: 'RUN-B')
  // and no caller-provided nonce, but receives an incomplete manifest (complete: false)
  // that lacks a manifest.scanRunId (or has mismatched scanRunId) while carrying nonce 'NONCE-RUN-A',
  // and 3 ballots from the previous run with nonce 'NONCE-RUN-A',
  // finalizeScan MUST NOT allow the incomplete manifest to supply effectiveNonce!
  // It must strictly fail closed to DEFERRED.
  const candidate = {
    id: 'SEC-MANIFEST-MISSING-RUNID-01',
    ruleId: 'CWE-89',
    title: 'SQL Injection Candidate Facing Manifest with Missing ScanRunId',
    location: { uri: 'skills/security-audit/scripts/safe-git.mjs', startLine: 10, endLine: 25 },
    modelEffort: 'high'
  };

  const incompleteManifestWithoutRunId = {
    complete: false,
    nonce: 'NONCE-RUN-A',
    taskCorrelationNonce: 'NONCE-RUN-A',
    entries: [{ path: 'skills/security-audit/scripts/safe-git.mjs', status: 'SCANNED' }]
  };

  const oldVotesWithOldNonce = [
    {
      findingId: candidate.id,
      reviewerId: 'rev-1',
      lens: 'REACHABILITY',
      decision: 'SUPPORTS',
      nonce: 'NONCE-RUN-A',
      evidence: [{ path: 'skills/security-audit/scripts/safe-git.mjs', line: 10, role: 'source' }]
    },
    {
      findingId: candidate.id,
      reviewerId: 'rev-2',
      lens: 'DEFENSES',
      decision: 'SUPPORTS',
      nonce: 'NONCE-RUN-A',
      evidence: [{ path: 'skills/security-audit/scripts/safe-git.mjs', line: 15, role: 'control' }]
    },
    {
      findingId: candidate.id,
      reviewerId: 'rev-3',
      lens: 'IMPACT',
      decision: 'SUPPORTS',
      nonce: 'NONCE-RUN-A',
      evidence: [{ path: 'skills/security-audit/scripts/safe-git.mjs', line: 25, role: 'sink' }]
    }
  ];

  const scanResult = finalizeScan({
    candidates: [candidate],
    manifest: incompleteManifestWithoutRunId,
    scanRunId: 'RUN-B',
    // Caller does not specify fresh nonce
    votes: oldVotesWithOldNonce,
    repoRoot: process.cwd(),
    allowSelfAudit: true
  });

  const resFinding = scanResult.canonicalFindings[0];
  assert.equal(resFinding.disposition, 'DEFERRED', 'Manifest missing scanRunId must not supply nonce to achieve REPORTABLE');
  assert.notEqual(resFinding.disposition, 'REPORTABLE', 'Must strictly not achieve REPORTABLE');
});

test('Authority Promotion Gate: Missing Both ScanRunIds Cannot Inherit Manifest Nonce Counterexample R10-F03-01 (Fail-Closed to DEFERRED)', () => {
  // Counterexample identified by ChatGPT R10 (R10-F03-01):
  // When finalizeScan is invoked with NO caller-provided scanRunId (scanRunId: null)
  // and NO caller-provided nonce (nonce: null),
  // but receives an incomplete manifest (complete: false) that also lacks scanRunId (manifest.scanRunId: missing)
  // while carrying nonce: 'NONCE-RUN-A',
  // and 3 ballots from a previous run with nonce: 'NONCE-RUN-A',
  // finalizeScan MUST NOT treat null === null as proof of execution identity parity!
  // Manifest nonce inheritance strictly requires both executionRunId and manifestRunId to be valid, non-empty, and matching.
  // It must strictly fail closed to DEFERRED.
  const candidate = {
    id: 'SEC-MANIFEST-DUAL-MISSING-RUNID-01',
    ruleId: 'CWE-89',
    title: 'SQL Injection Candidate Facing Manifest with Missing Both RunIds',
    location: { uri: 'skills/security-audit/scripts/safe-git.mjs', startLine: 10, endLine: 25 },
    modelEffort: 'high'
  };

  const incompleteManifestWithoutRunId = {
    complete: false,
    nonce: 'NONCE-RUN-A',
    taskCorrelationNonce: 'NONCE-RUN-A',
    entries: [{ path: 'skills/security-audit/scripts/safe-git.mjs', status: 'SCANNED' }]
  };

  const oldVotesWithOldNonce = [
    {
      findingId: candidate.id,
      reviewerId: 'rev-1',
      lens: 'REACHABILITY',
      decision: 'SUPPORTS',
      nonce: 'NONCE-RUN-A',
      evidence: [{ path: 'skills/security-audit/scripts/safe-git.mjs', line: 10, role: 'source' }]
    },
    {
      findingId: candidate.id,
      reviewerId: 'rev-2',
      lens: 'DEFENSES',
      decision: 'SUPPORTS',
      nonce: 'NONCE-RUN-A',
      evidence: [{ path: 'skills/security-audit/scripts/safe-git.mjs', line: 15, role: 'control' }]
    },
    {
      findingId: candidate.id,
      reviewerId: 'rev-3',
      lens: 'IMPACT',
      decision: 'SUPPORTS',
      nonce: 'NONCE-RUN-A',
      evidence: [{ path: 'skills/security-audit/scripts/safe-git.mjs', line: 25, role: 'sink' }]
    }
  ];

  const scanResult = finalizeScan({
    candidates: [candidate],
    manifest: incompleteManifestWithoutRunId,
    // Neither scanRunId nor nonce is provided (both null/undefined)
    votes: oldVotesWithOldNonce,
    repoRoot: process.cwd(),
    allowSelfAudit: true
  });

  const resFinding = scanResult.canonicalFindings[0];
  assert.equal(resFinding.disposition, 'DEFERRED', 'Manifest missing both scanRunIds must not supply nonce to achieve REPORTABLE');
  assert.notEqual(resFinding.disposition, 'REPORTABLE', 'Must strictly not achieve REPORTABLE');
});

test('Authority Promotion Gate: Public Renderer Canonical Parity Counterexample R11-F03-01 (renderSarif and renderMarkdown)', () => {
  // Counterexample identified by ChatGPT R11 (R11-F03-01):
  // Public renderers renderSarif and renderMarkdown must maintain 100% canonical parity.
  // Both must accept scanRunId and propagate it to finalizeScan, ensuring active in-progress
  // manifest nonce binding behaves identically whether generating SARIF or Markdown.
  const candidate = {
    id: 'SEC-PARITY-RENDERER-01',
    ruleId: 'CWE-89',
    title: 'SQL Injection in Auth for Parity Check',
    location: { uri: 'skills/security-audit/scripts/safe-git.mjs', startLine: 10, endLine: 25 },
    modelEffort: 'high'
  };

  const manifest = {
    complete: false,
    scanRunId: 'SCAN-PARITY-RUN-01',
    nonce: 'NONCE-PARITY-01',
    taskCorrelationNonce: 'NONCE-PARITY-01',
    entries: [{ path: 'skills/security-audit/scripts/safe-git.mjs', status: 'SCANNED' }]
  };

  const votes = [
    { findingId: candidate.id, reviewerId: 'rev-1', lens: 'REACHABILITY', decision: 'SUPPORTS', nonce: 'NONCE-PARITY-01', evidence: [{ path: 'skills/security-audit/scripts/safe-git.mjs', line: 10, role: 'source' }] },
    { findingId: candidate.id, reviewerId: 'rev-2', lens: 'DEFENSES', decision: 'SUPPORTS', nonce: 'NONCE-PARITY-01', evidence: [{ path: 'skills/security-audit/scripts/safe-git.mjs', line: 15, role: 'control' }] },
    { findingId: candidate.id, reviewerId: 'rev-3', lens: 'IMPACT', decision: 'SUPPORTS', nonce: 'NONCE-PARITY-01', evidence: [{ path: 'skills/security-audit/scripts/safe-git.mjs', line: 25, role: 'sink' }] }
  ];

  const sarifRes = renderSarif({ findings: [candidate], manifest, votes, scanRunId: 'SCAN-PARITY-RUN-01', repoRoot: process.cwd() });
  const mdRes = renderMarkdown({ findings: [candidate], manifest, votes, scanRunId: 'SCAN-PARITY-RUN-01', repoRoot: process.cwd() });

  assert.equal(sarifRes.runs[0].results[0].properties.disposition, 'REPORTABLE', 'renderSarif must promote finding to REPORTABLE');
  assert.ok(mdRes.includes('- **Confirmed Vulnerabilities (Reportable)**: 1'), 'renderMarkdown must reflect 1 Confirmed Vulnerabilities (Reportable)');
  assert.ok(mdRes.includes('- **Needs Manual Review (Deferred / Presumption of Non-Pass)**: 0'), 'renderMarkdown must reflect 0 deferred items');
  assert.ok(mdRes.includes('Confirmed Vulnerabilities (High Assurance)'), 'renderMarkdown must output Confirmed section');
  assert.ok(mdRes.includes('SQL Injection in Auth for Parity Check'), 'renderMarkdown must list candidate in Confirmed section');
});

test('Authority Promotion Gate: Direct-input CLI (render-sarif.mjs --input --votes) with trusted nonce produces REPORTABLE findings (R22-F03-01)', async () => {
  const { spawnSync } = await import('node:child_process');
  const fs = await import('node:fs');
  const os = await import('node:os');
  const path = await import('node:path');

  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'render-cli-test-'));
  const candidatesPath = path.join(tmpDir, 'candidates.json');
  const votesPath = path.join(tmpDir, 'votes.json');
  const sarifOut = path.join(tmpDir, 'output.sarif');
  const mdOut = path.join(tmpDir, 'output.md');

  const testNonce = 'nonce-cli-exec-test-01';
  const testRunId = 'SCAN-CLI-RUN-01';

  const candidate = {
    id: 'SEC-CLI-DIRECT-01',
    ruleId: 'CWE-89',
    title: 'SQL Injection in Direct CLI Path',
    location: { uri: 'skills/security-audit/scripts/safe-git.mjs', startLine: 10, endLine: 25 },
    modelEffort: 'high',
    nonce: testNonce,
    scanRunId: testRunId
  };

  const votes = [
    { findingId: candidate.id, reviewerId: 'rev-1', lens: 'REACHABILITY', decision: 'SUPPORTS', nonce: testNonce, scanRunId: testRunId, evidence: [{ path: 'skills/security-audit/scripts/safe-git.mjs', line: 10, role: 'source' }] },
    { findingId: candidate.id, reviewerId: 'rev-2', lens: 'DEFENSES', decision: 'SUPPORTS', nonce: testNonce, scanRunId: testRunId, evidence: [{ path: 'skills/security-audit/scripts/safe-git.mjs', line: 15, role: 'control' }] },
    { findingId: candidate.id, reviewerId: 'rev-3', lens: 'IMPACT', decision: 'SUPPORTS', nonce: testNonce, scanRunId: testRunId, evidence: [{ path: 'skills/security-audit/scripts/safe-git.mjs', line: 25, role: 'sink' }] }
  ];

  fs.writeFileSync(candidatesPath, JSON.stringify([candidate], null, 2), 'utf8');
  fs.writeFileSync(votesPath, JSON.stringify(votes, null, 2), 'utf8');

  try {
    const renderScript = path.resolve('skills/security-audit/scripts/render-sarif.mjs');
    const result = spawnSync(process.execPath, [
      renderScript,
      '--input', candidatesPath,
      '--votes', votesPath,
      '--nonce', testNonce,
      '--scan-run-id', testRunId,
      '--output-sarif', sarifOut,
      '--output-md', mdOut
    ], { encoding: 'utf8' });

    assert.equal(result.status, 0, `CLI failed with code ${result.status}: ${result.stderr}`);
    assert.ok(fs.existsSync(sarifOut), 'SARIF output file must exist');
    assert.ok(fs.existsSync(mdOut), 'Markdown output file must exist');

    const sarif = JSON.parse(fs.readFileSync(sarifOut, 'utf8'));
    assert.equal(sarif.runs[0].results.length, 1);
    assert.equal(sarif.runs[0].results[0].properties.disposition, 'REPORTABLE', 'Direct CLI with matching nonce must promote to REPORTABLE');

    const md = fs.readFileSync(mdOut, 'utf8');
    assert.ok(md.includes('- **Confirmed Vulnerabilities (Reportable)**: 1'));
    assert.ok(md.includes('- **Needs Manual Review (Deferred / Presumption of Non-Pass)**: 0'));
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test('Authority Promotion Gate: Direct-input CLI without nonce or with mismatched nonce strictly defaults to DEFERRED under Default-Deny (R22-F03-01)', async () => {
  const { spawnSync } = await import('node:child_process');
  const fs = await import('node:fs');
  const os = await import('node:os');
  const path = await import('node:path');

  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'render-cli-fail-'));
  const candidatesPath = path.join(tmpDir, 'candidates.json');
  const votesPath = path.join(tmpDir, 'votes.json');
  const sarifOut = path.join(tmpDir, 'output.sarif');

  const testNonce = 'nonce-cli-exec-test-02';
  const candidate = {
    id: 'SEC-CLI-DIRECT-02',
    ruleId: 'CWE-89',
    title: 'SQL Injection in Direct CLI Path Without Nonce',
    location: { uri: 'skills/security-audit/scripts/safe-git.mjs', startLine: 10, endLine: 25 },
    modelEffort: 'high',
    nonce: testNonce
  };

  const votes = [
    { findingId: candidate.id, reviewerId: 'rev-1', lens: 'REACHABILITY', decision: 'SUPPORTS', nonce: testNonce, evidence: [{ path: 'skills/security-audit/scripts/safe-git.mjs', line: 10, role: 'source' }] },
    { findingId: candidate.id, reviewerId: 'rev-2', lens: 'DEFENSES', decision: 'SUPPORTS', nonce: testNonce, evidence: [{ path: 'skills/security-audit/scripts/safe-git.mjs', line: 15, role: 'control' }] },
    { findingId: candidate.id, reviewerId: 'rev-3', lens: 'IMPACT', decision: 'SUPPORTS', nonce: testNonce, evidence: [{ path: 'skills/security-audit/scripts/safe-git.mjs', line: 25, role: 'sink' }] }
  ];

  fs.writeFileSync(candidatesPath, JSON.stringify([candidate], null, 2), 'utf8');
  fs.writeFileSync(votesPath, JSON.stringify(votes, null, 2), 'utf8');

  try {
    const renderScript = path.resolve('skills/security-audit/scripts/render-sarif.mjs');

    // Case 1: CLI invocation without --nonce
    const resNoNonce = spawnSync(process.execPath, [
      renderScript,
      '--input', candidatesPath,
      '--votes', votesPath,
      '--output-sarif', sarifOut
    ], { encoding: 'utf8' });

    assert.equal(resNoNonce.status, 0);
    const sarifNoNonce = JSON.parse(fs.readFileSync(sarifOut, 'utf8'));
    assert.equal(sarifNoNonce.runs[0].results[0].properties.disposition, 'DEFERRED', 'Omitted nonce must fail closed to DEFERRED');

    // Case 2: CLI invocation with mismatched nonce
    const resMismatch = spawnSync(process.execPath, [
      renderScript,
      '--input', candidatesPath,
      '--votes', votesPath,
      '--nonce', 'wrong-mismatched-nonce',
      '--output-sarif', sarifOut
    ], { encoding: 'utf8' });

    assert.equal(resMismatch.status, 0);
    const sarifMismatch = JSON.parse(fs.readFileSync(sarifOut, 'utf8'));
    assert.equal(sarifMismatch.runs[0].results[0].properties.disposition, 'DEFERRED', 'Mismatched nonce must fail closed to DEFERRED');
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test('Authority Promotion Gate: Direct-input CLI with Manifest Run Binding enforces fail-closed Default-Deny across completed, mismatched, and omitted Run ID, and allows active matching Run Binding (R23-F03-02)', async () => {
  const { spawnSync } = await import('node:child_process');
  const fs = await import('node:fs');
  const os = await import('node:os');
  const path = await import('node:path');

  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'render-cli-manifest-binding-'));
  const candidatesPath = path.join(tmpDir, 'candidates.json');
  const votesPath = path.join(tmpDir, 'votes.json');
  const manifestPath = path.join(tmpDir, 'manifest.json');
  const sarifOut = path.join(tmpDir, 'output.sarif');

  const manifestNonce = 'nonce-manifest-binding-test';
  const candidate = {
    id: 'SEC-CLI-MANIFEST-01',
    ruleId: 'CWE-89',
    title: 'SQL Injection in Manifest Run Binding Test',
    location: { uri: 'skills/security-audit/scripts/safe-git.mjs', startLine: 10, endLine: 25 },
    modelEffort: 'high',
    nonce: manifestNonce,
    scanRunId: 'RUN-MATCH-01'
  };

  const votes = [
    { findingId: candidate.id, reviewerId: 'rev-1', lens: 'REACHABILITY', decision: 'SUPPORTS', nonce: manifestNonce, scanRunId: 'RUN-MATCH-01', evidence: [{ path: 'skills/security-audit/scripts/safe-git.mjs', line: 10, role: 'source' }] },
    { findingId: candidate.id, reviewerId: 'rev-2', lens: 'DEFENSES', decision: 'SUPPORTS', nonce: manifestNonce, scanRunId: 'RUN-MATCH-01', evidence: [{ path: 'skills/security-audit/scripts/safe-git.mjs', line: 15, role: 'control' }] },
    { findingId: candidate.id, reviewerId: 'rev-3', lens: 'IMPACT', decision: 'SUPPORTS', nonce: manifestNonce, scanRunId: 'RUN-MATCH-01', evidence: [{ path: 'skills/security-audit/scripts/safe-git.mjs', line: 25, role: 'sink' }] }
  ];

  fs.writeFileSync(candidatesPath, JSON.stringify([candidate], null, 2), 'utf8');
  fs.writeFileSync(votesPath, JSON.stringify(votes, null, 2), 'utf8');

  const renderScript = path.resolve('skills/security-audit/scripts/render-sarif.mjs');

  try {
    // Scenario 1: Manifest complete: true (Fail-Closed: even with matching scan-run-id, completed manifest cannot inherit nonce)
    fs.writeFileSync(manifestPath, JSON.stringify({
      complete: true,
      scanRunId: 'RUN-MATCH-01',
      nonce: manifestNonce,
      taskCorrelationNonce: manifestNonce
    }, null, 2), 'utf8');

    const resCompleted = spawnSync(process.execPath, [
      renderScript,
      '--input', candidatesPath,
      '--votes', votesPath,
      '--manifest', manifestPath,
      '--scan-run-id', 'RUN-MATCH-01',
      '--output-sarif', sarifOut
    ], { encoding: 'utf8' });

    assert.equal(resCompleted.status, 0);
    const sarifCompleted = JSON.parse(fs.readFileSync(sarifOut, 'utf8'));
    assert.equal(sarifCompleted.runs[0].results[0].properties.disposition, 'DEFERRED', 'Completed manifest must NOT inherit nonce; must fail closed to DEFERRED');

    // Scenario 2: Mismatched Run ID (Manifest has RUN-MATCH-01, execution has RUN-MISMATCH-02)
    fs.writeFileSync(manifestPath, JSON.stringify({
      complete: false,
      scanRunId: 'RUN-MATCH-01',
      nonce: manifestNonce,
      taskCorrelationNonce: manifestNonce
    }, null, 2), 'utf8');

    const resMismatched = spawnSync(process.execPath, [
      renderScript,
      '--input', candidatesPath,
      '--votes', votesPath,
      '--manifest', manifestPath,
      '--scan-run-id', 'RUN-MISMATCH-02',
      '--output-sarif', sarifOut
    ], { encoding: 'utf8' });

    assert.equal(resMismatched.status, 0);
    const sarifMismatched = JSON.parse(fs.readFileSync(sarifOut, 'utf8'));
    assert.equal(sarifMismatched.runs[0].results[0].properties.disposition, 'DEFERRED', 'Mismatched run ID must NOT inherit nonce; must fail closed to DEFERRED');

    // Scenario 3: Omitted Execution Run ID (Manifest has RUN-MATCH-01, CLI supplies no --scan-run-id)
    const resOmitted = spawnSync(process.execPath, [
      renderScript,
      '--input', candidatesPath,
      '--votes', votesPath,
      '--manifest', manifestPath,
      '--output-sarif', sarifOut
    ], { encoding: 'utf8' });

    assert.equal(resOmitted.status, 0);
    const sarifOmitted = JSON.parse(fs.readFileSync(sarifOut, 'utf8'));
    assert.equal(sarifOmitted.runs[0].results[0].properties.disposition, 'DEFERRED', 'Omitted execution run ID must NOT inherit manifest nonce; must fail closed to DEFERRED');

    // Scenario 4: Positive Control: Active in-progress manifest (complete: false) + Matching execution Run ID
    const resPositive = spawnSync(process.execPath, [
      renderScript,
      '--input', candidatesPath,
      '--votes', votesPath,
      '--manifest', manifestPath,
      '--scan-run-id', 'RUN-MATCH-01',
      '--output-sarif', sarifOut
    ], { encoding: 'utf8' });

    assert.equal(resPositive.status, 0);
    const sarifPositive = JSON.parse(fs.readFileSync(sarifOut, 'utf8'));
    assert.equal(sarifPositive.runs[0].results[0].properties.disposition, 'REPORTABLE', 'Active matching manifest run binding must inherit nonce and promote to REPORTABLE');
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});








