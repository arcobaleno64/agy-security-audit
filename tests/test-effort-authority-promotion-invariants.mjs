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
