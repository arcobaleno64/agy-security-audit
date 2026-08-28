#!/usr/bin/env node
/**
 * run-discovery-eval.mjs
 * Real Agent Discovery Evaluation Benchmark for AGY Security Audit (R2-P0-08).
 * Evaluates discovery agent candidate generation against authentic security benchmark fixtures.
 *
 * Metrics computed:
 * - Candidate True Positives (candidateTP): Unique correctly identified vulnerable sites
 * - Candidate False Positives (candidateFP): Spurious candidates generated on safe/guarded sites
 * - Candidate False Negatives (candidateFN): Vulnerable sites missed by discovery
 * - Discovery Precision: candidateTP / (candidateTP + candidateFP)
 * - Discovery Recall: candidateTP / vulnerableCount
 * - Ground-Truth Coverage: Ratio of vulnerable fixtures discovered
 *
 * Modes:
 * - --candidates <path>: Evaluate real agent candidate findings against ground truth
 * - --simulated: Deterministic CI/CD verification of the discovery evaluation engine
 */

import fs from 'node:fs';
import path from 'node:path';
import { normalizeFilePath, computeLineageFingerprint } from './finalize-scan.mjs';

/**
 * Evaluates candidate findings against ground-truth fixtures.
 */
export function evaluateDiscovery(candidates = [], groundTruth = [], options = {}) {
  const normalizedTruth = groundTruth.map(gt => ({
    id: gt.id,
    cwe: gt.cwe,
    file: normalizeFilePath(gt.file),
    targetLine: gt.targetLine,
    expected: gt.expectedVerdict,
    lineageId: computeLineageFingerprint({
      ruleId: gt.cwe,
      uri: normalizeFilePath(gt.file)
    })
  }));

  const vulnerableTruth = normalizedTruth.filter(t => t.expected === 'VULNERABLE');
  const safeTruth = normalizedTruth.filter(t => t.expected === 'SAFE');

  // Match candidates against vulnerable ground truth
  const matchedVulnerable = new Set();
  const candidateMatches = [];

  let candidateTP = 0;
  let candidateFP = 0;
  let duplicateCandidateCount = 0;
  let uncategorizedCount = 0;

  for (const c of candidates) {
    if (!c || typeof c !== 'object') continue;
    const cUri = normalizeFilePath(c.location?.uri || c.location?.path || '');
    const cRule = c.ruleId || '';

    // Empty or blank URI can NEVER match any fixture (Finding 1 fix)
    if (!cUri || cUri.trim() === '') {
      uncategorizedCount++;
      candidateMatches.push({ candidate: c, groundTruthId: null, kind: 'UNCATEGORIZED' });
      continue;
    }

    // Check if candidate matches any vulnerable truth with path boundary safety
    const matchedVuln = vulnerableTruth.find(vt => {
      const uriMatch = vt.file === cUri || cUri.endsWith('/' + vt.file) || vt.file.endsWith('/' + cUri);
      const ruleMatch = !cRule || vt.cwe.toUpperCase() === cRule.toUpperCase() || cRule.includes(vt.cwe);
      return uriMatch && ruleMatch;
    });

    // Check if candidate flagged a safe/guarded site (False Positive)
    const matchedSafe = safeTruth.find(st => {
      const uriMatch = st.file === cUri || cUri.endsWith('/' + st.file) || st.file.endsWith('/' + cUri);
      return uriMatch;
    });

    if (matchedVuln) {
      if (matchedVulnerable.has(matchedVuln.id)) {
        // Already discovered this site: duplicate candidate does NOT inflate TP (Finding 2 fix)
        duplicateCandidateCount++;
        candidateMatches.push({ candidate: c, groundTruthId: matchedVuln.id, kind: 'DUPLICATE_TP' });
      } else {
        candidateTP++;
        matchedVulnerable.add(matchedVuln.id);
        candidateMatches.push({ candidate: c, groundTruthId: matchedVuln.id, kind: 'TP' });
      }
    } else if (matchedSafe) {
      candidateFP++;
      candidateMatches.push({ candidate: c, groundTruthId: matchedSafe.id, kind: 'FP' });
    } else {
      // Uncategorized / outside benchmark fixture set
      uncategorizedCount++;
      if (options.strictFP) {
        candidateFP++;
      }
      candidateMatches.push({ candidate: c, groundTruthId: null, kind: 'UNCATEGORIZED' });
    }
  }

  const candidateFN = vulnerableTruth.length - matchedVulnerable.size;
  const precision = (candidateTP + candidateFP > 0) ? candidateTP / (candidateTP + candidateFP) : 0;
  const recall = (vulnerableTruth.length > 0) ? candidateTP / vulnerableTruth.length : 0;
  const f1 = (precision + recall > 0) ? (2 * precision * recall) / (precision + recall) : 0;

  return {
    totalGroundTruth: groundTruth.length,
    vulnerableCount: vulnerableTruth.length,
    safeCount: safeTruth.length,
    totalCandidates: candidates.length,
    candidateTP,
    candidateFP,
    candidateFN,
    duplicateCandidateCount,
    uncategorizedCount,
    precision: Number(precision.toFixed(4)),
    recall: Number(recall.toFixed(4)),
    groundTruthRecall: Number(recall.toFixed(4)),
    f1: Number(f1.toFixed(4)),
    matches: candidateMatches,
    missedVulnerabilities: vulnerableTruth.filter(vt => !matchedVulnerable.has(vt.id)).map(vt => vt.id)
  };
}

/**
 * Generates simulated candidate findings for deterministic CI verification.
 */
export function generateSimulatedCandidates(groundTruth = [], profile = 'clean') {
  const candidates = [];
  for (const gt of groundTruth) {
    if (gt.expectedVerdict === 'VULNERABLE') {
      candidates.push({
        id: `SIM-CAND-${gt.id}`,
        ruleId: gt.cwe,
        title: gt.name,
        location: { uri: gt.file, startLine: gt.targetLine }
      });
    } else if (profile === 'noisy' && gt.expectedVerdict === 'SAFE') {
      candidates.push({
        id: `SIM-NOISY-${gt.id}`,
        ruleId: gt.cwe,
        title: `Spurious finding on ${gt.name}`,
        location: { uri: gt.file, startLine: gt.targetLine }
      });
    }
  }
  return candidates;
}

/**
 * Runs discovery evaluation.
 */
export function runDiscoveryEval(repoRoot = process.cwd(), options = {}) {
  const isRecorded = Boolean(options.candidatesFile);
  const evaluationMode = isRecorded ? 'RECORDED_AGENT_RUN' : 'SIMULATED_CI';
  const modelDependent = isRecorded;

  if (isRecorded) {
    console.log('Running Real Agent Discovery Evaluation Benchmark (Recorded Run)...\n');
  } else {
    console.log('Running Discovery Evaluation Harness — Simulated CI Mode...\n');
    console.log('  [Notice] Harness verification using synthetic candidates; not an empirical LLM measurement.\n');
  }

  const gtPath = path.resolve(repoRoot, 'evals/semantic-benchmark/ground-truth.json');
  if (!fs.existsSync(gtPath)) {
    throw new Error(`Ground truth file missing: ${gtPath}`);
  }
  const groundTruth = JSON.parse(fs.readFileSync(gtPath, 'utf8'));

  let candidates = [];
  if (isRecorded) {
    const candPath = path.resolve(repoRoot, options.candidatesFile);
    if (!fs.existsSync(candPath)) {
      throw new Error(`Candidates file missing: ${candPath}`);
    }
    candidates = JSON.parse(fs.readFileSync(candPath, 'utf8'));
  } else {
    // Default to simulated mode for CI invariant check
    candidates = generateSimulatedCandidates(groundTruth, options.profile || 'clean');
  }

  const evalResult = evaluateDiscovery(candidates, groundTruth, options);
  evalResult.evaluationMode = evaluationMode;
  evalResult.modelDependent = modelDependent;

  console.log('================================================================');
  console.log(isRecorded ? 'Real Agent Discovery Evaluation Metrics (Recorded Run):' : 'Discovery Evaluation Harness Metrics (Simulated CI):');
  console.log(`  Evaluation Mode:        ${evaluationMode}`);
  console.log(`  Model-Dependent Run:    ${modelDependent ? 'YES' : 'NO (Synthetic Harness Verification)'}`);
  console.log(`  Total Ground Truth:     ${evalResult.totalGroundTruth} (${evalResult.vulnerableCount} Vuln, ${evalResult.safeCount} Safe)`);
  console.log(`  Candidates Evaluated:   ${evalResult.totalCandidates}`);
  console.log(`  Candidate True Pos (TP): ${evalResult.candidateTP}`);
  console.log(`  Candidate False Pos(FP): ${evalResult.candidateFP}`);
  console.log(`  Candidate False Neg(FN): ${evalResult.candidateFN}`);
  console.log(`  Discovery Precision:    ${(evalResult.precision * 100).toFixed(1)}%`);
  console.log(`  Discovery Recall:       ${(evalResult.recall * 100).toFixed(1)}%`);
  console.log(`  Discovery F1 Score:     ${evalResult.f1.toFixed(3)}`);
  console.log('================================================================\n');

  return evalResult;
}

// -----------------------------------------------------------------------------
// CLI Dispatch
// -----------------------------------------------------------------------------
const isDirectExecution = process.argv[1] && process.argv[1].endsWith('run-discovery-eval.mjs');
if (isDirectExecution) {
  const args = process.argv.slice(2);
  const candIdx = args.indexOf('--candidates');
  const candidatesFile = candIdx !== -1 ? args[candIdx + 1] : null;
  const noisy = args.includes('--noisy');

  const res = runDiscoveryEval(process.cwd(), {
    candidatesFile,
    profile: noisy ? 'noisy' : 'clean'
  });

  if (res.recall < 1.0 && !candidatesFile) {
    console.error('❌ Discovery evaluation failed invariant verification.');
    process.exit(1);
  }
  console.log('✔ Discovery evaluation suite completed successfully.');
}
