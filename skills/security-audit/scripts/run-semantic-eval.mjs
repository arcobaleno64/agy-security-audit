#!/usr/bin/env node
/**
 * run-semantic-eval.mjs
 * L1.5 Disposition Ground-Truth Benchmark (Canonical Decision Invariants)
 * Evaluates deterministic finalizer decision compliance, ballot reconciliation, and Default-Deny gating
 * against ground-truth decision pairs across authentic complex vulnerability archetypes:
 * - Authorization Bypass (CWE-862)
 * - Cross-Tenant Data Access (CWE-639)
 * - Confused Deputy (CWE-441)
 * - State Machine Transition Bug (CWE-840)
 * - Validated vs. Consumed Mismatch (CWE-20)
 * - Partial Mitigation (CWE-79)
 * - Insecure Default (CWE-1188)
 * - Multi-Step Taint Flow (CWE-94)
 *
 * NOTE: This benchmark measures canonical decision invariants under fixed ballots,
 * NOT stochastic LLM discovery recall or agent hunting precision (R2-P0-08).
 * Real discovery evaluation is benchmarked by run-discovery-eval.mjs and run-stability-eval.mjs.
 *
 * Metrics computed:
 * - True Positives (TP)
 * - True Negatives (TN)
 * - False Positives (FP)
 * - False Negatives (FN)
 * - Decision Precision: TP / (TP + FP)
 * - Decision Recall: TP / (TP + FN)
 * - Decision F1 Score: 2 * (Precision * Recall) / (Precision + Recall)
 * - Decision Invariant Accuracy: (TP + TN) / Total
 * - Deterministic Stability (variance across repeated passes)
 */

import fs from 'node:fs';
import path from 'node:path';
import {
  deriveFinalDisposition,
  validateVoteEvidence,
  finalizeScan
} from './finalize-scan.mjs';

/**
 * Runs the disposition ground-truth benchmark against decision pairs.
 */
export function runSemanticEval(repoRoot = process.cwd(), iterations = 2) {
  console.log('Running L1.5 Disposition Ground-Truth Benchmark (Canonical Decision Invariants)...\n');
  console.log('  [Notice] Verifies canonical finalizer decision logic compliance; not stochastic agent discovery.\n');
  const groundTruthPath = path.resolve(repoRoot, 'evals/semantic-benchmark/ground-truth.json');
  if (!fs.existsSync(groundTruthPath)) {
    throw new Error(`Ground truth file not found at: ${groundTruthPath}`);
  }

  const groundTruth = JSON.parse(fs.readFileSync(groundTruthPath, 'utf8'));
  const results = [];
  const runSignatures = [];

  for (let iter = 1; iter <= iterations; iter++) {
    let tp = 0;
    let tn = 0;
    let fp = 0;
    let fn = 0;
    const iterFindings = [];

    for (const testCase of groundTruth) {
      const filePath = path.resolve(repoRoot, testCase.file);
      if (!fs.existsSync(filePath)) {
        throw new Error(`Benchmark fixture file missing: ${testCase.file}`);
      }

      // Construct candidate representation bound to ground truth coordinate
      const candidate = {
        id: testCase.id,
        ruleId: testCase.cwe,
        title: testCase.name,
        severity: testCase.severity,
        location: {
          uri: testCase.file,
          startLine: testCase.targetLine,
          endLine: testCase.targetLine
        }
      };

      let ballots = [];
      if (testCase.expectedVerdict === 'VULNERABLE') {
        // Construct evidence-bound 3-Lens panel ballots supporting vulnerability
        ballots = [
          {
            findingId: testCase.id,
            lens: 'REACHABILITY',
            decision: 'SUPPORTS',
            evidence: [{ path: testCase.file, line: testCase.targetLine, role: 'entrypoint' }]
          },
          {
            findingId: testCase.id,
            lens: 'DEFENSES',
            decision: 'SUPPORTS',
            evidence: [{ path: testCase.file, line: testCase.targetLine, role: 'guard' }]
          },
          {
            findingId: testCase.id,
            lens: 'IMPACT',
            decision: 'SUPPORTS',
            evidence: [{ path: testCase.file, line: testCase.targetLine, role: 'sink' }]
          }
        ];
      } else {
        // Safe case: Complete 3-Lens panel refutes with verified in-repo mitigation proof
        ballots = [
          {
            findingId: testCase.id,
            lens: 'DEFENSES',
            decision: 'REFUTES',
            mitigationProofLine: `${testCase.mitigationProof.path}:${testCase.mitigationProof.line}`,
            mitigationReason: testCase.mitigationProof.reason,
            evidence: [{ path: testCase.mitigationProof.path, line: testCase.mitigationProof.line, role: 'guard' }]
          },
          {
            findingId: testCase.id,
            lens: 'REACHABILITY',
            decision: 'REFUTES',
            reason: 'Path mitigated by guard invariant',
            evidence: [{ path: testCase.mitigationProof.path, line: testCase.mitigationProof.line, role: 'guard' }]
          },
          {
            findingId: testCase.id,
            lens: 'IMPACT',
            decision: 'REFUTES',
            reason: 'Zero exploitability due to guard invariant',
            evidence: [{ path: testCase.mitigationProof.path, line: testCase.mitigationProof.line, role: 'guard' }]
          }
        ];
      }

      const disposition = deriveFinalDisposition(candidate, ballots, { score: 0.9 }, repoRoot);
      const isReportable = disposition.disposition === 'REPORTABLE';
      const isSuppressed = disposition.disposition === 'SUPPRESSED';
      const expectedReportable = testCase.expectedVerdict === 'VULNERABLE';

      let casePassed = false;
      if (expectedReportable) {
        if (isReportable) {
          tp++;
          casePassed = true;
        } else {
          fn++;
        }
      } else {
        if (isSuppressed) {
          tn++;
          casePassed = true;
        } else {
          fp++;
        }
      }

      iterFindings.push({
        id: testCase.id,
        name: testCase.name,
        category: testCase.category,
        cwe: testCase.cwe,
        expected: testCase.expectedVerdict,
        verdict: disposition.mappedVerdict,
        disposition: disposition.disposition,
        passed: casePassed
      });
    }

    const signature = iterFindings.map(f => `${f.id}:${f.disposition}`).join('|');
    runSignatures.push(signature);

    if (iter === 1) {
      results.push(...iterFindings);
    }
  }

  // Print results table
  console.log('| ID | Category | CWE | Expected | Evaluated | Status |');
  console.log('| :--- | :--- | :--- | :--- | :--- | :--- |');
  for (const r of results) {
    const statusMark = r.passed ? '✔ PASS' : '❌ FAIL';
    console.log(`| ${r.id} | ${r.category} | ${r.cwe} | ${r.expected} | ${r.disposition} | ${statusMark} |`);
  }

  // Calculate metrics
  const total = results.length;
  const passedCount = results.filter(r => r.passed).length;
  const tp = results.filter(r => r.expected === 'VULNERABLE' && r.passed).length;
  const tn = results.filter(r => r.expected === 'SAFE' && r.passed).length;
  const fp = results.filter(r => r.expected === 'SAFE' && !r.passed).length;
  const fn = results.filter(r => r.expected === 'VULNERABLE' && !r.passed).length;

  const precision = tp + fp > 0 ? tp / (tp + fp) : 0;
  const recall = tp + fn > 0 ? tp / (tp + fn) : 0;
  const f1 = (precision + recall) > 0 ? (2 * precision * recall) / (precision + recall) : 0;
  const accuracy = total > 0 ? (tp + tn) / total : 0;

  // Run-to-run stability
  const isStable = runSignatures.every(s => s === runSignatures[0]);

  console.log('\n================================================================');
  console.log('L1.5 Disposition Ground-Truth Benchmark Metrics:');
  console.log('  Notice: Measures finalizer decision logic compliance; not LLM discovery rate.');
  console.log(`  Total Ground-Truth Pairs: ${total} (8 Vulnerable, 4 Safe/Guarded)`);
  console.log(`  True Positives (TP):      ${tp}`);
  console.log(`  True Negatives (TN):      ${tn}`);
  console.log(`  False Positives (FP):     ${fp}`);
  console.log(`  False Negatives (FN):     ${fn}`);
  console.log(`  Decision Precision:       ${(precision * 100).toFixed(1)}%`);
  console.log(`  Decision Recall:          ${(recall * 100).toFixed(1)}%`);
  console.log(`  Decision F1 Score:        ${f1.toFixed(3)}`);
  console.log(`  Decision Invariant Rate:  ${(accuracy * 100).toFixed(1)}%`);
  console.log(`  Run-to-Run Determinism:   ${isStable ? '100% Deterministic' : 'Variance Detected'}`);
  console.log('================================================================\n');

  return {
    total,
    passed: passedCount,
    failed: total - passedCount,
    tp,
    tn,
    fp,
    fn,
    precision,
    recall,
    f1,
    accuracy,
    isStable,
    results
  };
}

// -----------------------------------------------------------------------------
// CLI Dispatch
// -----------------------------------------------------------------------------
const isDirectExecution = process.argv[1] && process.argv[1].endsWith('run-semantic-eval.mjs');

if (isDirectExecution) {
  const result = runSemanticEval(process.cwd());
  if (result.failed > 0 || !result.isStable) {
    console.error(`❌ Disposition Ground-Truth Benchmark FAILED.`);
    process.exit(1);
  }
  console.log(`✔ All ${result.passed}/${result.total} disposition ground-truth invariant tests passed deterministically!\n`);
}
