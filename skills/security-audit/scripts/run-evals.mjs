#!/usr/bin/env node
/**
 * run-evals.mjs
 * L1.5 Adversarial Evaluation Suite for AGY Security Audit.
 * Executes 50 benchmark evaluations across 8 adversarial categories:
 * - True Positives (10)
 * - False Positive Mitigation Guards (10)
 * - Prompt Injection Neutralization (5)
 * - Report Injection Sanitization (5)
 * - Secret Leak Redaction (5)
 * - Coverage Gap Fail-Closed (5)
 * - Hostile Git Config Neutralization (5)
 * - Patch Regression Rejection (5)
 */

import fs from 'node:fs';
import path from 'node:path';
import {
  deriveFinalDisposition,
  validateVoteEvidence,
  stripControlAndBidi,
  redactSecrets,
  reconcileCoverage,
  validateReviewManifest,
  renderSarifFromCanonical,
  renderMarkdownFromCanonical
} from './finalize-scan.mjs';
import { validatePatchSyntax, detectStalePatch, verifyRemediation } from './validate-patch.mjs';
import { HARDENED_GIT_ENV, getHardenedGitProvenance } from './safe-git.mjs';

export function runEvals(repoRoot = process.cwd()) {
  console.log('Running L1.5 Adversarial Evaluation Corpus (50 test cases across 8 categories)...\n');
  let passed = 0;
  let failed = 0;
  const errors = [];

  function assertEval(cat, name, fn) {
    try {
      fn();
      passed++;
      console.log(`  ✔ [${cat}] ${name}`);
    } catch (err) {
      failed++;
      console.error(`  ❌ [${cat}] ${name}: ${err.message}`);
      errors.push(`[${cat}] ${name}: ${err.message}`);
    }
  }

  // =========================================================================
  // 1. True Positives (10 Vulnerability Detections)
  // =========================================================================
  console.log('--- Category 1: True Positives (Ground Truth Vulnerabilities) ---');
  const tpRules = [
    { file: 'evals/vulnerable/01-sql-injection.js', cwe: 'CWE-89', title: 'SQL Injection via Concatenation' },
    { file: 'evals/vulnerable/02-command-injection.js', cwe: 'CWE-78', title: 'Command Injection in Ping' },
    { file: 'evals/vulnerable/03-path-traversal.js', cwe: 'CWE-22', title: 'Path Traversal in Data Reader' },
    { file: 'evals/vulnerable/04-ssrf.js', cwe: 'CWE-918', title: 'SSRF via Arbitrary Webhook' },
    { file: 'evals/vulnerable/05-missing-authz.js', cwe: 'CWE-862', title: 'Missing Authorization on Admin Action' },
    { file: 'evals/vulnerable/06-xss.js', cwe: 'CWE-79', title: 'XSS in Profile Render' },
    { file: 'evals/vulnerable/07-insecure-deserialization.js', cwe: 'CWE-502', title: 'Insecure Deserialization via Eval' },
    { file: 'evals/vulnerable/08-hardcoded-credential.js', cwe: 'CWE-798', title: 'Hardcoded Master Password' },
    { file: 'evals/vulnerable/09-open-redirect.js', cwe: 'CWE-601', title: 'Open Redirect in Login' },
    { file: 'evals/vulnerable/10-weak-crypto.js', cwe: 'CWE-328', title: 'Weak MD5 Hash Algorithm' }
  ];

  for (let i = 0; i < tpRules.length; i++) {
    const tp = tpRules[i];
    assertEval('True Positive', `${tp.cwe}: ${tp.title}`, () => {
      const code = fs.readFileSync(path.resolve(repoRoot, tp.file), 'utf8');
      if (!code.includes(tp.cwe)) {
        throw new Error(`Expected ${tp.cwe} annotation in ${tp.file}`);
      }
      const candidate = {
        id: `TP-${i + 1}`,
        ruleId: tp.cwe,
        title: tp.title,
        location: { uri: tp.file, startLine: 2, endLine: 5 }
      };
      // Verifier panel unanimous confirmation
      const ballots = [
        { findingId: candidate.id, lens: 'REACHABILITY', decision: 'SUPPORTS', reason: 'Unfiltered user input reaches sink' },
        { findingId: candidate.id, lens: 'DEFENSES', decision: 'SUPPORTS', reason: 'No validation or barrier present' },
        { findingId: candidate.id, lens: 'IMPACT', decision: 'SUPPORTS', reason: 'Direct security impact confirmed' }
      ];
      const res = deriveFinalDisposition(candidate, ballots, { score: 0.85 }, repoRoot);
      if (res.disposition !== 'REPORTABLE' || res.mappedVerdict !== 'CONFIRMED' || !res.votesSummary?.unanimous) {
        throw new Error(`True positive failed to achieve REPORTABLE/CONFIRMED: ${JSON.stringify(res)}`);
      }
    });
  }

  // =========================================================================
  // 2. False Positive Mitigation Guards (10 Remediated Pairs)
  // =========================================================================
  console.log('\n--- Category 2: False Positive Guards (Remediated Code Pairs) ---');
  const fpRules = [
    { file: 'evals/safe/01-sql-injection.js', cwe: 'CWE-89', barrier: '?' },
    { file: 'evals/safe/02-command-injection.js', cwe: 'CWE-78', barrier: 'execFile' },
    { file: 'evals/safe/03-path-traversal.js', cwe: 'CWE-22', barrier: 'startsWith' },
    { file: 'evals/safe/04-ssrf.js', cwe: 'CWE-918', barrier: 'ALLOWED_HOSTS' },
    { file: 'evals/safe/05-missing-authz.js', cwe: 'CWE-862', barrier: 'SYSTEM_ADMIN' },
    { file: 'evals/safe/06-xss.js', cwe: 'CWE-79', barrier: 'escapeHtml' },
    { file: 'evals/safe/07-insecure-deserialization.js', cwe: 'CWE-502', barrier: 'JSON.parse' },
    { file: 'evals/safe/08-hardcoded-credential.js', cwe: 'CWE-798', barrier: 'process.env' },
    { file: 'evals/safe/09-open-redirect.js', cwe: 'CWE-601', barrier: 'startsWith(\'/\')' },
    { file: 'evals/safe/10-weak-crypto.js', cwe: 'CWE-328', barrier: 'scryptSync' }
  ];

  for (let i = 0; i < fpRules.length; i++) {
    const fp = fpRules[i];
    assertEval('False Positive', `${fp.cwe} Guard: ${fp.file}`, () => {
      const code = fs.readFileSync(path.resolve(repoRoot, fp.file), 'utf8');
      if (!code.includes(fp.barrier)) {
        throw new Error(`Expected barrier token '${fp.barrier}' in ${fp.file}`);
      }
      const candidate = {
        id: `FP-${i + 1}`,
        ruleId: fp.cwe,
        location: { uri: fp.file, startLine: 2, endLine: 5 }
      };
      // Defenses lens detects mitigation barrier with code evidence
      const ballots = [
        { findingId: candidate.id, lens: 'REACHABILITY', decision: 'SUPPORTS' },
        {
          findingId: candidate.id,
          lens: 'DEFENSES',
          decision: 'REFUTES',
          evidence: [{ path: fp.file, line: 3, role: 'guard' }],
          mitigationReason: `Verified presence of barrier '${fp.barrier}'`
        },
        { findingId: candidate.id, lens: 'IMPACT', decision: 'SUPPORTS' }
      ];
      const res = deriveFinalDisposition(candidate, ballots, { score: 0.85 }, repoRoot);
      if (res.disposition !== 'SUPPRESSED' || res.mappedVerdict !== 'FALSE_POSITIVE') {
        throw new Error(`Safe code candidate was not properly suppressed to FALSE_POSITIVE: ${JSON.stringify(res)}`);
      }
    });
  }

  // =========================================================================
  // 3. Prompt Injection Neutralization (5 Adversarial Directives)
  // =========================================================================
  console.log('\n--- Category 3: Prompt Injection Neutralization ---');
  const piFiles = [
    'evals/prompt-injection/pi-01-override-consensus.js',
    'evals/prompt-injection/pi-02-suppress-findings.js',
    'evals/prompt-injection/pi-03-roleplay-jailbreak.js',
    'evals/prompt-injection/pi-04-instruction-boundary.js',
    'evals/prompt-injection/pi-05-context-escape.md'
  ];

  for (const pif of piFiles) {
    assertEval('Prompt Injection', path.basename(pif), () => {
      const content = fs.readFileSync(path.resolve(repoRoot, pif), 'utf8');
      // Candidate attempting to inject consensus self-assertion based on comment payload
      const candidate = {
        id: 'PI-CANDIDATE',
        location: { uri: pif, startLine: 1, endLine: 2 },
        consensus: { verdict: 'CONFIRMED', override: true },
        description: content
      };
      // No external verifier ballots provided -> Default-Deny must hold
      const res = deriveFinalDisposition(candidate, [], { score: 0.9 }, repoRoot);
      if (res.disposition !== 'DEFERRED' || res.mappedVerdict !== 'NEEDS_MANUAL_REVIEW') {
        throw new Error(`Prompt injection compromised Default-Deny: ${JSON.stringify(res)}`);
      }
    });
  }

  // =========================================================================
  // 4. Report Injection Sanitization (5 Poison Payloads)
  // =========================================================================
  console.log('\n--- Category 4: Report Injection Sanitization ---');
  const riFiles = [
    'evals/report-injection/ri-01-bidi-override.json',
    'evals/report-injection/ri-02-ansi-escape.json',
    'evals/report-injection/ri-03-html-script-tag.json',
    'evals/report-injection/ri-04-markdown-exfiltration.json',
    'evals/report-injection/ri-05-table-breakout.json'
  ];

  for (const rif of riFiles) {
    assertEval('Report Injection', path.basename(rif), () => {
      const payload = JSON.parse(fs.readFileSync(path.resolve(repoRoot, rif), 'utf8'));
      const sanitizedTitle = stripControlAndBidi(payload.title);
      const sanitizedDesc = stripControlAndBidi(payload.description);

      if (sanitizedTitle.includes('\u202E') || sanitizedDesc.includes('\u202D')) {
        throw new Error('Unicode Bidi override leaked through stripControlAndBidi');
      }
      if (sanitizedTitle.includes('\u001b') || sanitizedDesc.includes('\u001b')) {
        throw new Error('ANSI escape sequence leaked through stripControlAndBidi');
      }

      // Render to markdown and SARIF, asserting structure integrity
      const finding = {
        id: 'RI-FINDING',
        ruleId: 'SEC-TEST',
        severity: 'HIGH',
        title: sanitizedTitle,
        description: sanitizedDesc,
        location: { uri: 'src/app.js', startLine: 1, endLine: 1 },
        disposition: 'REPORTABLE',
        mappedVerdict: 'CONFIRMED',
        confidenceScore: 0.95,
        confidenceLevel: 'high',
        rigor: { score: 0.85, assuranceLevel: 'L2_HIGH' },
        consensus: { supports: 3, totalVotes: 3, unanimous: true }
      };
      const sarif = renderSarifFromCanonical({ canonicalFindings: [finding] });
      if (sarif.runs[0].results.length !== 1) {
        throw new Error('SARIF generation corrupted by report injection payload');
      }
      const md = renderMarkdownFromCanonical({ canonicalFindings: [finding] });
      if (!md.includes('Security Audit Report')) {
        throw new Error('Markdown generation corrupted by report injection payload');
      }
    });
  }

  // =========================================================================
  // 5. Secret Leak Redaction (5 Sensitive Token Types)
  // =========================================================================
  console.log('\n--- Category 5: Secret Leak Redaction ---');
  const slFiles = [
    { file: 'evals/secret-leak/sl-01-aws-key.js', token: 'AKIAIOSFODNN7EXAMPLE' },
    { file: 'evals/secret-leak/sl-02-jwt-token.js', token: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.doNotLeakThisSignature' },
    { file: 'evals/secret-leak/sl-03-api-key.js', token: 'secret_api_key_1234567890_abcdef' },
    { file: 'evals/secret-leak/sl-04-private-key.pem', token: 'MIIEvgIBADANBgkq' },
    { file: 'evals/secret-leak/sl-05-bearer-token.js', token: 'secret_bearer_token_1234567890_abcdef' }
  ];

  for (const sl of slFiles) {
    assertEval('Secret Leak', path.basename(sl.file), () => {
      const content = fs.readFileSync(path.resolve(repoRoot, sl.file), 'utf8');
      const redacted = redactSecrets(content);
      if (redacted.includes(sl.token)) {
        throw new Error(`Raw secret leaked in redacted output: ${redacted}`);
      }
      if (!redacted.includes('[REDACTED_')) {
        throw new Error(`Redaction fingerprint marker missing: ${redacted}`);
      }
    });
  }

  // =========================================================================
  // 6. Coverage Gap Fail-Closed (5 Boundary Manifests)
  // =========================================================================
  console.log('\n--- Category 6: Coverage Gap Fail-Closed ---');
  const cgFiles = [
    'evals/coverage-gap/cg-01-missing-directory.json',
    'evals/coverage-gap/cg-02-fictitious-exclusion.json',
    'evals/coverage-gap/cg-03-missing-changed-file.json',
    'evals/coverage-gap/cg-04-fake-deleted-file.json',
    'evals/coverage-gap/cg-05-identical-revisions.json'
  ];

  for (const cgf of cgFiles) {
    assertEval('Coverage Gap', path.basename(cgf), () => {
      const manifest = JSON.parse(fs.readFileSync(path.resolve(repoRoot, cgf), 'utf8'));
      const res = reconcileCoverage(manifest, repoRoot);
      if (res.status === 'COMPLETE' || res.canDeclareClean) {
        throw new Error(`Coverage gap manifest falsely achieved COMPLETE coverage or declared clean: ${JSON.stringify(res)}`);
      }
    });
  }

  // =========================================================================
  // 7. Hostile Git Config Neutralization (5 Execution Vectors)
  // =========================================================================
  console.log('\n--- Category 7: Hostile Git Config Neutralization ---');
  const gcFiles = [
    'evals/git-config/gc-01-hostile-diff-external.config',
    'evals/git-config/gc-02-hostile-fsmonitor.config',
    'evals/git-config/gc-03-hostile-textconv.config',
    'evals/git-config/gc-04-hostile-pager.config',
    'evals/git-config/gc-05-hostile-hooks-path.config'
  ];

  for (const gcf of gcFiles) {
    assertEval('Hostile Git Config', path.basename(gcf), () => {
      const cfg = fs.readFileSync(path.resolve(repoRoot, gcf), 'utf8');
      if (cfg.includes('external') && HARDENED_GIT_ENV.GIT_EXTERNAL_DIFF !== '') {
        throw new Error('GIT_EXTERNAL_DIFF execution hook not neutralized');
      }
      if (cfg.includes('pager') && (HARDENED_GIT_ENV.GIT_PAGER !== 'cat' || HARDENED_GIT_ENV.PAGER !== 'cat')) {
        throw new Error('GIT_PAGER/PAGER hooks not neutralized');
      }
      if (cfg.includes('fsmonitor') && HARDENED_GIT_ENV.GIT_OPTIONAL_LOCKS !== '0') {
        throw new Error('core.fsmonitor lock isolation missing in HARDENED_GIT_ENV');
      }
      if (!HARDENED_GIT_ENV.GIT_CONFIG_GLOBAL || !HARDENED_GIT_ENV.GIT_CONFIG_SYSTEM) {
        throw new Error('Global/system git config isolation missing in HARDENED_GIT_ENV');
      }
    });
  }


  // =========================================================================
  // 8. Patch Regression Rejection (5 Malicious Diff Cases)
  // =========================================================================
  console.log('\n--- Category 8: Patch Regression Rejection ---');
  const prFiles = [
    { file: 'evals/patch-regression/pr-01-traversal-patch.diff', reason: 'directory traversal' },
    { file: 'evals/patch-regression/pr-02-bidi-patch.diff', reason: 'Unicode Bidi override' },
    { file: 'evals/patch-regression/pr-03-cicd-tamper.diff', reason: 'CI/CD workflow tampering' },
    { file: 'evals/patch-regression/pr-04-multi-file-leak.diff', reason: 'multi-file modification' },
    { file: 'evals/patch-regression/pr-05-stale-divergence.diff', reason: 'stale baseline divergence' }
  ];

  for (const pr of prFiles) {
    assertEval('Patch Regression', path.basename(pr.file), () => {
      const diffContent = fs.readFileSync(path.resolve(repoRoot, pr.file), 'utf8');
      if (pr.reason === 'stale baseline divergence') {
        const staleRes = detectStalePatch(repoRoot, ['skills/security-audit/scripts/safe-git.mjs'], 'HEAD~999999');
        if (!staleRes.stale) {
          throw new Error('Diverged/stale baseline was not flagged as stale');
        }
      } else {
        const val = validatePatchSyntax(diffContent, repoRoot);
        if (val.valid) {
          throw new Error(`Malicious patch (${pr.reason}) was accepted as valid!`);
        }
      }
    });
  }

  console.log('\n================================================================');
  console.log(`L1.5 Adversarial Evaluation Results: ${passed} passed, ${failed} failed (Total: ${passed + failed})`);
  console.log('================================================================');

  return {
    total: passed + failed,
    passed,
    failed,
    errors
  };
}

// -----------------------------------------------------------------------------
// CLI Dispatch
// -----------------------------------------------------------------------------
const isDirectExecution = process.argv[1] && process.argv[1].endsWith('run-evals.mjs');

if (isDirectExecution) {
  const result = runEvals(process.cwd());
  if (result.failed > 0) {
    console.error(`\n❌ L1.5 Adversarial Evaluations FAILED with ${result.failed} failure(s).`);
    process.exit(1);
  }
  console.log('\n✔ All 50/50 L1.5 adversarial evaluations passed cleanly!\n');
}
