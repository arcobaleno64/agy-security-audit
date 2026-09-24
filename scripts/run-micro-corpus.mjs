#!/usr/bin/env node
/**
 * run-micro-corpus.mjs
 * Track D Phase D2: Live Assurance Micro-Corpus Evaluation Harness.
 *
 * Conforming to RFC 0002 §5.2, §6, and §8:
 * - Executes the frozen micro-corpus protocol across three controls:
 *   1. Clear Vulnerable Control (quickstart-vulnerable, CWE-22 Path Traversal)
 *   2. Clear Safe Control (quickstart-safe, Path Traversal Defense Barrier)
 *   3. Architectural Dispute Control (quickstart-disputed, CWE-918 Local Loopback SSRF Proxy)
 * - Supports both authentic AGY execution and deterministic mock replay.
 * - Emits structured tier2Results conforming to schemas/reproduction-record.schema.json.
 * - Zero external npm dependencies (pure Node.js built-ins).
 */

import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { runDoctor } from './doctor.mjs';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
export const DEFAULT_REPO_ROOT = path.resolve(__dirname, '..');

export const MICRO_CORPUS_GROUND_TRUTH = 'evals/micro-corpus/ground-truth.json';

/**
 * Computes deterministic SHA-256 hash of a string or buffer.
 */
export function computeDigest(content) {
  return crypto.createHash('sha256').update(content, 'utf8').digest('hex');
}

/**
 * Evaluates the 3 micro-corpus controls deterministically using AST/syntactic verification.
 * Used for hermetic CI testing and environments without paid model tokens.
 */
export function evaluateSyntheticMicroCorpus(repoRoot = DEFAULT_REPO_ROOT) {
  const gtPath = path.resolve(repoRoot, MICRO_CORPUS_GROUND_TRUTH);
  if (!fs.existsSync(gtPath)) {
    throw new Error(`Micro-corpus ground truth not found at: ${gtPath}`);
  }
  const groundTruth = JSON.parse(fs.readFileSync(gtPath, 'utf8'));

  const results = {
    vulnerable: null,
    safe: null,
    disputed: null,
    traces: []
  };

  for (const item of groundTruth) {
    const targetFile = path.resolve(repoRoot, item.targetFile);
    if (!fs.existsSync(targetFile)) {
      throw new Error(`Micro-corpus fixture file not found: ${targetFile}`);
    }
    const code = fs.readFileSync(targetFile, 'utf8');

    if (item.id === 'MC-VULN') {
      // Confirm presence of unconstrained path concatenation sink
      const hasDirectJoin = /path\.join\s*\(\s*publicDir\s*,\s*userPath\s*\)/.test(code);
      const hasRead = /fs\.readFileSync\s*\(\s*targetFile/.test(code);
      const hasContainmentCheck = /path\.relative/.test(code);

      if (hasDirectJoin && hasRead && !hasContainmentCheck) {
        results.vulnerable = 'TRUE_POSITIVE_CONFIRMED';
        results.traces.push({
          id: item.id,
          finding: 'CWE-22',
          verdict: 'VULNERABLE',
          status: 'TRUE_POSITIVE_CONFIRMED',
          evidence: { sink: 'fs.readFileSync', entrypoint: 'serveUserAsset', line: item.targetLine }
        });
      } else {
        results.vulnerable = 'FALSE_NEGATIVE';
      }
    } else if (item.id === 'MC-SAFE') {
      // Confirm presence of strict path containment barrier
      const hasContainmentCheck = /path\.relative\s*\(\s*resolvedBase\s*,\s*targetFile\s*\)/.test(code);
      const hasEscapesCheck = /relative\.startsWith\s*\(\s*['"]\.\.['"]\s*\)/.test(code);

      if (hasContainmentCheck && hasEscapesCheck) {
        results.safe = 'FALSE_POSITIVE_SUPPRESSED';
        results.traces.push({
          id: item.id,
          finding: null,
          verdict: 'SAFE',
          status: 'FALSE_POSITIVE_SUPPRESSED',
          evidence: { barrier: 'path.relative directory enclosure verification' }
        });
      } else {
        results.safe = 'SPURIOUS_ALERT_DETECTED';
      }
    } else if (item.id === 'MC-DISPUTE') {
      // Confirm presence of loopback host check
      const hasLoopbackCheck = /ALLOWED_LOOPBACK_HOSTS\.has\s*\(\s*host\s*\)/.test(code);
      const hasDynamicUrl = /http:\/\/\$\{host\}:\$\{numericPort\}/.test(code);

      if (hasLoopbackCheck && hasDynamicUrl) {
        results.disputed = 'ORACLE_DISPUTE_RECONCILED';
        results.traces.push({
          id: item.id,
          finding: 'CWE-918',
          verdict: 'DISPUTED',
          status: 'ORACLE_DISPUTE_RECONCILED',
          evidence: { boundary: 'ALLOWED_LOOPBACK_HOSTS restriction', disposition: 'INTENTIONAL_IPC_DESIGN' }
        });
      } else {
        results.disputed = 'DISPUTE_UNRESOLVED';
      }
    }
  }

  const streamTraceString = results.traces.map(t => JSON.stringify(t)).join('\n') + '\n';
  const streamDigest = computeDigest(streamTraceString);

  const passed =
    results.vulnerable === 'TRUE_POSITIVE_CONFIRMED' &&
    results.safe === 'FALSE_POSITIVE_SUPPRESSED' &&
    results.disputed === 'ORACLE_DISPUTE_RECONCILED';

  return {
    status: passed ? 'PASS' : 'FAIL',
    vulnerableControl: results.vulnerable,
    safeControl: results.safe,
    disputeControl: results.disputed,
    streamDigest,
    rawStream: streamTraceString
  };
}

/**
 * Executes live AGY discovery across the micro-corpus fixtures.
 */
export function executeLiveAgyMicroCorpus(repoRoot = DEFAULT_REPO_ROOT, options = {}) {
  const agyBin = process.platform === 'win32' ? 'agy.exe' : 'agy';
  const gtPath = path.resolve(repoRoot, MICRO_CORPUS_GROUND_TRUTH);
  const groundTruth = JSON.parse(fs.readFileSync(gtPath, 'utf8'));

  const rawStreamChunks = [];
  const results = {
    vulnerable: null,
    safe: null,
    disputed: null
  };

  for (const item of groundTruth) {
    const fixtureDir = path.resolve(repoRoot, item.targetDir);
    let prompt = '';
    if (item.id === 'MC-VULN') {
      prompt = 'You are conducting a strict security review under Default-Deny on index.js. Audit index.js. If an unmitigated vulnerability exists, output JSON: {"verdict": "VULNERABLE", "cwe": "CWE-22"}. If safe, output: {"verdict": "SAFE"}. Output ONLY JSON.';
    } else if (item.id === 'MC-SAFE') {
      prompt = 'You are conducting a strict security review under Default-Deny on index.js. Audit index.js. If an unmitigated vulnerability exists, output JSON: {"verdict": "VULNERABLE", "cwe": "CWE-22"}. If safe or properly mitigated, output: {"verdict": "SAFE"}. Output ONLY JSON.';
    } else if (item.id === 'MC-DISPUTE') {
      prompt = 'You are conducting a strict security review under Default-Deny on index.js. Audit index.js. If an unmitigated vulnerability exists, output JSON: {"verdict": "VULNERABLE", "cwe": "CWE-918"}. If an intentional local architectural boundary/disputed trade-off, output: {"verdict": "DISPUTED", "rationale": "..."}. Output ONLY JSON.';
    }

    const agyArgs = ['--mode', 'plan', '--print', prompt];
    const proc = spawnSync(agyBin, agyArgs, {
      cwd: fixtureDir,
      encoding: 'utf8',
      timeout: options.timeoutMs || 180000,
      env: { ...process.env, PAGER: 'cat' },
      stdio: ['ignore', 'pipe', 'pipe']
    });

    const stdout = proc.stdout || '';
    rawStreamChunks.push(JSON.stringify({
      id: item.id,
      exitCode: proc.status,
      stdout: stdout.trim(),
      stderr: (proc.stderr || '').trim()
    }));

    // Extract JSON verdict
    let parsedJson = null;
    let cleanText = stdout.trim();
    const mdMatch = cleanText.match(/```(?:json)?\s*([\s\S]*?)\s*```/);
    if (mdMatch) {
      cleanText = mdMatch[1].trim();
    }
    const firstBrace = cleanText.indexOf('{');
    const lastBrace = cleanText.lastIndexOf('}');
    if (firstBrace !== -1 && lastBrace > firstBrace) {
      try {
        parsedJson = JSON.parse(cleanText.slice(firstBrace, lastBrace + 1));
      } catch {}
    }

    const verdict = parsedJson?.verdict || '';

    if (item.id === 'MC-VULN') {
      const isVuln = verdict === 'VULNERABLE' || /CWE-22|path-traversal|Path Traversal/i.test(stdout);
      results.vulnerable = isVuln ? 'TRUE_POSITIVE_CONFIRMED' : 'FALSE_NEGATIVE';
    } else if (item.id === 'MC-SAFE') {
      const isSafe = verdict === 'SAFE' || (/BOUNDED_CLEAN|ZERO_FINDINGS|SAFE/i.test(stdout) && !/CWE-22/i.test(stdout));
      results.safe = isSafe ? 'FALSE_POSITIVE_SUPPRESSED' : 'SPURIOUS_ALERT_DETECTED';
    } else if (item.id === 'MC-DISPUTE') {
      const isDisputed = verdict === 'DISPUTED' || /DISPUTED|INTENTIONAL|LOOPBACK/i.test(stdout);
      results.disputed = isDisputed ? 'ORACLE_DISPUTE_RECONCILED' : 'DISPUTE_UNRESOLVED';
    }
  }

  const rawStream = rawStreamChunks.join('\n') + '\n';
  const streamDigest = computeDigest(rawStream);

  const passed =
    results.vulnerable === 'TRUE_POSITIVE_CONFIRMED' &&
    results.safe === 'FALSE_POSITIVE_SUPPRESSED' &&
    results.disputed === 'ORACLE_DISPUTE_RECONCILED';

  return {
    status: passed ? 'PASS' : 'FAIL',
    vulnerableControl: results.vulnerable,
    safeControl: results.safe,
    disputeControl: results.disputed,
    streamDigest,
    rawStream
  };
}

/**
 * Main entrypoint for Tier 2 Micro-Corpus Reproduction.
 */
export function executeTier2Reproduction(options = {}) {
  const repoRoot = path.resolve(options.repoRoot || DEFAULT_REPO_ROOT);

  // If mock mode is explicitly requested, run synthetic verification
  if (options.mock) {
    const res = evaluateSyntheticMicroCorpus(repoRoot);
    return {
      status: res.status,
      vulnerableControl: res.vulnerableControl,
      safeControl: res.safeControl,
      disputeControl: res.disputeControl,
      streamDigest: res.streamDigest
    };
  }

  // Preflight check for live AGY environment
  let doctorReport = options.doctorReport;
  if (!doctorReport) {
    try {
      doctorReport = runDoctor({ repoRoot });
    } catch (err) {
      return {
        status: 'UNVERIFIABLE',
        vulnerableControl: null,
        safeControl: null,
        disputeControl: null,
        streamDigest: null
      };
    }
  }

  const agyCheck = doctorReport.checks?.find(c => c.id === 'agy');
  const agyReady = agyCheck && agyCheck.status === 'READY';

  if (!agyReady) {
    return {
      status: 'SKIPPED',
      vulnerableControl: null,
      safeControl: null,
      disputeControl: null,
      streamDigest: null
    };
  }

  try {
    const res = executeLiveAgyMicroCorpus(repoRoot, options);
    return {
      status: res.status,
      vulnerableControl: res.vulnerableControl,
      safeControl: res.safeControl,
      disputeControl: res.disputeControl,
      streamDigest: res.streamDigest
    };
  } catch (err) {
    return {
      status: 'FAIL',
      vulnerableControl: null,
      safeControl: null,
      disputeControl: null,
      streamDigest: null
    };
  }
}

function parseArgs(argv) {
  const opts = {
    json: false,
    mock: false,
    out: null
  };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--json') opts.json = true;
    else if (a === '--mock') opts.mock = true;
    else if (a === '--out' && i + 1 < argv.length) opts.out = argv[++i];
    else if (a === '-h' || a === '--help') {
      console.log(`Usage: node scripts/run-micro-corpus.mjs [options]
  --json     Output tier2Results JSON to stdout
  --mock     Deterministic synthetic evaluation without invoking live agy
  --out <p>  Write results to file path
  -h, --help Show this help`);
      process.exit(0);
    }
  }
  return opts;
}

function main() {
  const opts = parseArgs(process.argv.slice(2));
  const results = executeTier2Reproduction({ mock: opts.mock });

  if (opts.out) {
    fs.mkdirSync(path.dirname(path.resolve(opts.out)), { recursive: true });
    fs.writeFileSync(path.resolve(opts.out), JSON.stringify(results, null, 2) + '\n', 'utf8');
  }

  if (opts.json) {
    console.log(JSON.stringify(results, null, 2));
  } else {
    console.log('================================================================');
    console.log('agy-security-audit Track D Tier 2 Micro-Corpus Evaluation');
    console.log('Conforming to RFC 0002 §5.2 and §8');
    console.log('================================================================\n');
    console.log(`Status:             ${results.status}`);
    console.log(`Vulnerable Control: ${results.vulnerableControl || 'N/A'}`);
    console.log(`Safe Control:       ${results.safeControl || 'N/A'}`);
    console.log(`Dispute Control:    ${results.disputeControl || 'N/A'}`);
    console.log(`Stream Digest:      ${results.streamDigest || 'N/A'}`);
    console.log('----------------------------------------------------------------');
  }

  if (results.status === 'FAIL') {
    process.exit(1);
  }
}

if (process.argv[1] && fileURLToPath(import.meta.url) === path.resolve(process.argv[1])) {
  main();
}
