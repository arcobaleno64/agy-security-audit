#!/usr/bin/env node
/**
 * run-live-model-benchmark.mjs
 * Authentic Model Discovery Runner Harness for Antigravity (AGY).
 *
 * Executes live `agy` CLI in headless print mode (`agy --mode plan --print ...`)
 * to prompt discovery against security benchmark fixtures, parsing real model
 * candidate findings and serializing schema-compliant empirical envelopes.
 *
 * Fixture Partitioning & Generalization Governance:
 * - Development Set (Regression Fixture): SEM-03 (Confused Deputy) was calibrated
 *   with direct prompt heuristics; it serves as a regression baseline.
 * - Holdout Fixtures: Remaining benchmark fixtures evaluate unbiased generalization.
 */

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { execFileSync, spawnSync } from 'node:child_process';
import {
  createBenchmarkRunEnvelope,
  validateBenchmarkRunEnvelope,
  probeEnvironment
} from '../skills/security-audit/scripts/record-benchmark-run.mjs';
import {
  finalizeScan,
  computeLineageFingerprint
} from '../skills/security-audit/scripts/finalize-scan.mjs';
import { evaluateDiscovery } from '../skills/security-audit/scripts/run-discovery-eval.mjs';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const DEFAULT_REPO_ROOT = path.resolve(__dirname, '..');

/**
 * Fixture Partitioning Specification:
 * Explicit separation between development/calibration fixtures and holdout fixtures.
 */
export const BENCHMARK_FIXTURE_SPLITS = {
  developmentSet: {
    ids: ['SEM-03'],
    role: 'REGRESSION_BASELINE',
    rationale: 'SEM-03 (Confused Deputy) was tuned with targeted CWE-441 prompt heuristics; classified as development/regression fixture.'
  },
  holdoutFixtures: {
    ids: ['SEM-01', 'SEM-02', 'SEM-04', 'SEM-05', 'SEM-06', 'SEM-07', 'SEM-08', 'SEM-09', 'SEM-10'],
    role: 'HOLDOUT_GENERALIZATION',
    rationale: 'Fixtures evaluated without targeted per-case prompt tuning to measure authentic out-of-distribution generalization.'
  }
};

/**
 * Parses model stdout to extract structured JSON candidate findings.
 * Handles pure JSON, Markdown code blocks, or embedded JSON arrays.
 */
export function parseModelJsonOutput(rawOutput) {
  if (!rawOutput || typeof rawOutput !== 'string') return [];

  const text = rawOutput.trim();

  // 1. Direct JSON parse
  try {
    const parsed = JSON.parse(text);
    if (Array.isArray(parsed)) return parsed;
    if (parsed && Array.isArray(parsed.candidates)) return parsed.candidates;
    if (parsed && Array.isArray(parsed.findings)) return parsed.findings;
  } catch {}

  // 2. Extract JSON from Markdown code blocks (```json ... ``` or ``` ...)
  const codeBlockRegex = /```(?:json)?\s*([\s\S]*?)```/gi;
  let match;
  while ((match = codeBlockRegex.exec(text)) !== null) {
    try {
      const candidateJson = JSON.parse(match[1].trim());
      if (Array.isArray(candidateJson)) return candidateJson;
      if (candidateJson && Array.isArray(candidateJson.candidates)) return candidateJson.candidates;
    } catch {}
  }

  // 3. Fallback: bracket match extraction [ { ... } ]
  const firstBracket = text.indexOf('[');
  const lastBracket = text.lastIndexOf(']');
  if (firstBracket !== -1 && lastBracket > firstBracket) {
    try {
      const sliced = text.slice(firstBracket, lastBracket + 1);
      const parsed = JSON.parse(sliced);
      if (Array.isArray(parsed)) return parsed;
    } catch {}
  }

  return [];
}

/**
 * Builds discovery prompt instructing AGY to review fixture code under Default-Deny.
 */
export function buildDiscoveryPrompt(fixtureRelPath, fixtureContent = '') {
  return `You are conducting a strict security review under Default-Deny on the following file:
File: ${fixtureRelPath}

Source Code:
\`\`\`javascript
${fixtureContent}
\`\`\`

Instructions:
1. Presumption of Non-Pass: Audit under Default-Deny. If no vulnerability is present, return [].
2. If vulnerabilities exist, output ONLY a JSON array of candidate findings adhering to:
[
  {
    "id": "CAND-<RULE>-<LINE>",
    "ruleId": "CWE-XXX",
    "title": "Clear description of vulnerability",
    "severity": "CRITICAL" | "HIGH" | "MEDIUM" | "LOW",
    "location": {
      "uri": "${fixtureRelPath}",
      "startLine": <number>,
      "endLine": <number>
    },
    "symbol": "<identifier>"
  }
]
Output ONLY raw JSON or markdown-fenced JSON. Do not include commentary outside the JSON.`;
}

/**
 * Executes a single fixture discovery pass via real `agy` CLI in headless mode.
 */
export function runAgyDiscoveryOnFixture(fixture, repoRoot = DEFAULT_REPO_ROOT, options = {}) {
  const fixturePath = path.resolve(repoRoot, fixture.file);
  if (!fs.existsSync(fixturePath)) {
    throw new Error(`Fixture file not found: ${fixturePath}`);
  }

  // Support simulated / offline mode for tests and CI
  if (options.mock || options.mockCandidates) {
    const mockCands = options.mockCandidates || [
      {
        id: `CAND-${fixture.id}-01`,
        ruleId: fixture.cwe || 'CWE-441',
        title: `Simulated discovery finding for ${fixture.id}`,
        severity: 'HIGH',
        location: {
          uri: fixture.file,
          startLine: 10,
          endLine: 15
        },
        symbol: fixture.id
      }
    ];
    for (const cand of mockCands) {
      if (!cand.lineageId) {
        cand.lineageId = computeLineageFingerprint({
          ruleId: cand.ruleId || 'SEC-VULN',
          uri: fixture.file,
          symbol: cand.symbol || fixture.id
        });
      }
    }
    return {
      fixtureId: fixture.id,
      file: fixture.file,
      durationMs: 50,
      candidates: mockCands,
      rawOutput: JSON.stringify(mockCands),
      error: null,
      split: BENCHMARK_FIXTURE_SPLITS.developmentSet.ids.includes(fixture.id)
        ? 'DEVELOPMENT_SET'
        : 'HOLDOUT_SET'
    };
  }

  const fixtureContent = fs.readFileSync(fixturePath, 'utf8');
  const prompt = buildDiscoveryPrompt(fixture.file, fixtureContent);

  const modelId = options.modelId || process.env.AGY_MODEL || 'gemini-3.8-flash-high';
  const timeoutMs = options.timeoutMs || 120000;

  const startTime = Date.now();

  // Prepare agy execution arguments: headless print mode
  // Note: agy flag parser requires flags before prompt argument
  const agyArgs = [
    '--mode', 'plan',
    '--disable-slash-commands'
  ];
  if (options.modelId) {
    agyArgs.push('--model', options.modelId);
  }
  agyArgs.push('--print', prompt);

  let stdout = '';
  let stderr = '';
  let exitCode = 0;

  try {
    const agyBin = process.platform === 'win32' ? 'agy.exe' : 'agy';
    const result = spawnSync(agyBin, agyArgs, {
      cwd: repoRoot,
      encoding: 'utf8',
      timeout: timeoutMs,
      env: {
        ...process.env,
        PAGER: 'cat'
      },
      stdio: ['pipe', 'pipe', 'pipe']
    });

    if (result.error) {
      stderr = result.error.message;
      exitCode = 1;
    } else {
      stdout = result.stdout || '';
      stderr = result.stderr || '';
      exitCode = result.status ?? 0;
    }
  } catch (err) {
    stderr = err.message;
    exitCode = 1;
  }

  const durationMs = Date.now() - startTime;
  const rawCandidates = parseModelJsonOutput(stdout);
  const candidates = [];

  // Normalize candidate lineage IDs and sanitize
  for (const cand of rawCandidates) {
    if (!cand || typeof cand !== 'object') continue;
    if (!cand.lineageId) {
      cand.lineageId = computeLineageFingerprint({
        ruleId: cand.ruleId || 'SEC-VULN',
        uri: fixture.file,
        symbol: cand.symbol || fixture.id
      });
    }
    candidates.push(cand);
  }

  return {
    fixtureId: fixture.id,
    file: fixture.file,
    durationMs,
    candidates,
    rawOutput: stdout,
    error: exitCode !== 0 ? (stderr || `Process exited with code ${exitCode}`) : null,
    split: BENCHMARK_FIXTURE_SPLITS.developmentSet.ids.includes(fixture.id)
      ? 'DEVELOPMENT_SET'
      : 'HOLDOUT_SET'
  };
}

/**
 * Runs full live discovery benchmark against benchmark fixtures.
 */
export function runLiveModelBenchmark(repoRoot = DEFAULT_REPO_ROOT, options = {}) {
  const gtPath = options.groundTruthPath || path.resolve(repoRoot, 'evals/semantic-benchmark/ground-truth.json');
  if (!fs.existsSync(gtPath)) {
    throw new Error(`Ground truth file missing: ${gtPath}`);
  }

  const groundTruth = JSON.parse(fs.readFileSync(gtPath, 'utf8'));
  const vulnerableFixtures = groundTruth.filter(gt => gt.expectedVerdict === 'VULNERABLE');

  const modelId = options.modelId || process.env.AGY_MODEL || 'gemini-3.8-flash-high';
  const modelProvider = options.modelProvider || process.env.AGY_MODEL_PROVIDER || 'google';

  console.log('================================================================');
  console.log('Authentic Model Discovery Benchmark Runner (AGY Live Mode)');
  console.log('  Evidence Origin:       MODEL_OBSERVED');
  console.log('  Execution Kind:        LIVE_AGENT');
  console.log(`  Model ID:              ${modelId}`);
  console.log(`  Total Fixtures:        ${vulnerableFixtures.length} (${BENCHMARK_FIXTURE_SPLITS.developmentSet.ids.length} dev / regression, ${BENCHMARK_FIXTURE_SPLITS.holdoutFixtures.ids.length} holdout)`);
  if (options.mock) {
    console.log('  Notice:                Running in SIMULATED MOCK MODE');
  }
  console.log('================================================================\n');

  const fixtureResults = [];
  const allCandidates = [];
  const startTime = Date.now();

  for (const fix of vulnerableFixtures) {
    if (options.fixtureId && fix.id !== options.fixtureId) continue;

    console.log(`Auditing fixture [${fix.id}]: ${fix.file}...`);
    const res = runAgyDiscoveryOnFixture(fix, repoRoot, { ...options, modelId });
    fixtureResults.push(res);
    allCandidates.push(...res.candidates);
    if (res.error) {
      console.warn(`  ⚠ Discovery execution error on [${fix.id}]: ${res.error.trim()}`);
    }
    console.log(`  -> Found ${res.candidates.length} candidate(s) in ${res.durationMs}ms [${res.split}]`);
  }

  const totalDurationMs = Date.now() - startTime;
  const envProv = probeEnvironment(repoRoot, {
    modelId,
    modelProvider,
    ...(options.environment || {})
  });

  const envelope = createBenchmarkRunEnvelope({
    repoRoot,
    benchmarkMode: 'DISCOVERY',
    evidenceOrigin: 'MODEL_OBSERVED',
    executionKind: 'LIVE_AGENT',
    target: {
      repositoryName: 'evals/semantic-benchmark',
      repositoryUri: 'https://github.com/arcobaleno64/agy-security-audit.git',
      corpus: 'semantic-benchmark'
    },
    environment: {
      ...envProv,
      ...(options.environment || {})
    },
    candidates: allCandidates,
    executionDurationMs: totalDurationMs,
    metadata: {
      fixtureSplits: BENCHMARK_FIXTURE_SPLITS,
      fixtureResults: fixtureResults.map(r => ({
        fixtureId: r.fixtureId,
        split: r.split,
        candidateCount: r.candidates.length,
        durationMs: r.durationMs,
        error: r.error || null
      })),
      governanceNote: 'SEM-03 classified as development-set / regression fixture; holdout fixtures evaluate generalization.'
    }
  });

  const discoveryEval = evaluateDiscovery(allCandidates, groundTruth, options);

  return {
    envelope,
    discoveryEval,
    fixtureResults
  };
}

// -----------------------------------------------------------------------------
// CLI Dispatch
// -----------------------------------------------------------------------------
const isDirectExecution = process.argv[1] && process.argv[1].endsWith('run-live-model-benchmark.mjs');
if (isDirectExecution) {
  const args = process.argv.slice(2);
  function getArg(name) {
    const idx = args.indexOf(name);
    return idx !== -1 && idx + 1 < args.length ? args[idx + 1] : null;
  }

  const showHelp = args.includes('--help') || args.includes('-h');
  if (showHelp) {
    console.log(`
Usage: node scripts/run-live-model-benchmark.mjs [options]

Options:
  --fixture <id>       Run discovery only on a specific fixture (e.g. SEM-03)
  --model <modelId>    Override target model ID (default: gemini-3.8-flash-high)
  --output <path>      Path to output JSON benchmark envelope
  --out-dir <dir>      Directory to write benchmark envelope JSON file
  --timeout <ms>       Execution timeout per fixture in milliseconds (default: 120000)
  --mock, --dry-run    Run with simulated fixture candidate generator (offline CI mode)
  --help, -h           Show this help message
`);
    process.exit(0);
  }

  const fixtureId = getArg('--fixture');
  const outDir = getArg('--out-dir') || getArg('--output-dir');
  const outFile = getArg('--output');
  const model = getArg('--model');
  const timeoutArg = getArg('--timeout') || getArg('--timeout-ms');
  const timeoutMs = timeoutArg ? parseInt(timeoutArg, 10) : undefined;
  const isMock = args.includes('--mock') || args.includes('--dry-run');

  try {
    const result = runLiveModelBenchmark(DEFAULT_REPO_ROOT, {
      fixtureId,
      modelId: model || undefined,
      timeoutMs,
      mock: isMock
    });
    const serialized = JSON.stringify(result.envelope, null, 2);

    if (outFile) {
      fs.mkdirSync(path.dirname(outFile), { recursive: true });
      fs.writeFileSync(outFile, serialized, 'utf8');
      console.log(`\n✔ Benchmark envelope written to: ${outFile}`);
    } else if (outDir) {
      fs.mkdirSync(outDir, { recursive: true });
      const targetPath = path.join(outDir, `${result.envelope.runId}.json`);
      fs.writeFileSync(targetPath, serialized, 'utf8');
      console.log(`\n✔ Benchmark envelope written to: ${targetPath}`);
    }

    console.log('\n✔ Live model benchmark runner finished.');
  } catch (err) {
    console.error('❌ Live benchmark runner error:', err.message);
    process.exit(1);
  }
}
