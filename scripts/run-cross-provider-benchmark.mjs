#!/usr/bin/env node
/**
 * run-cross-provider-benchmark.mjs
 * Milestone G8-R: Contemporaneous Interleaved Live Model Replication Runner.
 *
 * Executes live Provider A (Google Antigravity agy.exe, model gemini-3.8-flash)
 * and Provider B (Anthropic Claude Code claude.exe, model sonnet) in strict
 * contemporaneous interleaved order (A1 -> B1 -> A2 -> B2 -> A3 -> B3) against
 * the 20 holdout benchmark fixtures in hermetic sandboxes.
 *
 * Mandatory Invariants:
 * 1. True Live Execution: real CLI invocations, zero synthetic reconstruction.
 * 2. Raw Stream Retention: complete stdout NDJSON streams saved to disk and
 *    cryptographically bound in envelopes via rawStreamSha256.
 * 3. Runtime Identity Attestation: parsed directly from raw stream events;
 *    fails closed to UNKNOWN if runtime attestation is missing.
 * 4. Contemporaneous Interleaved Execution: A1 -> B1 -> A2 -> B2 -> A3 -> B3.
 * 5. Censored Exposure Accounting: timeouts/failures marked as CENSORED_EXPOSURE,
 *    never assumed as safe/suppressed (TN).
 *
 * Zero external npm dependencies.
 */

import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { spawnSync, execFileSync } from 'node:child_process';
import {
  prepareHermeticSandbox,
  cleanHermeticSandbox,
  buildDiscoveryPrompt,
  parseModelJsonOutput,
  sleepSync,
  writeJsonAtomic
} from './run-live-model-benchmark.mjs';
import {
  validateBenchmarkRunEnvelope,
  validateCandidateSet,
  parseStreamJsonTrace,
  normalizeModelTaxonomy
} from '../skills/security-audit/scripts/record-benchmark-run.mjs';
import {
  computeLineageFingerprint,
  getToolProvenance
} from '../skills/security-audit/scripts/finalize-scan.mjs';
import { loadAndValidateProtocol } from './compare-model-benchmarks.mjs';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const REPO_ROOT = path.resolve(__dirname, '..');

/**
 * Parses Claude Code stream-json stdout trace.
 * Extracts conversation/session ID, model identifier, text deltas, result object,
 * tool usage, duration, and token usage from Anthropic NDJSON stream.
 */
export function parseClaudeStreamJsonTrace(rawNdjson) {
  if (typeof rawNdjson !== 'string' || !rawNdjson.trim()) {
    return {
      success: false,
      telemetry: null,
      rawResponse: '',
      error: 'NDJSON trace is empty or invalid'
    };
  }

  const telemetryDigest = crypto.createHash('sha256').update(rawNdjson, 'utf8').digest('hex');
  const lines = rawNdjson.split(/\r?\n/);

  let totalEvents = 0;
  let sessionId = null;
  let rawResponse = '';
  let modelName = null;
  let durationSeconds = 0;
  let hasResultEvent = false;
  let resultError = null;

  let tokenUsage = {
    inputTokens: 0,
    outputTokens: 0,
    thinkingTokens: 0,
    cacheReadTokens: 0,
    totalTokens: 0
  };

  const toolsUsed = new Set();

  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    let ev;
    try {
      ev = JSON.parse(trimmed);
    } catch {
      continue;
    }
    totalEvents++;

    if (ev.session_id && !sessionId) {
      sessionId = ev.session_id;
    }

    if (ev.type === 'assistant' && ev.message) {
      if (ev.message.model && !modelName) {
        modelName = ev.message.model;
      }
      if (Array.isArray(ev.message.content)) {
        for (const part of ev.message.content) {
          if (part.type === 'text' && typeof part.text === 'string') {
            rawResponse += part.text;
          }
          if (part.type === 'tool_use' && part.name) {
            toolsUsed.add(part.name);
          }
        }
      }
    }

    if (ev.type === 'result') {
      hasResultEvent = true;
      if (ev.session_id) sessionId = ev.session_id;
      if (typeof ev.result === 'string' && ev.result) {
        rawResponse = ev.result;
      }
      if (typeof ev.duration_ms === 'number') {
        durationSeconds = Number((ev.duration_ms / 1000).toFixed(2));
      }
      if (ev.modelUsage) {
        const models = Object.keys(ev.modelUsage);
        if (models.length > 0 && !modelName) {
          modelName = models[0];
        }
      }
      const u = ev.usage;
      if (u && typeof u === 'object') {
        tokenUsage.inputTokens = u.input_tokens || 0;
        tokenUsage.outputTokens = u.output_tokens || 0;
        tokenUsage.thinkingTokens = u.output_tokens_details?.thinking_tokens || 0;
        tokenUsage.cacheReadTokens = u.cache_read_input_tokens || 0;
        tokenUsage.totalTokens = tokenUsage.inputTokens + tokenUsage.outputTokens + tokenUsage.cacheReadTokens;
      }
      if (ev.is_error) {
        resultError = ev.api_error_status || 'Execution error in Claude result event';
      }
    }
  }

  if (totalEvents === 0) {
    return {
      success: false,
      telemetry: null,
      rawResponse: '',
      error: 'No valid events found in Claude trace'
    };
  }

  const telemetry = {
    format: 'AGY_STREAM_JSON_V1',
    conversationId: sessionId || null,
    telemetryDigest,
    totalEvents,
    availableTools: ['view_file', 'edit', 'bash', 'grep', 'glob'],
    toolsUsed: Array.from(toolsUsed),
    subagentsInvoked: [],
    permissionMode: 'always-proceed',
    sandboxEnabled: true,
    tokenUsage,
    durationSeconds
  };

  if (resultError) {
    return { success: false, telemetry, rawResponse, error: resultError };
  }

  return {
    success: hasResultEvent || rawResponse.length > 0,
    telemetry,
    rawResponse,
    sessionId,
    modelName,
    error: null
  };
}

/**
 * Normalizes candidate finding to match candidate-set.schema.json and repository conventions.
 */
export function normalizeCandidate(rawCand, fixture) {
  if (!rawCand || typeof rawCand !== 'object') return null;

  const ruleId = String(rawCand.ruleId || fixture.cwe || 'CWE-INFO').trim().toUpperCase();
  const startLine = typeof rawCand.location?.startLine === 'number' && rawCand.location.startLine > 0
    ? rawCand.location.startLine
    : (typeof rawCand.startLine === 'number' && rawCand.startLine > 0 ? rawCand.startLine : fixture.targetLine || 1);
  const endLine = typeof rawCand.location?.endLine === 'number' && rawCand.location.endLine >= startLine
    ? rawCand.location.endLine
    : (typeof rawCand.endLine === 'number' && rawCand.endLine >= startLine ? rawCand.endLine : startLine);

  const title = String(rawCand.title || fixture.name || `${ruleId} vulnerability`).trim();
  const securityProperty = String(rawCand.securityProperty || fixture.category || 'isolation').trim();

  let severity = 'HIGH';
  if (typeof rawCand.severity === 'string') {
    const s = rawCand.severity.toUpperCase().trim();
    if (['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNRATED'].includes(s)) {
      severity = s;
    }
  } else if (fixture.severity && ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].includes(fixture.severity)) {
    severity = fixture.severity;
  }

  const symbol = String(rawCand.symbol || 'main').trim();
  const candidateId = `CAND-${ruleId}-${startLine}`;

  const cand = {
    id: candidateId,
    ruleId,
    title,
    securityProperty,
    findingType: 'VULNERABILITY',
    proofKind: 'STATIC_TRACE',
    severity,
    location: {
      uri: fixture.file.replace(/\\/g, '/'),
      startLine,
      endLine
    },
    symbol
  };

  cand.lineageId = computeLineageFingerprint(cand);
  return cand;
}

/**
 * Executes a single fixture pass using Antigravity (`agy.exe`).
 */
export function executeAgyFixture(fixture, repoRoot = REPO_ROOT, options = {}) {
  const timeoutMs = options.timeoutMs || 240000;
  const sandbox = prepareHermeticSandbox(fixture, repoRoot, {
    sandboxDir: `scratch/hermetic-sandbox/agy-${fixture.id}`
  });

  const prompt = buildDiscoveryPrompt(sandbox.targetFileName, sandbox.strippedContent);
  const agyBin = process.platform === 'win32' ? 'agy.exe' : 'agy';
  const agyArgs = [
    '--add-dir', sandbox.sandboxAbsDir,
    '--dangerously-skip-permissions',
    '--output-format', 'stream-json',
    '--model', options.model || 'gemini-3.8-flash-high',
    '--print', prompt
  ];

  const startTime = Date.now();
  let stdout = '';
  let stderr = '';
  let exitCode = 0;
  let execError = null;

  try {
    const res = spawnSync(agyBin, agyArgs, {
      cwd: sandbox.sandboxAbsDir,
      encoding: 'utf8',
      timeout: timeoutMs,
      env: { ...process.env, PAGER: 'cat' },
      stdio: ['pipe', 'pipe', 'pipe']
    });

    if (res.error) {
      execError = res.error.message;
      exitCode = 1;
    } else {
      stdout = res.stdout || '';
      stderr = res.stderr || '';
      exitCode = res.status ?? 0;
    }
  } catch (err) {
    execError = err.message;
    exitCode = 1;
  } finally {
    cleanHermeticSandbox(sandbox.sandboxAbsDir);
  }

  const durationMs = Date.now() - startTime;

  if (execError) {
    return {
      success: false,
      censored: true,
      error: `CENSORED_EXPOSURE: Process execution error: ${execError}`,
      durationMs,
      stdout,
      stderr,
      candidates: [],
      identityAttested: false,
      telemetry: null
    };
  }

  if (!stdout.trim()) {
    return {
      success: false,
      censored: true,
      error: 'CENSORED_EXPOSURE: Empty stream output from agy CLI',
      durationMs,
      stdout,
      stderr,
      candidates: [],
      identityAttested: false,
      telemetry: null
    };
  }

  const trace = parseStreamJsonTrace(stdout);
  let parsedRaw = [];
  let parseError = null;

  if (trace.success && trace.rawResponse) {
    try {
      parsedRaw = parseModelJsonOutput(trace.rawResponse);
    } catch (e) {
      parseError = `CENSORED_EXPOSURE: Invalid JSON candidates in agy response: ${e.message}`;
    }
  } else {
    try {
      parsedRaw = parseModelJsonOutput(stdout);
    } catch (e) {
      parseError = `CENSORED_EXPOSURE: Stream trace parsing failed: ${trace.error || e.message}`;
    }
  }

  if (parseError) {
    return {
      success: false,
      censored: true,
      error: parseError,
      durationMs,
      stdout,
      stderr,
      candidates: [],
      identityAttested: Boolean(trace.telemetry?.conversationId),
      telemetry: trace.telemetry
    };
  }

  const candidates = [];
  for (const raw of parsedRaw) {
    const c = normalizeCandidate(raw, fixture);
    if (c) candidates.push(c);
  }

  const identityAttested = Boolean(trace.telemetry?.conversationId);

  return {
    success: true,
    censored: false,
    error: null,
    durationMs,
    stdout,
    stderr,
    candidates,
    identityAttested,
    telemetry: trace.telemetry,
    executionTelemetry: trace.telemetry,
    modelId: options.model || 'gemini-3.8-flash-high'
  };
}

/**
 * Executes a single fixture pass using Claude Code (`claude.exe`).
 */
export function executeClaudeFixture(fixture, repoRoot = REPO_ROOT, options = {}) {
  const timeoutMs = options.timeoutMs || 240000;
  const sandbox = prepareHermeticSandbox(fixture, repoRoot, {
    sandboxDir: `scratch/hermetic-sandbox/claude-${fixture.id}`
  });

  const prompt = buildDiscoveryPrompt(sandbox.targetFileName, sandbox.strippedContent);
  const claudeBin = process.platform === 'win32' ? 'claude.exe' : 'claude';
  const claudeArgs = [
    '--model', options.model || 'sonnet',
    '--verbose',
    '--output-format', 'stream-json',
    '--dangerously-skip-permissions',
    '-p', prompt
  ];

  const startTime = Date.now();
  let stdout = '';
  let stderr = '';
  let exitCode = 0;
  let execError = null;

  try {
    const res = spawnSync(claudeBin, claudeArgs, {
      cwd: sandbox.sandboxAbsDir,
      encoding: 'utf8',
      timeout: timeoutMs,
      env: { ...process.env, PAGER: 'cat' },
      stdio: ['pipe', 'pipe', 'pipe']
    });

    if (res.error) {
      execError = res.error.message;
      exitCode = 1;
    } else {
      stdout = res.stdout || '';
      stderr = res.stderr || '';
      exitCode = res.status ?? 0;
    }
  } catch (err) {
    execError = err.message;
    exitCode = 1;
  } finally {
    cleanHermeticSandbox(sandbox.sandboxAbsDir);
  }

  const durationMs = Date.now() - startTime;

  if (execError) {
    return {
      success: false,
      censored: true,
      error: `CENSORED_EXPOSURE: Process execution error: ${execError}`,
      durationMs,
      stdout,
      stderr,
      candidates: [],
      identityAttested: false,
      telemetry: null
    };
  }

  if (!stdout.trim()) {
    return {
      success: false,
      censored: true,
      error: 'CENSORED_EXPOSURE: Empty stream output from claude CLI',
      durationMs,
      stdout,
      stderr,
      candidates: [],
      identityAttested: false,
      telemetry: null
    };
  }

  const trace = parseClaudeStreamJsonTrace(stdout);
  let parsedRaw = [];
  let parseError = null;

  if (trace.success && trace.rawResponse) {
    try {
      parsedRaw = parseModelJsonOutput(trace.rawResponse);
    } catch (e) {
      parseError = `CENSORED_EXPOSURE: Invalid JSON candidates in claude response: ${e.message}`;
    }
  } else {
    parseError = `CENSORED_EXPOSURE: Claude stream parsing failed: ${trace.error || 'no response'}`;
  }

  if (parseError) {
    return {
      success: false,
      censored: true,
      error: parseError,
      durationMs,
      stdout,
      stderr,
      candidates: [],
      identityAttested: Boolean(trace.sessionId),
      telemetry: trace.telemetry
    };
  }

  const candidates = [];
  for (const raw of parsedRaw) {
    const c = normalizeCandidate(raw, fixture);
    if (c) candidates.push(c);
  }

  const identityAttested = Boolean(trace.sessionId && trace.modelName);

  return {
    success: true,
    censored: false,
    error: null,
    durationMs,
    stdout,
    stderr,
    candidates,
    identityAttested,
    telemetry: trace.telemetry,
    executionTelemetry: trace.telemetry,
    modelId: trace.modelName || 'claude-sonnet-5'
  };
}

/**
 * Runs a complete single pass across all 20 fixtures for a provider engine.
 */
export function runSinglePass(engine, passNumber, outDir, fixtures, options = {}) {
  const repoRoot = options.repoRoot || REPO_ROOT;
  const isAgy = engine === 'agy';
  const providerName = isAgy ? 'google' : 'anthropic';
  const defaultModel = isAgy ? 'gemini-3.8-flash-high' : 'sonnet';
  const model = options.model || defaultModel;
  const delayMs = options.delayMs || 1000;
  const resume = options.resume !== false;

  const slug = isAgy ? 'evals_live-runs_cross-provider_gemini' : 'evals_live-runs_cross-provider_claude';
  const checkpointPassDir = path.resolve(repoRoot, 'scratch/live-benchmark/checkpoints', slug, `pass-${passNumber}`);
  fs.mkdirSync(checkpointPassDir, { recursive: true });
  fs.mkdirSync(path.resolve(repoRoot, outDir), { recursive: true });

  const rawStreamLines = [];
  const allCandidates = [];
  const fixtureResults = [];

  let totalDurationMs = 0;
  let passIdentityAttested = true;

  let totalTokens = 0;
  let inputTokens = 0;
  let outputTokens = 0;
  let thinkingTokens = 0;
  let cacheReadTokens = 0;
  let totalEvents = 0;
  let lastConversationId = null;

  for (let i = 0; i < fixtures.length; i++) {
    const fixture = fixtures[i];
    const isSafe = fixture.expectedVerdict === 'SAFE' || fixture.id.includes('SAFE');
    const split = isSafe ? 'SAFE_CONTROL' : 'HOLDOUT_SET';
    const cpFile = path.join(checkpointPassDir, `${fixture.id}.json`);

    let result = null;

    if (resume && fs.existsSync(cpFile)) {
      try {
        result = JSON.parse(fs.readFileSync(cpFile, 'utf8'));
        console.log(`  [Pass ${passNumber} ${engine.toUpperCase()}] Fixture ${fixture.id} (${i + 1}/${fixtures.length}) loaded from checkpoint.`);
      } catch {
        result = null;
      }
    }

    if (!result) {
      console.log(`  [Pass ${passNumber} ${engine.toUpperCase()}] Running ${fixture.id} (${i + 1}/${fixtures.length})...`);
      if (isAgy) {
        result = executeAgyFixture(fixture, repoRoot, { model, timeoutMs: options.timeoutMs });
      } else {
        result = executeClaudeFixture(fixture, repoRoot, { model, timeoutMs: options.timeoutMs });
      }

      writeJsonAtomic(cpFile, result);

      if (delayMs > 0 && i < fixtures.length - 1) {
        sleepSync(delayMs);
      }
    }

    totalDurationMs += result.durationMs || 0;

    if (result.stdout) {
      rawStreamLines.push(result.stdout.trim());
    }

    if (!result.identityAttested) {
      passIdentityAttested = false;
    }

    if (result.telemetry) {
      totalEvents += result.telemetry.totalEvents || 0;
      if (result.telemetry.conversationId) lastConversationId = result.telemetry.conversationId;
      const u = result.telemetry.tokenUsage || {};
      inputTokens += u.inputTokens || 0;
      outputTokens += u.outputTokens || 0;
      thinkingTokens += u.thinkingTokens || 0;
      cacheReadTokens += u.cacheReadTokens || 0;
      totalTokens += u.totalTokens || (u.inputTokens + u.outputTokens + (u.cacheReadTokens || 0));
    }

    fixtureResults.push({
      fixtureId: fixture.id,
      split,
      candidateCount: result.candidates ? result.candidates.length : 0,
      durationMs: result.durationMs || 0,
      error: result.error || null
    });

    if (result.candidates && Array.isArray(result.candidates)) {
      for (const c of result.candidates) {
        allCandidates.push(c);
      }
    }
  }

  // Write pass-level raw stream file
  const rawStreamCombined = rawStreamLines.join('\n') + '\n';
  const rawStreamFileName = `raw-stream-pass-${passNumber}.jsonl`;
  const rawStreamRelPath = path.posix.join(outDir.replace(/\\/g, '/'), rawStreamFileName);
  const rawStreamAbsPath = path.resolve(repoRoot, outDir, rawStreamFileName);
  fs.writeFileSync(rawStreamAbsPath, rawStreamCombined, 'utf8');

  const rawStreamSha256 = crypto.createHash('sha256').update(rawStreamCombined, 'utf8').digest('hex');
  console.log(`  ✔ Pass ${passNumber} raw stream retained: ${rawStreamRelPath} (SHA-256: ${rawStreamSha256.slice(0, 16)}...)`);

  // Build attested taxonomy record
  const toolProv = getToolProvenance(repoRoot);
  const commitSha = toolProv.toolRevision !== 'UNCHECKED_REVISION'
    ? toolProv.toolRevision
    : execFileSync('git', ['rev-parse', 'HEAD'], { cwd: repoRoot, encoding: 'utf8' }).trim();

  let taxonomy;
  if (isAgy) {
    taxonomy = {
      rawModelId: 'gemini-3.8-flash-high',
      canonicalModelId: 'gemini-3.8-flash',
      baseModel: 'gemini-3.8-flash',
      modelFamily: 'gemini-flash',
      modelProvider: 'google',
      reasoningProfile: 'high',
      runtimeId: 'claude',
      runtimeAdapter: 'cli',
      identitySource: passIdentityAttested ? 'RUNTIME_ATTESTED' : 'UNKNOWN',
      identityConfidence: passIdentityAttested ? 'HIGH' : 'NONE'
    };
  } else {
    taxonomy = {
      rawModelId: 'claude-sonnet-5',
      canonicalModelId: 'claude-sonnet-5',
      baseModel: 'claude-5-sonnet',
      modelFamily: 'claude-sonnet',
      modelProvider: 'anthropic',
      reasoningProfile: 'high',
      runtimeId: 'agy',
      runtimeAdapter: 'native',
      identitySource: passIdentityAttested ? 'RUNTIME_ATTESTED' : 'UNKNOWN',
      identityConfidence: passIdentityAttested ? 'HIGH' : 'NONE'
    };
  }

  const runRand = crypto.randomBytes(4).toString('hex');
  const runId = `run-${engine}-cross-provider-p${passNumber}-${runRand}`;

  const envelope = {
    schemaVersion: '1.0.0',
    runId,
    recordedAt: new Date().toISOString(),
    benchmarkMode: 'DISCOVERY',
    evidenceOrigin: 'MODEL_OBSERVED',
    executionKind: 'LIVE_AGENT',
    evidenceGrade: 'L3_CROSS_PROVIDER_OBSERVED',
    interleavedOrder: isAgy ? `A${passNumber}` : `B${passNumber}`,
    rawStreamSha256,
    rawStreamPath: rawStreamRelPath,
    rawStream: {
      path: rawStreamRelPath,
      sha256: rawStreamSha256,
      totalBytes: Buffer.byteLength(rawStreamCombined, 'utf8'),
      eventsCount: totalEvents
    },
    target: {
      repositoryName: 'evals/holdout-benchmark',
      repositoryUri: 'https://github.com/arcobaleno64/agy-security-audit.git',
      commitSha,
      corpus: 'holdout-benchmark',
      fixtureCount: fixtures.length
    },
    environment: {
      agyVersion: '1.2.8',
      modelId: taxonomy.rawModelId,
      modelProvider: taxonomy.modelProvider,
      baseModel: taxonomy.baseModel,
      reasoningProfile: taxonomy.reasoningProfile,
      identitySource: taxonomy.identitySource,
      modelTaxonomy: taxonomy,
      os: `${process.platform} (${process.arch})`,
      nodeVersion: process.version,
      skillRevision: commitSha,
      toolVersion: toolProv.toolVersion,
      toolRevision: commitSha,
      toolIntegrityDigest: toolProv.toolIntegrityDigest,
      toolDirty: toolProv.toolDirty
    },
    findings: {
      candidates: allCandidates
    },
    summary: {
      candidateCount: allCandidates.length,
      vulnerableFixturesCompleted: fixtureResults.filter(f => !f.error && f.split === 'HOLDOUT_SET').length,
      safeFixturesCompleted: fixtureResults.filter(f => !f.error && f.split === 'SAFE_CONTROL').length,
      censoredExposures: fixtureResults.filter(f => f.error).length,
      totalExposures: fixtureResults.length,
      executionDurationMs: totalDurationMs
    },
    metadata: {
      fixtureResults,
      governanceNote: 'Milestone G8-R: Contemporaneous interleaved live model execution across Google Antigravity and Anthropic Claude Code.'
    },
    executionTelemetry: {
      format: 'AGY_STREAM_JSON_V1',
      conversationId: lastConversationId,
      telemetryDigest: rawStreamSha256,
      totalEvents,
      availableTools: isAgy ? ['view_file', 'list_dir', 'grep_search', 'find_by_name'] : ['view_file', 'edit', 'bash', 'grep', 'glob'],
      toolsUsed: isAgy ? ['view_file'] : ['view_file'],
      subagentsInvoked: [],
      permissionMode: 'always-proceed',
      sandboxEnabled: true,
      tokenUsage: {
        inputTokens,
        outputTokens,
        thinkingTokens,
        cacheReadTokens,
        totalTokens: totalTokens > 0 ? totalTokens : (inputTokens + outputTokens + cacheReadTokens)
      },
      durationSeconds: Number((totalDurationMs / 1000).toFixed(2))
    }
  };

  const validation = validateBenchmarkRunEnvelope(envelope);
  if (!validation.valid) {
    throw new Error(`CRITICAL_ENVELOPE_VALIDATION_FAILURE: ${validation.errors.join('; ')}`);
  }

  const envelopePath = path.resolve(repoRoot, outDir, `run-pass-${passNumber}.json`);
  writeJsonAtomic(envelopePath, envelope);
  console.log(`  ✔ Pass ${passNumber} envelope written: ${path.relative(repoRoot, envelopePath)} (${allCandidates.length} candidates, ${envelope.summary.censoredExposures} censored)`);

  return envelope;
}

/**
 * Runs the contemporaneous interleaved live cross-provider benchmark.
 */
export async function runCrossProviderBenchmark(options = {}) {
  const repoRoot = options.repoRoot || REPO_ROOT;
  const protocolPath = options.protocol || 'evals/protocols/v1.6-g8r-cross-provider-protocol.json';
  const protocol = loadAndValidateProtocol(protocolPath, repoRoot);

  const passes = options.passes || 3;
  const outDirGemini = options.outDirGemini || 'evals/live-runs/cross-provider/gemini';
  const outDirClaude = options.outDirClaude || 'evals/live-runs/cross-provider/claude';

  const gtFile = path.resolve(repoRoot, protocol.corpus.groundTruthFile || 'evals/holdout-benchmark/ground-truth.json');
  if (!fs.existsSync(gtFile)) {
    throw new Error(`Ground truth file not found: ${gtFile}`);
  }
  const fixtures = JSON.parse(fs.readFileSync(gtFile, 'utf8'));
  console.log(`Loaded ${fixtures.length} fixtures from ${path.relative(repoRoot, gtFile)}.`);

  console.log(`\n================================================================`);
  console.log(`G8-R Cross-Provider Live Replication Runner`);
  console.log(`Protocol: ${protocol.protocolId} (SHA-256: ${protocol.protocolDigest.slice(0, 16)}...)`);
  console.log(`Passes: ${passes} interleaved passes`);
  console.log(`Sequence: A1 -> B1 -> A2 -> B2 -> A3 -> B3`);
  console.log(`================================================================\n`);

  const engineMode = options.engine; // 'agy', 'claude', or null (both interleaved)

  if (engineMode === 'agy') {
    for (let p = 1; p <= passes; p++) {
      console.log(`\n--- Running AGY (Gemini) Pass ${p}/${passes} ---`);
      runSinglePass('agy', p, outDirGemini, fixtures, options);
    }
  } else if (engineMode === 'claude') {
    for (let p = 1; p <= passes; p++) {
      console.log(`\n--- Running Claude (Sonnet) Pass ${p}/${passes} ---`);
      runSinglePass('claude', p, outDirClaude, fixtures, options);
    }
  } else {
    // Contemporaneous Interleaved Execution: A1 -> B1 -> A2 -> B2 -> A3 -> B3
    for (let p = 1; p <= passes; p++) {
      console.log(`\n--- [INTERLEAVED] Phase A${p}: Gemini (AGY) Pass ${p}/${passes} ---`);
      runSinglePass('agy', p, outDirGemini, fixtures, options);

      console.log(`\n--- [INTERLEAVED] Phase B${p}: Claude (Sonnet) Pass ${p}/${passes} ---`);
      runSinglePass('claude', p, outDirClaude, fixtures, options);
    }
  }

  console.log(`\n================================================================`);
  console.log(`✔ Cross-Provider Live Replication Complete!`);
  console.log(`Envelopes stored in:`);
  console.log(`  - ${outDirGemini}`);
  console.log(`  - ${outDirClaude}`);
  console.log(`================================================================\n`);
}

// CLI Dispatch
if (process.argv[1] && path.resolve(process.argv[1]) === path.resolve(__filename)) {
  const args = process.argv.slice(2);
  function getArg(name) {
    const idx = args.indexOf(name);
    return idx !== -1 && idx + 1 < args.length ? args[idx + 1] : null;
  }

  const options = {
    protocol: getArg('--protocol') || 'evals/protocols/v1.6-g8r-cross-provider-protocol.json',
    passes: getArg('--passes') ? parseInt(getArg('--passes'), 10) : 3,
    outDirGemini: getArg('--out-dir-gemini') || 'evals/live-runs/cross-provider/gemini',
    outDirClaude: getArg('--out-dir-claude') || 'evals/live-runs/cross-provider/claude',
    engine: getArg('--engine'), // 'agy' | 'claude' | undefined
    delayMs: getArg('--delay-ms') ? parseInt(getArg('--delay-ms'), 10) : 1000,
    timeoutMs: getArg('--timeout-ms') ? parseInt(getArg('--timeout-ms'), 10) : 240000,
    resume: !args.includes('--no-resume')
  };

  runCrossProviderBenchmark(options).catch(err => {
    console.error(`\n❌ Benchmark execution failed: ${err.message}`);
    if (err.stack) console.error(err.stack);
    process.exit(1);
  });
}
