#!/usr/bin/env node
/**
 * record-benchmark-run.mjs
 * Recorded Empirical Benchmark Protocol Envelope Recorder (v1.1.0 P1).
 * Serializes agent execution passes into standardized benchmark run envelopes
 * conforming to schemas/empirical-benchmark-run.schema.json.
 */

import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { getHardenedGitProvenance } from './safe-git.mjs';
import { TOOL_VERSION, verifyToolSelfIntegrity, getToolProvenance } from './finalize-scan.mjs';

/**
 * Probes the runtime environment to extract authoritative provenance.
 */
export function probeEnvironment(repoRoot = process.cwd(), overrides = {}) {
  let agyVersion = overrides.agyVersion || process.env.AGY_VERSION || null;
  if (!agyVersion) {
    try {
      const out = execFileSync('agy', ['--version'], {
        encoding: 'utf8',
        timeout: 4000,
        stdio: ['pipe', 'pipe', 'ignore']
      }).trim();
      if (out) agyVersion = out;
    } catch {
      agyVersion = 'UNKNOWN';
    }
  }

  // Authoritative tool provenance from the security-audit tool root
  const defaultToolRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
  const toolProv = getToolProvenance(defaultToolRoot);

  return {
    agyVersion: agyVersion || 'UNKNOWN',
    modelId: overrides.modelId || process.env.AGY_MODEL || 'UNKNOWN',
    modelProvider: overrides.modelProvider || process.env.AGY_MODEL_PROVIDER || 'UNKNOWN',
    os: `${process.platform} (${process.arch})`,
    nodeVersion: process.version,
    skillRevision: toolProv.toolRevision,
    toolVersion: toolProv.toolVersion || TOOL_VERSION,
    toolRevision: toolProv.toolRevision,
    toolIntegrityDigest: toolProv.toolIntegrityDigest,
    toolDirty: toolProv.toolDirty
  };
}

/**
 * Validates an empirical benchmark run envelope against structural rules.
 */
export function validateBenchmarkRunEnvelope(envelope) {
  const errors = [];
  if (!envelope || typeof envelope !== 'object') {
    return { valid: false, errors: ['Envelope must be a non-null object'] };
  }

  if (envelope.schemaVersion !== '1.0.0' && envelope.schemaVersion !== '1') {
    errors.push(`Invalid schemaVersion: expected '1.0.0' or '1', got '${envelope.schemaVersion}'`);
  }
  if (typeof envelope.runId !== 'string' || !envelope.runId) {
    errors.push('Missing or invalid runId string');
  }
  if (typeof envelope.recordedAt !== 'string' || !envelope.recordedAt) {
    errors.push('Missing or invalid recordedAt ISO timestamp');
  }
  const VALID_MODES = ['DISCOVERY', 'AUDIT', 'VALIDATE', 'STABILITY'];
  if (!VALID_MODES.includes(envelope.benchmarkMode)) {
    errors.push(`Invalid benchmarkMode: expected one of ${VALID_MODES.join(', ')}, got '${envelope.benchmarkMode}'`);
  }
  const VALID_EVIDENCE_ORIGINS = ['MODEL_OBSERVED', 'SYNTHETIC', 'IMPORTED'];
  if (!VALID_EVIDENCE_ORIGINS.includes(envelope.evidenceOrigin)) {
    errors.push(`Invalid or missing evidenceOrigin: expected one of ${VALID_EVIDENCE_ORIGINS.join(', ')}, got '${envelope.evidenceOrigin}'`);
  }
  const VALID_EXECUTION_KINDS = ['LIVE_AGENT', 'SIMULATED_HARNESS', 'REPLAY_LOG'];
  if (envelope.executionKind !== undefined && !VALID_EXECUTION_KINDS.includes(envelope.executionKind)) {
    errors.push(`Invalid executionKind: expected one of ${VALID_EXECUTION_KINDS.join(', ')}, got '${envelope.executionKind}'`);
  }
  if (!envelope.target || typeof envelope.target !== 'object') {
    errors.push('Missing target object');
  } else {
    if (typeof envelope.target.repositoryName !== 'string') errors.push('target.repositoryName must be a string');
    if (typeof envelope.target.repositoryUri !== 'string') errors.push('target.repositoryUri must be a string');
    if (typeof envelope.target.commitSha !== 'string') errors.push('target.commitSha must be a string');
  }

  if (!envelope.environment || typeof envelope.environment !== 'object') {
    errors.push('Missing environment object');
  } else {
    if (typeof envelope.environment.agyVersion !== 'string') errors.push('environment.agyVersion must be a string');
    if (typeof envelope.environment.modelId !== 'string') errors.push('environment.modelId must be a string');
    if (typeof envelope.environment.modelProvider !== 'string') errors.push('environment.modelProvider must be a string');
    if (typeof envelope.environment.os !== 'string') errors.push('environment.os must be a string');
    if (typeof envelope.environment.nodeVersion !== 'string') errors.push('environment.nodeVersion must be a string');
  }

  if (!envelope.findings || typeof envelope.findings !== 'object') {
    errors.push('Missing findings object');
  } else {
    if (!Array.isArray(envelope.findings.candidates)) {
      errors.push('findings.candidates must be an array');
    }
  }

  if (!envelope.summary || typeof envelope.summary !== 'object') {
    errors.push('Missing summary object');
  } else {
    if (typeof envelope.summary.candidateCount !== 'number' || envelope.summary.candidateCount < 0) {
      errors.push('summary.candidateCount must be a non-negative number');
    }
  }

  return {
    valid: errors.length === 0,
    errors
  };
}

const VALID_FINDING_TYPES = new Set(['VULNERABILITY', 'HARDENING', 'INFORMATIONAL']);
const VALID_PROOF_KINDS = new Set([
  'STATIC_TRACE',
  'UNIT_TEST',
  'BENIGN_REPRODUCTION',
  'CONFIG_EVIDENCE',
  'DEPENDENCY_EVIDENCE',
  'EXTERNAL_SCANNER_EVIDENCE',
  'MANUAL_ATTESTATION'
]);
const VALID_SEVERITIES = new Set(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNRATED']);
const ALLOWED_ROOT_PROPERTIES = new Set(['schemaVersion', 'candidates', 'discoveryMetadata']);
const ALLOWED_CANDIDATE_PROPERTIES = new Set([
  'schemaVersion',
  'id',
  'ruleId',
  'title',
  'description',
  'securityProperty',
  'violation',
  'findingType',
  'proofKind',
  'severity',
  'location',
  'symbol',
  'proof',
  'attackPath',
  'evidence',
  'lineageId',
  'lineage',
  'component',
  'family'
]);
const ALLOWED_LOCATION_PROPERTIES = new Set(['uri', 'startLine', 'endLine', 'lineSnippet']);

/**
 * Validates candidate set structured output against candidate-set.schema.json.
 * Zero external dependencies.
 *
 * @param {any} data - Parsed candidate set object to validate.
 * @returns {{ valid: boolean, errors: string[] }}
 */
export function validateCandidateSet(data) {
  const errors = [];
  if (!data || typeof data !== 'object' || Array.isArray(data)) {
    return { valid: false, errors: ['Candidate set must be a non-null object'] };
  }

  for (const key of Object.keys(data)) {
    if (!ALLOWED_ROOT_PROPERTIES.has(key)) {
      errors.push(`Unexpected root property '${key}' (additionalProperties: false)`);
    }
  }

  if (data.schemaVersion !== undefined && data.schemaVersion !== '1' && data.schemaVersion !== '1.0.0') {
    errors.push(`Invalid schemaVersion: expected '1' or '1.0.0', got '${data.schemaVersion}'`);
  }

  if (!Array.isArray(data.candidates)) {
    errors.push('Candidate set missing required candidates array');
    return { valid: false, errors };
  }

  if (data.discoveryMetadata !== undefined && (typeof data.discoveryMetadata !== 'object' || data.discoveryMetadata === null || Array.isArray(data.discoveryMetadata))) {
    errors.push('discoveryMetadata must be an object if specified');
  }

  for (let i = 0; i < data.candidates.length; i++) {
    const cand = data.candidates[i];
    const prefix = `candidates[${i}]`;
    if (!cand || typeof cand !== 'object' || Array.isArray(cand)) {
      errors.push(`${prefix} must be a non-null object`);
      continue;
    }

    for (const key of Object.keys(cand)) {
      if (!ALLOWED_CANDIDATE_PROPERTIES.has(key)) {
        errors.push(`${prefix} has unexpected property '${key}' (additionalProperties: false)`);
      }
    }

    if (typeof cand.id !== 'string' || !cand.id.trim()) {
      errors.push(`${prefix}.id must be a non-empty string`);
    }
    if (typeof cand.ruleId !== 'string' || !cand.ruleId.trim()) {
      errors.push(`${prefix}.ruleId must be a non-empty string`);
    }
    if (typeof cand.title !== 'string' || !cand.title.trim()) {
      errors.push(`${prefix}.title must be a non-empty string`);
    }
    if (typeof cand.securityProperty !== 'string' || !cand.securityProperty.trim()) {
      errors.push(`${prefix}.securityProperty must be a non-empty string`);
    }
    if (!VALID_FINDING_TYPES.has(cand.findingType)) {
      errors.push(`${prefix}.findingType must be one of: ${Array.from(VALID_FINDING_TYPES).join(', ')} (got '${cand.findingType}')`);
    }
    if (!VALID_PROOF_KINDS.has(cand.proofKind)) {
      errors.push(`${prefix}.proofKind must be one of: ${Array.from(VALID_PROOF_KINDS).join(', ')} (got '${cand.proofKind}')`);
    }

    if (cand.severity !== undefined && !VALID_SEVERITIES.has(cand.severity)) {
      errors.push(`${prefix}.severity must be one of: ${Array.from(VALID_SEVERITIES).join(', ')} (got '${cand.severity}')`);
    }

    if (!cand.location || typeof cand.location !== 'object' || Array.isArray(cand.location)) {
      errors.push(`${prefix}.location must be an object`);
    } else {
      for (const locKey of Object.keys(cand.location)) {
        if (!ALLOWED_LOCATION_PROPERTIES.has(locKey)) {
          errors.push(`${prefix}.location has unexpected property '${locKey}' (additionalProperties: false)`);
        }
      }
      if (typeof cand.location.uri !== 'string' || !cand.location.uri.trim()) {
        errors.push(`${prefix}.location.uri must be a non-empty string`);
      }
      if (typeof cand.location.startLine !== 'number' || !Number.isInteger(cand.location.startLine) || cand.location.startLine < 1) {
        errors.push(`${prefix}.location.startLine must be an integer >= 1`);
      }
      if (cand.location.endLine !== undefined) {
        if (typeof cand.location.endLine !== 'number' || !Number.isInteger(cand.location.endLine) || cand.location.endLine < 1) {
          errors.push(`${prefix}.location.endLine must be an integer >= 1`);
        } else if (typeof cand.location.startLine === 'number' && cand.location.endLine < cand.location.startLine) {
          errors.push(`${prefix}.location.endLine (${cand.location.endLine}) cannot be less than startLine (${cand.location.startLine})`);
        }
      }
    }
  }

  return {
    valid: errors.length === 0,
    errors
  };
}

/**
 * Creates a schema-compliant empirical benchmark run envelope.
 */
export function createBenchmarkRunEnvelope(options = {}) {
  const repoRoot = options.repoRoot || process.cwd();
  const gitProv = getHardenedGitProvenance(repoRoot);

  const runId = options.runId || `run-${Date.now()}-${crypto.randomBytes(4).toString('hex')}`;
  const recordedAt = options.recordedAt || new Date().toISOString();
  const benchmarkMode = options.benchmarkMode || 'DISCOVERY';

  const target = {
    repositoryName: options.target?.repositoryName || path.basename(repoRoot) || 'unknown',
    repositoryUri: options.target?.repositoryUri || gitProv.repositoryUri || repoRoot,
    commitSha: options.target?.commitSha || gitProv.revisionId || gitProv.commitSha || 'UNKNOWN',
    corpus: options.target?.corpus || options.corpus || null
  };

  const cleanEnvOverrides = {};
  if (options.environment && typeof options.environment === 'object') {
    for (const [k, v] of Object.entries(options.environment)) {
      if (v !== undefined) cleanEnvOverrides[k] = v;
    }
  }

  const environment = {
    ...probeEnvironment(repoRoot, cleanEnvOverrides),
    ...cleanEnvOverrides
  };

  const candidates = Array.isArray(options.candidates) ? options.candidates : [];
  const verifiedFindings = Array.isArray(options.verifiedFindings)
    ? options.verifiedFindings
    : (Array.isArray(options.findings) ? options.findings : null);

  let verifiedCount = null;
  let deferredCount = null;
  let suppressedCount = null;

  if (verifiedFindings) {
    verifiedCount = verifiedFindings.filter(f => f.disposition === 'CONFIRMED' || f.disposition === 'REPORTABLE').length;
    deferredCount = verifiedFindings.filter(f => f.disposition === 'DEFERRED').length;
    suppressedCount = verifiedFindings.filter(f => f.disposition === 'FALSE_POSITIVE' || f.disposition === 'AFFIRMATIVELY_REFUTED').length;
  }

  const summary = {
    candidateCount: candidates.length,
    verifiedCount,
    deferredCount,
    suppressedCount,
    executionDurationMs: typeof options.executionDurationMs === 'number' ? options.executionDurationMs : null,
    ...(options.summary || {})
  };

  const evidenceOrigin = options.evidenceOrigin || 'MODEL_OBSERVED';
  const executionKind = options.executionKind || (evidenceOrigin === 'SYNTHETIC' ? 'SIMULATED_HARNESS' : 'LIVE_AGENT');

  const envelope = {
    schemaVersion: '1.0.0',
    runId,
    recordedAt,
    benchmarkMode,
    evidenceOrigin,
    executionKind,
    target,
    environment,
    findings: {
      candidates,
      verifiedFindings,
      unresolvedCandidates: options.unresolvedCandidates || null,
      suppressedCandidates: options.suppressedCandidates || null
    },
    summary,
    metadata: options.metadata || {}
  };

  const validation = validateBenchmarkRunEnvelope(envelope);
  if (!validation.valid) {
    throw new Error(`Invalid benchmark run envelope: ${validation.errors.join('; ')}`);
  }

  return envelope;
}

// -----------------------------------------------------------------------------
// CLI Dispatch
// -----------------------------------------------------------------------------
const isDirectExecution = process.argv[1] && process.argv[1].endsWith('record-benchmark-run.mjs');
if (isDirectExecution) {
  const args = process.argv.slice(2);
  function getArg(name) {
    const idx = args.indexOf(name);
    return idx !== -1 && idx + 1 < args.length ? args[idx + 1] : null;
  }

  const candPath = getArg('--candidates') || path.resolve('scratch/candidate-findings.json');
  const findingsPath = getArg('--findings') || getArg('--canonical') || path.resolve('scratch/canonical-findings.json');
  const outPath = getArg('--output');
  const outDir = getArg('--output-dir');
  const mode = getArg('--mode') || 'DISCOVERY';
  const model = getArg('--model');
  const provider = getArg('--provider');
  const corpus = getArg('--corpus');
  const originArg = getArg('--evidence-origin') || getArg('--origin');
  const executionKindArg = getArg('--execution-kind');

  let candidates = [];
  if (fs.existsSync(candPath)) {
    try {
      candidates = JSON.parse(fs.readFileSync(candPath, 'utf8'));
    } catch (e) {
      console.error(`Failed to parse candidates at ${candPath}:`, e.message);
      process.exit(1);
    }
  }

  let verifiedFindings = null;
  if (fs.existsSync(findingsPath)) {
    try {
      verifiedFindings = JSON.parse(fs.readFileSync(findingsPath, 'utf8'));
    } catch (e) {
      console.warn(`Could not parse findings at ${findingsPath}:`, e.message);
    }
  }

  const envelope = createBenchmarkRunEnvelope({
    benchmarkMode: mode,
    candidates,
    verifiedFindings,
    corpus,
    evidenceOrigin: originArg || undefined,
    executionKind: executionKindArg || undefined,
    environment: {
      modelId: model || undefined,
      modelProvider: provider || undefined
    }
  });

  const serialized = JSON.stringify(envelope, null, 2);

  if (outPath) {
    fs.mkdirSync(path.dirname(outPath), { recursive: true });
    fs.writeFileSync(outPath, serialized, 'utf8');
    console.log(`✔ Recorded benchmark envelope written to: ${outPath}`);
  } else if (outDir) {
    fs.mkdirSync(outDir, { recursive: true });
    const targetFile = path.join(outDir, `${envelope.runId}.json`);
    fs.writeFileSync(targetFile, serialized, 'utf8');
    console.log(`✔ Recorded benchmark envelope written to: ${targetFile}`);
  } else {
    process.stdout.write(serialized + '\n');
  }
}
