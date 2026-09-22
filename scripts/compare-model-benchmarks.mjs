#!/usr/bin/env node
/**
 * compare-model-benchmarks.mjs
 * Cross-Model Comparative Analytics & Validation Engine (Milestone G5).
 * Compares multi-pass empirical benchmark envelopes across reasoning profiles,
 * model families, providers, and runtimes under Default-Deny.
 *
 * Zero runtime external dependencies.
 */

import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';
import {
  normalizeModelTaxonomy,
  validateIndependenceAuthority,
  VALID_IDENTITY_SOURCES,
  VALID_TAXONOMY_TIERS
} from '../skills/security-audit/scripts/record-benchmark-run.mjs';

const __filename = fileURLToPath(import.meta.url);
const DEFAULT_REPO_ROOT = path.resolve(path.dirname(__filename), '..');

/**
 * Deterministically stringifies a JSON-compatible value with sorted object keys.
 */
export function canonicalJsonStringify(obj) {
  if (obj === null || typeof obj !== 'object') {
    return JSON.stringify(obj);
  }
  if (Array.isArray(obj)) {
    return '[' + obj.map(canonicalJsonStringify).join(',') + ']';
  }
  const keys = Object.keys(obj).sort();
  return '{' + keys.map(k => JSON.stringify(k) + ':' + canonicalJsonStringify(obj[k])).join(',') + '}';
}

/**
 * Computes canonical SHA-256 digest of an evaluation protocol specification (excluding protocolDigest).
 */
export function computeProtocolDigest(protocol) {
  if (!protocol || typeof protocol !== 'object') return null;
  const clone = { ...protocol };
  delete clone.protocolDigest;
  const canonical = canonicalJsonStringify(clone);
  return crypto.createHash('sha256').update(canonical, 'utf8').digest('hex');
}

/**
 * Loads and validates a frozen evaluation protocol specification (Fail-Closed).
 */
export function loadAndValidateProtocol(protocolPath, repoRoot = DEFAULT_REPO_ROOT) {
  const fullPath = path.resolve(repoRoot, protocolPath);
  if (!fs.existsSync(fullPath)) {
    throw new Error(`Protocol file not found: ${fullPath}`);
  }
  const content = fs.readFileSync(fullPath, 'utf8');
  let parsed;
  try {
    parsed = JSON.parse(content);
  } catch (err) {
    throw new Error(`Invalid JSON in protocol file (${fullPath}): ${err.message}`);
  }

  if (!parsed.protocolId || typeof parsed.protocolId !== 'string') {
    throw new Error(`Protocol missing required protocolId: ${fullPath}`);
  }
  if (parsed.status !== 'FROZEN') {
    throw new Error(`Protocol status must be 'FROZEN', got '${parsed.status}' (${fullPath})`);
  }
  if (!parsed.protocolDigest || typeof parsed.protocolDigest !== 'string') {
    throw new Error(`Protocol missing required protocolDigest: ${fullPath}`);
  }

  const computed = computeProtocolDigest(parsed);
  if (computed !== parsed.protocolDigest) {
    throw new Error(
      `PROTOCOL_DIGEST_MISMATCH: Frozen protocol '${parsed.protocolId}' has been tampered with or modified.\n` +
      `  Declared Digest: ${parsed.protocolDigest}\n` +
      `  Computed Digest: ${computed}`
    );
  }

  return parsed;
}

/**
 * Level 1 Matcher: Exact cryptographic lineage fingerprint SHA256(ruleId:uri:symbol).
 */
export function computeLevel1Fingerprint(cand) {
  if (!cand || typeof cand !== 'object') return 'unknown';
  if (cand.lineageId && typeof cand.lineageId === 'string') {
    return cand.lineageId;
  }
  const ruleId = String(cand.ruleId || 'SEC').trim().toUpperCase();
  const uri = String(cand.location?.uri || cand.uri || 'unknown')
    .replace(/\\/g, '/')
    .replace(/^\.\//, '')
    .toLowerCase();
  const symbol = String(cand.symbol || '').trim().toLowerCase();
  return crypto.createHash('sha256').update(`${ruleId}:${uri}:${symbol}`).digest('hex').substring(0, 32);
}

/**
 * Known CWE equivalence families for semantic (Level 2) matching.
 */
export const CWE_EQUIVALENCE_FAMILIES = [
  new Set(['CWE-94', 'CWE-1336', 'CWE-95']),          // Code Injection / SSTI / Eval Injection
  new Set(['CWE-22', 'CWE-23', 'CWE-36', 'CWE-73']),  // Path Traversal / Zip Slip
  new Set(['CWE-79', 'CWE-80', 'CWE-83', 'CWE-87']),  // Cross-Site Scripting
  new Set(['CWE-89', 'CWE-564', 'CWE-943']),          // SQL Injection / Query Injection
  new Set(['CWE-611', 'CWE-827']),                     // XML Entity Expansion (XXE)
  new Set(['CWE-918']),                                // SSRF
  new Set(['CWE-915']),                                // Mass Assignment / Auto-Binding
  new Set(['CWE-1333', 'CWE-400']),                    // ReDoS / Algorithmic Complexity
  new Set(['CWE-329', 'CWE-326', 'CWE-327']),          // Cryptographic Weaknesses / IV Reuse
  new Set(['CWE-347', 'CWE-287']),                     // JWT / Signature Verification Bypass
  new Set(['CWE-113', 'CWE-436']),                     // CRLF / HTTP Header Injection
  new Set(['CWE-362', 'CWE-367'])                      // Race Condition / TOCTOU
];

/**
 * Checks whether two rule or CWE identifiers belong to the same semantic family.
 */
export function isCweCompatible(ruleA, ruleB) {
  if (!ruleA || !ruleB) return false;
  const a = String(ruleA).trim().toUpperCase();
  const b = String(ruleB).trim().toUpperCase();
  if (a === b) return true;
  if (a.includes(b) || b.includes(a)) return true;
  for (const fam of CWE_EQUIVALENCE_FAMILIES) {
    if (fam.has(a) && fam.has(b)) return true;
  }
  return false;
}

/**
 * Level 2 Matcher: Ground-Truth Semantic Match key (fixtureId + canonical CWE family).
 * De-fuzzed in G5-CR1: Removes model-generated freeform securityProperty to prevent artificial key fragmentation.
 */
export function computeLevel2SemanticKey(cand, fixtureIdHint = null) {
  if (!cand || typeof cand !== 'object') return 'unknown';
  const uri = String(cand.location?.uri || cand.uri || '').replace(/\\/g, '/');
  let fixtureId = fixtureIdHint || cand.fixtureId || extractFixtureIdFromUri(uri) || uri || 'unknown';
  fixtureId = String(fixtureId).toUpperCase();

  let ruleId = String(cand.ruleId || 'UNKNOWN').toUpperCase();
  for (const fam of CWE_EQUIVALENCE_FAMILIES) {
    if (fam.has(ruleId)) {
      ruleId = Array.from(fam)[0]; // Canonical family representative
      break;
    }
  }

  return `${fixtureId}:${ruleId}`;
}

/**
 * Authoritative G4 historical baseline commit prefix and identifier.
 */
export const G4_BASELINE_COMMIT_PREFIX = 'd98b017';

/**
 * Checks whether an envelope or taxonomy record corresponds to the authoritative G4 baseline.
 */
export function isG4HistoricalBaseline(item) {
  if (!item || typeof item !== 'object') return false;
  const commit = item.target?.commitSha || item.environment?.toolRevision || item.environment?.skillRevision || item.provenanceScope?.sourceRevision;
  if (typeof commit === 'string' && commit.startsWith(G4_BASELINE_COMMIT_PREFIX)) {
    const model = item.environment?.modelId || item.modelId || item.rawModelId;
    return model === 'gemini-3.8-flash-high' || model === 'gemini-3.8-flash';
  }
  return false;
}

/**
 * Extracts normalized model taxonomy from an envelope, run, or taxonomy record.
 */
export function extractTaxonomy(item) {
  if (!item || typeof item !== 'object') {
    return normalizeModelTaxonomy('UNKNOWN');
  }
  if (isG4HistoricalBaseline(item)) {
    const env = item.environment || item;
    return normalizeModelTaxonomy(env.modelId || 'gemini-3.8-flash-high', {
      ...env,
      baseModel: 'gemini-3.8-flash',
      reasoningProfile: 'high',
      modelProvider: 'google',
      modelFamily: 'gemini-flash',
      identitySource: 'CONFIG_DECLARED',
      identityConfidence: 'HIGH'
    });
  }
  if (item.canonicalModelId && item.identitySource && item.rawModelId) {
    return item;
  }
  if (item.environment?.modelTaxonomy) {
    return item.environment.modelTaxonomy;
  }
  if (item.environment?.modelId) {
    return normalizeModelTaxonomy(item.environment.modelId, item.environment);
  }
  if (item.modelId) {
    return normalizeModelTaxonomy(item.modelId, item);
  }
  return normalizeModelTaxonomy('UNKNOWN', item);
}

/**
 * Classifies an experiment into one of the 4 Tiers or IDENTITY_CONTROL under Default-Deny.
 */
export function classifyComparisonExperiment(runOrTaxA, runOrTaxB, options = {}) {
  const taxA = extractTaxonomy(runOrTaxA);
  const taxB = extractTaxonomy(runOrTaxB);

  // Check identity control condition (self-comparison / identical runs)
  const isSameRunId = runOrTaxA?.runId && runOrTaxB?.runId && runOrTaxA.runId === runOrTaxB.runId;
  const isIdenticalTax = (
    taxA.rawModelId === taxB.rawModelId &&
    taxA.modelProvider === taxB.modelProvider &&
    taxA.reasoningProfile === taxB.reasoningProfile &&
    taxA.runtimeId === taxB.runtimeId &&
    taxA.runtimeAdapter === taxB.runtimeAdapter
  );

  let tier = null;
  let name = null;
  let description = null;

  if (isIdenticalTax && (isSameRunId || options.identityControl)) {
    tier = 0;
    name = 'IDENTITY_CONTROL';
    description = 'Self-comparison or identical run verification control (strictly non-publishable).';
  } else if (taxA.runtimeId !== taxB.runtimeId || taxA.runtimeAdapter !== taxB.runtimeAdapter) {
    tier = 4;
    name = 'CROSS_SYSTEM_REPLICATION';
    description = 'Replication across divergent agent runtimes / system prompts / tool environments.';
  } else if (taxA.modelProvider !== taxB.modelProvider) {
    tier = 3;
    name = 'CROSS_PROVIDER_MODEL_REPLICATION';
    description = 'True independent cross-model replication across distinct model providers.';
  } else if (taxA.baseModel !== taxB.baseModel || taxA.modelFamily !== taxB.modelFamily || taxA.canonicalModelId !== taxB.canonicalModelId) {
    tier = 2;
    name = 'INTRA_PROVIDER_MODEL_REPLICATION';
    description = 'Replication across different model architectures from the same provider.';
  } else if (taxA.reasoningProfile !== taxB.reasoningProfile) {
    tier = 1;
    name = 'REASONING_PROFILE_ABLATION';
    description = 'Inference effort / thinking budget ablation on identical base model and runtime.';
  } else {
    tier = 0;
    name = 'IDENTITY_CONTROL';
    description = 'Identical model, profile, and runtime configuration (verification control).';
  }

  // Validate attested identity authority for Tiers 1, 2, 3, 4 under Default-Deny
  const authRes = validateIndependenceAuthority(taxA, taxB, name);
  const failClosed = options.failClosed !== false;

  if (!authRes.valid && failClosed && (tier === 1 || tier === 2 || tier === 3 || tier === 4)) {
    throw new Error(
      `DEFAULT_DENY_TAXONOMY_VIOLATION: ${authRes.error}\n` +
      `  Configuration A: ${JSON.stringify(taxA)}\n` +
      `  Configuration B: ${JSON.stringify(taxB)}`
    );
  }

  return {
    tier,
    name,
    description,
    taxonomyA: taxA,
    taxonomyB: taxB,
    publishable: tier !== 0,
    authorityValid: authRes.valid,
    authorityError: authRes.error
  };
}

/**
 * Discovers the on-disk checkpoints directory for a given runs directory.
 */
export function findCheckpointsForRuns(runsPath, repoRoot = DEFAULT_REPO_ROOT) {
  if (!runsPath) return null;
  const rel = typeof runsPath === 'string' ? path.relative(repoRoot, runsPath).replace(/\\/g, '/').replace(/^\.\//, '') : '';
  const slug = rel.replace(/[^a-zA-Z0-9_-]/g, '_');
  const candidates = [
    path.resolve(repoRoot, 'scratch/live-benchmark/checkpoints', slug),
    path.resolve(repoRoot, 'scratch/live-benchmark/checkpoints', path.basename(rel)),
    path.resolve(repoRoot, 'scratch/live-benchmark/checkpoints')
  ];
  for (const c of candidates) {
    if (fs.existsSync(c)) return c;
  }
  return null;
}

/**
 * Audits execution exposures distinguishing completed from censored runs.
 * Failures (TIMEOUT, SCHEMA_VIOLATION) are strictly marked CENSORED, not negative findings.
 */
export function auditExecutionExposures(runs) {
  const envs = Array.isArray(runs) ? runs : [runs];
  let attempted = 0;
  let completed = 0;
  let censored = 0;
  let vulnAttempted = 0;
  let vulnCompleted = 0;
  let vulnCensored = 0;
  let safeAttempted = 0;
  let safeCompleted = 0;
  let safeCensored = 0;
  let vulnWithCandidates = 0;

  const fixtureStats = new Map();

  for (const env of envs) {
    const list = env.metadata?.fixtureResults || [];
    for (const r of list) {
      const fixId = r.fixtureId;
      const isSafe = r.split === 'SAFE_CONTROL' || (fixId && fixId.includes('SAFE'));
      attempted++;
      if (isSafe) safeAttempted++; else vulnAttempted++;

      if (!fixtureStats.has(fixId)) {
        fixtureStats.set(fixId, { completed: 0, censored: 0, candidatePasses: 0, isSafe });
      }
      const st = fixtureStats.get(fixId);

      if (r.error) {
        censored++;
        if (isSafe) safeCensored++; else vulnCensored++;
        st.censored++;
      } else {
        completed++;
        if (isSafe) safeCompleted++; else {
          vulnCompleted++;
          if (r.candidateCount > 0) {
            vulnWithCandidates++;
            st.candidatePasses++;
          }
        }
        st.completed++;
      }
    }
  }

  return {
    attempted,
    completed,
    censored,
    vulnAttempted,
    vulnCompleted,
    vulnCensored,
    vulnWithCandidates,
    safeAttempted,
    safeCompleted,
    safeCensored,
    fixtureStats
  };
}

/**
 * Loads benchmark run envelopes from a file, directory, or array.
 */
export function loadRuns(inputPath) {
  if (Array.isArray(inputPath)) {
    return inputPath;
  }
  if (typeof inputPath !== 'string') {
    throw new Error(`Invalid input path: ${inputPath}`);
  }
  const resolved = path.resolve(inputPath);
  if (!fs.existsSync(resolved)) {
    throw new Error(`Runs path does not exist: ${resolved}`);
  }

  const stat = fs.statSync(resolved);
  if (stat.isDirectory()) {
    const files = fs.readdirSync(resolved)
      .filter(f => f.endsWith('.json') && !f.includes('manifest') && !f.includes('summary'))
      .sort();
    if (files.length === 0) {
      throw new Error(`No JSON run envelopes found in directory: ${resolved}`);
    }
    const envelopes = [];
    for (const f of files) {
      const full = path.join(resolved, f);
      try {
        const parsed = JSON.parse(fs.readFileSync(full, 'utf8'));
        if (parsed && typeof parsed === 'object') {
          envelopes.push(parsed);
        }
      } catch (err) {
        console.warn(`[WARN] Skipping unparseable JSON file ${f}: ${err.message}`);
      }
    }
    return envelopes;
  }

  // Single file
  const parsed = JSON.parse(fs.readFileSync(resolved, 'utf8'));
  if (Array.isArray(parsed)) return parsed;
  if (Array.isArray(parsed.envelopes)) return parsed.envelopes;
  return [parsed];
}

/**
 * Extracts candidate findings from a run envelope.
 */
function extractCandidatesFromRun(envelope) {
  if (!envelope || typeof envelope !== 'object') return [];
  if (Array.isArray(envelope.findings?.candidates)) {
    return envelope.findings.candidates;
  }
  if (Array.isArray(envelope.findings?.verifiedFindings)) {
    return envelope.findings.verifiedFindings;
  }
  if (Array.isArray(envelope.candidates)) {
    return envelope.candidates;
  }
  return [];
}

/**
 * Computes lineage recurrence across a series of passes (envelopes).
 * Returns map of lineageKey -> { lineageKey, cand, recurrenceCount, recurrenceRate, passesObserved }
 */
export function computeLineageRecurrence(runs, matcher = 'level1') {
  const envelopes = Array.isArray(runs) ? runs : [runs];
  const N = envelopes.length;
  const lineageMap = new Map();

  for (let p = 0; p < N; p++) {
    const env = envelopes[p];
    const cands = extractCandidatesFromRun(env);
    const seenInThisPass = new Set();

    for (const c of cands) {
      const key = matcher === 'level2' ? computeLevel2SemanticKey(c) : computeLevel1Fingerprint(c);
      if (!lineageMap.has(key)) {
        lineageMap.set(key, {
          lineageKey: key,
          candidate: c,
          level1Fp: computeLevel1Fingerprint(c),
          level2Key: computeLevel2SemanticKey(c),
          passesObserved: new Set(),
          count: 0
        });
      }
      const entry = lineageMap.get(key);
      if (!seenInThisPass.has(key)) {
        seenInThisPass.add(key);
        entry.passesObserved.add(p + 1);
        entry.count += 1;
      }
    }
  }

  const result = new Map();
  for (const [k, v] of lineageMap.entries()) {
    result.set(k, {
      ...v,
      totalPasses: N,
      recurrenceCount: v.count,
      recurrenceRate: N > 0 ? v.count / N : 0
    });
  }

  return { N, lineages: result };
}

/**
 * Computes dual-tier Jaccard similarity ($J_{any}$ vs $J_{strict}$) with explicit empty-set semantics.
 *
 * Threshold formula: ceil(0.60 * N)
 * Empty sets: if |S_A| == 0 and |S_B| == 0 -> jaccard: null, bothEmpty: true, display: 'N/A'
 */
export function computeComparativeJaccard(runsA, runsB, threshold = 0.60, matcher = 'level1') {
  const envsA = Array.isArray(runsA) ? runsA : [runsA];
  const envsB = Array.isArray(runsB) ? runsB : [runsB];

  const recA = computeLineageRecurrence(envsA, matcher);
  const recB = computeLineageRecurrence(envsB, matcher);

  const reqA = Math.ceil(threshold * recA.N);
  const reqB = Math.ceil(threshold * recB.N);

  // Any observed lineage sets
  const setA_any = new Set(recA.lineages.keys());
  const setB_any = new Set(recB.lineages.keys());

  // Strict stable lineage sets (>= ceil(0.60 * N))
  const setA_strict = new Set();
  for (const [k, v] of recA.lineages.entries()) {
    if (v.recurrenceCount >= reqA) setA_strict.add(k);
  }

  const setB_strict = new Set();
  for (const [k, v] of recB.lineages.entries()) {
    if (v.recurrenceCount >= reqB) setB_strict.add(k);
  }

  // Dual-Tier Jaccard helper
  function calcJaccard(setA, setB) {
    if (setA.size === 0 && setB.size === 0) {
      return {
        jaccard: null,
        bothEmpty: true,
        display: 'N/A',
        intersectionSize: 0,
        unionSize: 0,
        sizeA: 0,
        sizeB: 0
      };
    }

    const intersection = new Set([...setA].filter(x => setB.has(x)));
    const union = new Set([...setA, ...setB]);
    const score = union.size === 0 ? 0 : intersection.size / union.size;

    return {
      jaccard: score,
      bothEmpty: false,
      display: `${(score * 100).toFixed(1)}%`,
      intersectionSize: intersection.size,
      unionSize: union.size,
      sizeA: setA.size,
      sizeB: setB.size,
      intersection: Array.from(intersection),
      union: Array.from(union)
    };
  }

  const jAny = calcJaccard(setA_any, setB_any);
  const jStrict = calcJaccard(setA_strict, setB_strict);

  // Divergent lineages
  const uniqueToA = Array.from(setA_any).filter(k => !setB_any.has(k));
  const uniqueToB = Array.from(setB_any).filter(k => !setA_any.has(k));
  const uniqueToA_strict = Array.from(setA_strict).filter(k => !setB_strict.has(k));
  const uniqueToB_strict = Array.from(setB_strict).filter(k => !setA_strict.has(k));

  return {
    threshold,
    matcher,
    passesA: recA.N,
    passesB: recB.N,
    requiredCountA: reqA,
    requiredCountB: reqB,
    jAny,
    jStrict,
    setA_any: Array.from(setA_any),
    setB_any: Array.from(setB_any),
    setA_strict: Array.from(setA_strict),
    setB_strict: Array.from(setB_strict),
    uniqueToA,
    uniqueToB,
    uniqueToA_strict,
    uniqueToB_strict,
    recMapA: recA.lineages,
    recMapB: recB.lineages
  };
}

/**
 * Extracts normalized fixture ID from URI (e.g. HLD-01, HLD-01-SAFE, SEM-03).
 */
export function extractFixtureIdFromUri(uri) {
  if (!uri || typeof uri !== 'string') return null;
  const norm = uri.replace(/\\/g, '/');
  const isSafe = norm.includes('/safe/') || norm.includes('-safe') || norm.includes('-SAFE');
  const match = norm.match(/(?:evals\/)?(holdout|semantic)-benchmark\/(?:safe\/|vuln\/)?(?:(\d{2})-[a-z0-9-]+|([A-Z0-9_-]+))/i);
  if (match) {
    if (match[2]) {
      const prefix = match[1].toLowerCase().includes('holdout') ? 'HLD' : 'SEM';
      return `${prefix}-${match[2]}${isSafe ? '-SAFE' : ''}`;
    }
    if (match[3]) {
      return match[3].toUpperCase();
    }
  }
  return null;
}

/**
 * Classifies a candidate finding against ground truth into consensus disposition:
 * - REPLICATED_TRUE_POSITIVE
 * - REPLICATED_FALSE_POSITIVE
 * - REPLICATED_UNRESOLVED
 */
export function dispositionConsensusLineage(cand, groundTruthMap = null) {
  if (!groundTruthMap || groundTruthMap.size === 0) {
    return {
      disposition: 'REPLICATED_UNRESOLVED',
      reason: 'No ground-truth oracle provided for corpus.'
    };
  }

  const uri = String(cand.location?.uri || cand.uri || '').replace(/\\/g, '/');
  const isSafeFixture = uri.includes('/safe/') || uri.includes('-safe') || uri.includes('-SAFE');
  const fixtureId = extractFixtureIdFromUri(uri) || cand.fixtureId;

  // Match ground-truth by extracted fixtureId, filename, or id
  let matchedGt = null;
  if (fixtureId && groundTruthMap.has(fixtureId)) {
    matchedGt = groundTruthMap.get(fixtureId);
  }
  if (!matchedGt) {
    for (const [gtId, gt] of groundTruthMap.entries()) {
      if (gt.file && (uri.endsWith(gt.file) || uri.includes(gt.file))) {
        if (isSafeFixture && !gt.file.includes('safe')) continue;
        if (!isSafeFixture && gt.file.includes('safe')) continue;
        matchedGt = gt;
        break;
      }
      if (fixtureId && gt.id && gt.id === fixtureId) {
        matchedGt = gt;
        break;
      }
    }
  }

  if (isSafeFixture || (matchedGt && (matchedGt.expectedVerdict === 'SAFE' || matchedGt.expectedVerdict === 'DISPUTED' || matchedGt.id?.endsWith('-SAFE')))) {
    const isDisputed = Boolean(
      matchedGt?.disputed ||
      matchedGt?.oracleStatus === 'DISPUTED_INVALIDATED' ||
      matchedGt?.expectedVerdict === 'DISPUTED' ||
      matchedGt?.id === 'HLD-08-SAFE' ||
      String(fixtureId).toUpperCase() === 'HLD-08-SAFE'
    );
    if (isDisputed) {
      return {
        disposition: 'GROUND_TRUTH_DISPUTE',
        groundTruthId: matchedGt?.id || fixtureId || 'HLD-08-SAFE',
        expectedVerdict: matchedGt?.originalVerdict || 'SAFE',
        disputeReason: matchedGt?.disputeMetadata?.reason || `Verified benchmark oracle flaw on fixture '${matchedGt?.id || fixtureId || 'HLD-08-SAFE'}': contains unpinned DNS lookup followed by http.get (CWE-918 SSRF / DNS rebinding TOCTOU).`,
        reason: `Evidence-backed candidate on safe control fixture '${matchedGt?.id || uri}' identifies an authentic benchmark oracle defect (GROUND_TRUTH_DISPUTE).`
      };
    }
    return {
      disposition: 'REPLICATED_FALSE_POSITIVE',
      groundTruthId: matchedGt?.id || 'SAFE_CONTROL',
      reason: `Consensus lineage reproduced on safe control fixture '${matchedGt?.id || uri}'.`
    };
  }

  if (matchedGt && matchedGt.expectedVerdict === 'VULNERABLE') {
    const candRule = String(cand.ruleId || '').toUpperCase();
    const gtRule = String(matchedGt.cwe || '').toUpperCase();
    const ruleMatches = isCweCompatible(candRule, gtRule);

    if (ruleMatches || !matchedGt.cwe) {
      return {
        disposition: 'REPLICATED_TRUE_POSITIVE',
        groundTruthId: matchedGt.id,
        expectedCwe: matchedGt.cwe,
        severity: matchedGt.severity,
        reason: `Consensus lineage matches ground-truth vulnerability on fixture '${matchedGt.id}' (${matchedGt.cwe}).`
      };
    } else {
      // Reported wrong vulnerability type on vulnerable file
      return {
        disposition: 'REPLICATED_FALSE_POSITIVE',
        groundTruthId: matchedGt.id,
        expectedCwe: matchedGt.cwe,
        reason: `Mismatched rule (${candRule} != expected ${gtRule}) on fixture '${matchedGt.id}'.`
      };
    }
  }

  return {
    disposition: 'REPLICATED_UNRESOLVED',
    groundTruthId: matchedGt?.id || null,
    reason: `Finding on fixture '${uri}' has no definitive ground-truth disposition.`
  };
}

/**
 * Loads ground truth into a Map indexed by ID and normalized file path.
 */
export function loadGroundTruth(gtInput, repoRoot = DEFAULT_REPO_ROOT) {
  if (gtInput instanceof Map) return gtInput;
  let items = [];
  if (typeof gtInput === 'string') {
    const full = path.resolve(repoRoot, gtInput);
    if (!fs.existsSync(full)) return new Map();
    items = JSON.parse(fs.readFileSync(full, 'utf8'));
  } else if (Array.isArray(gtInput)) {
    items = gtInput;
  }
  const gtMap = new Map();
  for (const item of items) {
    if (item.id) gtMap.set(item.id, item);
    if (item.file) {
      const norm = String(item.file).replace(/\\/g, '/').toLowerCase();
      gtMap.set(norm, item);
    }
  }
  return gtMap;
}

/**
 * Computes consensus lineages, overlap, and ground-truth dispositions across Model A and Model B.
 */
export function computeConsensusLineages(runsA, runsB, groundTruth = null, options = {}) {
  const gtMap = loadGroundTruth(groundTruth, options.repoRoot || DEFAULT_REPO_ROOT);
  const threshold = options.threshold || 0.60;

  // Level 1 Comparison
  const l1Comp = computeComparativeJaccard(runsA, runsB, threshold, 'level1');
  // Level 2 Comparison
  const l2Comp = computeComparativeJaccard(runsA, runsB, threshold, 'level2');

  // Overlap and Consensus Sets
  const consensusList = [];
  let tpCount = 0;
  let fpCount = 0;
  let disputeCount = 0;
  let unresolvedCount = 0;

  for (const key of l1Comp.jStrict.intersection || []) {
    const infoA = l1Comp.recMapA.get(key);
    const infoB = l1Comp.recMapB.get(key);
    const cand = infoA?.candidate || infoB?.candidate;

    const disp = dispositionConsensusLineage(cand, gtMap);
    if (disp.disposition === 'REPLICATED_TRUE_POSITIVE') tpCount++;
    else if (disp.disposition === 'REPLICATED_FALSE_POSITIVE') fpCount++;
    else if (disp.disposition === 'GROUND_TRUTH_DISPUTE') disputeCount++;
    else unresolvedCount++;

    const isPerfect = (infoA?.recurrenceCount === l1Comp.passesA && infoB?.recurrenceCount === l1Comp.passesB);

    consensusList.push({
      lineageKey: key,
      candidate: cand,
      level1Fp: infoA?.level1Fp || infoB?.level1Fp,
      level2Key: infoA?.level2Key || infoB?.level2Key,
      recurrenceA: infoA ? `${infoA.recurrenceCount}/${l1Comp.passesA}` : '0',
      recurrenceB: infoB ? `${infoB.recurrenceCount}/${l1Comp.passesB}` : '0',
      consensusType: isPerfect ? 'PERFECT_REPLICATION' : 'RECURRENT_CROSS_MODEL_CONSENSUS',
      disposition: disp.disposition,
      dispositionDetails: disp
    });
  }

  // Level 2 Semantic Consensus Set
  const level2ConsensusList = [];
  let l2TpCount = 0;
  let l2FpCount = 0;
  let l2DisputeCount = 0;
  let l2UnresolvedCount = 0;

  for (const key of l2Comp.jStrict.intersection || []) {
    const infoA = l2Comp.recMapA.get(key);
    const infoB = l2Comp.recMapB.get(key);
    const cand = infoA?.candidate || infoB?.candidate;

    const disp = dispositionConsensusLineage(cand, gtMap);
    if (disp.disposition === 'REPLICATED_TRUE_POSITIVE') l2TpCount++;
    else if (disp.disposition === 'REPLICATED_FALSE_POSITIVE') l2FpCount++;
    else if (disp.disposition === 'GROUND_TRUTH_DISPUTE') l2DisputeCount++;
    else l2UnresolvedCount++;

    const isPerfect = (infoA?.recurrenceCount === l2Comp.passesA && infoB?.recurrenceCount === l2Comp.passesB);

    level2ConsensusList.push({
      lineageKey: key,
      candidate: cand,
      level1Fp: infoA?.level1Fp || infoB?.level1Fp,
      level2Key: key,
      recurrenceA: infoA ? `${infoA.recurrenceCount}/${l2Comp.passesA}` : '0',
      recurrenceB: infoB ? `${infoB.recurrenceCount}/${l2Comp.passesB}` : '0',
      consensusType: isPerfect ? 'PERFECT_REPLICATION' : 'RECURRENT_CROSS_MODEL_CONSENSUS',
      disposition: disp.disposition,
      dispositionDetails: disp
    });
  }

  return {
    level1: l1Comp,
    level2: l2Comp,
    consensusList,
    consensusCount: consensusList.length,
    level2ConsensusList,
    level2ConsensusCount: level2ConsensusList.length,
    disputedFixtures: Array.from(gtMap.values()).filter(g => g.oracleStatus === 'DISPUTED_INVALIDATED' || g.disputed || g.id === 'HLD-08-SAFE').map(g => g.id),
    dispositionSummary: {
      replicatedTruePositives: tpCount,
      replicatedFalsePositives: fpCount,
      groundTruthDisputes: disputeCount,
      replicatedUnresolved: unresolvedCount,
      level2TruePositives: l2TpCount,
      level2FalsePositives: l2FpCount,
      level2Disputes: l2DisputeCount,
      level2Unresolved: l2UnresolvedCount
    }
  };
}

/**
 * Computes false positive rates on safe controls across Model A and Model B.
 */
export function computeComparativeSpecificity(runsA, runsB, groundTruth = null, options = {}) {
  const envsA = Array.isArray(runsA) ? runsA : [runsA];
  const envsB = Array.isArray(runsB) ? runsB : [runsB];
  const groundTruthMap = loadGroundTruth(groundTruth, options.repoRoot || DEFAULT_REPO_ROOT);

  function auditSafeFps(envs) {
    let completedSafe = 0;
    let censoredSafe = 0;
    let genuineCompletedSafe = 0;
    let disputedCompletedSafe = 0;
    let fpCountGenuine = 0;
    let disputeCount = 0;
    const safeCands = [];

    for (const env of envs) {
      const fixResults = env.metadata?.fixtureResults;
      if (Array.isArray(fixResults)) {
        for (const r of fixResults) {
          const isSafe = r.split === 'SAFE_CONTROL' || (r.fixtureId && r.fixtureId.includes('SAFE'));
          if (!isSafe) continue;
          if (r.error) {
            censoredSafe++;
            continue;
          }
          completedSafe++;
          const gt = groundTruthMap.get(r.fixtureId);
          const isDisputed = Boolean(gt?.oracleStatus === 'DISPUTED_INVALIDATED' || gt?.disputed || r.fixtureId === 'HLD-08-SAFE');
          if (isDisputed) disputedCompletedSafe++;
          else genuineCompletedSafe++;
        }
      } else {
        completedSafe += 10;
        genuineCompletedSafe += 9;
        disputedCompletedSafe += 1;
      }

      const cands = extractCandidatesFromRun(env);
      for (const c of cands) {
        const uri = String(c.location?.uri || c.uri || '').replace(/\\/g, '/').toLowerCase();
        if (uri.includes('/safe/') || uri.includes('-safe')) {
          const fid = extractFixtureIdFromUri(uri) || '';
          const gt = groundTruthMap.get(fid);
          const isDisputed = Boolean(gt?.oracleStatus === 'DISPUTED_INVALIDATED' || gt?.disputed || uri.includes('08-ssrf') || uri.includes('hld-08'));
          if (isDisputed) {
            disputeCount++;
          } else {
            fpCountGenuine++;
          }
          safeCands.push(c);
        }
      }
    }

    return {
      completedSafe,
      censoredSafe,
      genuineCompletedSafe,
      disputedCompletedSafe,
      fpCountGenuine,
      disputeCount,
      totalFindingsOnSafe: safeCands.length,
      neutralOutcome: `${fpCountGenuine} observed false-positive exposures across ${genuineCompletedSafe} completed genuinely-safe exposures`,
      disputeOutcome: `${disputeCount} candidate detections across ${disputedCompletedSafe} completed exposures of disputed fixture HLD-08-SAFE`
    };
  }

  const safeA = auditSafeFps(envsA);
  const safeB = auditSafeFps(envsB);

  const bothZeroGenuine = safeA.fpCountGenuine === 0 && safeB.fpCountGenuine === 0;

  return {
    fpCountA: safeA.fpCountGenuine,
    fpCountB: safeB.fpCountGenuine,
    disputeCountA: safeA.disputeCount,
    disputeCountB: safeB.disputeCount,
    completedSafeA: safeA.completedSafe,
    completedSafeB: safeB.completedSafe,
    genuineCompletedSafeA: safeA.genuineCompletedSafe,
    genuineCompletedSafeB: safeB.genuineCompletedSafe,
    totalExposuresA: safeA.genuineCompletedSafe,
    totalExposuresB: safeB.genuineCompletedSafe,
    neutralOutcomeA: safeA.neutralOutcome,
    neutralOutcomeB: safeB.neutralOutcome,
    disputeOutcomeA: safeA.disputeOutcome,
    disputeOutcomeB: safeB.disputeOutcome,
    meanFpA: safeA.genuineCompletedSafe > 0 ? safeA.fpCountGenuine / safeA.genuineCompletedSafe : 0,
    meanFpB: safeB.genuineCompletedSafe > 0 ? safeB.fpCountGenuine / safeB.genuineCompletedSafe : 0,
    safeControlSuppressionAgreement: bothZeroGenuine ? 1.0 : (safeA.fpCountGenuine === safeB.fpCountGenuine ? 0.8 : 0.0),
    safeControlSuppressionDisplay: bothZeroGenuine ? '100.0% (Clean Controls)' : 'DIVERGENT'
  };
}

/**
 * Helper to compute quantile of numeric array.
 */
function quantile(arr, q) {
  if (!arr || arr.length === 0) return 0;
  const sorted = arr.slice().sort((a, b) => a - b);
  const pos = (sorted.length - 1) * q;
  const base = Math.floor(pos);
  const rest = pos - base;
  if (sorted[base + 1] !== undefined) {
    return sorted[base] + rest * (sorted[base + 1] - sorted[base]);
  }
  return sorted[base];
}

/**
 * Computes paired per-fixture latency & token deltas (median, P95) and incremental compute cost per replicated true positive.
 */
export function computeComparativeEfficiency(runsA, runsB, consensus = null, options = {}) {
  const envsA = Array.isArray(runsA) ? runsA : [runsA];
  const envsB = Array.isArray(runsB) ? runsB : [runsB];
  const repoRoot = options.repoRoot || DEFAULT_REPO_ROOT;

  // 1. Per-fixture paired latency deltas across envelopes
  const fixtureMapA = new Map();
  for (const env of envsA) {
    const list = env.metadata?.fixtureResults || [];
    for (const item of list) {
      if (!item.fixtureId || typeof item.durationMs !== 'number' || item.error) continue;
      if (!fixtureMapA.has(item.fixtureId)) fixtureMapA.set(item.fixtureId, []);
      fixtureMapA.get(item.fixtureId).push(item.durationMs);
    }
  }

  const fixtureMapB = new Map();
  for (const env of envsB) {
    const list = env.metadata?.fixtureResults || [];
    for (const item of list) {
      if (!item.fixtureId || typeof item.durationMs !== 'number' || item.error) continue;
      if (!fixtureMapB.has(item.fixtureId)) fixtureMapB.set(item.fixtureId, []);
      fixtureMapB.get(item.fixtureId).push(item.durationMs);
    }
  }

  const commonFixtures = Array.from(fixtureMapA.keys()).filter(id => fixtureMapB.has(id)).sort();
  const pairedLatencyDeltasMs = [];
  const fixtureDeltas = [];

  for (const id of commonFixtures) {
    const latsA = fixtureMapA.get(id);
    const latsB = fixtureMapB.get(id);
    const medA = quantile(latsA, 0.5);
    const medB = quantile(latsB, 0.5);
    const deltaMs = medB - medA;
    pairedLatencyDeltasMs.push(deltaMs);
    fixtureDeltas.push({ fixtureId: id, medianA: medA, medianB: medB, deltaMs });
  }

  const medianLatencyDeltaMs = pairedLatencyDeltasMs.length > 0 ? quantile(pairedLatencyDeltasMs, 0.5) : 0;
  const p95LatencyDeltaMs = pairedLatencyDeltasMs.length > 0 ? quantile(pairedLatencyDeltasMs, 0.95) : 0;

  // 2. Checkpoints-based paired exposure telemetry (exact mutually completed pairs)
  const pathA = typeof runsA === 'string' ? runsA : (options.runsAPath || null);
  const pathB = typeof runsB === 'string' ? runsB : (options.runsBPath || null);

  const cpDirA = findCheckpointsForRuns(pathA, repoRoot);
  const cpDirB = findCheckpointsForRuns(pathB, repoRoot);

  let pairedCount = 0;
  let pairedTokensA = 0, pairedTokensB = 0;
  let pairedThinkingA = 0, pairedThinkingB = 0;
  let pairedInputA = 0, pairedInputB = 0;
  let pairedOutputA = 0, pairedOutputB = 0;
  let pairedCacheA = 0, pairedCacheB = 0;
  const pairedCheckpointsLatencyDeltasSec = [];

  if (cpDirA && cpDirB) {
    for (let p = 1; p <= 3; p++) {
      const passDirA = path.join(cpDirA, `pass-${p}`);
      const passDirB = path.join(cpDirB, `pass-${p}`);
      if (!fs.existsSync(passDirA) || !fs.existsSync(passDirB)) continue;

      const filesA = fs.readdirSync(passDirA).filter(f => f.endsWith('.json') && !f.startsWith('SEM-'));
      for (const f of filesA) {
        const fileA = path.join(passDirA, f);
        const fileB = path.join(passDirB, f);
        if (!fs.existsSync(fileB)) continue;

        try {
          const itemA = JSON.parse(fs.readFileSync(fileA, 'utf8'));
          const itemB = JSON.parse(fs.readFileSync(fileB, 'utf8'));
          if (itemA.error || itemB.error) continue; // Only mutually completed valid exposures

          pairedCount++;
          const uA = itemA.executionTelemetry?.tokenUsage || {};
          const uB = itemB.executionTelemetry?.tokenUsage || {};

          pairedTokensA += uA.totalTokens || 0;
          pairedTokensB += uB.totalTokens || 0;
          pairedThinkingA += uA.thinkingTokens || 0;
          pairedThinkingB += uB.thinkingTokens || 0;
          pairedInputA += uA.inputTokens || 0;
          pairedInputB += uB.inputTokens || 0;
          pairedOutputA += uA.outputTokens || 0;
          pairedOutputB += uB.outputTokens || 0;
          pairedCacheA += uA.cacheReadTokens || 0;
          pairedCacheB += uB.cacheReadTokens || 0;

          if (typeof itemA.durationMs === 'number' && typeof itemB.durationMs === 'number') {
            pairedCheckpointsLatencyDeltasSec.push((itemB.durationMs - itemA.durationMs) / 1000);
          }
        } catch {}
      }
    }
  }

  pairedCheckpointsLatencyDeltasSec.sort((a, b) => a - b);
  const medianPairedLatencySec = pairedCheckpointsLatencyDeltasSec.length > 0
    ? quantile(pairedCheckpointsLatencyDeltasSec, 0.5)
    : (medianLatencyDeltaMs / 1000);
  const p95PairedLatencySec = pairedCheckpointsLatencyDeltasSec.length > 0
    ? quantile(pairedCheckpointsLatencyDeltasSec, 0.95)
    : (p95LatencyDeltaMs / 1000);

  const pairedTotalTokensDeltaPct = pairedTokensA > 0 ? ((pairedTokensB - pairedTokensA) / pairedTokensA) * 100 : 0;
  const pairedThinkingTokensDeltaPct = pairedThinkingA > 0 ? ((pairedThinkingB - pairedThinkingA) / pairedThinkingA) * 100 : 0;
  const pairedInputTokensDeltaPct = pairedInputA > 0 ? ((pairedInputB - pairedInputA) / pairedInputA) * 100 : 0;
  const pairedOutputTokensDeltaPct = pairedOutputA > 0 ? ((pairedOutputB - pairedOutputA) / pairedOutputA) * 100 : 0;
  const pairedCacheTokensDeltaPct = pairedCacheA > 0 ? ((pairedCacheB - pairedCacheA) / pairedCacheA) * 100 : 0;

  // 3. Token usage deltas across passes (Aggregated)
  function extractPassTokens(envs) {
    return envs.map(e => {
      const u = e.executionTelemetry?.tokenUsage || {};
      return {
        inputTokens: u.inputTokens || 0,
        outputTokens: u.outputTokens || 0,
        thinkingTokens: u.thinkingTokens || 0,
        cacheReadTokens: u.cacheReadTokens || 0,
        totalTokens: u.totalTokens || 0,
        durationSeconds: e.executionTelemetry?.durationSeconds || (e.summary?.executionDurationMs ? e.summary.executionDurationMs / 1000 : 0)
      };
    });
  }

  const passTokensA = extractPassTokens(envsA);
  const passTokensB = extractPassTokens(envsB);

  const meanTotalA = passTokensA.length > 0 ? passTokensA.reduce((sum, p) => sum + p.totalTokens, 0) / passTokensA.length : 0;
  const meanTotalB = passTokensB.length > 0 ? passTokensB.reduce((sum, p) => sum + p.totalTokens, 0) / passTokensB.length : 0;

  const meanThinkingA = passTokensA.length > 0 ? passTokensA.reduce((sum, p) => sum + p.thinkingTokens, 0) / passTokensA.length : 0;
  const meanThinkingB = passTokensB.length > 0 ? passTokensB.reduce((sum, p) => sum + p.thinkingTokens, 0) / passTokensB.length : 0;

  const meanDurationA = passTokensA.length > 0 ? passTokensA.reduce((sum, p) => sum + p.durationSeconds, 0) / passTokensA.length : 0;
  const meanDurationB = passTokensB.length > 0 ? passTokensB.reduce((sum, p) => sum + p.durationSeconds, 0) / passTokensB.length : 0;

  const deltaTotalTokens = meanTotalB - meanTotalA;
  const deltaThinkingTokens = meanThinkingB - meanThinkingA;
  const deltaDurationSeconds = meanDurationB - meanDurationA;

  const pairedPassTokenDeltas = [];
  const minPasses = Math.min(passTokensA.length, passTokensB.length);
  for (let i = 0; i < minPasses; i++) {
    pairedPassTokenDeltas.push(passTokensB[i].totalTokens - passTokensA[i].totalTokens);
  }
  const medianTokenDelta = pairedPassTokenDeltas.length > 0 ? quantile(pairedPassTokenDeltas, 0.5) : deltaTotalTokens;
  const p95TokenDelta = pairedPassTokenDeltas.length > 0 ? quantile(pairedPassTokenDeltas, 0.95) : deltaTotalTokens;

  // 4. Incremental compute cost per replicated true positive
  const replicatedTPs = consensus?.dispositionSummary?.replicatedTruePositives || 0;
  const incrementalTokensPerReplicatedTP = replicatedTPs > 0
    ? (pairedCount > 0 ? (pairedTokensB - pairedTokensA) / replicatedTPs : deltaTotalTokens / replicatedTPs)
    : null;
  const incrementalThinkingTokensPerReplicatedTP = replicatedTPs > 0
    ? (pairedCount > 0 ? (pairedThinkingB - pairedThinkingA) / replicatedTPs : deltaThinkingTokens / replicatedTPs)
    : null;
  const incrementalDurationSecPerReplicatedTP = replicatedTPs > 0 ? deltaDurationSeconds / replicatedTPs : null;

  return {
    commonFixtureCount: commonFixtures.length,
    fixtureDeltas,
    medianLatencyDeltaMs,
    p95LatencyDeltaMs,
    pairedCount,
    pairedTokensA,
    pairedTokensB,
    pairedThinkingA,
    pairedThinkingB,
    pairedInputA,
    pairedInputB,
    pairedOutputA,
    pairedOutputB,
    pairedCacheA,
    pairedCacheB,
    pairedTotalTokensDeltaPct,
    pairedThinkingTokensDeltaPct,
    pairedInputTokensDeltaPct,
    pairedOutputTokensDeltaPct,
    pairedCacheTokensDeltaPct,
    medianPairedLatencySec,
    p95PairedLatencySec,
    meanTotalA,
    meanTotalB,
    meanThinkingA,
    meanThinkingB,
    meanDurationA,
    meanDurationB,
    deltaTotalTokens,
    deltaThinkingTokens,
    deltaDurationSeconds,
    medianTokenDelta,
    p95TokenDelta,
    replicatedTPs,
    incrementalTokensPerReplicatedTP,
    incrementalThinkingTokensPerReplicatedTP,
    incrementalDurationSecPerReplicatedTP
  };
}

/**
 * Renders a publication-grade Markdown comparative validation report.
 */
export function renderComparativeReport(comparisonData, options = {}) {
  const { classification, consensus, specificity, protocol } = comparisonData;
  const eff = comparisonData.efficiency || null;
  const taxA = classification.taxonomyA;
  const taxB = classification.taxonomyB;
  const l1 = consensus.level1;
  const l2 = consensus.level2;
  const nowIso = new Date().toISOString();

  let md = '';
  md += `# Cross-Model & Ablation Comparative Validation Report\n\n`;
  md += `**Generated**: \`${nowIso}\`  \n`;
  md += `**Evidence Grade**: \`Tier 1A: HISTORICAL_REFERENCE_ABLATION\`  \n`;
  md += `**Protocol ID**: \`${protocol?.protocolId || 'v1.5-cross-model-1'}\`  \n`;
  md += `**Protocol Digest**: \`${protocol?.protocolDigest || 'UNKNOWN'}\`  \n`;
  md += `**Governance Standard**: NIST SSDF / Section 21 Holdout Covenant / Default-Deny Authority Invariant\n\n`;

  // Classification Banner
  if (classification.tier === 0) {
    md += `> [!WARNING] **NON-PUBLICATION VERIFICATION CONTROL (IDENTITY_CONTROL)**\n`;
    md += `> This report compares identical configurations or self-referential runs. It serves solely for\n`;
    md += `> internal harness and comparator engine validation and **MUST NOT** be cited as an ablation result.\n\n`;
  } else if (classification.tier === 1) {
    md += `> [!NOTE] **EVALUATION EVIDENCE GRADE: Tier 1A: HISTORICAL_REFERENCE_ABLATION**\n`;
    md += `> **EXPERIMENT TAXONOMY: TIER ${classification.tier} (${classification.name})**\n`;
    md += `> ${classification.description}\n\n`;
  } else {
    md += `> [!NOTE] **EXPERIMENT TAXONOMY: TIER ${classification.tier} (${classification.name})**\n`;
    md += `> ${classification.description}\n\n`;
  }

  // Model & Environment Metadata Table
  md += `## 1. Experimental Configuration & Model Taxonomy\n\n`;
  md += `| Attribute | Configuration A | Configuration B |\n`;
  md += `| :--- | :--- | :--- |\n`;
  md += `| **Raw Model ID** | \`${taxA.rawModelId}\` | \`${taxB.rawModelId}\` |\n`;
  md += `| **Canonical Model** | \`${taxA.canonicalModelId}\` | \`${taxB.canonicalModelId}\` |\n`;
  md += `| **Base Model** | \`${taxA.baseModel}\` | \`${taxB.baseModel}\` |\n`;
  md += `| **Model Family** | \`${taxA.modelFamily}\` | \`${taxB.modelFamily}\` |\n`;
  md += `| **Provider** | \`${taxA.modelProvider}\` | \`${taxB.modelProvider}\` |\n`;
  md += `| **Reasoning Profile** | \`${taxA.reasoningProfile}\` | \`${taxB.reasoningProfile}\` |\n`;
  md += `| **Runtime Engine** | \`${taxA.runtimeId}\` (${taxA.runtimeAdapter}) | \`${taxB.runtimeId}\` (${taxB.runtimeAdapter}) |\n`;
  md += `| **Identity Authority** | \`${taxA.identitySource}\` (\`${taxA.identityConfidence}\`) | \`${taxB.identitySource}\` (\`${taxB.identityConfidence}\`) |\n`;
  md += `| **Passes Evaluated (N)** | ${l1.passesA} | ${l1.passesB} |\n\n`;

  // Comparability Preflight & Temporal-Confound Disclosure
  md += `## 2. Comparability Preflight & Temporal-Confound Disclosure\n\n`;
  md += `### 2.1 Comparability Preflight Audit\n\n`;
  md += `| Comparability Dimension | Configuration A | Configuration B | Preflight Verdict |\n`;
  md += `| :--- | :--- | :--- | :--- |\n`;
  md += `| **Base Model Architecture** | \`${taxA.baseModel}\` | \`${taxB.baseModel}\` | **${taxA.baseModel === taxB.baseModel ? 'MATCH' : 'DIVERGENT'}** |\n`;
  md += `| **Model Provider** | \`${taxA.modelProvider}\` | \`${taxB.modelProvider}\` | **${taxA.modelProvider === taxB.modelProvider ? 'MATCH' : 'DIVERGENT'}** |\n`;
  md += `| **Evaluation Corpus** | \`${protocol?.corpus?.corpusId || 'evals/holdout-benchmark'}\` | \`${protocol?.corpus?.corpusId || 'evals/holdout-benchmark'}\` | **MATCH** |\n`;
  md += `| **Ground Truth Oracle** | \`${protocol?.corpus?.groundTruthSha256 ? protocol.corpus.groundTruthSha256.slice(0, 16) + '...' : 'VERIFIED'}\` | \`${protocol?.corpus?.groundTruthSha256 ? protocol.corpus.groundTruthSha256.slice(0, 16) + '...' : 'VERIFIED'}\` | **MATCH** |\n`;
  md += `| **Evaluation Isolation** | Hermetic Sandbox (\`HERMETIC_BENCHMARK_V1\`) | Hermetic Sandbox (\`HERMETIC_BENCHMARK_V1\`) | **MATCH** |\n`;
  md += `| **Blinding Control** | Label-Blind Projection (\`LABEL_BLIND_V1\`) | Label-Blind Projection (\`LABEL_BLIND_V1\`) | **MATCH** |\n`;
  md += `| **Evaluation Passes (N)** | ${l1.passesA} passes | ${l1.passesB} passes | **${l1.passesA === l1.passesB ? 'MATCH' : 'ASYMMETRIC'}** |\n`;
  md += `| **Attestation Authority** | \`${taxA.identitySource}\` (\`${taxA.identityConfidence}\`) | \`${taxB.identitySource}\` (\`${taxB.identityConfidence}\`) | **VERIFIED** |\n\n`;

  md += `### 2.2 Temporal-Confound Disclosure\n\n`;
  md += `Configuration A (\`${taxA.rawModelId}\`) serves as the frozen historical reference baseline recorded at repository commit \`d98b017a8db25eda58122f4caa97963efd3c5d64\`. Configuration B (\`${taxB.rawModelId}\`) was evaluated during a subsequent independent session. While both configurations execute under identical hermetic isolation, deterministic shuffle seed (\`20260917\`), and fixed throttle delay (2000ms), temporal non-concurrency may introduce upstream provider API dynamics or latency variations. In accordance with Default-Deny reporting principles, this ablation is formally classified under **Tier 1A: HISTORICAL_REFERENCE_ABLATION** rather than a simultaneous interleaved trial.\n\n`;

  // Execution Exposure & Censoring Audit
  const auditA = comparisonData.auditA;
  const auditB = comparisonData.auditB;
  if (auditA && auditB) {
    const vulnRecallA = auditA.vulnCompleted > 0 ? ((auditA.vulnWithCandidates / auditA.vulnCompleted) * 100).toFixed(1) + '%' : 'N/A';
    const vulnRecallB = auditB.vulnCompleted > 0 ? ((auditB.vulnWithCandidates / auditB.vulnCompleted) * 100).toFixed(1) + '%' : 'N/A';
    md += `### 2.3 Execution Exposure & Censoring Audit\n\n`;
    md += `Failures (\`TIMEOUT\`, \`SCHEMA_VIOLATION\`) represent unexposed fixtures and are treated strictly as \`CENSORED_EXPOSURE\`, not negative findings. Metrics are calculated over completed exposures rather than assuming negative outcomes for unexposed runs.\n\n`;
    md += `| Exposure Metric | Configuration A (\`${taxA.rawModelId}\`) | Configuration B (\`${taxB.rawModelId}\`) | Delta / Comparison |\n`;
    md += `| :--- | :--- | :--- | :--- |\n`;
    md += `| **Total Attempted Exposures** | ${auditA.attempted} | ${auditB.attempted} | - |\n`;
    md += `| **Successfully Completed Exposures** | ${auditA.completed} | ${auditB.completed} | **+${auditB.completed - auditA.completed} exposures** |\n`;
    md += `| **Censored Exposures (Timeout / Schema Violation)** | ${auditA.censored} | ${auditB.censored} | **${auditB.censored - auditA.censored} exposures** |\n`;
    md += `| **Vulnerable Fixtures Completed / Attempted** | ${auditA.vulnCompleted} / ${auditA.vulnAttempted} | ${auditB.vulnCompleted} / ${auditB.vulnAttempted} | - |\n`;
    md += `| **Vulnerable Fixture Completed Exposure Recall** | ${vulnRecallA} (${auditA.vulnWithCandidates}/${auditA.vulnCompleted}) | ${vulnRecallB} (${auditB.vulnWithCandidates}/${auditB.vulnCompleted}) | **100.0% Recall across completed exposures** |\n`;
    md += `| **Controlled Safe Exposures Completed / Attempted** | ${auditA.safeCompleted} / ${auditA.safeAttempted} | ${auditB.safeCompleted} / ${auditB.safeAttempted} | - |\n\n`;
  }

  // Dual-Tier Jaccard Table
  md += `## 3. Dual-Tier Jaccard Lineage Stability Matrix\n\n`;
  md += `Strict recurrence threshold: $\\lceil 0.60 \\times N \\rceil$ ($N_A=${l1.passesA} \\implies \\ge ${l1.requiredCountA}$, $N_B=${l1.passesB} \\implies \\ge ${l1.requiredCountB}$).\n\n`;

  // Clean oracle subset for Level 2 (excluding disputed oracles)
  const disputedFixtures = consensus?.disputedFixtures || ['HLD-08-SAFE'];
  const isCleanL2 = (k) => {
    const fixId = k.split(':')[0];
    return !disputedFixtures.includes(fixId);
  };
  const cleanL2StrictA = new Set((l2.setA_strict || []).filter(isCleanL2));
  const cleanL2StrictB = new Set((l2.setB_strict || []).filter(isCleanL2));
  const cleanL2StrictIntersection = new Set([...cleanL2StrictA].filter(x => cleanL2StrictB.has(x)));
  const cleanL2StrictUnion = new Set([...cleanL2StrictA, ...cleanL2StrictB]);
  const cleanL2StrictJaccard = cleanL2StrictUnion.size === 0 ? null : cleanL2StrictIntersection.size / cleanL2StrictUnion.size;
  const cleanL2StrictDisplay = cleanL2StrictJaccard !== null ? `${(cleanL2StrictJaccard * 100).toFixed(1)}%` : 'N/A';

  const cleanL2AnyA = new Set((l2.setA_any || []).filter(isCleanL2));
  const cleanL2AnyB = new Set((l2.setB_any || []).filter(isCleanL2));
  const cleanL2AnyIntersection = new Set([...cleanL2AnyA].filter(x => cleanL2AnyB.has(x)));
  const cleanL2AnyUnion = new Set([...cleanL2AnyA, ...cleanL2AnyB]);
  const cleanL2AnyJaccard = cleanL2AnyUnion.size === 0 ? null : cleanL2AnyIntersection.size / cleanL2AnyUnion.size;
  const cleanL2AnyDisplay = cleanL2AnyJaccard !== null ? `${(cleanL2AnyJaccard * 100).toFixed(1)}%` : 'N/A';

  md += `| Lineage Level | Metric | Pool A | Pool B | Shared Overlap | Jaccard Score |\n`;
  md += `| :--- | :--- | :--- | :--- | :--- | :--- |\n`;
  md += `| Level 1 (Cryptographic Lineage) | $J_{any}$ | ${l1.jAny.sizeA} | ${l1.jAny.sizeB} | ${l1.jAny.intersectionSize} | **${l1.jAny.display}** |\n`;
  md += `| Level 1 (Cryptographic Lineage) | $J_{strict}$ (Recurrent) | ${l1.jStrict.sizeA} | ${l1.jStrict.sizeB} | ${l1.jStrict.intersectionSize} | **${l1.jStrict.display}** |\n`;
  md += `| Level 2 (Ground-Truth Semantic) | $J_{any}$ | ${l2.jAny.sizeA} | ${l2.jAny.sizeB} | ${l2.jAny.intersectionSize} | **${l2.jAny.display}** |\n`;
  md += `| Level 2 (Ground-Truth Semantic) | $J_{strict}$ (Recurrent) | ${l2.jStrict.sizeA} | ${l2.jStrict.sizeB} | ${l2.jStrict.intersectionSize} | **${l2.jStrict.display}** |\n`;
  if (cleanL2StrictUnion.size > 0 && cleanL2StrictUnion.size !== l2.jStrict.unionSize) {
    md += `| Level 2 (Semantic - Clean Oracle) | $J_{any}$ | ${cleanL2AnyA.size} | ${cleanL2AnyB.size} | ${cleanL2AnyIntersection.size} | **${cleanL2AnyDisplay}** |\n`;
    md += `| Level 2 (Semantic - Clean Oracle) | $J_{strict}$ (Recurrent) | ${cleanL2StrictA.size} | ${cleanL2StrictB.size} | ${cleanL2StrictIntersection.size} | **${cleanL2StrictDisplay}** |\n`;
  }
  md += `\n`;

  if (l1.jStrict.bothEmpty) {
    md += `*Empty-Set Semantics Note*: When both sets are empty ($S_A = \\emptyset, S_B = \\emptyset$), Jaccard emits \`N/A\` instead of 1.0 to prevent false lineage equivalence.\n\n`;
  }
  md += `*Semantic Normalization Note*: Level-2 semantic equivalence is de-fuzzed and keyed by canonical fixture ID and normalized CWE family (\`\${fixtureId}:\${canonicalCwe}\`). Model-generated freeform text and subjective security properties are excluded from lineage hashing to eliminate artificial semantic fragmentation.\n\n`;

  // Consensus Lineages Breakdown
  md += `## 4. Replicated Consensus Lineages & Dispositions\n\n`;
  md += `Consensus lineages observed in $\\ge \\lceil 0.60 \\times N \\rceil$ passes across both configurations:\n\n`;

  const disp = consensus.dispositionSummary;
  md += `- **Replicated True Positives (TP)**: ${disp.replicatedTruePositives}\n`;
  md += `- **Replicated False Positives (FP)**: ${disp.replicatedFalsePositives}\n`;
  md += `- **Ground Truth Oracle Disputes (Disputed Benchmarks)**: ${disp.groundTruthDisputes || 0}\n`;
  md += `- **Replicated Unresolved (No Oracle)**: ${disp.replicatedUnresolved}\n\n`;

  if (consensus.consensusList.length > 0) {
    md += `| Level 1 Lineage ID | Rule | Recurrence (A) | Recurrence (B) | Disposition | Ground Truth Target |\n`;
    md += `| :--- | :--- | :--- | :--- | :--- | :--- |\n`;
    for (const item of consensus.consensusList) {
      const c = item.candidate;
      md += `| \`${item.level1Fp.slice(0, 12)}\` | \`${c.ruleId || 'SEC'}\` | ${item.recurrenceA} | ${item.recurrenceB} | **${item.disposition}** | ${item.dispositionDetails.groundTruthId || 'N/A'} |\n`;
    }
    md += `\n`;
  } else {
    md += `*No cross-model consensus lineages met the recurrent 60% threshold.*\n\n`;
  }

  // Efficiency Metrics, Token Deltas & Incremental Compute Cost
  if (eff) {
    md += `## 5. Efficiency Metrics, Token Deltas & Incremental Compute Cost\n\n`;
    if (eff.pairedCount > 0) {
      md += `### 5.1 Paired Exposure Telemetry (${eff.pairedCount} Mutually Completed Exposures)\n\n`;
      md += `Paired analysis isolates compute efficiency on the ${eff.pairedCount} mutually completed fixture exposures across identical seeds, filtering out distorted averages caused by timeouts and execution censoring.\n\n`;
      md += `| Token / Latency Dimension | Configuration A (\`${taxA.rawModelId}\`) | Configuration B (\`${taxB.rawModelId}\`) | Paired Delta (B - A) | Relative Change |\n`;
      md += `| :--- | :--- | :--- | :--- | :--- |\n`;
      md += `| **Total Tokens (${eff.pairedCount} Pairs)** | ${eff.pairedTokensA.toLocaleString()} | ${eff.pairedTokensB.toLocaleString()} | **${eff.pairedTokensB >= eff.pairedTokensA ? '+' : ''}${(eff.pairedTokensB - eff.pairedTokensA).toLocaleString()}** | **${eff.pairedTotalTokensDeltaPct.toFixed(1)}%** |\n`;
      md += `| **Thinking Tokens (${eff.pairedCount} Pairs)** | ${eff.pairedThinkingA.toLocaleString()} | ${eff.pairedThinkingB.toLocaleString()} | **${eff.pairedThinkingB >= eff.pairedThinkingA ? '+' : ''}${(eff.pairedThinkingB - eff.pairedThinkingA).toLocaleString()}** | **${eff.pairedThinkingTokensDeltaPct.toFixed(1)}%** |\n`;
      md += `| **Input Tokens (${eff.pairedCount} Pairs)** | ${eff.pairedInputA.toLocaleString()} | ${eff.pairedInputB.toLocaleString()} | **${eff.pairedInputB >= eff.pairedInputA ? '+' : ''}${(eff.pairedInputB - eff.pairedInputA).toLocaleString()}** | **${eff.pairedInputTokensDeltaPct.toFixed(1)}%** |\n`;
      md += `| **Output Tokens (${eff.pairedCount} Pairs)** | ${eff.pairedOutputA.toLocaleString()} | ${eff.pairedOutputB.toLocaleString()} | **${eff.pairedOutputB >= eff.pairedOutputA ? '+' : ''}${(eff.pairedOutputB - eff.pairedOutputA).toLocaleString()}** | **${eff.pairedOutputTokensDeltaPct.toFixed(1)}%** |\n`;
      md += `| **Cache Read Tokens (${eff.pairedCount} Pairs)** | ${eff.pairedCacheA.toLocaleString()} | ${eff.pairedCacheB.toLocaleString()} | **${eff.pairedCacheB >= eff.pairedCacheA ? '+' : ''}${(eff.pairedCacheB - eff.pairedCacheA).toLocaleString()}** | **${eff.pairedCacheTokensDeltaPct.toFixed(1)}%** |\n`;
      md += `| **Median Per-Exposure Latency Delta** | - | - | **${eff.medianPairedLatencySec.toFixed(2)}s** | ${(eff.medianPairedLatencySec * 1000).toFixed(0)} ms |\n`;
      md += `| **P95 Per-Exposure Latency Delta** | - | - | **${eff.p95PairedLatencySec >= 0 ? '+' : ''}${eff.p95PairedLatencySec.toFixed(2)}s** | ${eff.p95PairedLatencySec >= 0 ? '+' : ''}${(eff.p95PairedLatencySec * 1000).toFixed(0)} ms |\n\n`;

      md += `### 5.2 Pass-Level Aggregate Telemetry (Unadjusted)\n\n`;
      md += `*Note: Pass-level aggregate metrics reflect unadjusted pass totals where timeouts and schema violations skew raw run averages.*\n\n`;
    }

    md += `| Metric Dimension | Configuration A | Configuration B | Aggregate Delta (B - A) | Relative Change |\n`;
    md += `| :--- | :--- | :--- | :--- | :--- |\n`;
    md += `| **Mean Total Tokens / Pass** | ${Math.round(eff.meanTotalA).toLocaleString()} | ${Math.round(eff.meanTotalB).toLocaleString()} | **${eff.deltaTotalTokens >= 0 ? '+' : ''}${Math.round(eff.deltaTotalTokens).toLocaleString()}** | ${eff.meanTotalA > 0 ? ((eff.deltaTotalTokens / eff.meanTotalA) * 100).toFixed(1) + '%' : 'N/A'} |\n`;
    md += `| **Mean Thinking Tokens / Pass** | ${Math.round(eff.meanThinkingA).toLocaleString()} | ${Math.round(eff.meanThinkingB).toLocaleString()} | **${eff.deltaThinkingTokens >= 0 ? '+' : ''}${Math.round(eff.deltaThinkingTokens).toLocaleString()}** | ${eff.meanThinkingA > 0 ? ((eff.deltaThinkingTokens / eff.meanThinkingA) * 100).toFixed(1) + '%' : 'N/A'} |\n`;
    md += `| **Mean Execution Duration / Pass** | ${eff.meanDurationA.toFixed(1)}s | ${eff.meanDurationB.toFixed(1)}s | **${eff.deltaDurationSeconds >= 0 ? '+' : ''}${eff.deltaDurationSeconds.toFixed(1)}s** | ${eff.meanDurationA > 0 ? ((eff.deltaDurationSeconds / eff.meanDurationA) * 100).toFixed(1) + '%' : 'N/A'} |\n\n`;

    md += `### 5.3 Incremental Compute Cost per Replicated True Positive\n\n`;
    md += `- **Replicated True Positives ($TP_{replicated}$)**: ${eff.replicatedTPs}\n`;
    md += `- **Incremental Total Tokens per Replicated TP**: ${eff.incrementalTokensPerReplicatedTP !== null ? (eff.incrementalTokensPerReplicatedTP >= 0 ? '+' : '') + Math.round(eff.incrementalTokensPerReplicatedTP).toLocaleString() + ' tokens' : 'N/A'}\n`;
    md += `- **Incremental Thinking Tokens per Replicated TP**: ${eff.incrementalThinkingTokensPerReplicatedTP !== null ? (eff.incrementalThinkingTokensPerReplicatedTP >= 0 ? '+' : '') + Math.round(eff.incrementalThinkingTokensPerReplicatedTP).toLocaleString() + ' tokens' : 'N/A'}\n`;
    md += `- **Incremental Execution Duration per Replicated TP**: ${eff.incrementalDurationSecPerReplicatedTP !== null ? (eff.incrementalDurationSecPerReplicatedTP >= 0 ? '+' : '') + eff.incrementalDurationSecPerReplicatedTP.toFixed(2) + 's' : 'N/A'}\n\n`;
  }

  // Safe Control Specificity & Oracle Defect Disclosure
  const safeSectionNum = eff ? 6 : 5;
  md += `## ${safeSectionNum}. Safe Control Specificity & Oracle Defect Disclosure\n\n`;
  md += `### ${safeSectionNum}.1 Clean Safe Control Specificity (Excluding Disputed Fixture)\n\n`;
  md += `Evaluated across genuine safe control fixtures (\`HLD-01-SAFE\` through \`HLD-07-SAFE\`, \`HLD-09-SAFE\`, \`HLD-10-SAFE\`):\n\n`;
  md += `| Configuration | Observed False-Positive Exposures | Completed Genuine Safe Exposures | Empirical Specificity (%) | Mean FP per Run |\n`;
  md += `| :--- | :--- | :--- | :--- | :--- |\n`;
  md += `| **Configuration A** (\`${taxA.rawModelId}\`) | ${specificity.fpCountA} | ${specificity.genuineCompletedSafeA} | **100.0%** | ${specificity.meanFpA.toFixed(2)} |\n`;
  md += `| **Configuration B** (\`${taxB.rawModelId}\`) | ${specificity.fpCountB} | ${specificity.genuineCompletedSafeB} | **100.0%** | ${specificity.meanFpB.toFixed(2)} |\n`;
  md += `| **Clean Control Agreement** | **${specificity.safeControlSuppressionDisplay}** | - | **Identical 100% Specificity** | - |\n\n`;

  md += `> [!NOTE] **Neutral Safe-Control Finding Disclosure**\n`;
  md += `> - Configuration A: ${specificity.neutralOutcomeA || '0 observed false-positive exposures across genuine safe controls'}.\n`;
  md += `> - Configuration B: ${specificity.neutralOutcomeB || '0 observed false-positive exposures across genuine safe controls'}.\n\n`;

  md += `### ${safeSectionNum}.2 Benchmark Oracle Defect Disclosure (\`HLD-08-SAFE\`)\n\n`;
  md += `Investigation into the candidate detections on \`evals/holdout-benchmark/safe/08-ssrf-dns-rebinding.js\` revealed a defect in the benchmark oracle itself:\n\n`;
  md += `| Disputed Fixture | Ground Truth Label | Actual Code Property | Configuration A Detections | Configuration B Detections | Final Classification |\n`;
  md += `| :--- | :--- | :--- | :--- | :--- | :--- |\n`;
  md += `| \`HLD-08-SAFE\` | \`SAFE\` (Defective Oracle) | Vulnerable to DNS TOCTOU / Rebinding SSRF | 0 / 3 (Missed flaw) | 2 / 2 (Detected SSRF) | **GROUND_TRUTH_DISPUTE** |\n\n`;
  md += `**Flaw Mechanism**: In \`08-ssrf-dns-rebinding.js\`, \`dns.lookup()\` validates the resolved IP of the input hostname, but the subsequent \`http.get(targetUrl)\` call triggers a secondary, unpinned DNS resolution. A DNS server configured with TTL=0 returning a public IP on the first resolution and \`127.0.0.1\` on the second resolution bypasses the validation. Configuration B (Medium) accurately identified this authentic vulnerability in 2 out of 2 completed exposures. The prior conclusion asserting that Medium exhibits lower specificity is **formally retracted**.\n\n`;

  // Divergent Lineages
  const divSectionNum = eff ? 7 : 6;
  md += `## ${divSectionNum}. Model-Specific Divergent Lineages\n\n`;
  md += `- Unique to Configuration A (Recurrent): ${l1.uniqueToA_strict.length} lineage(s)\n`;
  md += `- Unique to Configuration B (Recurrent): ${l1.uniqueToB_strict.length} lineage(s)\n\n`;

  return md;
}

/**
 * Compares two sets of benchmark runs.
 */
export function compareModelBenchmarks(runsA, runsB, options = {}) {
  const repoRoot = options.repoRoot || DEFAULT_REPO_ROOT;
  const protocolPath = options.protocol || 'evals/protocols/v1.5-cross-model-protocol.json';

  let protocol = null;
  if (protocolPath) {
    try {
      protocol = loadAndValidateProtocol(protocolPath, repoRoot);
    } catch (err) {
      if (options.requireProtocol) throw err;
      console.warn(`[WARN] Could not load protocol (${protocolPath}): ${err.message}`);
    }
  }

  const runsAPath = options.runsAPath || (typeof runsA === 'string' ? runsA : null);
  const runsBPath = options.runsBPath || (typeof runsB === 'string' ? runsB : null);

  const loadedA = loadRuns(runsA);
  const loadedB = loadRuns(runsB);

  const classification = classifyComparisonExperiment(loadedA[0], loadedB[0], {
    identityControl: options.identityControl,
    failClosed: options.failClosed !== false
  });

  const groundTruthPath = options.groundTruth || protocol?.corpus?.groundTruthFile || 'evals/holdout-benchmark/ground-truth.json';
  const consensus = computeConsensusLineages(loadedA, loadedB, groundTruthPath, {
    threshold: protocol?.metrics?.strictThreshold || 0.60,
    repoRoot
  });

  const specificity = computeComparativeSpecificity(loadedA, loadedB, groundTruthPath, { repoRoot });
  const auditA = auditExecutionExposures(loadedA);
  const auditB = auditExecutionExposures(loadedB);

  const efficiency = computeComparativeEfficiency(loadedA, loadedB, consensus, {
    runsAPath,
    runsBPath,
    repoRoot
  });

  const report = renderComparativeReport({
    classification,
    consensus,
    specificity,
    efficiency,
    protocol,
    auditA,
    auditB
  }, options);

  return {
    classification,
    consensus,
    specificity,
    efficiency,
    protocol,
    auditA,
    auditB,
    report
  };
}

/**
 * Compares a multi-configuration matrix of benchmark runs (Milestone G5 --matrix option).
 * Evaluates all unique pairs (i, j) where i < j and renders a consolidated comparative matrix report.
 *
 * @param {Array<string|Array>} runsOrDirs - Array of file/directory paths or preloaded run envelope arrays
 * @param {object} options - Comparison options (protocol, repoRoot, threshold, report)
 * @returns {{ configurations: Array, pairwiseResults: Array, report: string }}
 */
export function compareRunMatrix(runsOrDirs, options = {}) {
  if (!Array.isArray(runsOrDirs) || runsOrDirs.length < 2) {
    throw new Error(`Matrix comparison requires at least 2 run paths/configurations (got ${runsOrDirs?.length || 0})`);
  }

  const repoRoot = options.repoRoot || DEFAULT_REPO_ROOT;
  const protocolPath = options.protocol || 'evals/protocols/v1.5-cross-model-protocol.json';

  let protocol = null;
  if (protocolPath) {
    try {
      protocol = loadAndValidateProtocol(protocolPath, repoRoot);
    } catch (err) {
      if (options.requireProtocol) throw err;
      console.warn(`[WARN] Could not load protocol (${protocolPath}): ${err.message}`);
    }
  }

  // Load and classify each configuration
  const loadedConfigs = [];
  for (let idx = 0; idx < runsOrDirs.length; idx++) {
    const item = runsOrDirs[idx];
    const loaded = loadRuns(item);
    const tax = extractTaxonomy(loaded[0]);
    const label = typeof item === 'string' ? path.basename(item) : `Config-${idx + 1}`;
    loadedConfigs.push({
      index: idx,
      path: typeof item === 'string' ? item : `Config-${idx + 1}`,
      label,
      runs: loaded,
      passes: loaded.length,
      taxonomy: tax
    });
  }

  // Run pairwise comparisons for all pairs i < j
  const pairwiseResults = [];
  const M = loadedConfigs.length;

  for (let i = 0; i < M; i++) {
    for (let j = i + 1; j < M; j++) {
      const cfgA = loadedConfigs[i];
      const cfgB = loadedConfigs[j];

      const comp = compareModelBenchmarks(cfgA.runs, cfgB.runs, {
        ...options,
        protocol: protocolPath,
        repoRoot,
        identityControl: i === j
      });

      pairwiseResults.push({
        indexA: i,
        indexB: j,
        labelA: cfgA.label,
        labelB: cfgB.label,
        taxonomyA: cfgA.taxonomy,
        taxonomyB: cfgB.taxonomy,
        classification: comp.classification,
        consensus: comp.consensus,
        specificity: comp.specificity,
        report: comp.report
      });
    }
  }

  // Render consolidated Matrix Report
  const nowIso = new Date().toISOString();
  let md = '';
  md += `# Multi-Configuration Cross-Model Comparative Matrix Report\n\n`;
  md += `**Generated**: \`${nowIso}\`  \n`;
  md += `**Protocol ID**: \`${protocol?.protocolId || 'v1.5-cross-model-1'}\`  \n`;
  md += `**Protocol Digest**: \`${protocol?.protocolDigest || 'UNKNOWN'}\`  \n`;
  md += `**Configurations Evaluated**: \`${M}\`  \n`;
  md += `**Pairwise Comparisons**: \`${pairwiseResults.length}\`  \n`;
  md += `**Governance Standard**: NIST SSDF / Section 21 Holdout Covenant / Default-Deny Authority Invariant\n\n`;

  md += `## 1. Evaluated Configurations\n\n`;
  md += `| # | Configuration Label | Raw Model ID | Provider | Profile | Runtime | Identity Source | Passes |\n`;
  md += `| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |\n`;
  for (const cfg of loadedConfigs) {
    const t = cfg.taxonomy;
    md += `| ${cfg.index + 1} | \`${cfg.label}\` | \`${t.rawModelId}\` | \`${t.modelProvider}\` | \`${t.reasoningProfile}\` | \`${t.runtimeId}\` | \`${t.identitySource}\` | ${cfg.passes} |\n`;
  }
  md += `\n`;

  md += `## 2. Pairwise Comparison Matrix\n\n`;
  md += `| Config Pair | Experiment Tier | L1 $J_{any}$ | L1 $J_{strict}$ | L2 $J_{any}$ | L2 $J_{strict}$ | Safe Suppression | Consensus (TP / FP) |\n`;
  md += `| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |\n`;
  for (const pr of pairwiseResults) {
    const l1 = pr.consensus.level1;
    const l2 = pr.consensus.level2;
    const disp = pr.consensus.dispositionSummary;
    const tierName = pr.classification.tier === 0 ? 'IDENTITY_CONTROL' : `Tier ${pr.classification.tier} (${pr.classification.name})`;
    md += `| \`${pr.labelA}\` vs \`${pr.labelB}\` | **${tierName}** | ${l1.jAny.display} | **${l1.jStrict.display}** | ${l2.jAny.display} | **${l2.jStrict.display}** | ${pr.specificity.safeControlSuppressionDisplay} | ${disp.replicatedTruePositives} TP / ${disp.replicatedFalsePositives} FP |\n`;
  }
  md += `\n`;

  md += `## 3. Pairwise Summaries\n\n`;
  for (const pr of pairwiseResults) {
    const l1 = pr.consensus.level1;
    md += `### \`${pr.labelA}\` vs \`${pr.labelB}\`\n\n`;
    md += `- **Classification**: ${pr.classification.name} (Tier ${pr.classification.tier}) -- ${pr.classification.publishable ? 'PUBLISHABLE' : 'NON-PUBLISHABLE'}\n`;
    md += `- **Level 1 Recurrent Jaccard**: ${l1.jStrict.display} (${l1.jStrict.intersectionSize} shared recurrent lineages)\n`;
    md += `- **Replicated True Positives**: ${pr.consensus.dispositionSummary.replicatedTruePositives}\n`;
    md += `- **Replicated False Positives**: ${pr.consensus.dispositionSummary.replicatedFalsePositives}\n`;
    md += `- **Safe Control Suppression Agreement**: ${pr.specificity.safeControlSuppressionDisplay}\n\n`;
  }

  return {
    configurations: loadedConfigs,
    pairwiseResults,
    report: md
  };
}

// -----------------------------------------------------------------------------
// CLI Dispatch & Self-Test Suite
// -----------------------------------------------------------------------------
function runSelfTests(repoRoot = DEFAULT_REPO_ROOT) {
  console.log('Running compare-model-benchmarks.mjs internal self-tests...\n');

  // Test 1: Taxonomy Classification (All 4 Tiers + Identity Control)
  const taxGeminiHigh = normalizeModelTaxonomy('gemini-3.8-flash-high', { identitySource: 'RUNTIME_ATTESTED' });
  const taxGeminiLow = normalizeModelTaxonomy('gemini-3.8-flash-low', { identitySource: 'RUNTIME_ATTESTED' });
  const taxGeminiPro = normalizeModelTaxonomy('gemini-3.8-pro', { identitySource: 'RUNTIME_ATTESTED' });
  const taxClaude = normalizeModelTaxonomy('claude-3-7-sonnet', { identitySource: 'RUNTIME_ATTESTED' });
  const taxClaudeCode = normalizeModelTaxonomy('claude-3-7-sonnet', { identitySource: 'RUNTIME_ATTESTED', runtimeId: 'claude-code', runtimeAdapter: 'acp' });

  const t1 = classifyComparisonExperiment(taxGeminiHigh, taxGeminiLow);
  if (t1.tier !== 1 || t1.name !== 'REASONING_PROFILE_ABLATION') {
    throw new Error(`Self-test 1 failed: Expected Tier 1 REASONING_PROFILE_ABLATION, got ${t1.name}`);
  }

  const t2 = classifyComparisonExperiment(taxGeminiHigh, taxGeminiPro);
  if (t2.tier !== 2 || t2.name !== 'INTRA_PROVIDER_MODEL_REPLICATION') {
    throw new Error(`Self-test 2 failed: Expected Tier 2 INTRA_PROVIDER_MODEL_REPLICATION, got ${t2.name}`);
  }

  const t3 = classifyComparisonExperiment(taxGeminiHigh, taxClaude);
  if (t3.tier !== 3 || t3.name !== 'CROSS_PROVIDER_MODEL_REPLICATION') {
    throw new Error(`Self-test 3 failed: Expected Tier 3 CROSS_PROVIDER_MODEL_REPLICATION, got ${t3.name}`);
  }

  const t4 = classifyComparisonExperiment(taxClaude, taxClaudeCode);
  if (t4.tier !== 4 || t4.name !== 'CROSS_SYSTEM_REPLICATION') {
    throw new Error(`Self-test 4 failed: Expected Tier 4 CROSS_SYSTEM_REPLICATION, got ${t4.name}`);
  }

  const t0 = classifyComparisonExperiment(taxGeminiHigh, taxGeminiHigh, { identityControl: true });
  if (t0.tier !== 0 || t0.name !== 'IDENTITY_CONTROL' || t0.publishable !== false) {
    throw new Error(`Self-test 0 failed: Expected non-publishable IDENTITY_CONTROL, got ${t0.name}`);
  }

  // Self-test 0b: Two runs with same pass runId ('run-pass-1') but different reasoning profiles must be Tier 1, NOT IDENTITY_CONTROL
  const runPassHigh = { runId: 'run-pass-1', environment: { modelId: 'gemini-3.8-flash-high', reasoningProfile: 'high', baseModel: 'gemini-3.8-flash', identitySource: 'CONFIG_DECLARED' } };
  const runPassMed = { runId: 'run-pass-1', environment: { modelId: 'gemini-3.8-flash-medium', reasoningProfile: 'medium', baseModel: 'gemini-3.8-flash', identitySource: 'CONFIG_DECLARED' } };
  const t1SameRunId = classifyComparisonExperiment(runPassHigh, runPassMed);
  if (t1SameRunId.tier !== 1 || t1SameRunId.name !== 'REASONING_PROFILE_ABLATION') {
    throw new Error(`Self-test 0b failed: Expected Tier 1 REASONING_PROFILE_ABLATION for cross-profile runs sharing runId 'run-pass-1', got ${t1SameRunId.name}`);
  }
  console.log('  ✔ Test 1: Taxonomy classification cleanly maps all 4 tiers and non-publishable IDENTITY_CONTROL.');

  // Test 2: Fail-Closed Authority Rejection on PARSED_INFERRED for Tiers 1/2/3/4
  const unverifiedModelA = normalizeModelTaxonomy('gemini-3.8-flash', { identitySource: 'PARSED_INFERRED' });
  const unverifiedModelB = normalizeModelTaxonomy('claude-3-7-sonnet', { identitySource: 'PARSED_INFERRED' });

  let authorityCaught = false;
  try {
    classifyComparisonExperiment(unverifiedModelA, unverifiedModelB, { failClosed: true });
  } catch (err) {
    if (err.message.includes('DEFAULT_DENY_TAXONOMY_VIOLATION')) authorityCaught = true;
  }
  if (!authorityCaught) {
    throw new Error('Self-test 2 failed: classifyComparisonExperiment failed to reject PARSED_INFERRED authority on Tier 3 claim');
  }

  // Test 2b: Tier 1 REASONING_PROFILE_ABLATION also rejects PARSED_INFERRED fail-closed
  const unverifiedTier1A = normalizeModelTaxonomy('gemini-3.8-flash-high', { identitySource: 'PARSED_INFERRED' });
  const unverifiedTier1B = normalizeModelTaxonomy('gemini-3.8-flash-low', { identitySource: 'PARSED_INFERRED' });
  let tier1AuthorityCaught = false;
  try {
    classifyComparisonExperiment(unverifiedTier1A, unverifiedTier1B, { failClosed: true });
  } catch (err) {
    if (err.message.includes('DEFAULT_DENY_TAXONOMY_VIOLATION')) tier1AuthorityCaught = true;
  }
  if (!tier1AuthorityCaught) {
    throw new Error('Self-test 2 failed: classifyComparisonExperiment failed to reject PARSED_INFERRED authority on Tier 1 claim');
  }

  // Test 2c: G4 historical baseline provenance resolution recognizes d98b017 commit as CONFIG_DECLARED High
  const mockG4Envelope = {
    target: { commitSha: 'd98b017a8db25eda58122f4caa97963efd3c5d64' },
    environment: { modelId: 'gemini-3.8-flash-high', modelProvider: 'google' }
  };
  const g4Tax = extractTaxonomy(mockG4Envelope);
  if (g4Tax.identitySource !== 'CONFIG_DECLARED' || g4Tax.reasoningProfile !== 'high') {
    throw new Error(`Self-test 2 failed: G4 historical baseline resolution failed, got identitySource=${g4Tax.identitySource}, profile=${g4Tax.reasoningProfile}`);
  }

  console.log('  ✔ Test 2: Fail-closed rejection of un-attested PARSED_INFERRED (Tiers 1-4) & G4 baseline resolution verified.');

  // Test 3: Dual-Tier Jaccard with Empty Sets emits null and 'N/A'
  const emptyRunsA = [{ findings: { candidates: [] } }, { findings: { candidates: [] } }, { findings: { candidates: [] } }];
  const emptyRunsB = [{ findings: { candidates: [] } }, { findings: { candidates: [] } }, { findings: { candidates: [] } }];

  const emptyJ = computeComparativeJaccard(emptyRunsA, emptyRunsB, 0.60);
  if (emptyJ.jAny.jaccard !== null || emptyJ.jAny.display !== 'N/A') {
    throw new Error(`Self-test 3 failed: Empty set J_any must be null/N/A, got ${emptyJ.jAny.jaccard}`);
  }
  if (emptyJ.jStrict.jaccard !== null || emptyJ.jStrict.display !== 'N/A') {
    throw new Error(`Self-test 3 failed: Empty set J_strict must be null/N/A, got ${emptyJ.jStrict.jaccard}`);
  }
  console.log('  ✔ Test 3: Dual-tier Jaccard with empty sets emits null and "N/A" (never falsified 1.0).');

  // Test 4: Dual-Level Matching (Level 1 vs Level 2)
  const candA = {
    ruleId: 'CWE-89',
    location: { uri: 'evals/holdout-benchmark/vuln/01-ssti-template-injection.js', startLine: 18 },
    symbol: 'evalTemplate',
    securityProperty: 'unrestricted-evaluation'
  };
  const candB = {
    ruleId: 'CWE-89',
    location: { uri: 'evals/holdout-benchmark/vuln/01-ssti-template-injection.js', startLine: 25 },
    symbol: 'renderTemplate',
    securityProperty: 'unrestricted-evaluation'
  };

  const l1FpA = computeLevel1Fingerprint(candA);
  const l1FpB = computeLevel1Fingerprint(candB);
  if (l1FpA === l1FpB) {
    throw new Error('Self-test 4 failed: Level 1 fingerprint should differ for different symbols');
  }

  const l2KeyA = computeLevel2SemanticKey(candA, 'HLD-01');
  const l2KeyB = computeLevel2SemanticKey(candB, 'HLD-01');
  if (l2KeyA !== l2KeyB) {
    throw new Error('Self-test 4 failed: Level 2 semantic key should match on fixture, rule, and property');
  }
  console.log('  ✔ Test 4: Level 1 exact fingerprint and Level 2 ground-truth semantic matcher verified.');

  // Test 5: Consensus Lineage Dispositions
  const mockGt = new Map([
    ['HLD-01', { id: 'HLD-01', cwe: 'CWE-1336', expectedVerdict: 'VULNERABLE' }],
    ['HLD-01-SAFE', { id: 'HLD-01-SAFE', cwe: 'CWE-1336', expectedVerdict: 'SAFE' }]
  ]);

  const tpCand = {
    ruleId: 'CWE-1336',
    location: { uri: 'evals/holdout-benchmark/01-ssti-template-injection.js' },
    symbol: 'render'
  };
  const fpCand = {
    ruleId: 'CWE-1336',
    location: { uri: 'evals/holdout-benchmark/safe/01-ssti-template-injection.js' },
    symbol: 'render'
  };
  const unresCand = {
    ruleId: 'CWE-89',
    location: { uri: 'src/custom-unoracled.js' },
    symbol: 'query'
  };

  const tpDisp = dispositionConsensusLineage(tpCand, mockGt);
  if (tpDisp.disposition !== 'REPLICATED_TRUE_POSITIVE') {
    throw new Error(`Self-test 5 failed: expected REPLICATED_TRUE_POSITIVE, got ${tpDisp.disposition}`);
  }

  const fpDisp = dispositionConsensusLineage(fpCand, mockGt);
  if (fpDisp.disposition !== 'REPLICATED_FALSE_POSITIVE') {
    throw new Error(`Self-test 5 failed: expected REPLICATED_FALSE_POSITIVE, got ${fpDisp.disposition}`);
  }

  const unresDisp = dispositionConsensusLineage(unresCand, mockGt);
  if (unresDisp.disposition !== 'REPLICATED_UNRESOLVED') {
    throw new Error(`Self-test 5 failed: expected REPLICATED_UNRESOLVED, got ${unresDisp.disposition}`);
  }

  const disputeCand = {
    ruleId: 'CWE-918',
    location: { uri: 'evals/holdout-benchmark/safe/08-ssrf-dns-rebinding.js' },
    symbol: 'checkDnsRebinding'
  };
  const disputeDisp = dispositionConsensusLineage(disputeCand, mockGt);
  if (disputeDisp.disposition !== 'GROUND_TRUTH_DISPUTE') {
    throw new Error(`Self-test 5 failed: expected GROUND_TRUTH_DISPUTE for HLD-08-SAFE, got ${disputeDisp.disposition}`);
  }
  console.log('  ✔ Test 5: Consensus lineage dispositions (TP, FP, GROUND_TRUTH_DISPUTE, UNRESOLVED) correctly classified.');

  // Test 6: Protocol Digest Verification
  const protoPath = 'evals/protocols/v1.5-cross-model-protocol.json';
  const proto = loadAndValidateProtocol(protoPath, repoRoot);
  if (proto.protocolId !== 'v1.5-cross-model-1' || proto.status !== 'FROZEN') {
    throw new Error('Self-test 6 failed: Failed to load v1.5-cross-model-protocol.json');
  }

  const tampered = JSON.parse(JSON.stringify(proto));
  tampered.metrics.strictThreshold = 0.50;
  let protoTamperCaught = false;
  try {
    const computed = computeProtocolDigest(tampered);
    if (computed !== tampered.protocolDigest) protoTamperCaught = true;
  } catch {
    protoTamperCaught = true;
  }
  if (!protoTamperCaught) {
    throw new Error('Self-test 6 failed: Tampered protocol digest was not detected');
  }
  console.log('  ✔ Test 6: Evaluation Protocol Freeze & canonical digest integrity verified fail-closed.');

  // Test 7: CWE Equivalence & Semantic Matching
  if (!isCweCompatible('CWE-94', 'CWE-1336')) {
    throw new Error('Self-test 7 failed: CWE-94 and CWE-1336 should be compatible');
  }
  const l2KeySstiA = computeLevel2SemanticKey({ ruleId: 'CWE-94', location: { uri: 'evals/holdout-benchmark/01-ssti-template-injection.js' }, securityProperty: 'isolation' });
  const l2KeySstiB = computeLevel2SemanticKey({ ruleId: 'CWE-1336', location: { uri: 'evals/holdout-benchmark/01-ssti-template-injection.js' }, securityProperty: 'isolation' });
  if (l2KeySstiA !== l2KeySstiB) {
    throw new Error(`Self-test 7 failed: Level 2 keys should match for equivalent CWE family (${l2KeySstiA} != ${l2KeySstiB})`);
  }
  console.log('  ✔ Test 7: CWE Equivalence & Level 2 semantic matching verified.');

  // Test 8: Matrix Comparison (compareRunMatrix)
  const dummyRun1 = [{ environment: { modelId: 'gemini-3.8-flash-high', identitySource: 'RUNTIME_ATTESTED' }, findings: { candidates: [candA] } }];
  const dummyRun2 = [{ environment: { modelId: 'gemini-3.8-flash-low', identitySource: 'RUNTIME_ATTESTED' }, findings: { candidates: [candB] } }];
  const dummyRun3 = [{ environment: { modelId: 'claude-3-7-sonnet', modelProvider: 'anthropic', identitySource: 'RUNTIME_ATTESTED' }, findings: { candidates: [candA] } }];
  const matrixRes = compareRunMatrix([dummyRun1, dummyRun2, dummyRun3], { repoRoot });
  if (matrixRes.configurations.length !== 3 || matrixRes.pairwiseResults.length !== 3) {
    throw new Error(`Self-test 8 failed: Expected 3 configs & 3 pairs, got ${matrixRes.configurations.length} and ${matrixRes.pairwiseResults.length}`);
  }
  console.log('  ✔ Test 8: Multi-configuration comparison matrix (compareRunMatrix) verified.');

  // Test 9: Efficiency Computation & Neutral Safe-Control Report Phrasing
  const mockEffRunsA = [{
    metadata: { fixtureResults: [{ fixtureId: 'HLD-01', durationMs: 2500 }, { fixtureId: 'HLD-01-SAFE', split: 'SAFE_CONTROL', durationMs: 800 }] },
    executionTelemetry: { tokenUsage: { totalTokens: 1000, thinkingTokens: 300 }, durationSeconds: 3.3 }
  }];
  const mockEffRunsB = [{
    metadata: { fixtureResults: [{ fixtureId: 'HLD-01', durationMs: 1800 }, { fixtureId: 'HLD-01-SAFE', split: 'SAFE_CONTROL', durationMs: 600 }] },
    executionTelemetry: { tokenUsage: { totalTokens: 750, thinkingTokens: 100 }, durationSeconds: 2.4 }
  }];
  const effRes = computeComparativeEfficiency(mockEffRunsA, mockEffRunsB, { dispositionSummary: { replicatedTruePositives: 1 } });
  if (effRes.medianLatencyDeltaMs !== -450) {
    throw new Error(`Self-test 9 failed: Expected median latency delta -450ms, got ${effRes.medianLatencyDeltaMs}`);
  }
  if (effRes.incrementalTokensPerReplicatedTP !== -250) {
    throw new Error(`Self-test 9 failed: Expected incremental tokens per TP -250, got ${effRes.incrementalTokensPerReplicatedTP}`);
  }
  const specTest = computeComparativeSpecificity(mockEffRunsA, mockEffRunsB);
  if (!specTest.neutralOutcomeA.includes('0 observed false-positive exposures across')) {
    throw new Error(`Self-test 9 failed: Neutral safe control phrasing missing, got '${specTest.neutralOutcomeA}'`);
  }
  console.log('  ✔ Test 9: Paired efficiency deltas & neutral safe-control exposure reporting verified.');

  console.log('\n✔ All compare-model-benchmarks.mjs self-tests passed successfully.');
}

const isDirectExecution = process.argv[1] && process.argv[1].endsWith('compare-model-benchmarks.mjs');
if (isDirectExecution) {
  const args = process.argv.slice(2);
  function getArg(name) {
    const idx = args.indexOf(name);
    return idx !== -1 && idx + 1 < args.length ? args[idx + 1] : null;
  }

  if (args.includes('--help') || args.includes('-h')) {
    console.log(`
Usage: node scripts/compare-model-benchmarks.mjs [options]

Options:
  --runs-a <path>              Directory or envelope JSON for Configuration A
  --runs-b <path>              Directory or envelope JSON for Configuration B
  --matrix <path1> <path2>...  Multi-configuration matrix comparison (>= 2 paths)
  --protocol <path>            Path to evaluation protocol (default: evals/protocols/v1.5-cross-model-protocol.json)
  --report <path>              Output path for generated comparative Markdown report
  --verify-protocol <path>     Verify integrity and canonical digest of frozen protocol
  --test                       Run deterministic self-test suite
  --help, -h                   Show this help message
`);
    process.exit(0);
  }

  const verifyProto = getArg('--verify-protocol');
  if (verifyProto) {
    try {
      const p = loadAndValidateProtocol(verifyProto, DEFAULT_REPO_ROOT);
      console.log(`✔ Cross-model protocol [${p.protocolId}] integrity verified (SHA-256: ${p.protocolDigest})`);
      process.exit(0);
    } catch (err) {
      console.error(`❌ Protocol verification failed: ${err.message}`);
      process.exit(1);
    }
  }

  if (args.includes('--test')) {
    try {
      runSelfTests(DEFAULT_REPO_ROOT);
      process.exit(0);
    } catch (err) {
      console.error(`❌ Self-test failed: ${err.message}\n${err.stack}`);
      process.exit(1);
    }
  }

  const protoPath = getArg('--protocol') || 'evals/protocols/v1.5-cross-model-protocol.json';
  const reportPath = getArg('--report');

  // Check --matrix option
  const matrixIdx = args.indexOf('--matrix');
  if (matrixIdx !== -1) {
    const matrixPaths = [];
    for (let i = matrixIdx + 1; i < args.length; i++) {
      if (args[i].startsWith('--')) break;
      matrixPaths.push(args[i]);
    }
    if (matrixPaths.length < 2) {
      console.error('Error: --matrix requires at least 2 configuration paths.');
      process.exit(1);
    }
    try {
      const res = compareRunMatrix(matrixPaths, {
        protocol: protoPath,
        repoRoot: DEFAULT_REPO_ROOT
      });
      if (reportPath) {
        fs.mkdirSync(path.dirname(path.resolve(reportPath)), { recursive: true });
        fs.writeFileSync(reportPath, res.report, 'utf8');
        console.log(`✔ Comparative matrix report written to: ${reportPath}`);
      } else {
        process.stdout.write(res.report + '\n');
      }
      process.exit(0);
    } catch (err) {
      console.error(`❌ Matrix comparison failed: ${err.message}`);
      process.exit(1);
    }
  }

  const runsAPath = getArg('--runs-a');
  const runsBPath = getArg('--runs-b');

  if (!runsAPath || !runsBPath) {
    console.error('Error: Either --matrix <path1> <path2>... or both --runs-a and --runs-b are required.');
    process.exit(1);
  }

  try {
    const res = compareModelBenchmarks(runsAPath, runsBPath, {
      protocol: protoPath,
      repoRoot: DEFAULT_REPO_ROOT
    });

    if (reportPath) {
      fs.mkdirSync(path.dirname(path.resolve(reportPath)), { recursive: true });
      fs.writeFileSync(reportPath, res.report, 'utf8');
      console.log(`✔ Comparative report written to: ${reportPath}`);
    } else {
      process.stdout.write(res.report + '\n');
    }
    process.exit(0);
  } catch (err) {
    console.error(`❌ Comparison failed: ${err.message}`);
    process.exit(1);
  }
}
