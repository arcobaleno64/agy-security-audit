#!/usr/bin/env node
/**
 * scripts/adapters/cloudflare-adapter.mjs
 * Standalone, zero-dependency Finding Producer Adapter for Cloudflare `security-audit-skill`.
 *
 * Provides lossless, deterministic unidirectional ingestion of Cloudflare `findings.json`
 * and `coverage-ledger.json` into AGY's canonical evidence model under Default-Deny.
 *
 * Requirements:
 * - R1: Lossless Canonical Finding Translation (confirmed -> REPORTABLE/CONFIRMED/AFFIRMATIVELY_VERIFIED,
 *       needs_validation -> DEFERRED/NEEDS_MANUAL_REVIEW/EVIDENCE_INCOMPLETE with severity UNRATED,
 *       rejected -> SUPPRESSED/FALSE_POSITIVE/AFFIRMATIVELY_REFUTED,
 *       unadulterated metadata preserved in extensions.cloudflare).
 * - R2: Coverage Ledger Ingestion & Quarantine Boundary (presumption of non-pass, partial/deferred
 *       coverage quarantines findings to DEFERRED / COVERAGE_PARTIAL, strictly prevents premature clean claims).
 * - R3: Deterministic verification, zero-dependency standard library only, schema validation support.
 */

import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';

export const SCHEMA_VERSION = '1.0.0';

/**
 * Valid severity values in AGY Canonical Finding Schema.
 */
export const VALID_CANONICAL_SEVERITIES = new Set([
  'CRITICAL',
  'HIGH',
  'MEDIUM',
  'LOW',
  'UNRATED'
]);

/**
 * Valid finding types in AGY Canonical Finding Schema.
 */
export const VALID_FINDING_TYPES = new Set([
  'VULNERABILITY',
  'HARDENING',
  'INFORMATIONAL'
]);

/**
 * Valid proof kinds in AGY Canonical Finding Schema.
 */
export const VALID_PROOF_KINDS = new Set([
  'STATIC_TRACE',
  'UNIT_TEST',
  'BENIGN_REPRODUCTION',
  'CONFIG_EVIDENCE',
  'DEPENDENCY_EVIDENCE',
  'EXTERNAL_SCANNER_EVIDENCE',
  'MANUAL_ATTESTATION'
]);

/**
 * Computes deterministic SHA-256 hex digest of a string or buffer.
 * @param {string|Buffer} data
 * @returns {string}
 */
export function sha256(data) {
  return crypto.createHash('sha256').update(data).digest('hex');
}

/**
 * Canonicalizes an object/array recursively so that object keys are deterministically sorted.
 * Guarantees bitwise run-to-run identity.
 * @param {any} value
 * @returns {any}
 */
export function canonicalizeJson(value) {
  if (value === null || typeof value !== 'object') {
    return value;
  }
  if (Array.isArray(value)) {
    return value.map(canonicalizeJson);
  }
  const sorted = {};
  const keys = Object.keys(value).sort();
  for (const k of keys) {
    if (value[k] !== undefined) {
      sorted[k] = canonicalizeJson(value[k]);
    }
  }
  return sorted;
}

/**
 * Serializes data into deterministic JSON with sorted keys.
 * @param {any} value
 * @param {number} space
 * @returns {string}
 */
export function deterministicStringify(value, space = 2) {
  return JSON.stringify(canonicalizeJson(value), null, space) + '\n';
}

/**
 * Normalizes input: parses JSON string if needed, fails closed on malformed input.
 * @param {string|object|Array} input
 * @param {string} label
 * @returns {any}
 */
export function parseInputSafe(input, label = 'Input') {
  if (typeof input === 'string') {
    if (fs.existsSync(input)) {
      try {
        const fileContent = fs.readFileSync(input, 'utf8');
        return JSON.parse(fileContent);
      } catch (err) {
        throw new Error(`[DEFAULT_DENY_INPUT_ERROR] Failed to read or parse ${label} file '${input}': ${err.message}`);
      }
    }
    try {
      return JSON.parse(input);
    } catch (err) {
      throw new Error(`[DEFAULT_DENY_INPUT_ERROR] Malformed JSON in ${label}: ${err.message}`);
    }
  }
  if (input === null || typeof input !== 'object') {
    throw new Error(`[DEFAULT_DENY_INPUT_ERROR] ${label} must be a non-null object or array, got ${typeof input}`);
  }
  return input;
}

/**
 * Checks if a given path escapes the repository root boundary, contains URL-encoded traversals,
 * Windows drive letters, URI schemes, UNC paths, null bytes, or is invalid.
 * @param {string} filePath
 * @returns {boolean} True if the path escapes or is invalid
 */
export function isEscapingOrInvalidPath(filePath) {
  if (!filePath || typeof filePath !== 'string' || !filePath.trim()) return true;
  if (filePath.includes('\0') || filePath.includes('%00')) return true;
  // URL-encoded traversals or path separators
  if (/%2e/i.test(filePath) || /%2f/i.test(filePath) || /%5c/i.test(filePath)) return true;
  // Windows drive letters: C:/, C:\, C:
  if (/^[a-zA-Z]:[/\\$]/i.test(filePath) || /^[a-zA-Z]:$/i.test(filePath)) return true;
  // URI schemes: file:, http:, https:, etc.
  if (/^[a-zA-Z][a-zA-Z0-9+.-]*:/i.test(filePath)) return true;
  // UNC paths: //server, \\server
  if (filePath.startsWith('//') || filePath.startsWith('\\\\') || /^\/{2,}/.test(filePath)) return true;
  let p = filePath.replace(/\\/g, '/');
  p = path.posix.normalize(p);
  // Strip relative prefixes and single leading slash for workspace paths
  p = p.replace(/^(\.\/)+/, '').replace(/^\/+/, '').replace(/\/+$/, '');
  if (p === '' || p === '.' || p === '..' || p.startsWith('../') || p.includes('/../')) return true;
  return false;
}

/**
 * Normalizes a file path to canonical POSIX relative form without traversal segments or leading slashes.
 * @param {string} filePath
 * @returns {string}
 */
export function normalizePath(filePath) {
  if (!filePath || typeof filePath !== 'string') return '';
  if (isEscapingOrInvalidPath(filePath)) return '';
  let p = filePath.replace(/\\/g, '/');
  p = path.posix.normalize(p);
  p = p.replace(/^(\.\/)+/, '').replace(/^\/+/, '');
  p = p.replace(/\/+$/, '');
  if (p === '.' || p === '' || p === '..' || p.startsWith('../')) return '';
  return p;
}

/**
 * Extracts primary location from Cloudflare finding's trace, evidence, or direct location fields.
 * @param {object} finding
 * @returns {{ uri: string, startLine: number, endLine: number, lineSnippet: string|null }}
 */
export function extractPrimaryLocation(finding) {
  if (Array.isArray(finding.trace) && finding.trace.length > 0) {
    // Prefer sink step
    const sinkStep = finding.trace.find(s => s && s.kind === 'sink' && normalizePath(s.file) && Number.isInteger(s.line) && s.line >= 1);
    if (sinkStep) {
      const startLine = sinkStep.line;
      return {
        uri: normalizePath(sinkStep.file),
        startLine,
        endLine: startLine,
        lineSnippet: typeof sinkStep.description === 'string' ? sinkStep.description : (typeof sinkStep.scope === 'string' ? sinkStep.scope : null)
      };
    }
    // Fall back to first valid trace step
    const firstStep = finding.trace.find(s => s && normalizePath(s.file) && Number.isInteger(s.line) && s.line >= 1);
    if (firstStep) {
      const startLine = firstStep.line;
      return {
        uri: normalizePath(firstStep.file),
        startLine,
        endLine: startLine,
        lineSnippet: typeof firstStep.description === 'string' ? firstStep.description : (typeof firstStep.scope === 'string' ? firstStep.scope : null)
      };
    }
  }

  // Check evidence array
  if (Array.isArray(finding.evidence) && finding.evidence.length > 0) {
    const firstEv = finding.evidence.find(e => e && normalizePath(e.file) && Number.isInteger(e.line) && e.line >= 1);
    if (firstEv) {
      const startLine = firstEv.line;
      return {
        uri: normalizePath(firstEv.file),
        startLine,
        endLine: startLine,
        lineSnippet: typeof firstEv.description === 'string' ? firstEv.description : null
      };
    }
  }

  // Check direct location property
  if (finding.location && typeof finding.location === 'object') {
    const locUri = normalizePath(finding.location.uri || finding.location.file || '');
    const locLine = Number.isInteger(finding.location.startLine) && finding.location.startLine >= 1
      ? finding.location.startLine
      : (Number.isInteger(finding.location.line) && finding.location.line >= 1 ? finding.location.line : 1);
    if (locUri) {
      const startLine = Math.max(1, locLine);
      const rawEnd = Number.isInteger(finding.location.endLine) && finding.location.endLine >= 1 ? finding.location.endLine : locLine;
      const endLine = Math.max(startLine, Math.max(1, rawEnd));
      return {
        uri: locUri,
        startLine,
        endLine,
        lineSnippet: typeof finding.location.lineSnippet === 'string' ? finding.location.lineSnippet : null
      };
    }
  }

  // Check direct file / line properties
  if (typeof finding.file === 'string' && normalizePath(finding.file)) {
    const directLine = Number.isInteger(finding.line) && finding.line >= 1 ? finding.line : 1;
    const startLine = directLine;
    return {
      uri: normalizePath(finding.file),
      startLine,
      endLine: startLine,
      lineSnippet: null
    };
  }

  return {
    uri: 'unknown',
    startLine: 1,
    endLine: 1,
    lineSnippet: null
  };
}

/**
 * Maps Cloudflare severity representation to AGY Canonical Severity.
 * Cloudflare uses { overall_severity: 'critical'|'high'|'medium'|'low'|'informational', ... }
 * or simple strings.
 * @param {any} rawSeverity
 * @returns {string} 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'UNRATED'
 */
export function mapCloudflareSeverity(rawSeverity) {
  if (!rawSeverity) return 'UNRATED';
  if (typeof rawSeverity === 'number') {
    if (rawSeverity >= 9.0) return 'CRITICAL';
    if (rawSeverity >= 7.0) return 'HIGH';
    if (rawSeverity >= 4.0) return 'MEDIUM';
    if (rawSeverity > 0.0) return 'LOW';
    return 'UNRATED';
  }
  let sevStr = '';
  if (typeof rawSeverity === 'string') {
    sevStr = rawSeverity.toUpperCase();
  } else if (typeof rawSeverity === 'object') {
    if (typeof rawSeverity.score === 'number') {
      const s = rawSeverity.score;
      if (s >= 9.0) return 'CRITICAL';
      if (s >= 7.0) return 'HIGH';
      if (s >= 4.0) return 'MEDIUM';
      if (s > 0.0) return 'LOW';
      return 'UNRATED';
    }
    if (rawSeverity.overall_severity) {
      sevStr = String(rawSeverity.overall_severity).toUpperCase();
    } else if (rawSeverity.score) {
      const parsedNum = Number(rawSeverity.score);
      if (!Number.isNaN(parsedNum)) {
        if (parsedNum >= 9.0) return 'CRITICAL';
        if (parsedNum >= 7.0) return 'HIGH';
        if (parsedNum >= 4.0) return 'MEDIUM';
        if (parsedNum > 0.0) return 'LOW';
        return 'UNRATED';
      }
      sevStr = String(rawSeverity.score).toUpperCase();
    }
  }

  switch (sevStr) {
    case 'CRITICAL':
      return 'CRITICAL';
    case 'HIGH':
      return 'HIGH';
    case 'MEDIUM':
      return 'MEDIUM';
    case 'LOW':
      return 'LOW';
    case 'INFORMATIONAL':
      return 'LOW';
    default:
      return 'UNRATED';
  }
}

/**
 * Validates a raw Cloudflare finding for required core properties.
 * Throws on malformed inputs under Default-Deny.
 * @param {object} finding
 * @param {number} index
 */
export function validateCloudflareFindingShape(finding, index = 0) {
  if (!finding || typeof finding !== 'object' || Array.isArray(finding)) {
    throw new Error(`[DEFAULT_DENY_SCHEMA_ERROR] Finding at index ${index} is not an object.`);
  }

  if (typeof finding.verdict !== 'string') {
    throw new Error(`[DEFAULT_DENY_SCHEMA_ERROR] Finding at index ${index} missing required 'verdict' string.`);
  }

  const validVerdicts = ['confirmed', 'needs_validation', 'rejected'];
  const verdictNorm = finding.verdict.toLowerCase().trim();
  if (!validVerdicts.includes(verdictNorm)) {
    throw new Error(`[DEFAULT_DENY_SCHEMA_ERROR] Finding at index ${index} has unrecognized verdict '${finding.verdict}'. Expected one of: ${validVerdicts.join(', ')}.`);
  }

  if (typeof finding.fingerprint !== 'string' || !finding.fingerprint.trim()) {
    throw new Error(`[DEFAULT_DENY_SCHEMA_ERROR] Finding at index ${index} missing required 'fingerprint' string.`);
  }

  if (typeof finding.title !== 'string' || !finding.title.trim()) {
    throw new Error(`[DEFAULT_DENY_SCHEMA_ERROR] Finding at index ${index} missing required 'title' string.`);
  }

  if (typeof finding.description !== 'string' || !finding.description.trim()) {
    throw new Error(`[DEFAULT_DENY_SCHEMA_ERROR] Finding at index ${index} missing required 'description' string.`);
  }
}

/**
 * Checks whether a confirmed finding has conclusive affirmative verifier proof under Default-Deny.
 * Prevents unevidenced findings or findings without verifier confirmation from obtaining REPORTABLE/CONFIRMED authority.
 *
 * @param {object} raw - Raw Cloudflare finding
 * @param {object} loc - Extracted primary location
 * @returns {boolean} True if conclusive affirmative verifier proof is established
 */
export function hasConclusiveVerifierProof(raw, loc) {
  // 1. Must have physical code location (not "unknown") and strictly contained within repository boundary
  if (!loc || !loc.uri || loc.uri === 'unknown' || !Number.isInteger(loc.startLine) || loc.startLine < 1) {
    return false;
  }

  // Reject paths escaping repository root boundary (path traversal, absolute, scheme, UNC, null byte)
  if (isEscapingOrInvalidPath(loc.uri)) {
    return false;
  }

  // 2. Must have affirmative trace steps or evidence items within repository boundary with valid positive line numbers
  const hasTrace = Array.isArray(raw.trace) && raw.trace.some(s => {
    if (!s || !s.file || !Number.isInteger(s.line) || s.line < 1) return false;
    return !isEscapingOrInvalidPath(s.file);
  });

  const hasEvidence = Array.isArray(raw.evidence) && raw.evidence.some(e => {
    if (!e || !e.file || !Number.isInteger(e.line) || e.line < 1) return false;
    return !isEscapingOrInvalidPath(e.file);
  });

  if (!hasTrace && !hasEvidence) {
    return false;
  }

  // 3. Must not be in exploratory/hunting phase without verifier proof (Discovery/Hunting generate hypotheses, not confirmed proof)
  const phase = (typeof raw.phase === 'string' ? raw.phase : '').toLowerCase();
  if (
    phase.includes('discovery') ||
    phase.includes('phase-1') ||
    phase.includes('recon') ||
    phase.includes('hunting') ||
    phase.includes('phase-2') ||
    phase.includes('triage') ||
    phase.includes('hypothesis') ||
    phase.includes('candidate')
  ) {
    return false;
  }

  // 4. Must not have refutation indicators or low/unconfirmed confidence (supporting both string and object/number shapes)
  let confStr = '';
  if (typeof raw.confidence === 'string') {
    confStr = raw.confidence.toLowerCase().trim();
  } else if (typeof raw.confidence === 'number') {
    if (raw.confidence < 0.7) return false;
    confStr = raw.confidence >= 0.7 ? 'high' : 'medium';
  } else if (raw.confidence && typeof raw.confidence === 'object') {
    if (typeof raw.confidence.score === 'number') {
      if (raw.confidence.score < 0.7) return false;
      confStr = raw.confidence.score >= 0.7 ? 'high' : 'medium';
    } else {
      confStr = String(raw.confidence.score || '').toLowerCase().trim();
    }
  }

  const disallowedConfidence = [
    'low', 'none', 'unverified', 'unconfirmed', 'refuted', 'false', 'zero',
    'inconclusive', 'disputed', 'tentative', 'failed', 'doubtful', 'provisional',
    'rejected', 'heuristic'
  ];
  if (disallowedConfidence.includes(confStr)) {
    return false;
  }

  // 5. Must have affirmative execution instructions/payloads or verified verifier confidence
  // If observed_result is present, it MUST NOT indicate execution failure or negative reproduction
  let hasValidObservedResult = false;
  if (raw.execution && typeof raw.execution === 'object') {
    if (typeof raw.execution.observed_result === 'string' && raw.execution.observed_result.trim().length > 0) {
      const obsLower = raw.execution.observed_result.toLowerCase();
      const failureKeywords = [
        'fail', 'not vuln', 'could not reproduce', 'cannot reproduce',
        'unreproducible', 'inconclusive', 'negative result', 'refuted', 'error'
      ];
      const isFailedExecution = failureKeywords.some(kw => obsLower.includes(kw));
      if (isFailedExecution) {
        return false; // Explicit failure/non-reproduction strictly denies affirmative proof
      }
      hasValidObservedResult = true;
    }
  }

  const hasExecution = raw.execution && typeof raw.execution === 'object' && (
    (Array.isArray(raw.execution.payloads) && raw.execution.payloads.some(p => p !== null && p !== undefined && String(p).trim().length > 0)) ||
    (Array.isArray(raw.execution.instructions) && raw.execution.instructions.some(i => i !== null && i !== undefined && String(i).trim().length > 0)) ||
    hasValidObservedResult
  );

  const hasHighConfidence = (confStr === 'high' || confStr === 'confirmed');

  return Boolean(hasExecution || hasHighConfidence);
}

/**
 * Translates a single Cloudflare finding into an AGY Canonical Finding.
 * Conforms to `schemas/canonical-finding.schema.json`.
 *
 * @param {object} raw - Raw Cloudflare finding
 * @param {object} options
 * @param {boolean} [options.failClosedOnInjectedSeverity=false] - Fail closed if needs_validation has severity
 * @param {object} [options.coverageLedgerResult] - Result from ingestCoverageLedger for quarantine checks
 * @returns {object} Canonical Finding conforming to canonical-finding.schema.json
 */
export function toCanonicalFinding(raw, options = {}) {
  validateCloudflareFindingShape(raw);

  const loc = extractPrimaryLocation(raw);
  const fingerprint = raw.fingerprint.trim();
  const verdictRaw = raw.verdict.toLowerCase().trim();

  const id = raw.id || `CF-${fingerprint}`;
  const rawRule = raw.ruleId || raw.rule_id || (typeof raw.attack_class === 'string' && raw.attack_class.trim() ? raw.attack_class.trim() : (Array.isArray(raw.attack_class) && raw.attack_class.length > 0 ? String(raw.attack_class[0]) : null));
  const ruleId = typeof rawRule === 'string' && rawRule.trim() ? rawRule.trim() : `CF-RULE-${fingerprint}`;
  const title = raw.title.trim();
  const description = raw.description.trim();

  let disposition;
  let verdict;
  let reasonCode;
  let dispositionReason;
  let severity;
  let findingType = 'VULNERABILITY';

  // R1 Requirement Mapping
  // R1 Requirement Mapping
  // Default-Deny Authority Invariant:
  // An upstream producer's confirmed verdict is an unassessed producer claim until AGY independent verifiers vote.
  // Unless options.trustProducerAsAuthority === true is explicitly requested, confirmed findings map to
  // DEFERRED / NEEDS_MANUAL_REVIEW / UNVERIFIED_CLAIM, preserving the producer's claim in extensions.producer.
  const isAffirmativelyVerified = hasConclusiveVerifierProof(raw, loc);
  const trustProducerAsAuthority = Boolean(options.trustProducerAsAuthority);

  if (verdictRaw === 'confirmed') {
    if (trustProducerAsAuthority && isAffirmativelyVerified) {
      disposition = 'REPORTABLE';
      verdict = 'CONFIRMED';
      reasonCode = 'AFFIRMATIVELY_VERIFIED';
      dispositionReason = raw.dispositionReason || 'Affirmatively verified by independent verifier with reproducible execution trace (explicit authority grant).';
      severity = mapCloudflareSeverity(raw.severity);
      if (typeof raw.severity === 'object' && raw.severity?.overall_severity === 'informational') {
        findingType = 'INFORMATIONAL';
      }
    } else {
      // Ingested producer-confirmed finding awaiting AGY authority
      disposition = 'DEFERRED';
      verdict = 'NEEDS_MANUAL_REVIEW';
      reasonCode = isAffirmativelyVerified ? 'UNVERIFIED_CLAIM' : 'EVIDENCE_INCOMPLETE';
      severity = 'UNRATED';
      dispositionReason = raw.dispositionReason || (isAffirmativelyVerified
        ? `Producer-Claim: Finding '${fingerprint}' was confirmed by Cloudflare verifier, but AGY independent verification is pending; quarantined to DEFERRED under Default-Deny.`
        : `Presumption of Non-Pass: Finding '${fingerprint}' claimed confirmed verdict but lacks conclusive affirmative verifier proof or physical code location; downgraded to DEFERRED under Default-Deny.`);
    }
  } else if (verdictRaw === 'needs_validation') {
    // Cloudflare severity-omission invariant: strictly UNRATED
    if (raw.severity !== undefined && raw.severity !== null) {
      if (options.failClosedOnInjectedSeverity) {
        throw new Error(`[FAIL_CLOSED_SEVERITY_ERROR] needs_validation finding '${fingerprint}' contains injected severity; rejected under Default-Deny.`);
      }
    }
    disposition = 'DEFERRED';
    verdict = 'NEEDS_MANUAL_REVIEW';
    reasonCode = 'EVIDENCE_INCOMPLETE';
    severity = 'UNRATED';
    const blockersText = Array.isArray(raw.blockers) && raw.blockers.length > 0 ? ` Blockers: ${raw.blockers.join('; ')}` : '';
    dispositionReason = raw.dispositionReason || `Candidate validation incomplete; manual review required.${blockersText}`;
  } else if (verdictRaw === 'rejected') {
    disposition = 'SUPPRESSED';
    verdict = 'FALSE_POSITIVE';
    reasonCode = 'AFFIRMATIVELY_REFUTED';
    dispositionReason = raw.reason || raw.refutation_reason || raw.dispositionReason || 'Affirmatively refuted by verifier with counter-evidence.';
    severity = 'UNRATED';
  } else {
    throw new Error(`[DEFAULT_DENY_ERROR] Unexpected verdict '${verdictRaw}' for finding '${fingerprint}'`);
  }

  // R2 Coverage Ledger Quarantine Boundary Check:
  // If finding path or any of its trace steps or evidence items belong to a partial, unverified,
  // or budget-deferred ledger unit, fail closed to DEFERRED / COVERAGE_PARTIAL under Presumption of Non-Pass
  if (options.coverageLedgerResult && (disposition === 'REPORTABLE' || verdictRaw === 'confirmed')) {
    let quarantineCheck = checkPathQuarantine(loc.uri, options.coverageLedgerResult);

    // Also verify all steps in the execution trace
    if (!quarantineCheck.quarantined && Array.isArray(raw.trace)) {
      for (const step of raw.trace) {
        if (step && step.file) {
          const stepQ = checkPathQuarantine(step.file, options.coverageLedgerResult);
          if (stepQ.quarantined) {
            quarantineCheck = stepQ;
            break;
          }
        }
      }
    }

    // Also verify all evidence items
    if (!quarantineCheck.quarantined && Array.isArray(raw.evidence)) {
      for (const ev of raw.evidence) {
        if (ev && ev.file) {
          const evQ = checkPathQuarantine(ev.file, options.coverageLedgerResult);
          if (evQ.quarantined) {
            quarantineCheck = evQ;
            break;
          }
        }
      }
    }

    if (quarantineCheck.quarantined) {
      disposition = 'DEFERRED';
      verdict = 'NEEDS_MANUAL_REVIEW';
      reasonCode = 'COVERAGE_PARTIAL';
      dispositionReason = `Presumption of Non-Pass: Source path '${loc.uri}' belongs to unverified, partial, or budget-deferred coverage unit '${quarantineCheck.unitId || 'unknown'}' (status: ${quarantineCheck.status || 'PARTIAL'}).`;
    }
  }

  // Consensus modeling under Default-Deny:
  // Adapter NEVER manufactures simulated AGY consensus unless explicitly in trusted override mode.
  const consensus = raw.consensus && typeof raw.consensus === 'object' ? raw.consensus : (
    trustProducerAsAuthority && verdictRaw === 'confirmed' && disposition === 'REPORTABLE'
      ? { supports: 3, refutes: 0, totalVotes: 3, unanimous: true, source: 'cloudflare-verifier' }
      : verdictRaw === 'rejected'
        ? { supports: 0, refutes: 1, totalVotes: 1, unanimous: false, source: 'cloudflare-verifier' }
        : { supports: 0, refutes: 0, totalVotes: 0, unanimous: false, source: 'cloudflare-unassessed' }
  );

  // Security property inference
  const securityProperty = typeof raw.securityProperty === 'string' && raw.securityProperty.trim()
    ? raw.securityProperty.trim()
    : (typeof raw.intended_behavior === 'string' && raw.intended_behavior.trim()
      ? raw.intended_behavior.trim()
      : (typeof raw.attack_class === 'string' && raw.attack_class.trim()
        ? `Defend against ${raw.attack_class.replace(/_/g, ' ')}`
        : 'Maintain system confidentiality, integrity, and availability'));

  // Binding proof: traces, conditions, execution steps
  const proof = {
    trace: Array.isArray(raw.trace) ? raw.trace : [],
    conditions: Array.isArray(raw.conditions) ? raw.conditions : [],
    execution: raw.execution && typeof raw.execution === 'object' ? raw.execution : (typeof raw.execution === 'string' ? { instructions: [raw.execution] } : null)
  };

  // Defect management: rootCause, preventiveAction, missingControl, affectedPattern
  let preventiveAction = '';
  if (typeof raw.remediation === 'string' && raw.remediation.trim()) {
    preventiveAction = raw.remediation.trim();
  } else if (raw.remediation && typeof raw.remediation === 'object') {
    preventiveAction = raw.remediation.strategy ||
      raw.remediation.recommendation ||
      raw.remediation.description ||
      raw.remediation.action ||
      (typeof raw.remediation.summary === 'string' ? raw.remediation.summary : '');
  } else if (raw.defectManagement?.preventiveAction) {
    preventiveAction = String(raw.defectManagement.preventiveAction);
  }

  const rootCause = typeof (raw.root_cause || raw.claimed_root_cause) === 'string'
    ? (raw.root_cause || raw.claimed_root_cause).trim()
    : (raw.root_cause?.description || raw.claimed_root_cause?.description || raw.defectManagement?.rootCause || '');

  const missingControl = typeof raw.intended_behavior === 'string'
    ? raw.intended_behavior.trim()
    : (raw.intended_behavior?.description || raw.defectManagement?.missingControl || '');

  const affectedPattern = typeof raw.attack_class === 'string'
    ? raw.attack_class.trim()
    : (Array.isArray(raw.attack_class) ? raw.attack_class.join(', ') : (raw.defectManagement?.affectedPattern || ''));

  const defectManagement = {
    rootCause,
    missingControl,
    affectedPattern,
    preventiveAction
  };

  // Location Fingerprint & Lineage ID
  const locationFingerprint = sha256(`${ruleId}:${loc.uri}:${loc.startLine}`);
  const lineageId = sha256(`${ruleId}:${loc.uri}:${fingerprint}`);

  // Location Hash
  const lineHash = sha256(`${loc.uri}:${loc.startLine}:${loc.lineSnippet || ''}`);

  // Preserving unadulterated Cloudflare-specific metadata in extensions.cloudflare
  // Retains ALL raw properties lossless plus canonical mappings
  const extensions = {
    ...(raw.extensions && typeof raw.extensions === 'object' ? raw.extensions : {}),
    producer: {
      type: 'cloudflare-security-audit',
      claimedVerdict: raw.verdict,
      claimedSeverity: raw.severity ? (typeof raw.severity === 'string' ? raw.severity.toUpperCase() : (raw.severity.overall_severity || 'UNRATED').toUpperCase()) : 'UNRATED',
      claimedVerification: isAffirmativelyVerified ? 'VERIFIED_BY_PRODUCER' : 'UNVERIFIED_BY_PRODUCER',
      authorityStatus: (trustProducerAsAuthority && disposition === 'REPORTABLE') ? 'AUTHORIZED_OVERRIDE' : 'UNASSESSED',
      verifierProofPresent: isAffirmativelyVerified,
      ruleId: raw.ruleId || raw.rule_id || null,
      attackClass: raw.attack_class || null
    },
    cloudflare: {
      ...raw,
      fingerprint,
      original_verdict: raw.verdict,
      attack_class: raw.attack_class || null,
      phase: raw.phase || null,
      raw_tokens: raw.raw_tokens || raw.tokens || null,
      root_cause: raw.root_cause || null,
      claimed_root_cause: raw.claimed_root_cause || null,
      intended_behavior: raw.intended_behavior || null,
      trace: Array.isArray(raw.trace) ? raw.trace : null,
      evidence: Array.isArray(raw.evidence) ? raw.evidence : null,
      conditions: Array.isArray(raw.conditions) ? raw.conditions : null,
      execution: raw.execution || null,
      remediation: raw.remediation || null,
      severity: raw.severity || null,
      confidence: raw.confidence || null,
      blockers: Array.isArray(raw.blockers) ? raw.blockers : null,
      validation_plan: raw.validation_plan || null,
      reason: raw.reason || null
    }
  };

  const canonical = {
    schemaVersion: SCHEMA_VERSION,
    id,
    ruleId,
    title,
    description,
    disposition,
    verdict,
    dispositionReason,
    reasonCode,
    severity,
    findingType,
    proofKind: 'STATIC_TRACE',
    securityProperty,
    location: {
      uri: loc.uri,
      startLine: loc.startLine,
      endLine: loc.endLine,
      lineSnippet: loc.lineSnippet,
      lineHash
    },
    consensus,
    locationFingerprint,
    lineageId,
    proof,
    defectManagement,
    extensions
  };

  return canonicalizeJson(canonical);
}

/**
 * Translates a single Cloudflare finding into an AGY Candidate conforming to `candidate-set.schema.json`.
 * Note: `candidate-set.schema.json` strictly enforces `additionalProperties: false`.
 *
 * @param {object} raw
 * @param {object} options
 * @returns {object} Candidate conforming to candidate-set.schema.json items
 */
export function toCandidate(raw, options = {}) {
  validateCloudflareFindingShape(raw);

  const loc = extractPrimaryLocation(raw);
  const fingerprint = raw.fingerprint.trim();
  const verdictRaw = raw.verdict.toLowerCase().trim();
  const id = raw.id || `CF-${fingerprint}`;
  const rawRule = raw.ruleId || raw.rule_id || (typeof raw.attack_class === 'string' && raw.attack_class.trim() ? raw.attack_class.trim() : (Array.isArray(raw.attack_class) && raw.attack_class.length > 0 ? String(raw.attack_class[0]) : null));
  const ruleId = typeof rawRule === 'string' && rawRule.trim() ? rawRule.trim() : `CF-RULE-${fingerprint}`;
  const title = raw.title.trim();
  const description = raw.description.trim();

  const securityProperty = typeof raw.securityProperty === 'string' && raw.securityProperty.trim()
    ? raw.securityProperty.trim()
    : (typeof raw.intended_behavior === 'string' && raw.intended_behavior.trim()
      ? raw.intended_behavior.trim()
      : (typeof raw.attack_class === 'string' && raw.attack_class.trim()
        ? `Defend against ${raw.attack_class.replace(/_/g, ' ')}`
        : 'Maintain system integrity'));

  let severity = 'UNRATED';
  let findingType = 'VULNERABILITY';

  if (verdictRaw === 'confirmed') {
    // Only grant mapped severity if conclusive verifier proof exists
    if (hasConclusiveVerifierProof(raw, loc)) {
      severity = mapCloudflareSeverity(raw.severity);
      if (typeof raw.severity === 'object' && raw.severity?.overall_severity === 'informational') {
        findingType = 'INFORMATIONAL';
      }
    } else {
      severity = 'UNRATED';
    }
  } else if (verdictRaw === 'needs_validation') {
    if (raw.severity !== undefined && raw.severity !== null) {
      if (options.failClosedOnInjectedSeverity) {
        throw new Error(`[FAIL_CLOSED_SEVERITY_ERROR] needs_validation finding '${fingerprint}' contains injected severity.`);
      }
    }
    severity = 'UNRATED';
  }

  // Location conforming strictly to candidate-set location schema (additionalProperties: false)
  const candidateLocation = {
    uri: loc.uri,
    startLine: loc.startLine,
    endLine: loc.endLine
  };
  if (loc.lineSnippet !== null && loc.lineSnippet !== undefined) {
    candidateLocation.lineSnippet = loc.lineSnippet;
  }

  const proof = {
    trace: Array.isArray(raw.trace) ? raw.trace : [],
    conditions: Array.isArray(raw.conditions) ? raw.conditions : [],
    execution: raw.execution && typeof raw.execution === 'object' ? raw.execution : (typeof raw.execution === 'string' ? { instructions: [raw.execution] } : null)
  };

  const lineageId = sha256(`${ruleId}:${loc.uri}:${fingerprint}`);

  const component = typeof raw.subsystem === 'string' && raw.subsystem.trim()
    ? raw.subsystem.trim()
    : (loc.uri !== 'unknown' && path.posix.dirname(loc.uri) !== '.' ? path.posix.dirname(loc.uri) : 'core');

  const family = typeof raw.attack_class === 'string' && raw.attack_class.trim()
    ? raw.attack_class.trim()
    : (Array.isArray(raw.attack_class) && raw.attack_class.length > 0 ? String(raw.attack_class[0]) : 'general');

  const violation = typeof (raw.root_cause || raw.claimed_root_cause) === 'string'
    ? (raw.root_cause || raw.claimed_root_cause).trim()
    : (raw.root_cause?.description || raw.claimed_root_cause?.description || 'Security invariant violation');

  const candidate = {
    schemaVersion: SCHEMA_VERSION,
    id,
    ruleId,
    title,
    description,
    securityProperty,
    violation,
    findingType,
    proofKind: 'STATIC_TRACE',
    severity,
    location: candidateLocation,
    proof,
    evidence: Array.isArray(raw.evidence) ? raw.evidence : (raw.evidence || []),
    lineageId,
    component,
    family
  };

  return canonicalizeJson(candidate);
}

/**
 * Normalizes any format of Cloudflare findings (array or grouped object) into a flat array.
 * @param {any} input
 * @returns {object[]}
 */
export function normalizeCloudflareFindingsList(input) {
  const parsed = parseInputSafe(input, 'Cloudflare Findings');

  if (Array.isArray(parsed)) {
    return parsed;
  }

  if (parsed && typeof parsed === 'object') {
    // If grouped by verdict: { confirmed: [...], needs_validation: [...], rejected: [...] }
    const hasGroupArrays = (
      Array.isArray(parsed.confirmed) ||
      Array.isArray(parsed.needs_validation) ||
      Array.isArray(parsed.rejected)
    );

    if (hasGroupArrays) {
      const list = [];
      if (Array.isArray(parsed.confirmed)) {
        for (const item of parsed.confirmed) {
          list.push({ ...item, verdict: item.verdict || 'confirmed' });
        }
      }
      if (Array.isArray(parsed.needs_validation)) {
        for (const item of parsed.needs_validation) {
          list.push({ ...item, verdict: item.verdict || 'needs_validation' });
        }
      }
      if (Array.isArray(parsed.rejected)) {
        for (const item of parsed.rejected) {
          list.push({ ...item, verdict: item.verdict || 'rejected' });
        }
      }
      return list;
    }

    if (Array.isArray(parsed.findings)) {
      return parsed.findings;
    }
  }

  throw new Error('[DEFAULT_DENY_SCHEMA_ERROR] Input does not contain a recognizable list of Cloudflare findings.');
}

/**
 * Ingests Cloudflare findings into AGY Canonical Findings.
 *
 * @param {string|object|Array} input - Path or JSON content of Cloudflare findings.json
 * @param {object} options
 * @returns {{ schemaVersion: string, canonicalFindings: object[], summary: object }}
 */
export function ingestFindings(input, options = {}) {
  const rawList = normalizeCloudflareFindingsList(input);
  const canonicalFindings = [];

  const counts = {
    total: rawList.length,
    confirmed: 0,
    needs_validation: 0,
    rejected: 0,
    reportable: 0,
    deferred: 0,
    suppressed: 0
  };

  for (let i = 0; i < rawList.length; i++) {
    const raw = rawList[i];
    const canonical = toCanonicalFinding(raw, options);
    canonicalFindings.push(canonical);

    const v = (raw.verdict || '').toLowerCase().trim();
    if (v === 'confirmed') counts.confirmed++;
    else if (v === 'needs_validation') counts.needs_validation++;
    else if (v === 'rejected') counts.rejected++;

    if (canonical.disposition === 'REPORTABLE') counts.reportable++;
    else if (canonical.disposition === 'DEFERRED') counts.deferred++;
    else if (canonical.disposition === 'SUPPRESSED') counts.suppressed++;
  }

  const ingestedAt = options.timestamp || (options.liveTimestamp ? new Date().toISOString() : '2026-09-28T00:00:00.000Z');

  return canonicalizeJson({
    schemaVersion: SCHEMA_VERSION,
    canonicalFindings,
    summary: {
      findingCounts: counts,
      ingestedAt
    }
  });
}

/**
 * Ingests Cloudflare findings into AGY Candidate Set conforming to `candidate-set.schema.json`.
 *
 * @param {string|object|Array} input
 * @param {object} options
 * @returns {{ schemaVersion: string, candidates: object[] }}
 */
export function toCandidateSet(input, options = {}) {
  const rawList = normalizeCloudflareFindingsList(input);
  const candidates = rawList.map(raw => toCandidate(raw, options));
  const timestamp = options.timestamp || (options.liveTimestamp ? new Date().toISOString() : '2026-09-28T00:00:00.000Z');

  return canonicalizeJson({
    schemaVersion: SCHEMA_VERSION,
    candidates,
    discoveryMetadata: {
      source: 'cloudflare-security-audit-adapter',
      candidateCount: candidates.length,
      timestamp
    }
  });
}

/**
 * Validates the structure of Cloudflare coverage-ledger.json unit.
 * @param {object} unit
 * @param {number} index
 */
export function validateCoverageUnitShape(unit, index = 0) {
  if (!unit || typeof unit !== 'object' || Array.isArray(unit)) {
    throw new Error(`[DEFAULT_DENY_SCHEMA_ERROR] Coverage unit at index ${index} is not an object.`);
  }
  if (typeof unit.coverage_id !== 'string' || !unit.coverage_id.trim()) {
    throw new Error(`[DEFAULT_DENY_SCHEMA_ERROR] Coverage unit at index ${index} missing required 'coverage_id' string.`);
  }
  if (typeof unit.status !== 'string' || !unit.status.trim()) {
    throw new Error(`[DEFAULT_DENY_SCHEMA_ERROR] Coverage unit at index ${index} missing required 'status' string.`);
  }
}

/**
 * Helper to record path coverage state ensuring that partial status cannot be overwritten by covered status.
 */
function recordPathStatus(pathMap, normPath, unitId, unitStatus, isCovered) {
  if (!normPath) return;
  const existing = pathMap.get(normPath);
  if (!existing) {
    pathMap.set(normPath, {
      path: normPath,
      coverageId: unitId,
      status: isCovered ? 'COVERED' : 'PARTIAL',
      unitStatus
    });
  } else if (!isCovered) {
    // Fail closed to PARTIAL
    pathMap.set(normPath, {
      path: normPath,
      coverageId: unitId,
      status: 'PARTIAL',
      unitStatus
    });
  }
}

/**
 * Ingests Cloudflare `coverage-ledger.json` into AGY evidence ledger accounting.
 *
 * Enforces Presumption of Non-Pass:
 * Unaudited, partial, or budget-deferred paths map to DEFERRED / COVERAGE_PARTIAL,
 * strictly preventing premature clean claims.
 *
 * @param {string|object|Array} input - Cloudflare coverage-ledger.json content or path
 * @param {object} options
 * @returns {object} Parsed evidence ledger accounting
 */
export function ingestCoverageLedger(input, options = {}) {
  const parsed = parseInputSafe(input, 'Cloudflare Coverage Ledger');
  let units = [];
  if (Array.isArray(parsed)) {
    units = parsed;
  } else if (parsed && typeof parsed === 'object' && Array.isArray(parsed.units)) {
    units = parsed.units;
  } else {
    throw new Error('[DEFAULT_DENY_SCHEMA_ERROR] Coverage ledger must be an array of units or an object with a units array.');
  }

  const counts = {
    totalUnits: units.length,
    covered: 0,
    not_applicable: 0,
    out_of_scope: 0,
    in_progress: 0,
    planned: 0,
    blocked: 0,
    deferred: 0,
    candidate: 0
  };

  const pathCoverageMap = new Map();
  const partialUnits = [];
  const discoveryCells = [];

  for (let i = 0; i < units.length; i++) {
    const unit = units[i];
    validateCoverageUnitShape(unit, i);
    const status = (unit.status || '').toLowerCase().trim();

    if (counts[status] !== undefined) {
      counts[status]++;
    } else {
      counts.deferred++;
    }

    const startingPaths = Array.isArray(unit.starting_paths) ? unit.starting_paths.map(normalizePath).filter(Boolean) : [];
    const reviewedPaths = Array.isArray(unit.reviewed_paths) ? unit.reviewed_paths.map(normalizePath).filter(Boolean) : [];

    const isNotApplicable = (status === 'not_applicable');
    const isOutOfScope = (status === 'out_of_scope');
    const isCoveredStatus = (status === 'covered');

    if (isNotApplicable) {
      if (reviewedPaths.length === 0 && startingPaths.length > 0) {
        partialUnits.push({
          coverageId: unit.coverage_id,
          status: 'unreviewed_not_applicable_unit',
          subsystem: unit.subsystem || 'unknown',
          attackClass: unit.attack_class || 'unknown',
          paths: startingPaths,
          unresolved: ['Unit claimed not_applicable but contains 0 reviewed paths']
        });
        for (const p of startingPaths) {
          recordPathStatus(pathCoverageMap, p, unit.coverage_id, 'unreviewed_not_applicable_unit', false);
        }
      } else {
        const allPaths = Array.from(new Set([...startingPaths, ...reviewedPaths]));
        for (const p of allPaths) {
          recordPathStatus(pathCoverageMap, p, unit.coverage_id, status, true);
        }
      }
    } else if (isOutOfScope) {
      // Under Presumption of Non-Pass: Out-of-scope paths are UNAUDITED.
      // Must map to PARTIAL / DEFERRED and strictly prevent clean claims.
      const allPaths = Array.from(new Set([...startingPaths, ...reviewedPaths]));
      for (const p of allPaths) {
        recordPathStatus(pathCoverageMap, p, unit.coverage_id, 'out_of_scope', false);
      }
      partialUnits.push({
        coverageId: unit.coverage_id,
        status: 'out_of_scope',
        subsystem: unit.subsystem || 'unknown',
        attackClass: unit.attack_class || 'unknown',
        paths: allPaths,
        unresolved: ['Unit explicitly marked out_of_scope; unaudited path']
      });
    } else if (isCoveredStatus) {
      if (reviewedPaths.length === 0) {
        // Under Presumption of Non-Pass: Unit claimed covered status but has zero reviewed paths
        partialUnits.push({
          coverageId: unit.coverage_id,
          status: 'unreviewed_covered_unit',
          subsystem: unit.subsystem || 'unknown',
          attackClass: unit.attack_class || 'unknown',
          paths: startingPaths,
          unresolved: ['Unit claimed covered status but contains 0 reviewed paths']
        });
        for (const p of startingPaths) {
          recordPathStatus(pathCoverageMap, p, unit.coverage_id, 'unreviewed_covered_unit', false);
        }
      } else {
        // Active covered status: ONLY reviewed_paths are affirmatively covered
        const reviewedSet = new Set(reviewedPaths);
        for (const p of reviewedPaths) {
          recordPathStatus(pathCoverageMap, p, unit.coverage_id, status, true);
        }

        // Any starting_paths NOT reviewed are unreviewed starting paths under Presumption of Non-Pass
        const unreviewed = startingPaths.filter(p => !reviewedSet.has(p));
        if (unreviewed.length > 0) {
          for (const p of unreviewed) {
            recordPathStatus(pathCoverageMap, p, unit.coverage_id, 'unreviewed_starting_path', false);
          }
          partialUnits.push({
            coverageId: unit.coverage_id,
            status: 'unreviewed_starting_paths',
            subsystem: unit.subsystem || 'unknown',
            attackClass: unit.attack_class || 'unknown',
            paths: unreviewed,
            unresolved: [`Starting paths omitted from review: ${unreviewed.join(', ')}`]
          });
        }
      }
    } else {
      // Unit is in_progress, deferred, blocked, planned, etc.
      const allPaths = Array.from(new Set([...startingPaths, ...reviewedPaths]));
      for (const p of allPaths) {
        recordPathStatus(pathCoverageMap, p, unit.coverage_id, status, false);
      }
      partialUnits.push({
        coverageId: unit.coverage_id,
        status,
        subsystem: unit.subsystem || 'unknown',
        attackClass: unit.attack_class || 'unknown',
        paths: allPaths,
        unresolved: Array.isArray(unit.unresolved) ? unit.unresolved : []
      });
    }

    // Build discovery matrix cell for AGY
    const matrixPaths = Array.from(new Set([...startingPaths, ...reviewedPaths]));
    discoveryCells.push({
      component: unit.subsystem || 'default',
      family: unit.attack_class || 'general',
      status: (status === 'covered' && reviewedPaths.length > 0 && (!unit.starting_paths || startingPaths.every(p => reviewedPaths.includes(p))))
        ? 'REVIEWED_NO_CANDIDATE'
        : (isNotApplicable ? 'NOT_APPLICABLE' : 'PENDING'),
      reviewedEvidence: matrixPaths.map(p => ({ path: p, line: 1 })),
      notes: `Cloudflare coverage unit: ${unit.coverage_id} (${unit.status})`
    });
  }

  // Under Presumption of Non-Pass:
  // If ANY unit is not covered / not_applicable, or is out_of_scope, or has unreviewed starting paths, coverage is strictly PARTIAL.
  const hasIncompleteUnits = (
    counts.in_progress > 0 ||
    counts.planned > 0 ||
    counts.blocked > 0 ||
    counts.deferred > 0 ||
    counts.candidate > 0 ||
    counts.out_of_scope > 0 ||
    partialUnits.length > 0
  );

  const coverageStatus = (hasIncompleteUnits || counts.totalUnits === 0) ? 'COVERAGE_PARTIAL' : 'COMPLETE';
  const canDeclareClean = (coverageStatus === 'COMPLETE' && counts.covered > 0);

  return canonicalizeJson({
    schemaVersion: SCHEMA_VERSION,
    coverageStatus,
    canDeclareClean,
    summary: {
      totalUnits: counts.totalUnits,
      coveredUnits: counts.covered,
      partialUnitsCount: partialUnits.length,
      unitCounts: counts,
      canDeclareClean,
      reason: canDeclareClean
        ? 'All declared coverage ledger units successfully accounted and covered.'
        : `Presumption of Non-Pass: Coverage is partial (${counts.covered}/${counts.totalUnits} units covered; ${partialUnits.length} incomplete/deferred). Clean claim prohibited.`
    },
    partialUnits,
    pathCoverageMap: Object.fromEntries(pathCoverageMap),
    discoveryMatrix: discoveryCells
  });
}

/**
 * Checks whether a given file path is quarantined by partial coverage.
 * Under Presumption of Non-Pass, any partial unit or unmapped/uncovered path quarantines the finding.
 *
 * @param {string} filePath
 * @param {object} coverageResult
 * @returns {{ quarantined: boolean, unitId?: string, status?: string }}
 */
export function checkPathQuarantine(filePath, coverageResult) {
  if (!coverageResult) {
    return { quarantined: false };
  }

  const normTarget = normalizePath(filePath);
  if (!normTarget || normTarget === 'unknown') {
    return { quarantined: true, unitId: 'UNKNOWN_LOCATION', status: 'UNKNOWN' };
  }

  // 1. Check partialUnits first! (If ANY partial unit contains this path or child/parent, quarantine immediately)
  if (Array.isArray(coverageResult.partialUnits)) {
    for (const pu of coverageResult.partialUnits) {
      if (Array.isArray(pu.paths)) {
        for (const p of pu.paths) {
          if (normTarget === p || normTarget.startsWith(p + '/') || p.startsWith(normTarget + '/')) {
            return { quarantined: true, unitId: pu.coverageId, status: pu.status };
          }
        }
      }
    }
  }

  const pathMap = coverageResult.pathCoverageMap || {};

  // 2. Exact path check
  if (pathMap[normTarget]) {
    const info = pathMap[normTarget];
    if (info.status !== 'COVERED') {
      return { quarantined: true, unitId: info.coverageId, status: info.unitStatus };
    }
    return { quarantined: false };
  }

  // 3. Prefix checks in pathMap
  const matchingPrefixes = [];
  for (const [p, info] of Object.entries(pathMap)) {
    if (normTarget.startsWith(p + '/')) {
      matchingPrefixes.push(info);
    }
  }

  if (matchingPrefixes.length > 0) {
    // If ANY matching prefix is not covered, quarantine!
    const partialMatch = matchingPrefixes.find(info => info.status !== 'COVERED');
    if (partialMatch) {
      return { quarantined: true, unitId: partialMatch.coverageId, status: partialMatch.unitStatus };
    }
    // All matching prefixes are covered
    return { quarantined: false };
  }

  // 4. Path is absent from pathCoverageMap (unmapped path)
  // Under Presumption of Non-Pass, an unaudited/unmapped path cannot claim clean coverage
  return {
    quarantined: true,
    unitId: 'UNAUDITED_PATH',
    status: 'UNAUDITED'
  };
}

/**
 * Ingests a complete Cloudflare audit session: findings + coverage ledger.
 * Applies Quarantine Boundary: any finding associated with a partial coverage unit
 * or missing verifier confirmation fails closed to DEFERRED / COVERAGE_PARTIAL.
 *
 * @param {object} session
 * @param {string|object|Array} session.findings - Cloudflare findings.json
 * @param {string|object|Array} [session.coverageLedger] - Cloudflare coverage-ledger.json
 * @param {object} [options]
 * @returns {object} Complete canonical audit bundle
 */
export function ingestAuditSession({ findings, coverageLedger }, options = {}) {
  let coverageResult = null;
  if (coverageLedger) {
    coverageResult = ingestCoverageLedger(coverageLedger, options);
  }

  const findingsResult = ingestFindings(findings, {
    ...options,
    coverageLedgerResult: coverageResult
  });

  const candidatesResult = toCandidateSet(findings, options);

  // Overall clean declaration gate
  const reportableCount = findingsResult.summary.findingCounts.reportable;
  const coverageAllowsClean = coverageResult ? coverageResult.canDeclareClean : false;
  const canDeclareClean = Boolean(coverageAllowsClean && reportableCount === 0);

  return canonicalizeJson({
    schemaVersion: SCHEMA_VERSION,
    canonicalFindings: findingsResult.canonicalFindings,
    candidates: candidatesResult.candidates,
    coverageLedger: coverageResult,
    canDeclareClean,
    summary: {
      ...findingsResult.summary,
      coverageStatus: coverageResult ? coverageResult.coverageStatus : 'UNCHECKABLE',
      canDeclareClean,
      assuranceReason: canDeclareClean
        ? 'Bounded Clean Assurance: 0 reportable findings and complete ledger coverage.'
        : `Default-Deny Active: canDeclareClean=false (reportableFindings=${reportableCount}, coverage=${coverageResult ? coverageResult.coverageStatus : 'UNCHECKABLE'}).`
    }
  });
}

/**
 * Recovers a Cloudflare finding from an AGY Canonical Finding with zero semantic loss.
 * Preserves 100% of Cloudflare-specific unmapped metadata fields.
 *
 * @param {object} canonical
 * @returns {object} Cloudflare finding
 */
export function toCloudflareFinding(canonical) {
  if (!canonical || typeof canonical !== 'object') {
    throw new Error('[DEFAULT_DENY_ERROR] Cannot convert null or non-object canonical finding.');
  }

  const cfExt = canonical.extensions?.cloudflare || {};

  // Recover original verdict (normalized)
  let rawVerdict = cfExt.original_verdict;
  if (!rawVerdict) {
    if (canonical.disposition === 'REPORTABLE' || canonical.verdict === 'CONFIRMED') {
      rawVerdict = 'confirmed';
    } else if (canonical.disposition === 'SUPPRESSED' || canonical.verdict === 'FALSE_POSITIVE') {
      rawVerdict = 'rejected';
    } else {
      rawVerdict = 'needs_validation';
    }
  }
  const verdict = String(rawVerdict).toLowerCase().trim();

  const fingerprint = cfExt.fingerprint || canonical.lineageId || canonical.id;
  const title = canonical.title;
  const description = canonical.description;

  const trace = cfExt.trace || (canonical.proof && Array.isArray(canonical.proof.trace) ? canonical.proof.trace : [
    {
      kind: 'sink',
      file: canonical.location?.uri || 'unknown',
      line: canonical.location?.startLine || 1,
      scope: 'main',
      description: canonical.location?.lineSnippet || 'Vulnerability location'
    }
  ]);

  const evidence = cfExt.evidence || (canonical.evidence && Array.isArray(canonical.evidence) ? canonical.evidence : [
    {
      file: canonical.location?.uri || 'unknown',
      line: canonical.location?.startLine || 1,
      description: canonical.location?.lineSnippet || canonical.title
    }
  ]);

  const conditions = cfExt.conditions || (canonical.proof && Array.isArray(canonical.proof.conditions) ? canonical.proof.conditions : null);

  const recovered = {
    verdict,
    fingerprint,
    title,
    description
  };

  if (verdict === 'confirmed') {
    recovered.root_cause = cfExt.root_cause || canonical.defectManagement?.rootCause || 'Root cause verified by verifier';
    recovered.intended_behavior = cfExt.intended_behavior || canonical.securityProperty || 'Intended security behavior';
    recovered.trace = trace;
    recovered.evidence = evidence;
    recovered.conditions = conditions || [];
    recovered.execution = cfExt.execution || canonical.proof?.execution || {
      attacker_perspective: 'Remote Caller',
      payloads: ['reproduction-payload'],
      instructions: ['Execute reproduction'],
      observed_result: 'Vulnerability verified'
    };
    recovered.remediation = cfExt.remediation || {
      strategy: canonical.defectManagement?.preventiveAction || 'Implement security controls'
    };
    recovered.severity = cfExt.severity || {
      likelihood: { score: 'high', reason: 'Verified' },
      impact: { score: canonical.severity ? canonical.severity.toLowerCase() : 'high', reason: 'Demonstrated' },
      overall_severity: canonical.severity ? canonical.severity.toLowerCase() : 'high'
    };
    recovered.confidence = cfExt.confidence || {
      score: 'high',
      reason: 'Affirmatively verified'
    };
  } else if (verdict === 'needs_validation') {
    recovered.claimed_root_cause = cfExt.claimed_root_cause || cfExt.root_cause || canonical.defectManagement?.rootCause || 'Hypothesized root cause';
    recovered.trace = trace;
    recovered.evidence = evidence;
    if (Array.isArray(conditions) && conditions.length > 0) {
      recovered.conditions = conditions;
    }
    if (cfExt.execution) {
      recovered.execution = cfExt.execution;
    }
    if (cfExt.remediation) {
      recovered.remediation = cfExt.remediation;
    }
    recovered.blockers = cfExt.blockers || [canonical.dispositionReason || 'Validation blocked pending evidence'];
    recovered.validation_plan = cfExt.validation_plan || {
      local: 'Run unit test reproduction',
      deployment: 'Verify environment configuration'
    };
  } else if (verdict === 'rejected') {
    recovered.claimed_root_cause = cfExt.claimed_root_cause || cfExt.root_cause || canonical.defectManagement?.rootCause || 'Hypothesized root cause';
    recovered.trace = trace;
    recovered.evidence = evidence;
    if (Array.isArray(conditions) && conditions.length > 0) {
      recovered.conditions = conditions;
    }
    if (cfExt.execution) {
      recovered.execution = cfExt.execution;
    }
    if (cfExt.remediation) {
      recovered.remediation = cfExt.remediation;
    }
    recovered.reason = cfExt.reason || canonical.dispositionReason || 'Refuted by verifier';
  }

  // Preserve core Cloudflare properties
  if (cfExt.attack_class) recovered.attack_class = cfExt.attack_class;
  if (cfExt.phase) recovered.phase = cfExt.phase;
  if (cfExt.raw_tokens) recovered.raw_tokens = cfExt.raw_tokens;

  // Recover ALL unmapped properties present in extensions.cloudflare
  const knownKeys = new Set([
    'original_verdict', 'verdict', 'fingerprint', 'title', 'description',
    'root_cause', 'claimed_root_cause', 'intended_behavior',
    'trace', 'evidence', 'conditions', 'execution', 'remediation',
    'severity', 'confidence', 'blockers', 'validation_plan', 'reason',
    'attack_class', 'phase', 'raw_tokens'
  ]);

  for (const [k, v] of Object.entries(cfExt)) {
    if (!knownKeys.has(k) && v !== undefined && v !== null) {
      recovered[k] = v;
    }
  }

  return canonicalizeJson(recovered);
}

/**
 * Recovers an array of Cloudflare findings from an array of Canonical Findings.
 * @param {object[]} canonicalList
 * @returns {object[]}
 */
export function toCloudflareFindings(canonicalList) {
  if (!Array.isArray(canonicalList)) {
    throw new Error('[DEFAULT_DENY_ERROR] Expected array of canonical findings.');
  }
  return canonicalList.map(toCloudflareFinding);
}

// -----------------------------------------------------------------------------
// CLI Execution
// -----------------------------------------------------------------------------

function printUsage() {
  console.log(`
Cloudflare Security Audit Adapter (scripts/adapters/cloudflare-adapter.mjs)
Lossless unidirectional ingestion of Cloudflare findings and coverage ledger into AGY.

Usage:
  node scripts/adapters/cloudflare-adapter.mjs [options]

Options:
  --findings <path>             Path to Cloudflare findings.json
  --coverage <path>             Path to Cloudflare coverage-ledger.json
  --output-canonical <path>     Write canonical findings JSON to path
  --output-candidates <path>    Write candidate set JSON to path
  --output-ledger <path>        Write evidence ledger JSON to path
  --output-session <path>       Write combined session output JSON to path
  --fail-closed-severity        Fail closed on injected severity in needs_validation
  --help                        Display this help message
`);
}

export async function runCli() {
  const args = process.argv.slice(2);
  if (args.includes('--help') || args.includes('-h') || args.length === 0) {
    printUsage();
    process.exit(0);
  }

  const getArg = (flag) => {
    const idx = args.indexOf(flag);
    return idx !== -1 && idx + 1 < args.length ? args[idx + 1] : null;
  };

  const findingsPath = getArg('--findings');
  const coveragePath = getArg('--coverage');
  const outCanonical = getArg('--output-canonical');
  const outCandidates = getArg('--output-candidates');
  const outLedger = getArg('--output-ledger');
  const outSession = getArg('--output-session');
  const failClosedSeverity = args.includes('--fail-closed-severity');

  const options = {
    failClosedOnInjectedSeverity: failClosedSeverity
  };

  let findingsContent = null;
  if (findingsPath) {
    if (!fs.existsSync(findingsPath)) {
      console.error(`Error: Findings file not found at '${findingsPath}'`);
      process.exit(1);
    }
    findingsContent = fs.readFileSync(findingsPath, 'utf8');
  }

  let coverageContent = null;
  if (coveragePath) {
    if (!fs.existsSync(coveragePath)) {
      console.error(`Error: Coverage ledger file not found at '${coveragePath}'`);
      process.exit(1);
    }
    coverageContent = fs.readFileSync(coveragePath, 'utf8');
  }

  if (!findingsContent && !coverageContent) {
    console.error('Error: At least one of --findings or --coverage must be provided.');
    process.exit(1);
  }

  if (outSession && (findingsContent || coverageContent)) {
    const sessionRes = ingestAuditSession({
      findings: findingsContent || [],
      coverageLedger: coverageContent || null
    }, options);
    fs.mkdirSync(path.dirname(path.resolve(outSession)), { recursive: true });
    fs.writeFileSync(outSession, deterministicStringify(sessionRes), 'utf8');
    console.log(`Wrote session output to ${outSession}`);
  }

  if (findingsContent) {
    if (outCanonical) {
      const canonicalRes = ingestFindings(findingsContent, options);
      fs.mkdirSync(path.dirname(path.resolve(outCanonical)), { recursive: true });
      fs.writeFileSync(outCanonical, deterministicStringify(canonicalRes), 'utf8');
      console.log(`Wrote canonical findings to ${outCanonical}`);
    }
    if (outCandidates) {
      const candRes = toCandidateSet(findingsContent, options);
      fs.mkdirSync(path.dirname(path.resolve(outCandidates)), { recursive: true });
      fs.writeFileSync(outCandidates, deterministicStringify(candRes), 'utf8');
      console.log(`Wrote candidate set to ${outCandidates}`);
    }
  }

  if (coverageContent && outLedger) {
    const ledgerRes = ingestCoverageLedger(coverageContent, options);
    fs.mkdirSync(path.dirname(path.resolve(outLedger)), { recursive: true });
    fs.writeFileSync(outLedger, deterministicStringify(ledgerRes), 'utf8');
    console.log(`Wrote coverage ledger to ${outLedger}`);
  }
}

const isDirectExecution = process.argv[1] && fileURLToPath(import.meta.url) === path.resolve(process.argv[1]);
if (isDirectExecution) {
  runCli().catch(err => {
    console.error(`Fatal: ${err.message}`);
    process.exit(1);
  });
}
