#!/usr/bin/env node
/**
 * finalize-scan.mjs
 * Deterministic Security Authority for the AGY Security Audit Skill.
 * Enforces canonical scan contracts, default-deny disposition derivation,
 * confidence clamping, secret redaction, output sanitization,
 * and coverage reconciliation.
 */

import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { getHardenedGitProvenance, runSafeGit } from './safe-git.mjs';

export const CVSS_V4_REGEX = /^CVSS:4\.0\/AV:[NALP]\/AC:[LH]\/AT:[NP]\/PR:[NLH]\/UI:[NPA]\/VC:[HLN]\/VI:[HLN]\/VA:[HLN]\/SC:[HLN]\/SI:[HLN]\/SA:[HLN]/;

// Common secret patterns for deterministic redaction
export const SECRET_PATTERNS = [
  { type: 'AWS_ACCESS_KEY', regex: /(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}/g },
  { type: 'BEARER_TOKEN', regex: /bearer\s+[a-zA-Z0-9_\-\.:=_\+\/]{20,}/gi },
  { type: 'PRIVATE_KEY', regex: /-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----/g },
  { type: 'GENERIC_SECRET_KV', regex: /(?:api[_-]?key|access[_-]?token|auth[_-]?token|secret[_-]?key|password|passwd|pwd)\s*[:=]\s*["']?([a-zA-Z0-9_\-\.\+=/]{16,})["']?/gi },
  { type: 'JWT_TOKEN', regex: /eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*/g }
];

/**
 * Strips ANSI escapes, C0/C1 non-printable controls, and Bidi override characters.
 */
export function stripControlAndBidi(str) {
  if (!str) return '';
  return String(str)
    .replace(/\x1B(?:\[[0-?]*[ -/]*[@-~]|[@-Z\\-_])/g, '') // ANSI escape sequences
    .replace(/[\u200E\u200F\u202A-\u202E\u2066-\u2069]/g, '') // Bidi overrides
    .replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F-\x9F]/g, ''); // C0 and C1 controls (preserving \t and \n)
}

/**
 * Escapes standard HTML entities.
 */
export function escapeHtml(str) {
  if (!str) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

/**
 * Sanitizes inline markdown text (anti-HTML + anti-link breakout + strip controls).
 */
export function sanitizeInlineText(str) {
  if (!str) return '';
  const cleaned = stripControlAndBidi(str);
  return escapeHtml(cleaned)
    .replace(/!\[/g, '&#33;&#91;')
    .replace(/\[/g, '&#91;')
    .replace(/\]/g, '&#93;')
    .replace(/\(/g, '&#40;')
    .replace(/\)/g, '&#41;');
}

/**
 * Sanitizes text destined for Markdown table cells (escapes pipes and converts newlines).
 */
export function sanitizeTableCell(str) {
  if (!str) return '';
  return sanitizeInlineText(str)
    .replace(/\|/g, '&#124;')
    .replace(/\r?\n/g, ' ');
}

/**
 * Sanitizes block Markdown text (escapes heading injection and code fence breakout).
 */
export function sanitizeBlockText(str) {
  if (!str) return '';
  const cleaned = stripControlAndBidi(str);
  const escaped = escapeHtml(cleaned)
    .replace(/^(\s*)(#+)/gm, '$1\\$2') // Escape markdown headings
    .replace(/```/g, '\\`\\`\\`'); // Escape code fence breakouts
  return escaped;
}

/**
 * Sanitizes code snippets (escapes code fence breakouts).
 */
export function sanitizeCodeSnippet(str) {
  if (!str) return '';
  const cleaned = stripControlAndBidi(str);
  return cleaned.replace(/```/g, '\\`\\`\\`');
}

/**
 * Deterministically redacts secrets from arbitrary text, returning sanitized text.
 */
export function redactSecrets(text) {
  if (!text) return '';
  let result = String(text);
  for (const { type, regex } of SECRET_PATTERNS) {
    result = result.replace(regex, (match) => {
      const hash = crypto.createHash('sha256').update(match).digest('hex').substring(0, 8);
      return `[REDACTED_${type}; len=${match.length}; fp=${hash}]`;
    });
  }
  return result;
}

/**
 * Calculates objective mathematical rigor score in [0.0, 1.0].
 */
export function calculateRigor(metrics = {}) {
  const sSink = metrics.sinkVerified ? 1.0 : 0.0;
  const sSource = metrics.sourceVerified ? 1.0 : 0.0;
  const flowTotal = Number(metrics.dataflowTotalSteps) || 0;
  const flowVerified = Number(metrics.dataflowVerifiedSteps) || 0;
  const flowRatio = flowTotal > 0 ? Math.min(1.0, Math.max(0.0, flowVerified / flowTotal)) : 0.0;
  const sPoc = metrics.pocSyntacticDemonstrated ? 1.0 : 0.0;
  const sMitigation = metrics.mitigationInspected ? 1.0 : 0.0;

  const score = Number((0.25 * sSink + 0.25 * sSource + 0.25 * flowRatio + 0.15 * sPoc + 0.10 * sMitigation).toFixed(4));

  let assuranceLevel = 'LOW_RIGOR';
  if (score >= 0.85) {
    assuranceLevel = 'HIGH_RIGOR';
  } else if (score >= 0.60) {
    assuranceLevel = 'MODERATE_RIGOR';
  }

  return { score, assuranceLevel };
}

/**
 * Validates Directory Reconciliation Manifest according to Directory Accounting standards.
 */
export function validateDirectoryManifest(manifest) {
  if (!manifest || !Array.isArray(manifest.entries)) {
    return { valid: false, error: 'Manifest must contain an "entries" array.' };
  }
  if (manifest.entries.length === 0) {
    return { valid: false, error: 'UNACCOUNTED_DIRECTORY_ERROR: Directory manifest cannot be empty.' };
  }

  const validStatuses = new Set([
    'SCANNED',
    'EXCLUDED_VENDORED',
    'EXCLUDED_GENERATED',
    'EXCLUDED_NON_CODE',
    'EXCLUDED_TEST'
  ]);

  for (const entry of manifest.entries) {
    if (!entry.path) {
      return { valid: false, error: 'Directory entry missing "path" property.' };
    }
    if (!validStatuses.has(entry.status)) {
      return {
        valid: false,
        error: `UNACCOUNTED_DIRECTORY_ERROR: Directory "${entry.path}" has invalid or unaccounted status "${entry.status}".`
      };
    }
    if (entry.status.startsWith('EXCLUDED_') && (!entry.reason || entry.reason.trim().length === 0)) {
      return {
        valid: false,
        error: `UNACCOUNTED_DIRECTORY_ERROR: Excluded directory "${entry.path}" lacks explicit audit reason.`
      };
    }
  }

  return { valid: true };
}

/**
 * Validates Review Manifest according to Review mode standards.
 */
export function validateReviewManifest(manifest) {
  if (!manifest || typeof manifest !== 'object') {
    return { valid: false, error: 'Review manifest must be a valid object.' };
  }
  const inventory = manifest.reviewInventory || manifest;
  const changed = Array.isArray(inventory.changedFiles) ? inventory.changedFiles : [];
  const deleted = Array.isArray(inventory.deletedFiles) ? inventory.deletedFiles : [];

  if (!Array.isArray(inventory.changedFiles) && !Array.isArray(inventory.deletedFiles)) {
    return { valid: false, error: 'Review manifest must contain changedFiles or deletedFiles array.' };
  }

  for (const f of changed) {
    if (!f.path) return { valid: false, error: 'Changed file entry missing path property.' };
  }
  for (const f of deleted) {
    if (!f.path) return { valid: false, error: 'Deleted file entry missing path property.' };
  }

  return { valid: true, totalAccounted: changed.length + deleted.length };
}

/**
 * Reconciles coverage across scan and review manifests.
 */
export function reconcileCoverage(manifest) {
  if (!manifest) {
    return { valid: false, status: 'UNCHECKABLE', mode: 'none', error: 'No coverage manifest provided.' };
  }
  if (manifest.mode === 'review' || manifest.reviewInventory || (Array.isArray(manifest.changedFiles) && !Array.isArray(manifest.entries))) {
    const res = validateReviewManifest(manifest);
    return {
      valid: res.valid,
      status: res.valid ? 'COMPLETE' : 'PARTIAL',
      mode: 'review',
      error: res.error || null
    };
  }
  const res = validateDirectoryManifest(manifest);
  return {
    valid: res.valid,
    status: res.valid ? 'COMPLETE' : 'PARTIAL',
    mode: 'scan',
    error: res.error || null
  };
}


/**
 * Validates that a path does not escape the repository boundary via path traversal.
 */
export function isPathContained(repoRoot, filePath) {
  if (!filePath || typeof filePath !== 'string') return false;
  // Deny explicit traversal sequences
  if (filePath.includes('..\\') || filePath.includes('../') || filePath === '..' || filePath.endsWith('/..') || filePath.endsWith('\\..')) {
    return false;
  }
  const resolved = path.isAbsolute(filePath) ? path.resolve(filePath) : path.resolve(repoRoot, filePath);
  const rootResolved = path.resolve(repoRoot);
  const relative = path.relative(rootResolved, resolved);
  return !relative.startsWith('..') && !path.isAbsolute(relative);
}

/**
 * Normalizes any OS path to an RFC 3986 compliant relative forward-slash URI.
 */
export function normalizeUri(repoRoot, filePath) {
  if (!filePath) return 'unknown';
  const rel = path.isAbsolute(filePath)
    ? path.relative(repoRoot, filePath)
    : filePath;
  const forwardSlash = rel.split(path.sep).join('/');
  return forwardSlash.split('/').map(segment => encodeURIComponent(segment)).join('/');
}

/**
 * Validates CVSS v4 vector fail-closed. Never substitutes a fake high-severity vector.
 */
export function validateCvssV4(cvssObj) {
  if (!cvssObj || typeof cvssObj !== 'object') {
    return { valid: false, vector: null, score: null, severity: 'UNRATED' };
  }

  const rawVector = cvssObj.vector;
  if (!rawVector || !CVSS_V4_REGEX.test(rawVector)) {
    return {
      valid: false,
      vector: null,
      score: null,
      severity: 'UNRATED',
      error: 'Invalid or missing CVSS v4 vector'
    };
  }

  const rawScore = typeof cvssObj.score === 'number' ? cvssObj.score : null;
  const clampedScore = rawScore !== null ? Math.min(10.0, Math.max(0.0, rawScore)) : null;

  return {
    valid: true,
    vector: rawVector,
    score: clampedScore,
    severity: cvssObj.severity || (clampedScore >= 9.0 ? 'CRITICAL' : clampedScore >= 7.0 ? 'HIGH' : clampedScore >= 4.0 ? 'MEDIUM' : 'LOW')
  };
}

/**
 * Derives the deterministic disposition under the Presumption of Non-Pass (Default-Deny).
 * Raw verdict from input is strictly treated as an untrusted candidate hint and NEVER has authority.
 */
export function deriveFinalDisposition(candidate, votes = [], rigor = { score: 0 }) {
  // 1. Schema & Location Containment Validation
  if (!candidate || typeof candidate !== 'object') {
    return { disposition: 'DEFERRED', mappedVerdict: 'NEEDS_MANUAL_REVIEW', reason: 'Malformed candidate' };
  }

  const loc = candidate.location || {};
  const uri = loc.uri || loc.path;
  const startLine = Number(loc.startLine);

  if (!uri || isNaN(startLine) || startLine < 1) {
    return { disposition: 'DEFERRED', mappedVerdict: 'NEEDS_MANUAL_REVIEW', reason: 'Missing concrete location' };
  }

  // 2. Candidate task-binding and deduplication of votes
  const candidateVotes = votes.filter(v => v && (v.findingId === candidate.id || !v.findingId));
  const dedupedVotes = [];
  const seenKeys = new Set();

  for (const v of candidateVotes) {
    const key = v.reviewerId || v.persona || (v.lens ? `lens:${v.lens}` : null) || JSON.stringify(v);
    if (!seenKeys.has(key)) {
      seenKeys.add(key);
      dedupedVotes.push(v);
    }
  }

  // 3. Evaluate votes if present
  if (dedupedVotes.length > 0) {
    let supports = 0;
    let refutes = 0;
    let hasDecisiveMitigation = false;

    for (const v of dedupedVotes) {
      const decision = String(v.decision || v.verdict || '').toUpperCase();
      if (['CONFIRMED', 'SUPPORTS', 'REPORTABLE'].includes(decision)) {
        supports++;
      } else if (['FALSE_POSITIVE', 'REFUTES', 'SUPPRESSED'].includes(decision)) {
        refutes++;
        if (v.mitigationProofLine || (v.mitigationReason && v.mitigationReason.trim().length > 0)) {
          hasDecisiveMitigation = true;
        }
      }
    }

    const total = dedupedVotes.length;

    // Decisive counterevidence refutation
    if (hasDecisiveMitigation && refutes > supports) {
      return {
        disposition: 'SUPPRESSED',
        mappedVerdict: 'FALSE_POSITIVE',
        reason: 'Affirmatively refuted by verifier with positive mitigation evidence',
        votesSummary: { total, supports, refutes, unanimous: refutes === total }
      };
    }

    // Quorum rule: Need at least 2 independent votes
    if (total < 2) {
      return {
        disposition: 'DEFERRED',
        mappedVerdict: 'NEEDS_MANUAL_REVIEW',
        reason: 'Quorum not met: requires at least 2 independent verifier votes',
        votesSummary: { total, supports, refutes, unanimous: false }
      };
    }

    const supportRatio = supports / total;

    // Reportable requirement: 2/3 supermajority + rigor or verified flow
    if (supportRatio >= 0.66 && (rigor.score >= 0.60 || candidate.dataflowVerified || candidate.sourceVerified || candidate.rigorMetrics?.sourceVerified)) {
      return {
        disposition: 'REPORTABLE',
        mappedVerdict: 'CONFIRMED',
        reason: 'Confirmed by 2/3 verifier supermajority with verified taint evidence',
        votesSummary: { total, supports, refutes, unanimous: supports === total }
      };
    }

    // Refuted requirement: 3/4 supermajority + affirmative mitigation
    if (refutes / total >= 0.75 && (candidate.mitigationProofLine || candidate.mitigationReason)) {
      return {
        disposition: 'SUPPRESSED',
        mappedVerdict: 'FALSE_POSITIVE',
        reason: 'Refuted by 3/4 verifier supermajority with affirmative mitigation',
        votesSummary: { total, supports, refutes, unanimous: refutes === total }
      };
    }

    // Fallback on dispute / split decision
    return {
      disposition: 'DEFERRED',
      mappedVerdict: 'NEEDS_MANUAL_REVIEW',
      reason: 'Panel split or unproven evidence under default-deny',
      votesSummary: { total, supports, refutes, unanimous: false }
    };
  }

  // 4. If no votes array, check candidate.consensus if supplied
  if (candidate.consensus && typeof candidate.consensus === 'object') {
    const total = Number(candidate.consensus.totalVotes) || 0;
    const unanimous = Boolean(candidate.consensus.unanimous);

    // CRITICAL: 0 votes CANNOT be confirmed! Missing consensus cannot default to unanimous!
    if (total === 0) {
      return {
        disposition: 'DEFERRED',
        mappedVerdict: 'NEEDS_MANUAL_REVIEW',
        reason: 'Zero votes recorded; cannot confirm under default-deny',
        votesSummary: { total: 0, supports: 0, refutes: 0, unanimous: false }
      };
    }

    if (total >= 2 && unanimous && (rigor.score >= 0.60 || candidate.sourceVerified || candidate.rigorMetrics?.sourceVerified)) {
      return {
        disposition: 'REPORTABLE',
        mappedVerdict: 'CONFIRMED',
        reason: 'Consensus validated with quorum',
        votesSummary: { total, supports: total, refutes: 0, unanimous: true }
      };
    }

    return {
      disposition: 'DEFERRED',
      mappedVerdict: 'NEEDS_MANUAL_REVIEW',
      reason: 'Consensus lacks quorum or unanimity',
      votesSummary: { total, supports: 0, refutes: 0, unanimous }
    };
  }

  // 5. Default-Deny: 0 votes and no consensus -> DEFERRED
  return {
    disposition: 'DEFERRED',
    mappedVerdict: 'NEEDS_MANUAL_REVIEW',
    reason: 'No verifier panel or consensus record; presumed unverified',
    votesSummary: { total: 0, supports: 0, refutes: 0, unanimous: false }
  };
}

/**
 * Clamps confidence objectively based on derived disposition and panel agreement.
 */
export function clampConfidence(disposition, votesSummary = {}, rawConfidence = null) {
  const conf = typeof rawConfidence === 'number' ? rawConfidence : null;

  if (disposition === 'DEFERRED') {
    return { score: conf !== null ? Math.min(0.40, conf) : 0.30, level: 'low' };
  }

  if (disposition === 'SUPPRESSED') {
    return { score: conf !== null ? Math.min(0.50, conf) : 0.40, level: 'low' };
  }

  if (disposition === 'REPORTABLE') {
    const { total = 0, unanimous = false } = votesSummary;
    if (total >= 3 && unanimous) {
      return { score: conf !== null ? Math.min(0.95, Math.max(0.75, conf)) : 0.85, level: 'high' };
    }
    // 2/3 majority or 2-member unanimous panel clamps to medium
    return { score: conf !== null ? Math.min(0.70, Math.max(0.50, conf)) : 0.65, level: 'medium' };
  }

  return { score: 0.20, level: 'low' };
}

/**
 * Computes deterministic partial fingerprint for line hash.
 */
export function computeLineHash(content) {
  if (!content) return '0000000000000000';
  return crypto.createHash('sha256').update(content.trim()).digest('hex').substring(0, 16);
}

/**
 * Computes stable finding fingerprint.
 */
export function computeFindingFingerprint(ruleId, uri, startLine) {
  const payload = `${ruleId || 'SEC'}:${uri || 'unknown'}:${startLine || 1}`;
  return crypto.createHash('sha256').update(payload).digest('hex').substring(0, 16);
}

/**
 * Central deterministic finalizer: transforms candidates into canonical findings.
 */
export function finalizeScan({
  candidates = [],
  manifest = null,
  repoRoot = process.cwd(),
  provenance = null,
  votes = []
}) {
  // 1. Coverage Reconciliation
  const coverageReconciliation = reconcileCoverage(manifest);
  const coverageStatus = coverageReconciliation.status;
  const coverageMode = coverageReconciliation.mode;


  // 2. Process Candidates into Canonical Findings
  const canonicalFindings = [];

  for (let i = 0; i < candidates.length; i++) {
    const raw = candidates[i];
    const candidateId = raw.id || `SEC-${String(i + 1).padStart(3, '0')}`;
    const ruleId = raw.ruleId || 'SEC-VULN';

    // Target containment check
    const rawUri = raw.location?.uri || raw.location?.path || 'unknown';
    const pathContained = isPathContained(repoRoot, rawUri);
    const normalizedRelativeUri = pathContained ? normalizeUri(repoRoot, rawUri) : 'invalid_path_escaped';

    const startLine = Number(raw.location?.startLine) >= 1 ? Number(raw.location?.startLine) : 1;
    const endLine = Number(raw.location?.endLine) >= startLine ? Number(raw.location?.endLine) : startLine;

    // Mathematical Rigor
    const rigor = calculateRigor(raw.rigorMetrics);

    // CVSS v4 Validation
    const cvss = validateCvssV4(raw.cvssV4);

    // Check if this is a credential/secret finding
    const isCredentialFinding = /secret|credential|cwe-798|token|password|api[_-]?key/i.test(ruleId) ||
      /secret|credential|token|password|api[_-]?key/i.test(raw.title || '');

    // Secret Redaction & Sanitization
    const rawSnippet = raw.location?.lineSnippet || '';
    const sanitizedSnippet = isCredentialFinding
      ? '[Line snippet suppressed for credential finding]'
      : sanitizeCodeSnippet(redactSecrets(rawSnippet));

    const lineHash = computeLineHash(rawSnippet);

    const titleRedacted = redactSecrets(raw.title || `Security finding in ${normalizedRelativeUri}`);
    const descRedacted = redactSecrets(raw.description || titleRedacted);

    // Disposition Derivation
    let dispositionResult;
    if (!pathContained) {
      dispositionResult = {
        disposition: 'DEFERRED',
        mappedVerdict: 'NEEDS_MANUAL_REVIEW',
        reason: 'Path escapes repository root via traversal sequence',
        votesSummary: { total: 0, supports: 0, refutes: 0, unanimous: false }
      };
    } else {
      dispositionResult = deriveFinalDisposition(raw, votes, rigor);
    }

    // Confidence Clamp
    const confidence = clampConfidence(
      dispositionResult.disposition,
      dispositionResult.votesSummary,
      raw.confidence
    );

    // Severity determination
    let severity = String(raw.severity || cvss.severity || 'HIGH').toUpperCase();
    if (!['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].includes(severity)) {
      severity = 'MEDIUM';
    }

    const stableFingerprint = computeFindingFingerprint(ruleId, normalizedRelativeUri, startLine);

    canonicalFindings.push({
      id: candidateId,
      ruleId,
      title: titleRedacted,
      description: descRedacted,
      disposition: dispositionResult.disposition,
      verdict: dispositionResult.mappedVerdict,
      dispositionReason: dispositionResult.reason,
      severity,
      confidenceScore: confidence.score,
      confidenceLevel: confidence.level,
      location: {
        uri: normalizedRelativeUri,
        startLine,
        endLine,
        lineSnippet: sanitizedSnippet,
        lineHash
      },
      cvssV4: cvss.valid ? { vector: cvss.vector, score: cvss.score, severity: cvss.severity } : null,
      rigor,
      consensus: dispositionResult.votesSummary || {
        totalVotes: 0,
        unanimous: false,
        minorityEscalated: false
      },
      fingerprint: stableFingerprint,
      tags: raw.tags || []
    });
  }

  // 3. Summary Statistics
  const confirmedCount = canonicalFindings.filter(f => f.disposition === 'REPORTABLE').length;
  const deferredCount = canonicalFindings.filter(f => f.disposition === 'DEFERRED').length;
  const suppressedCount = canonicalFindings.filter(f => f.disposition === 'SUPPRESSED').length;

  const canDeclareClean = (coverageStatus === 'COMPLETE' && confirmedCount === 0 && deferredCount === 0);

  const summary = {
    totalCandidates: canonicalFindings.length,
    confirmedCount,
    deferredCount,
    suppressedCount,
    coverageStatus,
    manifestValid: coverageReconciliation.valid,
    coverageMode,
    canDeclareClean
  };

  return {
    summary,
    coverageStatus,
    coverageMode,
    manifest,
    manifestValidation: coverageReconciliation,
    provenance: provenance || getHardenedGitProvenance(repoRoot),
    canonicalFindings
  };

}

/**
 * Maps finding severity to SARIF level and security-severity float.
 */
export function mapSeverityToSarif(severity, cvssScore) {
  const sev = String(severity || '').toUpperCase();
  let level = 'warning';
  let defaultScore = '5.0';

  if (sev === 'CRITICAL') {
    level = 'error';
    defaultScore = '9.5';
  } else if (sev === 'HIGH') {
    level = 'error';
    defaultScore = '8.0';
  } else if (sev === 'MEDIUM') {
    level = 'warning';
    defaultScore = '5.5';
  } else if (sev === 'LOW') {
    level = 'note';
    defaultScore = '2.5';
  }

  const numericScore = typeof cvssScore === 'number'
    ? cvssScore.toFixed(1)
    : defaultScore;

  return { level, securitySeverity: numericScore };
}

/**
 * Renders SARIF 2.1.0 document from canonical findings.
 */
export function renderSarifFromCanonical({
  canonicalFindings = [],
  manifest = null,
  coverageStatus = 'COMPLETE',
  provenance = null,
  repoRoot = process.cwd()
}) {
  const rulesMap = new Map();
  const results = [];

  for (const f of canonicalFindings) {
    const ruleId = f.ruleId || 'SEC-VULN';
    const cvssScore = f.cvssV4 ? f.cvssV4.score : null;
    const { level, securitySeverity } = mapSeverityToSarif(f.severity, cvssScore);

    if (!rulesMap.has(ruleId)) {
      rulesMap.set(ruleId, {
        id: ruleId,
        name: f.title || ruleId,
        shortDescription: { text: f.title || ruleId },
        fullDescription: { text: f.description || f.title || ruleId },
        properties: {
          'security-severity': securitySeverity,
          cvssV4Vector: f.cvssV4?.vector || null,
          tags: ['security', 'vulnerability', ...(f.tags || [])]
        }
      });
    }

    const ruleIndex = Array.from(rulesMap.keys()).indexOf(ruleId);

    // SARIF result level: error for reportable, warning for deferred, note for suppressed
    const resultLevel = f.disposition === 'REPORTABLE' ? level : f.disposition === 'DEFERRED' ? 'warning' : 'note';

    results.push({
      ruleId,
      ruleIndex,
      level: resultLevel,
      message: { text: f.description || f.title },
      locations: [
        {
          physicalLocation: {
            artifactLocation: {
              uri: f.location.uri,
              uriBaseId: '%SRCROOT%'
            },
            region: {
              startLine: f.location.startLine,
              endLine: f.location.endLine
            }
          }
        }
      ],
      partialFingerprints: {
        primaryLocationLineHash: f.location.lineHash,
        stableFingerprint: f.fingerprint
      },
      properties: {
        disposition: f.disposition,
        verdict: f.verdict,
        dispositionReason: f.dispositionReason,
        confidence: f.confidenceScore,
        confidenceLevel: f.confidenceLevel,
        cvssV4: f.cvssV4,
        computedRigor: f.rigor,
        consensus: f.consensus
      }
    });
  }

  const run = {
    tool: {
      driver: {
        name: 'AGY Security Audit',
        version: '0.9.1',
        informationUri: 'https://antigravity.google/docs/security',
        rules: Array.from(rulesMap.values())
      }
    },
    versionControlProvenance: provenance ? [provenance] : [],
    results,
    properties: {
      coverageStatus,
      directoryReconciliationManifest: manifest
    }
  };

  return {
    version: '2.1.0',
    $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
    runs: [run]
  };
}

/**
 * Renders hardened Markdown report from canonical findings.
 */
export function renderMarkdownFromCanonical({
  canonicalFindings = [],
  manifest = null,
  coverageStatus = 'COMPLETE',
  provenance = null
}) {
  const timestamp = new Date().toISOString();
  const sha12 = (provenance?.properties?.sha12) || 'unknown';
  const branch = provenance?.branch || 'unknown';
  const isDirty = (provenance?.properties?.isDirty) ? ' (DIRTY)' : ' (CLEAN)';

  let md = '# Security Audit Report\n\n';
  md += `- **Generated At (UTC)**: \`${timestamp}\`\n`;
  md += `- **Target Revision**: \`${sha12}\` on branch \`${branch}\`${isDirty}\n`;
  if (provenance?.properties?.dirtyDiffSha256) {
    md += `- **Dirty Diff SHA-256**: \`${provenance.properties.dirtyDiffSha256}\`\n`;
  }
  md += `- **Coverage Status**: **${coverageStatus}**\n`;
  md += '- **Audit Axiom**: **Presumption of Non-Pass (Default-Deny)**\n\n';
  md += '---\n\n';

  // Coverage Reconciliation Section
  if (manifest && (manifest.mode === 'review' || manifest.reviewInventory || (Array.isArray(manifest.changedFiles) && !Array.isArray(manifest.entries)))) {
    md += '## 1. Changed Files Accounting Manifest (Review Mode)\n\n';
    const inv = manifest.reviewInventory || manifest;
    const changed = Array.isArray(inv.changedFiles) ? inv.changedFiles : [];
    const deleted = Array.isArray(inv.deletedFiles) ? inv.deletedFiles : [];
    if (changed.length === 0 && deleted.length === 0) {
      md += '*No files modified or deleted in target diff.*\n';
    } else {
      md += '| File Path | Status | Details |\n';
      md += '| :--- | :--- | :--- |\n';
      for (const f of changed) {
        md += `| \`${sanitizeTableCell(f.path)}\` | **${sanitizeTableCell(f.status)}** | ${f.originalPath ? `Renamed from \`${sanitizeTableCell(f.originalPath)}\`` : 'Active in change diff'} |\n`;
      }
      for (const f of deleted) {
        md += `| \`${sanitizeTableCell(f.path)}\` | **${sanitizeTableCell(f.status)}** | Baseline: \`${sanitizeTableCell(f.baselineRevision ? f.baselineRevision.substring(0, 12) : 'HEAD')}\` |\n`;
      }
    }
  } else {
    // Directory Reconciliation Section (Scan Mode)
    md += '## 1. Directory Reconciliation Manifest\n\n';
    if (manifest && Array.isArray(manifest.entries)) {
      md += '| Directory Path | Audit Status | Files | Reconciliation Reason |\n';
      md += '| :--- | :--- | :--- | :--- |\n';
      for (const e of manifest.entries) {
        md += `| \`${sanitizeTableCell(e.path)}\` | **${sanitizeTableCell(e.status)}** | ${Number(e.fileCount) || 0} | ${sanitizeTableCell(e.reason)} |\n`;
      }
    } else {
      md += '> [!WARNING]\n> No Directory Reconciliation Manifest provided. Default-deny flags this audit as unverified coverage.\n';
    }
  }


  if (coverageStatus !== 'COMPLETE') {
    md += '\n> [!WARNING]\n> **Incomplete Coverage**: Under Default-Deny, repository cannot be certified clean when coverage is PARTIAL or UNCHECKABLE.\n';
  }
  md += '\n---\n\n';

  // Categorize canonical findings
  const confirmed = canonicalFindings.filter(f => f.disposition === 'REPORTABLE');
  const manualReview = canonicalFindings.filter(f => f.disposition === 'DEFERRED');
  const falsePositives = canonicalFindings.filter(f => f.disposition === 'SUPPRESSED');

  md += '## 2. Findings Summary\n\n';
  md += `- **Confirmed Vulnerabilities (Reportable)**: ${confirmed.length}\n`;
  md += `- **Needs Manual Review (Deferred / Presumption of Non-Pass)**: ${manualReview.length}\n`;
  md += `- **Affirmatively Refuted (Suppressed)**: ${falsePositives.length}\n\n`;

  // Section 3: Confirmed
  md += '## 3. Confirmed Vulnerabilities (High Assurance)\n\n';
  if (confirmed.length === 0) {
    if (coverageStatus === 'COMPLETE') {
      if (manualReview.length > 0) {
        md += `*No confirmed vulnerabilities found matching default-deny verification criteria in fully reconciled coverage (${manualReview.length} item(s) deferred for manual review under default-deny).*\n\n`;
      } else {
        md += '*No confirmed vulnerabilities found matching default-deny verification criteria in fully reconciled coverage.*\n\n';
      }
    } else {
      md += '*No reportable findings were found in the reviewed coverage (Coverage is PARTIAL/UNCHECKABLE; repository cannot be certified clean under default-deny).*\n\n';
    }
  } else {
    for (const f of confirmed) {
      md += `### [${sanitizeInlineText(f.severity)}] ${sanitizeInlineText(f.title)}\n\n`;
      md += `- **Rule / CWE**: \`${sanitizeInlineText(f.ruleId)}\`\n`;
      md += `- **Location**: \`${sanitizeInlineText(f.location.uri)}:${f.location.startLine}\`\n`;
      md += `- **Confidence**: \`${f.confidenceScore}\` (${f.confidenceLevel})\n`;
      if (f.cvssV4?.vector) {
        md += `- **CVSS v4.0**: \`${sanitizeInlineText(f.cvssV4.vector)}\` (Score: ${f.cvssV4.score})\n`;
      }
      md += `- **Mathematical Rigor**: \`${f.rigor.score}\` (${f.rigor.assuranceLevel})\n`;
      md += `- **Verifier Consensus**: ${f.consensus.supports}/${f.consensus.totalVotes} votes support (unanimous=${f.consensus.unanimous})\n`;
      md += `\n**Description**:\n${sanitizeBlockText(f.description)}\n\n`;
      if (f.location.lineSnippet) {
        md += `**Code Reference**:\n\`\`\`\n${f.location.lineSnippet}\n\`\`\`\n\n`;
      }
    }
  }

  // Section 4: Deferred / Needs Manual Review
  md += '## 4. Needs Manual Review (Presumption of Non-Pass / Deferred)\n\n';
  if (manualReview.length === 0) {
    md += '*No open items pending manual review.*\n\n';
  } else {
    for (const f of manualReview) {
      md += `### [REVIEW REQUIRED] ${sanitizeInlineText(f.title)}\n\n`;
      md += `- **Rule / CWE**: \`${sanitizeInlineText(f.ruleId)}\`\n`;
      md += `- **Location**: \`${sanitizeInlineText(f.location.uri)}:${f.location.startLine}\`\n`;
      md += `- **Calculated Rigor**: \`${f.rigor.score}\` (${f.rigor.assuranceLevel})\n`;
      md += `- **Deferral Reason**: ${sanitizeInlineText(f.dispositionReason || 'Unproven taint flow or missing verifier consensus')}\n\n`;
      md += '> [!IMPORTANT]\n> Under default-deny, this candidate is retained and marked unverified until manual inspection or panel quorum.\n\n';
    }
  }

  // Section 5: Affirmatively Refuted
  md += '## 5. Affirmatively Refuted Items (Suppressed)\n\n';
  if (falsePositives.length === 0) {
    md += '*No items affirmatively refuted.*\n\n';
  } else {
    for (const f of falsePositives) {
      md += `### [REFUTED] ${sanitizeInlineText(f.title)}\n\n`;
      md += `- **Location**: \`${sanitizeInlineText(f.location.uri)}:${f.location.startLine}\`\n`;
      md += `- **Refutation Reason**: ${sanitizeInlineText(f.dispositionReason || 'Documented mitigation invariant verified by panel')}\n\n`;
    }
  }

  return md;
}

// -----------------------------------------------------------------------------
// CLI Dispatch
// -----------------------------------------------------------------------------
const isDirectExecution = process.argv[1] && process.argv[1].endsWith('finalize-scan.mjs');

if (isDirectExecution) {
  const args = process.argv.slice(2);
  function getArg(name) {
    const idx = args.indexOf(name);
    if (idx !== -1 && idx + 1 < args.length) {
      return args[idx + 1];
    }
    return null;
  }

  const inputPath = getArg('--input');
  const outputSarifPath = getArg('--output-sarif');
  const outputMdPath = getArg('--output-md');
  const outputJsonPath = getArg('--output-json');
  const manifestPath = getArg('--manifest');
  const votesPath = getArg('--votes');

  if (inputPath) {
  try {
    const rawData = fs.readFileSync(inputPath, 'utf8');
    const candidates = JSON.parse(rawData);

    let manifest = null;
    if (manifestPath && fs.existsSync(manifestPath)) {
      manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
    }

    let votes = [];
    if (votesPath && fs.existsSync(votesPath)) {
      votes = JSON.parse(fs.readFileSync(votesPath, 'utf8'));
    }

    const repoRoot = process.cwd();
    const finalization = finalizeScan({ candidates, manifest, repoRoot, votes });

    if (outputSarifPath) {
      const sarif = renderSarifFromCanonical({
        canonicalFindings: finalization.canonicalFindings,
        manifest: finalization.manifest,
        coverageStatus: finalization.coverageStatus,
        provenance: finalization.provenance,
        repoRoot
      });
      fs.mkdirSync(path.dirname(outputSarifPath), { recursive: true });
      fs.writeFileSync(outputSarifPath, JSON.stringify(sarif, null, 2), 'utf8');
      console.log(`✔ Generated SARIF report: ${outputSarifPath}`);
    }

    if (outputMdPath) {
      const md = renderMarkdownFromCanonical({
        canonicalFindings: finalization.canonicalFindings,
        manifest: finalization.manifest,
        coverageStatus: finalization.coverageStatus,
        provenance: finalization.provenance
      });
      fs.mkdirSync(path.dirname(outputMdPath), { recursive: true });
      fs.writeFileSync(outputMdPath, md, 'utf8');
      console.log(`✔ Generated Markdown report: ${outputMdPath}`);
    }

    if (outputJsonPath) {
      fs.mkdirSync(path.dirname(outputJsonPath), { recursive: true });
      fs.writeFileSync(outputJsonPath, JSON.stringify(finalization.canonicalFindings, null, 2), 'utf8');
      console.log(`✔ Generated Canonical Findings JSON: ${outputJsonPath}`);
    }

    const outputCoveragePath = getArg('--output-coverage');
    if (outputCoveragePath) {
      const coveragePayload = {
        schemaVersion: '1',
        coverageStatus: finalization.coverageStatus,
        canDeclareClean: finalization.summary.canDeclareClean,
        coverageMode: manifest?.mode || (manifest?.reviewInventory ? 'review' : 'scan'),
        manifest: finalization.manifest,
        provenance: finalization.provenance
      };
      fs.mkdirSync(path.dirname(outputCoveragePath), { recursive: true });
      fs.writeFileSync(outputCoveragePath, JSON.stringify(coveragePayload, null, 2), 'utf8');
      console.log(`✔ Generated Coverage JSON: ${outputCoveragePath}`);
    }
  } catch (err) {

    console.error('Error in finalize-scan:', err.message);
    process.exit(1);
  }
}
}

