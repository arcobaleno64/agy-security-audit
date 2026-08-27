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
import { validateAttackPath, detectProofGaps } from './validate-attack-path.mjs';
import { buildDirectoryManifest, extractChangedFiles } from './build-inventory.mjs';



export const CVSS_V4_REGEX = /^CVSS:4\.0\/AV:[NALP]\/AC:[LH]\/AT:[NP]\/PR:[NLH]\/UI:[NPA]\/VC:[HLN]\/VI:[HLN]\/VA:[HLN]\/SC:[HLN]\/SI:[HLN]\/SA:[HLN]$/;


// Common secret patterns for deterministic redaction
export const SECRET_PATTERNS = [
  { type: 'AWS_ACCESS_KEY', regex: /(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}/g },
  { type: 'GITHUB_TOKEN', regex: /(?:ghp_[a-zA-Z0-9]{36,40}|github_pat_[a-zA-Z0-9_]{82}|gh[orpus]_[a-zA-Z0-9]{36,40})/g },
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
 * Normalizes a directory path for deterministic reconciliation.
 */
export function normalizeDirectoryPath(p) {
  if (!p || typeof p !== 'string') return '';
  let clean = p.replace(/\\/g, '/').trim();
  if (clean === '.' || clean === './' || clean === '/') return './';
  clean = clean.replace(/^\.\//, '').replace(/^\/+/, '');
  if (!clean.endsWith('/')) {
    clean += '/';
  }
  return clean;
}

/**
 * Normalizes a repo-relative file path.
 */
export function normalizeFilePath(p) {
  if (!p || typeof p !== 'string') return '';
  return p.replace(/\\/g, '/').replace(/^\.\//, '').replace(/^\/+/, '').trim();
}

/**
 * Validates Directory Reconciliation Manifest according to Directory Accounting standards
 * and performs authoritative reconciliation against the real filesystem when repoRoot is supplied.
 */
export function validateDirectoryManifest(manifest, repoRoot = null) {
  if (!manifest || typeof manifest !== 'object') {
    return { valid: false, status: 'UNCHECKABLE', error: 'Manifest must be an object.' };
  }

  // Unwrap directoryManifest if nested
  const rawEntries = Array.isArray(manifest.entries)
    ? manifest.entries
    : (manifest.directoryManifest && Array.isArray(manifest.directoryManifest.entries) ? manifest.directoryManifest.entries : null);

  if (!rawEntries) {
    return { valid: false, status: 'UNCHECKABLE', error: 'Manifest must contain an "entries" array.' };
  }
  if (rawEntries.length === 0) {
    return { valid: false, status: 'PARTIAL', error: 'UNACCOUNTED_DIRECTORY_ERROR: Directory manifest cannot be empty.' };
  }

  const validStatuses = new Set([
    'SCANNED',
    'EXCLUDED_VENDORED',
    'EXCLUDED_GENERATED',
    'EXCLUDED_NON_CODE',
    'EXCLUDED_TEST'
  ]);

  const claimedMap = new Map();
  const duplicates = [];

  for (const entry of rawEntries) {
    if (!entry || !entry.path) {
      return { valid: false, status: 'PARTIAL', error: 'Directory entry missing "path" property.' };
    }
    const norm = normalizeDirectoryPath(entry.path);
    if (claimedMap.has(norm)) {
      duplicates.push(norm);
    }
    claimedMap.set(norm, entry);

    if (!validStatuses.has(entry.status)) {
      return {
        valid: false,
        status: 'PARTIAL',
        error: `UNACCOUNTED_DIRECTORY_ERROR: Directory "${entry.path}" has invalid or unaccounted status "${entry.status}".`
      };
    }
    if (entry.status.startsWith('EXCLUDED_') && (!entry.reason || entry.reason.trim().length === 0)) {
      return {
        valid: false,
        status: 'PARTIAL',
        error: `UNACCOUNTED_DIRECTORY_ERROR: Excluded directory "${entry.path}" lacks explicit audit reason.`
      };
    }
  }

  if (duplicates.length > 0) {
    return {
      valid: false,
      status: 'PARTIAL',
      duplicates,
      error: `UNACCOUNTED_DIRECTORY_ERROR: Duplicate directory entries found: [${duplicates.join(', ')}]`
    };
  }

  // If repoRoot is omitted or null, syntax is valid but coverage cannot be verified
  if (!repoRoot || typeof repoRoot !== 'string' || !fs.existsSync(path.resolve(repoRoot))) {
    return {
      valid: true,
      status: 'UNCHECKABLE',
      missing: [],
      unexpected: [],
      error: 'UNCHECKABLE: Authoritative repoRoot is required to reconcile filesystem coverage.'
    };
  }

  // Authoritative Filesystem Reconciliation (P0-02)
  let actualManifest;
  try {
    actualManifest = buildDirectoryManifest(repoRoot);
  } catch (e) {
    return {
      valid: false,
      status: 'UNCHECKABLE',
      error: `FS_RECONCILIATION_ERROR: Failed to inspect filesystem at ${repoRoot}: ${e.message}`
    };
  }

  const actualMap = new Map();
  for (const actualEntry of actualManifest.entries) {
    actualMap.set(normalizeDirectoryPath(actualEntry.path), actualEntry);
  }

  const missing = [];
  for (const actualPath of actualMap.keys()) {
    if (!claimedMap.has(actualPath)) {
      missing.push(actualPath);
    }
  }

  const unexpected = [];
  for (const claimedPath of claimedMap.keys()) {
    if (!actualMap.has(claimedPath)) {
      unexpected.push(claimedPath);
    }
  }

  // Check for False Exclusion / Categorization Fabrication
  const statusMismatches = [];
  let hasScannedCodeDirectory = false;

  for (const [actualPath, actualEntry] of actualMap.entries()) {
    const claimedEntry = claimedMap.get(actualPath);
    if (claimedEntry) {
      if (actualEntry.status === 'SCANNED') {
        if (claimedEntry.status !== 'SCANNED') {
          statusMismatches.push({ path: actualPath, expected: actualEntry.status, claimed: claimedEntry.status });
        } else {
          hasScannedCodeDirectory = true;
        }
      }
    }
  }

  if (statusMismatches.length > 0) {
    return {
      valid: false,
      status: 'PARTIAL',
      statusMismatches,
      missing,
      unexpected,
      error: `UNACCOUNTED_DIRECTORY_ERROR: Source code directory falsely excluded: [${statusMismatches.map(m => `${m.path} claimed ${m.claimed}`).join(', ')}]`
    };
  }

  if (!hasScannedCodeDirectory) {
    return {
      valid: false,
      status: 'PARTIAL',
      error: 'UNACCOUNTED_DIRECTORY_ERROR: Complete scan must include at least one SCANNED source code directory.'
    };
  }

  if (missing.length > 0 || unexpected.length > 0) {
    return {
      valid: false,
      status: 'PARTIAL',
      missing,
      unexpected,
      error: `UNACCOUNTED_DIRECTORY_ERROR: Directory reconciliation mismatch. Missing: [${missing.join(', ')}]; Unexpected: [${unexpected.join(', ')}]`
    };
  }

  return { valid: true, status: 'COMPLETE', missing: [], unexpected: [] };
}

/**
 * Validates Review Manifest according to Review mode standards
 * and performs authoritative reconciliation against actual Git diff when repoRoot is supplied.
 */
export function validateReviewManifest(manifest, repoRoot = null) {
  if (!manifest || typeof manifest !== 'object') {
    return { valid: false, status: 'UNCHECKABLE', error: 'Review manifest must be a valid object.' };
  }
  const inventory = manifest.reviewInventory || manifest;
  const changed = Array.isArray(inventory.changedFiles) ? inventory.changedFiles : null;
  const deleted = Array.isArray(inventory.deletedFiles) ? inventory.deletedFiles : null;

  if (!changed && !deleted) {
    return { valid: false, status: 'PARTIAL', error: 'Review manifest must contain changedFiles or deletedFiles array.' };
  }

  const claimedChangedList = changed || [];
  const claimedDeletedList = deleted || [];

  for (const f of claimedChangedList) {
    if (!f || !f.path) return { valid: false, status: 'PARTIAL', error: 'Changed file entry missing path property.' };
  }
  for (const f of claimedDeletedList) {
    if (!f || !f.path) return { valid: false, status: 'PARTIAL', error: 'Deleted file entry missing path property.' };
  }

  // If repoRoot is omitted or null, syntax is valid but coverage cannot be verified
  if (!repoRoot || typeof repoRoot !== 'string' || !fs.existsSync(path.resolve(repoRoot))) {
    return {
      valid: true,
      status: 'UNCHECKABLE',
      totalAccounted: claimedChangedList.length + claimedDeletedList.length,
      error: 'UNCHECKABLE: Authoritative repoRoot is required to reconcile git review coverage.'
    };
  }

  // Authoritative Git Diff Reconciliation (P0-02)
  const baseRev = manifest.base || inventory.base || manifest.baselineRevision || inventory.baselineRevision || null;
  const headRev = manifest.head || inventory.head || manifest.targetRevision || inventory.targetRevision || null;

  if (baseRev && headRev && baseRev === headRev) {
    return {
      valid: false,
      status: 'PARTIAL',
      error: `REVIEW_RECONCILIATION_ERROR: Identical revisions specified (${baseRev}...${headRev}) which trivially suppresses review diff.`
    };
  }

  let actualChanged = [];
  let actualDeleted = [];
  try {
    const actualDiff = extractChangedFiles(repoRoot, { base: baseRev, head: headRev });
    actualChanged = actualDiff.changedFiles.map(f => normalizeFilePath(f.path));
    actualDeleted = actualDiff.deletedFiles.map(f => normalizeFilePath(f.path));
  } catch (e) {
    return {
      valid: false,
      status: 'UNCHECKABLE',
      error: `GIT_ACCOUNTING_ERROR: ${e.message}`
    };
  }

  const claimedChanged = claimedChangedList.map(f => normalizeFilePath(f.path));
  const claimedDeleted = claimedDeletedList.map(f => normalizeFilePath(f.path));

  const missingChanged = actualChanged.filter(f => !claimedChanged.includes(f));
  const missingDeleted = actualDeleted.filter(f => !claimedDeleted.includes(f));
  const unexpectedChanged = claimedChanged.filter(f => !actualChanged.includes(f));
  const unexpectedDeleted = claimedDeleted.filter(f => !actualDeleted.includes(f));

  if (missingChanged.length > 0 || missingDeleted.length > 0 || unexpectedChanged.length > 0 || unexpectedDeleted.length > 0) {
    return {
      valid: false,
      status: 'PARTIAL',
      missingChanged,
      missingDeleted,
      unexpectedChanged,
      unexpectedDeleted,
      error: `REVIEW_RECONCILIATION_ERROR: Changed/deleted files mismatch against git diff. Missing changed: [${missingChanged.join(', ')}], Missing deleted: [${missingDeleted.join(', ')}], Unexpected changed: [${unexpectedChanged.join(', ')}], Unexpected deleted: [${unexpectedDeleted.join(', ')}]`
    };
  }

  return {
    valid: true,
    status: 'COMPLETE',
    totalAccounted: claimedChangedList.length + claimedDeletedList.length,
    missingChanged: [],
    missingDeleted: [],
    unexpectedChanged: [],
    unexpectedDeleted: []
  };
}

/**
 * Reconciles coverage across scan and review manifests against authoritative filesystem/git ground truth.
 */
export function reconcileCoverage(manifest, repoRoot = null) {
  if (!manifest) {
    return { valid: false, status: 'UNCHECKABLE', mode: 'none', error: 'No coverage manifest provided.' };
  }
  if (manifest.mode === 'review' || manifest.reviewInventory || (Array.isArray(manifest.changedFiles) && !Array.isArray(manifest.entries))) {
    const res = validateReviewManifest(manifest, repoRoot);
    return {
      valid: res.valid,
      status: res.valid ? res.status : (res.status || 'PARTIAL'),
      mode: 'review',
      error: res.error || null,
      missingChanged: res.missingChanged || [],
      missingDeleted: res.missingDeleted || [],
      unexpectedChanged: res.unexpectedChanged || [],
      unexpectedDeleted: res.unexpectedDeleted || []
    };
  }
  const res = validateDirectoryManifest(manifest, repoRoot);
  return {
    valid: res.valid,
    status: res.valid ? res.status : (res.status || 'PARTIAL'),
    mode: 'scan',
    error: res.error || null,
    missing: res.missing || [],
    unexpected: res.unexpected || [],
    duplicates: res.duplicates || []
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
 * Parses a standard CVSS v4.0 vector string into a key-value metric map.
 */
export function parseCvssV4Vector(vectorStr) {
  if (!vectorStr || typeof vectorStr !== 'string') return null;
  const parts = vectorStr.trim().split('/');
  if (parts[0] !== 'CVSS:4.0') return null;
  const metrics = {};
  for (let i = 1; i < parts.length; i++) {
    const [k, v] = parts[i].split(':');
    if (k && v) metrics[k] = v;
  }
  return metrics;
}

/**
 * Validates consistency between CVSS v4.0 vector metrics, score, and severity.
 * Fails closed on any contradiction or fabricated authority claim (R1-P1-04).
 */
export function validateCvssV4Consistency(metrics, score, severity) {
  if (!metrics) return { valid: false, error: 'Missing metrics' };

  const allImpactsNone = (
    metrics.VC === 'N' && metrics.VI === 'N' && metrics.VA === 'N' &&
    metrics.SC === 'N' && metrics.SI === 'N' && metrics.SA === 'N'
  );

  // 1. Zero-impact invariant: if all impacts are None, score must be 0.0 or null
  if (allImpactsNone) {
    if (score !== null && score !== undefined && score > 0.0) {
      return {
        valid: false,
        error: `CVSS consistency violation: zero-impact vector (all N) cannot have non-zero score (${score})`
      };
    }
    if (severity && severity !== 'NONE' && severity !== 'UNRATED') {
      return {
        valid: false,
        error: `CVSS consistency violation: zero-impact vector cannot have severity '${severity}'`
      };
    }
  }

  // 2. Score vs Severity consistency check
  if (score !== null && score !== undefined && severity && severity !== 'UNRATED') {
    let expectedSeverity = 'NONE';
    if (score >= 9.0) expectedSeverity = 'CRITICAL';
    else if (score >= 7.0) expectedSeverity = 'HIGH';
    else if (score >= 4.0) expectedSeverity = 'MEDIUM';
    else if (score > 0.0) expectedSeverity = 'LOW';

    if (severity !== expectedSeverity) {
      return {
        valid: false,
        error: `CVSS consistency violation: score ${score} maps to ${expectedSeverity}, but claimed severity is '${severity}'`
      };
    }
  }

  // 3. Physical attack vector constraint: AV:P cannot be CRITICAL (neither score >= 9.0 nor severity 'CRITICAL')
  if (metrics.AV === 'P' && ((score !== null && score !== undefined && score >= 9.0) || severity === 'CRITICAL')) {
    return {
      valid: false,
      error: `CVSS consistency violation: Physical attack vector (AV:P) cannot be CRITICAL (score=${score}, severity=${severity})`
    };
  }

  // 4. Zero vulnerable system impact constraint: VC:N, VI:N, VA:N cannot be CRITICAL
  if (metrics.VC === 'N' && metrics.VI === 'N' && metrics.VA === 'N' && ((score !== null && score !== undefined && score >= 9.0) || severity === 'CRITICAL')) {
    return {
      valid: false,
      error: `CVSS consistency violation: zero vulnerable-system impact (VC:N/VI:N/VA:N) cannot be CRITICAL (score=${score}, severity=${severity})`
    };
  }

  // 4b. Vulnerable system impact without any High metric (VC/VI/VA not H) cannot be CRITICAL
  if (metrics.VC !== 'H' && metrics.VI !== 'H' && metrics.VA !== 'H' && ((score !== null && score !== undefined && score >= 9.0) || severity === 'CRITICAL')) {
    return {
      valid: false,
      error: `CVSS consistency violation: vulnerable system without High impact (VC/VI/VA not H) cannot be CRITICAL (score=${score}, severity=${severity})`
    };
  }

  // 5. Maximal impact and exploitability cannot have score < 7.0
  if (metrics.AV === 'N' && metrics.AC === 'L' && metrics.AT === 'N' && metrics.PR === 'N' && metrics.UI === 'N' &&
      metrics.VC === 'H' && metrics.VI === 'H' && metrics.VA === 'H' &&
      score !== null && score !== undefined && score < 7.0) {
    return {
      valid: false,
      error: `CVSS consistency violation: maximal impact and exploitability cannot have score < 7.0 (${score})`
    };
  }

  return { valid: true };
}

/**
 * Validates CVSS v4 vector fail-closed. Never substitutes a fake high-severity vector or clamped invalid scores.
 * Enforces consistency between vector metrics and score/severity under Default-Deny (R1-P1-04).
 */
export function validateCvssV4(cvssObj) {
  if (!cvssObj || typeof cvssObj !== 'object') {
    return { valid: false, vector: null, score: null, severity: 'UNRATED' };
  }

  const rawVector = cvssObj.vector;
  if (!rawVector || typeof rawVector !== 'string' || !CVSS_V4_REGEX.test(rawVector.trim())) {
    return {
      valid: false,
      vector: null,
      score: null,
      severity: 'UNRATED',
      error: 'Invalid or missing CVSS v4 vector'
    };
  }

  const trimmedVector = rawVector.trim();
  const metrics = parseCvssV4Vector(trimmedVector);

  let validatedScore = null;
  if (cvssObj.score !== undefined && cvssObj.score !== null) {
    if (
      typeof cvssObj.score !== 'number' ||
      !Number.isFinite(cvssObj.score) ||
      Number.isNaN(cvssObj.score) ||
      cvssObj.score < 0.0 ||
      cvssObj.score > 10.0
    ) {
      return {
        valid: false,
        vector: null,
        score: null,
        severity: 'UNRATED',
        error: `Invalid CVSS score: ${cvssObj.score}. Must be a finite number between 0.0 and 10.0.`
      };
    }
    validatedScore = Number(cvssObj.score.toFixed(1));
  }

  let severity = 'UNRATED';
  if (cvssObj.severity && typeof cvssObj.severity === 'string') {
    severity = cvssObj.severity.toUpperCase();
  } else if (validatedScore !== null) {
    severity = validatedScore >= 9.0 ? 'CRITICAL' : validatedScore >= 7.0 ? 'HIGH' : validatedScore >= 4.0 ? 'MEDIUM' : validatedScore > 0 ? 'LOW' : 'NONE';
  } else {
    // Derive qualitative severity from vector when score is null
    const allImpactsNone = (
      metrics.VC === 'N' && metrics.VI === 'N' && metrics.VA === 'N' &&
      metrics.SC === 'N' && metrics.SI === 'N' && metrics.SA === 'N'
    );
    if (allImpactsNone) {
      severity = 'NONE';
    } else if (metrics.AV === 'N' && metrics.AC === 'L' && metrics.PR === 'N' && metrics.VC === 'H' && metrics.VI === 'H') {
      severity = 'CRITICAL';
    } else if (metrics.VC === 'H' || metrics.VI === 'H') {
      severity = 'HIGH';
    } else if (metrics.VC === 'L' || metrics.VI === 'L' || metrics.VA === 'L') {
      severity = 'MEDIUM';
    } else {
      severity = 'LOW';
    }
  }

  // R1-P1-04: Strict consistency check between vector, score, and severity
  const consistencyCheck = validateCvssV4Consistency(metrics, validatedScore, severity);
  if (!consistencyCheck.valid) {
    return {
      valid: false,
      vector: null,
      score: null,
      severity: 'UNRATED',
      error: consistencyCheck.error
    };
  }

  return {
    valid: true,
    vector: trimmedVector,
    score: validatedScore,
    severity
  };
}


/**
 * Unifies multi-run discovery candidate sets using deterministic fingerprints.
 */
export function unionCandidates(runs = [], repoRoot = process.cwd()) {
  if (!Array.isArray(runs) || runs.length === 0) return [];
  const fingerprintMap = new Map();
  const totalRuns = runs.length;

  for (let runIdx = 0; runIdx < totalRuns; runIdx++) {
    const runCandidates = runs[runIdx] || [];
    const seenInRun = new Set();

    for (const c of runCandidates) {
      if (!c || typeof c !== 'object') continue;
      const ruleId = c.ruleId || 'SEC-VULN';
      const loc = c.location || {};
      const rawUri = loc.uri || loc.path || 'unknown';
      const normUri = normalizeUri(repoRoot, rawUri);
      const startLine = Number(loc.startLine) || 1;
      const fp = computeFindingFingerprint(ruleId, normUri, startLine);

      if (!fingerprintMap.has(fp)) {
        fingerprintMap.set(fp, {
          ...c,
          id: c.id || `SEC-${fp.substring(0, 8)}`,
          location: {
            ...loc,
            uri: normUri,
            startLine
          },
          fingerprint: fp,
          recurrenceCount: 1,
          runsObserved: [runIdx + 1],
          proofGaps: Array.isArray(c.proofGaps) ? [...c.proofGaps] : []
        });
        seenInRun.add(fp);
      } else {
        const existing = fingerprintMap.get(fp);
        // Only increment recurrence if not duplicate within this single run
        if (!seenInRun.has(fp)) {
          existing.recurrenceCount += 1;
          existing.runsObserved.push(runIdx + 1);
          seenInRun.add(fp);
        }

        // Structurally deduplicate proof gaps across runs
        if (Array.isArray(c.proofGaps)) {
          existing.proofGaps = existing.proofGaps || [];
          const existingKeys = new Set(existing.proofGaps.map(g => `${g.stepIndex ?? g.target}:${g.unprovenProperty}:${g.location || ''}`));
          for (const g of c.proofGaps) {
            const key = `${g.stepIndex ?? g.target}:${g.unprovenProperty}:${g.location || ''}`;
            if (!existingKeys.has(key)) {
              existingKeys.add(key);
              existing.proofGaps.push(g);
            }
          }
        }

        // Merge extra attack path dataflow steps if newly discovered in this run
        if (c.attackPath && Array.isArray(c.attackPath.steps) && (!existing.attackPath || !existing.attackPath.steps || c.attackPath.steps.length > existing.attackPath.steps.length)) {
          existing.attackPath = c.attackPath;
        }
      }
    }
  }

  return Array.from(fingerprintMap.values());
}

/**
 * Extracts candidate evidence items from a verifier vote (P1-02).
 */
export function extractVoteEvidence(vote, candidate = {}) {
  const items = [];
  const defaultCandidatePath = candidate.location?.uri || candidate.location?.path || null;

  const parsePathLine = (val, defaultPath, defaultRole = null) => {
    if (val === null || val === undefined) return null;
    if (typeof val === 'number') {
      return { path: defaultPath, line: val, role: defaultRole };
    }
    if (typeof val === 'string') {
      const trimmed = val.trim();
      const match = trimmed.match(/^([^:]+):(\d+)$/);
      if (match) {
        return { path: match[1], line: parseInt(match[2], 10), role: defaultRole };
      }
      const lineOnly = parseInt(trimmed, 10);
      if (!isNaN(lineOnly) && lineOnly > 0 && !trimmed.includes('/') && !trimmed.includes('\\')) {
        return { path: defaultPath, line: lineOnly, role: defaultRole };
      }
      return { path: trimmed, line: null, role: defaultRole };
    }
    if (typeof val === 'object' && val !== null) {
      const p = val.path || val.uri || val.file || defaultPath;
      const l = Number(val.line || val.startLine);
      return { path: p, line: (!isNaN(l) && l > 0) ? l : null, role: val.role || defaultRole };
    }
    return null;
  };

  const voteLens = vote.lens ? String(vote.lens).toUpperCase() : null;

  if (Array.isArray(vote.evidence)) {
    for (let i = 0; i < vote.evidence.length; i++) {
      const e = vote.evidence[i];
      let defRole = null;
      if (voteLens === 'REACHABILITY') {
        if (vote.evidence.length >= 2) defRole = (i === 0) ? 'source' : 'sink';
        else defRole = 'entrypoint';
      } else if (voteLens === 'DEFENSES') {
        defRole = 'control';
      } else if (voteLens === 'IMPACT') {
        defRole = 'impact-boundary';
      }
      const parsed = parsePathLine(e, defaultCandidatePath, defRole);
      if (parsed) items.push(parsed);
    }
  } else if (vote.evidence) {
    let defRole = null;
    if (voteLens === 'REACHABILITY') defRole = 'entrypoint';
    else if (voteLens === 'DEFENSES') defRole = 'control';
    else if (voteLens === 'IMPACT') defRole = 'impact-boundary';
    const parsed = parsePathLine(vote.evidence, defaultCandidatePath, defRole);
    if (parsed) items.push(parsed);
  }

  if (vote.source) {
    const parsed = parsePathLine(vote.source, defaultCandidatePath, 'source');
    if (parsed) items.push(parsed);
  }
  if (vote.entrypoint) {
    const parsed = parsePathLine(vote.entrypoint, defaultCandidatePath, 'entrypoint');
    if (parsed) items.push(parsed);
  }
  if (vote.sink) {
    const parsed = parsePathLine(vote.sink, defaultCandidatePath, 'sink');
    if (parsed) items.push(parsed);
  }
  if (vote.mitigationProofLine) {
    const parsed = parsePathLine(vote.mitigationProofLine, defaultCandidatePath, 'guard');
    if (parsed) items.push(parsed);
  }
  if (vote.unreachableProofLine) {
    const parsed = parsePathLine(vote.unreachableProofLine, defaultCandidatePath, 'dead-path');
    if (parsed) items.push(parsed);
  }
  if (vote.containmentProofLine) {
    const parsed = parsePathLine(vote.containmentProofLine, defaultCandidatePath, 'impact-boundary');
    if (parsed) items.push(parsed);
  }
  if (vote.proofLine) {
    const parsed = parsePathLine(vote.proofLine, defaultCandidatePath, 'guard');
    if (parsed) items.push(parsed);
  }
  if (vote.path && vote.line) {
    const parsed = parsePathLine({ path: vote.path, line: vote.line }, defaultCandidatePath);
    if (parsed) items.push(parsed);
  }

  return items;
}

/**
 * Validates vote evidence fail-closed under Default-Deny (P1-02, R1-P0-01).
 * Both SUPPORTS and REFUTES decisions mandate verified evidence binding.
 */
export function validateVoteEvidence(vote, candidate = {}, repoRoot = null) {
  if (!vote || typeof vote !== 'object') {
    return { valid: false, reason: 'Malformed vote object' };
  }

  // 1. FindingId Match
  const voteFindingId = vote.findingId;
  const candidateId = candidate.id || candidate.findingId;
  if (!voteFindingId || (candidateId && voteFindingId !== candidateId)) {
    return { valid: false, reason: `Vote findingId '${voteFindingId}' does not match candidate '${candidateId}'` };
  }

  // 2. Extract Evidence
  const evidenceItems = extractVoteEvidence(vote, candidate);
  if (evidenceItems.length === 0) {
    return { valid: false, reason: 'Vote requires non-empty evidence binding' };
  }

  // 3. Validate Each Evidence Item
  for (const item of evidenceItems) {
    if (!item.path || typeof item.path !== 'string') {
      return { valid: false, reason: 'Evidence missing valid file path' };
    }
    if (!Number.isInteger(item.line) || item.line <= 0) {
      return { valid: false, reason: `Evidence line must be a positive integer, got '${item.line}'` };
    }

    const normPath = item.path.replace(/\\/g, '/').replace(/^\.\//, '');

    // Anti-traversal check
    if (normPath.startsWith('..') || normPath.includes('/../') || path.isAbsolute(item.path)) {
      return { valid: false, reason: `Evidence path escapes workspace: '${item.path}'` };
    }

    // Real filesystem verification if repoRoot is provided
    if (repoRoot) {
      const fullTarget = path.resolve(repoRoot, normPath);
      const relToRepo = path.relative(repoRoot, fullTarget);
      if (relToRepo.startsWith('..') || path.isAbsolute(relToRepo)) {
        return { valid: false, reason: `Evidence path outside repository root: '${normPath}'` };
      }
      if (!fs.existsSync(fullTarget)) {
        return { valid: false, reason: `Evidence file does not exist: '${normPath}'` };
      }
      try {
        const fileContent = fs.readFileSync(fullTarget, 'utf8');
        const lineCount = fileContent.split('\n').length;
        if (item.line > lineCount) {
          return { valid: false, reason: `Evidence line ${item.line} exceeds file length (${lineCount} lines) in '${normPath}'` };
        }
      } catch (e) {
        return { valid: false, reason: `Failed to inspect evidence file '${normPath}': ${e.message}` };
      }
    }
  }

  return { valid: true, evidence: evidenceItems };
}

/**
 * Derives authoritative mathematical rigor from validated evidence.
 * Raw candidate.rigorMetrics is strictly treated as an untrusted hint and CANNOT self-certify authority (R1-P0-01).
 */
export function deriveAuthoritativeRigor(candidate = {}, validSupportVotes = [], repoRoot = null) {
  const allEvidence = [];
  for (const v of validSupportVotes) {
    if (v && v._validatedEvidence) {
      allEvidence.push(...v._validatedEvidence);
    }
  }

  const hasSource = allEvidence.some(e => ['source', 'entrypoint', 'origin'].includes(e.role));
  const candidateUri = candidate.location?.uri || candidate.location?.path;
  const candidateLine = Number(candidate.location?.startLine);
  const hasSink = allEvidence.some(e => ['sink', 'root-control', 'target'].includes(e.role)) ||
    (candidateUri && allEvidence.some(e => e.path === candidateUri && e.line === candidateLine));
  const hasControlInspection = allEvidence.some(e => ['control', 'closest-control', 'guard', 'defense', 'inspected-control', 'mitigation'].includes(e.role));

  const sSource = hasSource ? 1.0 : 0.0;
  const sSink = hasSink ? 1.0 : 0.0;
  const sMitigation = hasControlInspection ? 1.0 : 0.0;

  // Dataflow verification
  let flowTotal = 0;
  let flowVerified = 0;
  if (candidate.attackPath && Array.isArray(candidate.attackPath.steps)) {
    flowTotal = candidate.attackPath.steps.length;
    flowVerified = (candidate.proofGaps && candidate.proofGaps.length > 0) ? 0 : flowTotal;
  } else if (hasSource && hasSink) {
    flowTotal = 1;
    flowVerified = 1;
  }
  const flowRatio = flowTotal > 0 ? Math.min(1.0, Math.max(0.0, flowVerified / flowTotal)) : 0.0;
  const sPoc = (candidate.attackPath?.proofOfConcept || candidate.pocSyntacticDemonstrated) ? 1.0 : 0.0;

  const score = Number((0.25 * sSink + 0.25 * sSource + 0.25 * flowRatio + 0.15 * sPoc + 0.10 * sMitigation).toFixed(4));

  let assuranceLevel = 'LOW_RIGOR';
  if (score >= 0.85) {
    assuranceLevel = 'HIGH_RIGOR';
  } else if (score >= 0.60) {
    assuranceLevel = 'MODERATE_RIGOR';
  }

  return {
    score,
    assuranceLevel,
    metrics: {
      sinkVerified: hasSink,
      sourceVerified: hasSource,
      dataflowTotalSteps: flowTotal,
      dataflowVerifiedSteps: flowVerified,
      mitigationInspected: hasControlInspection
    }
  };
}

/**
 * Validates a verifier ballot against candidate identity and task correlation nonce (R1-P1-05).
 */
export function validateBallot(vote, candidate = null, options = {}) {
  if (!vote || typeof vote !== 'object') {
    return { valid: false, reason: 'Ballot must be a non-null object' };
  }
  if (!vote.findingId || typeof vote.findingId !== 'string') {
    return { valid: false, reason: 'Ballot missing valid findingId string' };
  }
  if (candidate && candidate.id && vote.findingId !== candidate.id) {
    return { valid: false, reason: `Finding ID mismatch: ballot for '${vote.findingId}' passed to candidate '${candidate.id}'` };
  }

  // Task-correlation nonce enforcement
  const expectedNonce = options.expectedNonce || candidate?.nonce;
  if (expectedNonce) {
    if (!vote.nonce) {
      return { valid: false, reason: `Missing required task-correlation nonce (expected '${expectedNonce}')` };
    }
    if (vote.nonce !== expectedNonce) {
      return { valid: false, reason: `Task-correlation nonce mismatch: expected '${expectedNonce}', got '${vote.nonce}'` };
    }
  }

  const validLenses = ['REACHABILITY', 'DEFENSES', 'IMPACT'];
  if (vote.lens && !validLenses.includes(String(vote.lens).toUpperCase())) {
    return { valid: false, reason: `Invalid lens '${vote.lens}'. Must be one of: ${validLenses.join(', ')}` };
  }

  const validDecisions = ['CONFIRMED', 'SUPPORTS', 'REPORTABLE', 'FALSE_POSITIVE', 'REFUTES', 'SUPPRESSED', 'DEFERRED', 'NEEDS_MANUAL_REVIEW'];
  const decision = String(vote.decision || vote.verdict || '').toUpperCase();
  if (!validDecisions.includes(decision)) {
    return { valid: false, reason: `Invalid ballot decision '${vote.decision}'` };
  }

  return { valid: true };
}

/**
 * Derives the deterministic disposition under the Presumption of Non-Pass (Default-Deny).
 * Raw verdict from input is strictly treated as an untrusted candidate hint and NEVER has authority.
 * Every REFUTES decision strictly requires verifiable evidence binding (P1-02).
 * Every SUPPORTS decision strictly requires verifiable evidence binding and cannot self-certify via raw rigorMetrics (R1-P0-01).
 */
export function deriveFinalDisposition(candidate, votes = [], rigor = { score: 0 }, repoRoot = null) {
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

  // 1.5 Proof-Gap Check (Default-Deny)
  const rawGaps = candidate.proofGaps?.proofGaps || candidate.proofGaps;
  if (Array.isArray(rawGaps) && rawGaps.length > 0) {
    return {
      disposition: 'DEFERRED',
      mappedVerdict: 'NEEDS_MANUAL_REVIEW',
      reason: `Unclosed proof gap: ${rawGaps.length} step(s) unverified under default-deny`,
      votesSummary: { total: 0, supports: 0, refutes: 0, unanimous: false },
      proofGaps: rawGaps
    };
  }

  // 2. Candidate task-binding and deduplication of votes
  const safeVotes = Array.isArray(votes) ? votes : [];
  const candidateVotes = safeVotes.filter(v => {
    if (!v) return false;
    return validateBallot(v, candidate).valid;
  });

  const dedupedVotes = [];
  const seenKeys = new Set();

  for (const v of candidateVotes) {
    const key = v.reviewerId || v.persona || (v.lens ? `lens:${String(v.lens).toUpperCase()}` : null) || JSON.stringify(v);
    if (!seenKeys.has(key)) {
      seenKeys.add(key);
      dedupedVotes.push(v);
    }
  }

  // 3. Evaluate votes if present
  if (dedupedVotes.length > 0) {
    let supports = 0;
    let refutes = 0;
    let validDecisiveMitigationVote = null;
    let reachabilityRefuted = false;
    let defensesRefuted = false;
    let impactRefuted = false;
    let invalidRefutation = null;
    let invalidSupport = null;
    const validSupportVotes = [];
    let reachabilitySupports = null;
    let defensesSupports = null;
    let impactSupports = null;
    const lenses = new Set();

    for (const v of dedupedVotes) {
      if (v.lens) lenses.add(String(v.lens).toUpperCase());
      const decision = String(v.decision || v.verdict || '').toUpperCase();
      const lens = v.lens ? String(v.lens).toUpperCase() : null;

      if (['CONFIRMED', 'SUPPORTS', 'REPORTABLE'].includes(decision)) {
        // R1-P0-01: SUPPORTS must also be evidence-bound
        const evCheck = validateVoteEvidence(v, candidate, repoRoot);
        if (!evCheck.valid) {
          invalidSupport = {
            vote: v,
            lens: lens || 'GENERAL',
            reason: evCheck.reason
          };
        } else {
          v._validatedEvidence = evCheck.evidence;
          supports++;
          validSupportVotes.push(v);
          if (lens === 'REACHABILITY') reachabilitySupports = v;
          if (lens === 'DEFENSES') defensesSupports = v;
          if (lens === 'IMPACT') impactSupports = v;
        }
      } else if (['FALSE_POSITIVE', 'REFUTES', 'SUPPRESSED'].includes(decision)) {
        refutes++;
        // P1-02: Every REFUTES must have verifiable evidence binding
        const evCheck = validateVoteEvidence(v, candidate, repoRoot);
        if (!evCheck.valid) {
          invalidRefutation = {
            vote: v,
            lens: lens || 'GENERAL',
            reason: evCheck.reason
          };
        } else {
          validDecisiveMitigationVote = v;
          if (lens === 'REACHABILITY') {
            reachabilityRefuted = true;
          } else if (lens === 'DEFENSES') {
            defensesRefuted = true;
          } else if (lens === 'IMPACT') {
            impactRefuted = true;
          }
        }
      }
    }

    const total = dedupedVotes.length;
    const isThreeLens = lenses.has('REACHABILITY') && lenses.has('DEFENSES') && lenses.has('IMPACT');

    // If any refutation failed evidence validation, candidate cannot be suppressed OR confirmed -> DEFERRED
    if (invalidRefutation) {
      return {
        disposition: 'DEFERRED',
        mappedVerdict: 'NEEDS_MANUAL_REVIEW',
        reason: `Unverified refutation: ${invalidRefutation.lens} lens refuted without valid evidence binding (${invalidRefutation.reason}); deferred under default-deny`,
        votesSummary: { total, supports, refutes, unanimous: false, isThreeLens, lenses: Array.from(lenses) }
      };
    }

    // 3-Lens Conjunctive Evaluation
    if (isThreeLens) {
      // If Reachability refutes with valid evidence -> Unreachable (FALSE_POSITIVE)
      if (reachabilityRefuted) {
        return {
          disposition: 'SUPPRESSED',
          mappedVerdict: 'FALSE_POSITIVE',
          reason: 'Unreachable: refuted by 3-Lens REACHABILITY analysis with verified evidence',
          votesSummary: { total, supports, refutes, unanimous: false, isThreeLens, lenses: Array.from(lenses) }
        };
      }

      // If Defenses refutes with valid evidence -> Neutralized by sanitizer / validation barrier (FALSE_POSITIVE)
      if (defensesRefuted) {
        return {
          disposition: 'SUPPRESSED',
          mappedVerdict: 'FALSE_POSITIVE',
          reason: 'Neutralized: affirmative defense proven by 3-Lens DEFENSES analysis with verified evidence',
          votesSummary: { total, supports, refutes, unanimous: false, isThreeLens, lenses: Array.from(lenses) }
        };
      }

      // If Impact refutes with valid evidence -> Purely theoretical / zero demonstrable harm (FALSE_POSITIVE)
      if (impactRefuted) {
        return {
          disposition: 'SUPPRESSED',
          mappedVerdict: 'FALSE_POSITIVE',
          reason: 'Zero demonstrable harm: refuted by 3-Lens IMPACT analysis with verified evidence',
          votesSummary: { total, supports, refutes, unanimous: false, isThreeLens, lenses: Array.from(lenses) }
        };
      }

      // If any support failed evidence validation, candidate cannot be confirmed -> DEFERRED (R1-P0-01)
      if (invalidSupport) {
        return {
          disposition: 'DEFERRED',
          mappedVerdict: 'NEEDS_MANUAL_REVIEW',
          reason: `Unverified support: ${invalidSupport.lens} lens voted SUPPORTS without valid evidence binding (${invalidSupport.reason}); deferred under default-deny`,
          votesSummary: { total, supports, refutes, unanimous: false, isThreeLens, lenses: Array.from(lenses) }
        };
      }

      // 3-Lens requires unanimous confirmation (supports === 3)
      if (supports === 3) {
        // R1-P0-01: Verify required evidence tuple:
        // 1. REACHABILITY must prove source/entrypoint
        const reachEv = reachabilitySupports?._validatedEvidence || [];
        const hasSource = reachEv.some(e => ['source', 'entrypoint', 'origin'].includes(e.role));
        if (!hasSource) {
          return {
            disposition: 'DEFERRED',
            mappedVerdict: 'NEEDS_MANUAL_REVIEW',
            reason: 'Incomplete evidence tuple: REACHABILITY lens missing verified source/entrypoint evidence; deferred under default-deny',
            votesSummary: { total, supports, refutes, unanimous: false, isThreeLens, lenses: Array.from(lenses) }
          };
        }

        // 2. Must prove sink / root-control
        const allEv = validSupportVotes.flatMap(v => v._validatedEvidence || []);
        const candidatePath = candidate.location?.uri || candidate.location?.path;
        const candidateLine = Number(candidate.location?.startLine);

        if (candidatePath && repoRoot) {
          const fullCandTarget = path.resolve(repoRoot, candidatePath);
          if (!fs.existsSync(fullCandTarget)) {
            return {
              disposition: 'DEFERRED',
              mappedVerdict: 'NEEDS_MANUAL_REVIEW',
              reason: `Candidate target file does not exist: '${candidatePath}'; deferred under default-deny`,
              votesSummary: { total, supports, refutes, unanimous: false, isThreeLens, lenses: Array.from(lenses) }
            };
          }
        }

        const hasSink = allEv.some(e => ['sink', 'root-control', 'target'].includes(e.role)) ||
          (candidatePath && allEv.some(e => e.path === candidatePath && e.line === candidateLine));
        if (!hasSink) {
          return {
            disposition: 'DEFERRED',
            mappedVerdict: 'NEEDS_MANUAL_REVIEW',
            reason: 'Incomplete evidence tuple: missing verified sink/root-control evidence; deferred under default-deny',
            votesSummary: { total, supports, refutes, unanimous: false, isThreeLens, lenses: Array.from(lenses) }
          };
        }

        // 3. Authoritative rigor derived strictly from verified evidence (R1-P0-01)
        const authoritativeRigor = deriveAuthoritativeRigor(candidate, validSupportVotes, repoRoot);
        if (authoritativeRigor.score < 0.60) {
          return {
            disposition: 'DEFERRED',
            mappedVerdict: 'NEEDS_MANUAL_REVIEW',
            reason: `Authoritative rigor insufficient (${authoritativeRigor.score} < 0.60); candidate claims lack validated evidence backing; deferred under default-deny`,
            votesSummary: { total, supports, refutes, unanimous: false, isThreeLens, lenses: Array.from(lenses) },
            authoritativeRigor
          };
        }

        return {
          disposition: 'REPORTABLE',
          mappedVerdict: 'CONFIRMED',
          reason: 'Confirmed by unanimous 3-Lens panel with verified source-control-sink evidence',
          votesSummary: { total, supports: 3, refutes: 0, unanimous: true, isThreeLens, lenses: Array.from(lenses) },
          authoritativeRigor
        };
      }

      // Any split or incomplete support in 3-Lens defaults to DEFERRED
      return {
        disposition: 'DEFERRED',
        mappedVerdict: 'NEEDS_MANUAL_REVIEW',
        reason: '3-Lens panel non-unanimous; candidate unproven under default-deny',
        votesSummary: { total, supports, refutes, unanimous: false, isThreeLens, lenses: Array.from(lenses) }
      };
    }

    // If lens ballots were submitted but the 3-Lens panel is incomplete (missing required lens), fail-closed under Default-Deny
    if (lenses.size > 0 && !isThreeLens) {
      return {
        disposition: 'DEFERRED',
        mappedVerdict: 'NEEDS_MANUAL_REVIEW',
        reason: `Incomplete 3-Lens panel: received [${Array.from(lenses).join(', ')}]; missing required lenses under default-deny`,
        votesSummary: { total, supports, refutes, unanimous: false, isThreeLens: false, lenses: Array.from(lenses) }
      };
    }

    // General Persona Evaluation: Decisive counterevidence refutation always suppresses
    if (validDecisiveMitigationVote) {
      return {
        disposition: 'SUPPRESSED',
        mappedVerdict: 'FALSE_POSITIVE',
        reason: 'Affirmatively refuted by verifier with verified mitigation evidence',
        votesSummary: { total, supports, refutes, unanimous: refutes === total, lenses: Array.from(lenses) }
      };
    }

    // If any support failed evidence validation, candidate cannot be confirmed -> DEFERRED (R1-P0-01)
    if (invalidSupport) {
      return {
        disposition: 'DEFERRED',
        mappedVerdict: 'NEEDS_MANUAL_REVIEW',
        reason: `Unverified support: ${invalidSupport.lens} lens voted SUPPORTS without valid evidence binding (${invalidSupport.reason}); deferred under default-deny`,
        votesSummary: { total, supports, refutes, unanimous: false, lenses: Array.from(lenses) }
      };
    }

    // Quorum rule: Need at least 2 independent votes
    if (total < 2) {
      return {
        disposition: 'DEFERRED',
        mappedVerdict: 'NEEDS_MANUAL_REVIEW',
        reason: 'Quorum not met: requires at least 2 independent verifier votes',
        votesSummary: { total, supports, refutes, unanimous: false, lenses: Array.from(lenses) }
      };
    }

    const supportRatio = supports / total;
    const authoritativeRigor = deriveAuthoritativeRigor(candidate, validSupportVotes, repoRoot);

    // Reportable requirement: 2/3 supermajority + authoritative rigor >= 0.60 + source & sink verified
    if (supportRatio >= 0.66 && total >= 2 && authoritativeRigor.score >= 0.60 && authoritativeRigor.metrics.sourceVerified && authoritativeRigor.metrics.sinkVerified) {
      return {
        disposition: 'REPORTABLE',
        mappedVerdict: 'CONFIRMED',
        reason: 'Confirmed by 2/3 verifier supermajority with verified evidence',
        votesSummary: {
          total,
          supports,
          refutes,
          unanimous: supports === total,
          isThreeLens: false,
          lenses: Array.from(lenses)
        },
        authoritativeRigor
      };
    }

    // Refuted requirement: 3/4 supermajority + affirmative verifier mitigation proof
    if (refutes / total >= 0.75 && validDecisiveMitigationVote) {
      return {
        disposition: 'SUPPRESSED',
        mappedVerdict: 'FALSE_POSITIVE',
        reason: 'Refuted by 3/4 verifier supermajority with affirmative mitigation',
        votesSummary: { total, supports, refutes, unanimous: refutes === total, lenses: Array.from(lenses) }
      };
    }

    // Fallback on dispute / split decision
    return {
      disposition: 'DEFERRED',
      mappedVerdict: 'NEEDS_MANUAL_REVIEW',
      reason: 'Panel split or unproven evidence under default-deny',
      votesSummary: { total, supports, refutes, unanimous: false, lenses: Array.from(lenses) }
    };
  }

  // 4. Default-Deny: No independent verifier votes -> DEFERRED (Cannot self-certify)
  return {
    disposition: 'DEFERRED',
    mappedVerdict: 'NEEDS_MANUAL_REVIEW',
    reason: 'No independently recorded verifier votes; presumed unverified under default-deny',
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
  const r = String(ruleId || 'SEC');
  const u = String(uri || 'unknown');
  const l = String(startLine || 1);
  const payload = `${r.length}:${r}:${u.length}:${u}:${l}`;
  return crypto.createHash('sha256').update(payload).digest('hex').substring(0, 32);
}


/**
 * Central deterministic finalizer: transforms candidates into canonical findings.
 */
export function finalizeScan({
  candidates = [],
  manifest = null,
  repoRoot = process.cwd(),
  provenance = null,
  votes = [],
  expectedMode = null
}) {
  const safeVotes = Array.isArray(votes) ? votes : [];
  const safeRepoRoot = (typeof repoRoot === 'string' && repoRoot.trim().length > 0) ? repoRoot : null;

  // 1. Coverage Reconciliation against real repoRoot
  const coverageReconciliation = reconcileCoverage(manifest, safeRepoRoot);
  let coverageStatus = coverageReconciliation.status;
  const coverageMode = coverageReconciliation.mode;

  if (expectedMode && coverageMode !== expectedMode) {
    coverageStatus = 'PARTIAL';
  }




  // 2. Process Candidates into Canonical Findings
  const canonicalFindings = [];

  for (let i = 0; i < candidates.length; i++) {
    const raw = { ...candidates[i] };
    const candidateId = raw.id || `SEC-${String(i + 1).padStart(3, '0')}`;
    raw.id = candidateId;
    const ruleId = raw.ruleId || 'SEC-VULN';

    // Strip untrusted authority self-assertions from candidate ingress
    delete raw.consensus;
    delete raw.sourceVerified;
    delete raw.dataflowVerified;
    delete raw.pocSyntacticDemonstrated;
    delete raw.isSingleCandidate;
    delete raw.mitigationProofLine;
    delete raw.mitigationReason;

    // Sanitize attackPath location types: candidates cannot self-assert preimage/artifact types
    if (raw.attackPath && typeof raw.attackPath === 'object') {
      if (raw.attackPath.source && typeof raw.attackPath.source === 'object') delete raw.attackPath.source.locationType;
      if (raw.attackPath.sink && typeof raw.attackPath.sink === 'object') delete raw.attackPath.sink.locationType;
      if (Array.isArray(raw.attackPath.steps)) {
        for (const s of raw.attackPath.steps) {
          if (s && typeof s === 'object') delete s.locationType;
        }
      }
    }

    // If attackPath is supplied, validate schema and detect proof gaps
    if (raw.attackPath && typeof raw.attackPath === 'object') {
      const apVal = validateAttackPath(raw.attackPath, safeRepoRoot);
      if (!apVal.valid) {
        raw.proofGaps = raw.proofGaps || [];
        raw.proofGaps.push({ target: 'attackPath', unprovenProperty: apVal.error });
      } else {
        const gapCheck = detectProofGaps(raw.attackPath);
        if (gapCheck.hasGaps) {
          raw.proofGaps = raw.proofGaps || [];
          raw.proofGaps.push(...gapCheck.proofGaps);
        }
      }
    }


    // Target containment check
    const rawUri = raw.location?.uri || raw.location?.path || 'unknown';
    const pathContained = isPathContained(safeRepoRoot, rawUri);
    const normalizedRelativeUri = pathContained ? normalizeUri(safeRepoRoot, rawUri) : 'invalid_path_escaped';

    const startLine = Number(raw.location?.startLine) >= 1 ? Number(raw.location?.startLine) : 1;
    const endLine = Number(raw.location?.endLine) >= startLine ? Number(raw.location?.endLine) : startLine;

    // Mathematical Rigor
    const rigor = calculateRigor(raw.rigorMetrics);

    // Check for IMPACT lens calibration (strictly validating candidate identity, lens, and nonce)
    const candidateVotes = safeVotes.filter(v => {
      if (!v || (v.findingId !== raw.id && v.findingId !== candidateId)) return false;
      return validateBallot(v, raw).valid;
    });
    const impactVote = candidateVotes.find(v => v.lens && String(v.lens).toUpperCase() === 'IMPACT');

    // CVSS v4 Validation (calibrated by impact verifier if present)
    const cvss = validateCvssV4((impactVote && impactVote.cvssV4Vector) ? { vector: impactVote.cvssV4Vector } : raw.cvssV4);



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
      dispositionResult = deriveFinalDisposition(raw, safeVotes, rigor, safeRepoRoot);
    }



    // Confidence Clamp
    const confidence = clampConfidence(
      dispositionResult.disposition,
      dispositionResult.votesSummary,
      raw.confidence
    );

    // Severity determination (calibrated by impact verifier if available)
    let severity = (impactVote && impactVote.calibratedSeverity)
      ? String(impactVote.calibratedSeverity).toUpperCase()
      : (cvss.valid && cvss.severity && cvss.severity !== 'UNRATED')
        ? cvss.severity
        : (raw.cvssV4 && !cvss.valid)
          ? 'MEDIUM' // Default-deny clamp if submitted CVSS was invalid/contradictory
          : String(raw.severity || 'MEDIUM').toUpperCase();
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
      rigor: dispositionResult.authoritativeRigor || rigor,
      consensus: dispositionResult.votesSummary || {
        totalVotes: 0,
        unanimous: false,
        minorityEscalated: false
      },
      fingerprint: stableFingerprint,
      tags: raw.tags || [],
      proofGaps: Array.isArray(raw.proofGaps) ? raw.proofGaps : (dispositionResult.proofGaps || []),
      attackPath: raw.attackPath || null
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
 * Validates canonical findings under Default-Deny before rendering.
 * Enforces schema integrity, reapplies secret redaction, and downgrades
 * any self-asserted or unsupported REPORTABLE claims to DEFERRED.
 */
export function validateCanonicalFindings(findings, repoRoot = process.cwd()) {
  if (!Array.isArray(findings)) {
    if (findings && typeof findings === 'object' && Array.isArray(findings.canonicalFindings)) {
      findings = findings.canonicalFindings;
    } else {
      return [];
    }
  }

  const validated = [];

  for (const raw of findings) {
    if (!raw || typeof raw !== 'object') continue;

    const id = String(raw.id || raw.findingId || 'SEC-UNKNOWN');
    const ruleId = String(raw.ruleId || 'SEC-VULN');
    const severity = String(raw.severity || 'MEDIUM').toUpperCase();

    // Re-apply secret redaction and sanitization across all text fields
    const title = redactSecrets(stripControlAndBidi(String(raw.title || 'Security Finding')));
    const description = redactSecrets(stripControlAndBidi(String(raw.description || '')));
    const uri = raw.location?.uri ? String(raw.location.uri) : 'unknown';
    const startLine = Number(raw.location?.startLine || 1);
    const endLine = Number(raw.location?.endLine || startLine);
    let lineSnippet = raw.location?.lineSnippet ? redactSecrets(stripControlAndBidi(String(raw.location.lineSnippet))) : null;

    // Suppress snippet for secrets
    const isCredential = /(?:secret|credential|token|password|api[_-]?key|cwe-798)/i.test(`${title} ${ruleId} ${id}`);
    if (isCredential) {
      lineSnippet = '[Line snippet suppressed for credential finding]';
    }

    let disposition = String(raw.disposition || 'DEFERRED').toUpperCase();
    let verdict = String(raw.verdict || 'NEEDS_MANUAL_REVIEW').toUpperCase();
    let dispositionReason = redactSecrets(stripControlAndBidi(String(raw.dispositionReason || '')));

    const consensus = (raw.consensus && typeof raw.consensus === 'object') ? raw.consensus : { supports: 0, refutes: 0, totalVotes: 0, unanimous: false };
    const rigor = (raw.rigor && typeof raw.rigor === 'object') ? raw.rigor : { score: 0.0, assuranceLevel: 'NONE' };

    // Default-Deny Invariant: REPORTABLE / CONFIRMED cannot be asserted without quorum, unanimity/supermajority, and rigor
    if (disposition === 'REPORTABLE' || verdict === 'CONFIRMED') {
      const totalVotes = Number(consensus.total !== undefined ? consensus.total : (consensus.totalVotes !== undefined ? consensus.totalVotes : 0));
      const supports = Number(consensus.supports || 0);
      const refutes = Number(consensus.refutes || 0);
      const hasQuorum = supports >= 2 && totalVotes >= 2 && refutes === 0 && (supports === totalVotes || (supports / totalVotes >= 0.66));
      const hasRigor = Number(rigor.score || 0) >= 0.60;
      let fileExists = true;
      if (repoRoot && uri !== 'unknown') {
        const normUri = uri.replace(/\\/g, '/').replace(/^\.\//, '');
        if (normUri.startsWith('..') || normUri.includes('/../') || path.isAbsolute(uri)) {
          fileExists = false;
        } else {
          const fullTarget = path.resolve(repoRoot, normUri);
          const relToRepo = path.relative(repoRoot, fullTarget);
          if (relToRepo.startsWith('..') || path.isAbsolute(relToRepo) || !fs.existsSync(fullTarget)) {
            fileExists = false;
          }
        }
      }

      if (!hasQuorum || !hasRigor || !fileExists) {
        disposition = 'DEFERRED';
        verdict = 'NEEDS_MANUAL_REVIEW';
        dispositionReason = `Presumption of Non-Pass: Canonical finding lacked authoritative verifier quorum (${supports}/${totalVotes}, refutes=${refutes}) or rigor (${rigor.score || 0}).`;
      }
    }

    let validatedCvss = null;
    if (raw.cvssV4 && typeof raw.cvssV4 === 'object') {
      const cvssRes = validateCvssV4(raw.cvssV4);
      if (cvssRes && cvssRes.valid) {
        validatedCvss = {
          vector: cvssRes.vector,
          score: cvssRes.score,
          severity: cvssRes.severity
        };
      }
    }

    validated.push({
      ...raw,
      id,
      ruleId,
      severity,
      title,
      description,
      location: {
        uri,
        startLine,
        endLine,
        lineSnippet,
        lineHash: raw.location?.lineHash || ''
      },
      confidenceScore: raw.confidenceScore !== undefined ? raw.confidenceScore : 0.5,
      confidenceLevel: raw.confidenceLevel || 'LOW',
      cvssV4: validatedCvss,
      rigor,
      consensus,
      disposition,
      verdict,
      dispositionReason,
      fingerprint: raw.fingerprint || '',
      tags: Array.isArray(raw.tags) ? raw.tags : []
    });
  }

  return validated;
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
  const safeFindings = validateCanonicalFindings(canonicalFindings, repoRoot);
  const rulesMap = new Map();
  const results = [];

  for (const f of safeFindings) {
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
        version: '1.0.0',
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
  provenance = null,
  repoRoot = process.cwd()
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
    const entries = manifest && (Array.isArray(manifest.entries) ? manifest.entries : (manifest.directoryManifest && Array.isArray(manifest.directoryManifest.entries) ? manifest.directoryManifest.entries : null));
    if (entries) {
      md += '| Directory Path | Audit Status | Files | Reconciliation Reason |\n';
      md += '| :--- | :--- | :--- | :--- |\n';
      for (const e of entries) {
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

  const safeFindings = validateCanonicalFindings(canonicalFindings, repoRoot);

  // Categorize canonical findings
  const confirmed = safeFindings.filter(f => f.disposition === 'REPORTABLE');
  const manualReview = safeFindings.filter(f => f.disposition === 'DEFERRED');
  const falsePositives = safeFindings.filter(f => f.disposition === 'SUPPRESSED');

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
        md += `- **CVSS v4.0**: \`${sanitizeInlineText(f.cvssV4.vector)}\`${f.cvssV4.score !== null ? ` (Score: ${f.cvssV4.score})` : ' (Score: Unrated / Vector-Only)'}\n`;
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
      if (f.description) {
        md += `**Description**:\n${sanitizeBlockText(f.description)}\n\n`;
      }
      if (Array.isArray(f.proofGaps) && f.proofGaps.length > 0) {
        md += `- **Unclosed Proof Gaps**:\n`;
        for (const g of f.proofGaps) {
          const safeTarget = redactSecrets(sanitizeInlineText(String(g.target || (g.stepIndex !== undefined ? 'step ' + g.stepIndex : 'evidence'))));
          const safeProp = redactSecrets(sanitizeInlineText(g.unprovenProperty || 'Unverified step'));
          const safeLoc = g.location ? ` (\`${redactSecrets(sanitizeInlineText(g.location))}\`)` : '';
          md += `  - [${safeTarget}] ${safeProp}${safeLoc}\n`;
        }
        md += '\n';
      }
      if (f.location.lineSnippet) {
        md += `**Code Reference**:\n\`\`\`\n${f.location.lineSnippet}\n\`\`\`\n\n`;
      }
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
/**
 * Loads and aggregates verifier votes from a file or directory (supports nested subdirectories).
 * Supports optional nonce filtering via options.expectedNonces (R1-P1-05).
 */
export function loadVotes(votesPath, options = {}) {
  if (!votesPath || !fs.existsSync(votesPath)) return [];
  try {
    let rawVotes = [];
    const stat = fs.statSync(votesPath);
    if (stat.isDirectory()) {
      const files = fs.readdirSync(votesPath, { recursive: true });
      for (const file of files) {
        const filePath = typeof file === 'string' ? file : file.name;
        if (filePath.endsWith('.json')) {
          try {
            const content = JSON.parse(fs.readFileSync(path.join(votesPath, filePath), 'utf8'));
            if (Array.isArray(content)) {
              rawVotes.push(...content);
            } else if (content && typeof content === 'object') {
              rawVotes.push(content);
            }
          } catch {}
        }
      }
    } else {
      const content = JSON.parse(fs.readFileSync(votesPath, 'utf8'));
      rawVotes = Array.isArray(content) ? content : [content];
    }

    if (options && options.expectedNonces) {
      const nonceMap = options.expectedNonces instanceof Map
        ? options.expectedNonces
        : new Map(Object.entries(options.expectedNonces));
      return rawVotes.filter(v => {
        if (!v || !v.findingId) return false;
        const expected = nonceMap.get(v.findingId);
        return expected !== undefined && v.nonce === expected;
      });
    }

    return rawVotes;
  } catch {
    return [];
  }
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

  const inputPath = getArg('--candidates') || getArg('--input');
  const votesPath = getArg('--votes');
  const manifestPath = getArg('--manifest');
  const repoRootArg = getArg('--repo-root') || process.cwd();
  const outputJsonPath = getArg('--output') || getArg('--output-json');
  const outputSarifPath = getArg('--output-sarif');
  const outputMdPath = getArg('--output-md');
  const outputCoveragePath = getArg('--output-coverage');

  if (inputPath) {
    try {
      const rawData = fs.readFileSync(inputPath, 'utf8');
      const candidates = JSON.parse(rawData);

      let manifest = null;
      if (manifestPath && fs.existsSync(manifestPath)) {
        manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
      }

      const votes = loadVotes(votesPath);
      if (candidates.length > 0 && votes.length === 0) {
        console.warn('[DEFAULT-DENY] No verifier votes provided via --votes. All candidates will be derived as DEFERRED under Default-Deny.');
      }

      const repoRoot = path.resolve(repoRootArg);
      const finalization = finalizeScan({ candidates, manifest, repoRoot, votes });

      if (outputJsonPath) {
        fs.mkdirSync(path.dirname(outputJsonPath), { recursive: true });
        fs.writeFileSync(outputJsonPath, JSON.stringify(finalization.canonicalFindings, null, 2), 'utf8');
        console.log(`✔ Generated Canonical Findings JSON: ${outputJsonPath}`);
      }

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


