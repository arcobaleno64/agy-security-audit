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
 * Validates CVSS v4 vector fail-closed. Never substitutes a fake high-severity vector or clamped invalid scores.
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
  }

  return {
    valid: true,
    vector: rawVector.trim(),
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
    if (v.findingId) return v.findingId === candidate.id;
    return false;
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
    let hasDecisiveMitigation = false;
    let reachabilityRefuted = false;
    const lenses = new Set();

    for (const v of dedupedVotes) {
      if (v.lens) lenses.add(String(v.lens).toUpperCase());
      const decision = String(v.decision || v.verdict || '').toUpperCase();
      if (['CONFIRMED', 'SUPPORTS', 'REPORTABLE'].includes(decision)) {
        supports++;
      } else if (['FALSE_POSITIVE', 'REFUTES', 'SUPPRESSED'].includes(decision)) {
        refutes++;
        if (v.mitigationProofLine || (v.mitigationReason && v.mitigationReason.trim().length > 0)) {
          hasDecisiveMitigation = true;
        }
        if (v.lens && String(v.lens).toUpperCase() === 'REACHABILITY') {
          reachabilityRefuted = true;
        }
      }
    }

    const total = dedupedVotes.length;
    const isThreeLens = lenses.has('REACHABILITY') && lenses.has('DEFENSES') && lenses.has('IMPACT');

    // 3-Lens Conjunctive Evaluation
    if (isThreeLens) {
      // If Reachability refutes -> Unreachable (FALSE_POSITIVE)
      if (reachabilityRefuted) {
        return {
          disposition: 'SUPPRESSED',
          mappedVerdict: 'FALSE_POSITIVE',
          reason: 'Unreachable: refuted by 3-Lens REACHABILITY analysis',
          votesSummary: { total, supports, refutes, unanimous: false, isThreeLens, lenses: Array.from(lenses) }
        };
      }

      // If Defenses refutes -> Neutralized by sanitizer / validation barrier (FALSE_POSITIVE)
      const defensesVote = dedupedVotes.find(v => v.lens && String(v.lens).toUpperCase() === 'DEFENSES');
      if (defensesVote && ['FALSE_POSITIVE', 'REFUTES', 'SUPPRESSED'].includes(String(defensesVote.decision || defensesVote.verdict).toUpperCase())) {
        const hasMitigation = defensesVote.mitigationProofLine || (defensesVote.mitigationReason && defensesVote.mitigationReason.trim().length > 0);
        if (hasMitigation) {
          return {
            disposition: 'SUPPRESSED',
            mappedVerdict: 'FALSE_POSITIVE',
            reason: 'Neutralized: affirmative defense proven by 3-Lens DEFENSES analysis',
            votesSummary: { total, supports, refutes, unanimous: false, isThreeLens, lenses: Array.from(lenses) }
          };
        }
      }


      // If Impact refutes -> Purely theoretical / zero demonstrable harm (FALSE_POSITIVE)
      const impactVote = dedupedVotes.find(v => v.lens && String(v.lens).toUpperCase() === 'IMPACT');
      if (impactVote && ['FALSE_POSITIVE', 'REFUTES', 'SUPPRESSED'].includes(String(impactVote.decision || impactVote.verdict).toUpperCase())) {
        return {
          disposition: 'SUPPRESSED',
          mappedVerdict: 'FALSE_POSITIVE',
          reason: 'Zero demonstrable harm: refuted by 3-Lens IMPACT analysis',
          votesSummary: { total, supports, refutes, unanimous: false, isThreeLens, lenses: Array.from(lenses) }
        };
      }

      // 3-Lens requires unanimous confirmation (supports === 3)
      if (supports === 3 && rigor.score >= 0.60) {
        return {
          disposition: 'REPORTABLE',
          mappedVerdict: 'CONFIRMED',
          reason: 'Confirmed by unanimous 3-Lens panel (Reachability, Defenses, Impact)',
          votesSummary: { total, supports: 3, refutes: 0, unanimous: true, isThreeLens, lenses: Array.from(lenses) }
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

    // General Persona Evaluation: Decisive counterevidence refutation always suppresses
    if (hasDecisiveMitigation) {
      return {
        disposition: 'SUPPRESSED',
        mappedVerdict: 'FALSE_POSITIVE',
        reason: 'Affirmatively refuted by verifier with positive mitigation evidence',
        votesSummary: { total, supports, refutes, unanimous: refutes === total, lenses: Array.from(lenses) }
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

    // Reportable requirement: 2/3 supermajority + rigor
    if (supportRatio >= 0.66 && total >= 2 && rigor.score >= 0.60) {
      return {
        disposition: 'REPORTABLE',
        mappedVerdict: 'CONFIRMED',
        reason: 'Confirmed by 2/3 verifier supermajority with verified taint evidence',
        votesSummary: {
          total,
          supports,
          refutes,
          unanimous: supports === total,
          isThreeLens: false,
          lenses: Array.from(lenses)
        }
      };
    }


    // Refuted requirement: 3/4 supermajority + affirmative verifier mitigation proof
    if (refutes / total >= 0.75 && hasDecisiveMitigation) {
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
    delete raw.isSingleCandidate;
    delete raw.mitigationProofLine;
    delete raw.mitigationReason;


    // If attackPath is supplied, validate schema and detect proof gaps
    if (raw.attackPath && typeof raw.attackPath === 'object') {
      const apVal = validateAttackPath(raw.attackPath, repoRoot);
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
    const pathContained = isPathContained(repoRoot, rawUri);
    const normalizedRelativeUri = pathContained ? normalizeUri(repoRoot, rawUri) : 'invalid_path_escaped';

    const startLine = Number(raw.location?.startLine) >= 1 ? Number(raw.location?.startLine) : 1;
    const endLine = Number(raw.location?.endLine) >= startLine ? Number(raw.location?.endLine) : startLine;

    // Mathematical Rigor
    const rigor = calculateRigor(raw.rigorMetrics);

    // Check for IMPACT lens calibration
    const candidateVotes = safeVotes.filter(v => v && (v.findingId === raw.id || v.findingId === candidateId));
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
      dispositionResult = deriveFinalDisposition(raw, safeVotes, rigor);
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
      : String(raw.severity || cvss.severity || 'HIGH').toUpperCase();
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
      if (Array.isArray(f.proofGaps) && f.proofGaps.length > 0) {
        md += `- **Unclosed Proof Gaps**:\n`;
        for (const g of f.proofGaps) {
          md += `  - [${sanitizeInlineText(String(g.target || (g.stepIndex !== undefined ? 'step ' + g.stepIndex : 'evidence')))}] ${sanitizeInlineText(g.unprovenProperty || 'Unverified step')}${g.location ? ` (\`${sanitizeInlineText(g.location)}\`)` : ''}\n`;
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
 */
export function loadVotes(votesPath) {
  if (!votesPath || !fs.existsSync(votesPath)) return [];
  try {
    const stat = fs.statSync(votesPath);
    if (stat.isDirectory()) {
      const votes = [];
      const files = fs.readdirSync(votesPath, { recursive: true });
      for (const file of files) {
        const filePath = typeof file === 'string' ? file : file.name;
        if (filePath.endsWith('.json')) {
          try {
            const content = JSON.parse(fs.readFileSync(path.join(votesPath, filePath), 'utf8'));
            if (Array.isArray(content)) {
              votes.push(...content);
            } else if (content && typeof content === 'object') {
              votes.push(content);
            }
          } catch {}
        }
      }
      return votes;
    } else {
      const content = JSON.parse(fs.readFileSync(votesPath, 'utf8'));
      return Array.isArray(content) ? content : [content];
    }
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


