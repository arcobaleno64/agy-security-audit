#!/usr/bin/env node
/**
 * validate-patch.mjs
 * Validates unified diff patch syntax, checks Patch Jail perimeter,
 * detects stale baselines, and applies candidate patches into sandbox workspaces.
 */

import fs from 'node:fs';
import path from 'node:path';
import { runSafeGit, getHardenedGitProvenance } from './safe-git.mjs';
import { isPathContained } from './finalize-scan.mjs';

// CVE-2021-42574: Invisible Bidirectional control characters
const BIDI_REGEX = /[\u202A-\u202E\u2066-\u2069]/;

// Forbidden manifest and CI/CD paths (Patch Jail Rule 3)
const FORBIDDEN_PATHS = [
  '.git/',
  '.github/',
  '.gitlab-ci.yml',
  '.circleci/',
  'package.json',
  'package-lock.json',
  'yarn.lock',
  'pnpm-lock.yaml',
  'go.mod',
  'go.sum',
  'Cargo.toml',
  'Cargo.lock',
  'requirements.txt',
  'pyproject.toml',
  'Dockerfile',
  'docker-compose',
  '.gitignore'
];

/**
 * Normalizes diff header path, stripping quotes, prefixes, and timestamps.
 */
function normalizeDiffHeaderPath(rawLine, prefix) {
  let line = rawLine.trim();
  if (line.startsWith(prefix)) {
    line = line.substring(prefix.length).trim();
  } else if (line.startsWith(prefix.replace('/', ' "'))) {
    line = line.substring(prefix.length + 1).trim();
  }

  // Strip tab-separated timestamps
  const tabIdx = line.indexOf('\t');
  if (tabIdx !== -1) {
    line = line.substring(0, tabIdx).trim();
  }

  // Strip surrounding quotes
  if ((line.startsWith('"') && line.endsWith('"')) || (line.startsWith("'") && line.endsWith("'"))) {
    line = line.substring(1, line.length - 1);
  }

  // Strip git standard a/ and b/ prefixes
  if (line.startsWith('a/') || line.startsWith('b/')) {
    line = line.substring(2);
  }

  // Normalize path separators and remove leading ./ or /
  line = line.replace(/\\/g, '/').replace(/^\.\//, '').replace(/^\/+/, '');

  return line.trim();
}


/**
 * Validates unified diff syntax and enforces Patch Jail rules.
 */
export function validatePatchSyntax(patchContent, repoRoot = process.cwd(), options = {}) {
  if (!patchContent || typeof patchContent !== 'string' || patchContent.trim().length === 0) {
    return { valid: false, targetFiles: [], error: 'Patch content must be a non-empty string' };
  }

  // Patch Jail Rule 5: Unicode Bidi filtering (CVE-2021-42574)
  if (BIDI_REGEX.test(patchContent)) {
    return { valid: false, targetFiles: [], error: 'Patch rejected: Contains bidirectional Unicode control characters (CVE-2021-42574)' };
  }

  const lines = patchContent.split(/\r?\n/);
  const targetFiles = new Set();
  let hasHunk = false;

  for (const line of lines) {
    // Patch Jail Rule 2: No new files allowed
    if (line.startsWith('new file mode')) {
      return { valid: false, targetFiles: [], error: 'Patch rejected: Remediation patches are forbidden from creating new files' };
    }

    if (line.startsWith('--- ') && !line.startsWith('--- /dev/null')) {
      const p = normalizeDiffHeaderPath(line, '--- ');
      if (!isPathContained(repoRoot, p)) {
        return { valid: false, targetFiles: [], error: `Patch file escapes repository root: ${p}` };
      }
      targetFiles.add(p);
    } else if (line.startsWith('+++ ') && !line.startsWith('+++ /dev/null')) {
      const p = normalizeDiffHeaderPath(line, '+++ ');
      if (!isPathContained(repoRoot, p)) {
        return { valid: false, targetFiles: [], error: `Patch file escapes repository root: ${p}` };
      }
      targetFiles.add(p);
    } else if (line.startsWith('@@ ') && line.includes(' @@')) {
      hasHunk = true;
    }
  }

  if (targetFiles.size === 0) {
    return { valid: false, targetFiles: [], error: 'No unified diff file headers found (expected --- a/... and +++ b/...)' };
  }

  if (!hasHunk) {
    return { valid: false, targetFiles: [], error: 'No unified diff hunk headers found (expected @@ -l,s +l,s @@)' };
  }

  const fileList = Array.from(targetFiles);

  // Patch Jail Rule 1: Single-file confinement (unless explicitly allowed)
  if (!options.allowMultipleFiles && fileList.length > 1) {
    return { valid: false, targetFiles: fileList, error: `Patch rejected: Violates single-file confinement (${fileList.length} files targeted)` };
  }

  // Patch Jail Rule 3: No CI/CD or manifest tampering
  for (const f of fileList) {
    const cleanPath = f.replace(/\\/g, '/').replace(/^\.\//, '').replace(/^\/+/, '').toLowerCase();
    for (const forbidden of FORBIDDEN_PATHS) {
      const forbLower = forbidden.toLowerCase();
      if (cleanPath === forbLower || cleanPath.startsWith(forbLower) || cleanPath.endsWith(forbLower) || cleanPath.includes('/' + forbLower)) {
        return { valid: false, targetFiles: fileList, error: `Patch rejected: Modifying CI/CD or package manifest is strictly forbidden: ${f}` };
      }
    }
  }


  return {
    valid: true,
    targetFiles: fileList,
    error: null
  };
}

const REVISION_REGEX = /^[a-zA-Z0-9_./@~^{}-]+$/;

/**
 * Detects whether target files have diverged since the baseline audit commit.
 */
export function detectStalePatch(repoRoot = process.cwd(), targetFiles = [], baseRevision = 'HEAD') {
  if (!Array.isArray(targetFiles) || targetFiles.length === 0) {
    return { stale: false, modifiedFiles: [] };
  }

  // Option injection defense: reject revisions starting with '-' or illegal characters
  if (typeof baseRevision !== 'string' || baseRevision.startsWith('-') || !REVISION_REGEX.test(baseRevision)) {
    return {
      stale: true,
      modifiedFiles: [],
      error: `Invalid or unsafe baseRevision parameter: ${baseRevision}`
    };
  }

  const modifiedFiles = [];

  for (const file of targetFiles) {
    const diffRes = runSafeGit(repoRoot, ['diff', '--name-only', '--no-ext-diff', '--no-textconv', baseRevision, '--', file]);
    // Fail-Closed: if git fails, treat as diverged / stale
    if (diffRes.status !== 0) {
      return {
        stale: true,
        modifiedFiles: [file],
        error: `Git diff failed on baseline revision ${baseRevision}: ${diffRes.stderr}`
      };
    }

    if (diffRes.stdout.trim().length > 0) {
      modifiedFiles.push(file);
    }
  }

  return {
    stale: modifiedFiles.length > 0,
    modifiedFiles,
    reason: modifiedFiles.length > 0
      ? `Target file(s) have diverged from baseline revision ${baseRevision}: ${modifiedFiles.join(', ')}`
      : null
  };
}

/**
 * Validates candidate remediation against the full 3-Lens panel under Default-Deny (P1-03).
 * Requires all 3 lenses (DEFENSES, REACHABILITY, IMPACT).
 * Missing votes fail verification fail-closed (silence is not approval).
 */
export function verifyRemediation(finding, verifierVotes = []) {
  if (!finding || typeof finding !== 'object') {
    return { verified: false, reason: 'Invalid finding object' };
  }

  const findingId = finding.id || finding.findingId;
  if (!findingId) {
    return { verified: false, reason: 'Finding missing concrete identifier' };
  }

  // Strict task-binding: only inspect votes matching this specific finding
  const safeVotes = Array.isArray(verifierVotes) ? verifierVotes : [];
  const relevantVotes = safeVotes.filter(v => v && v.findingId === findingId);

  // 1. Strict Requirement: All 3 Lenses Must Be Present
  const defensesVote = relevantVotes.find(v => v.lens && String(v.lens).toUpperCase() === 'DEFENSES');
  const reachabilityVote = relevantVotes.find(v => v.lens && String(v.lens).toUpperCase() === 'REACHABILITY');
  const impactVote = relevantVotes.find(v => v.lens && String(v.lens).toUpperCase() === 'IMPACT');

  const missingLenses = [];
  if (!defensesVote) missingLenses.push('DEFENSES');
  if (!reachabilityVote) missingLenses.push('REACHABILITY');
  if (!impactVote) missingLenses.push('IMPACT');

  if (missingLenses.length > 0) {
    return {
      verified: false,
      reason: `Incomplete 3-Lens panel: missing required vote(s) from [${missingLenses.join(', ')}]. Silence is not approval under default-deny.`
    };
  }

  // 2. DEFENSES Lens Verification
  const defDecision = String(defensesVote.decision || defensesVote.verdict || '').toUpperCase();
  const isDefRefutes = ['REFUTES', 'FALSE_POSITIVE', 'SUPPRESSED'].includes(defDecision);

  const proofLine = defensesVote.mitigationProofLine
    ? String(defensesVote.mitigationProofLine).trim()
    : (Array.isArray(defensesVote.evidence) && defensesVote.evidence[0]
        ? (typeof defensesVote.evidence[0] === 'object' ? `${defensesVote.evidence[0].path}:${defensesVote.evidence[0].line}` : String(defensesVote.evidence[0]))
        : null);
  const proofReason = defensesVote.mitigationReason
    ? String(defensesVote.mitigationReason).trim()
    : (defensesVote.reason ? String(defensesVote.reason).trim() : null);

  const hasDefProof = Boolean(
    proofLine &&
    proofLine.length > 0 &&
    proofReason &&
    proofReason.length > 0
  );

  if (!isDefRefutes || !hasDefProof) {
    return {
      verified: false,
      reason: 'DEFENSES lens must vote REFUTES with affirmative mitigation proof (mitigationProofLine and mitigationReason)'
    };
  }

  // 3. REACHABILITY Lens Verification
  const reachDecision = String(reachabilityVote.decision || reachabilityVote.verdict || '').toUpperCase();
  if (['CONFIRMED', 'SUPPORTS', 'REPORTABLE'].includes(reachDecision)) {
    return {
      verified: false,
      reason: 'REACHABILITY lens confirms that attack path remains active despite patch'
    };
  }
  if (!['REFUTES', 'FALSE_POSITIVE', 'SUPPRESSED'].includes(reachDecision)) {
    return {
      verified: false,
      reason: `REACHABILITY lens decision '${reachDecision}' does not refute reachability under default-deny`
    };
  }

  // 4. IMPACT Lens Verification
  const impactDecision = String(impactVote.decision || impactVote.verdict || '').toUpperCase();
  if (['CONFIRMED', 'SUPPORTS', 'REPORTABLE'].includes(impactDecision)) {
    return {
      verified: false,
      reason: 'IMPACT lens confirms that security consequence remains obtainable despite patch'
    };
  }
  if (!['REFUTES', 'FALSE_POSITIVE', 'SUPPRESSED'].includes(impactDecision)) {
    return {
      verified: false,
      reason: `IMPACT lens decision '${impactDecision}' does not refute security impact under default-deny`
    };
  }

  return {
    verified: true,
    reason: 'Full 3-Lens panel (DEFENSES, REACHABILITY, IMPACT) unanimously verifies remediation under default-deny',
    mitigationProofLine: proofLine,
    mitigationReason: proofReason
  };
}

// -----------------------------------------------------------------------------
// CLI Dispatch
// -----------------------------------------------------------------------------
const isDirectExecution = process.argv[1] && process.argv[1].endsWith('validate-patch.mjs');

if (isDirectExecution) {
  const args = process.argv.slice(2);
  const patchFile = args[0];
  if (!patchFile) {
    console.error('Usage: node validate-patch.mjs <patch-file>');
    process.exit(1);
  }

  try {
    const patchContent = fs.readFileSync(patchFile, 'utf8');
    const result = validatePatchSyntax(patchContent);
    if (!result.valid) {
      console.error(`❌ Patch Validation Failed: ${result.error}`);
      process.exit(1);
    }
    const staleResult = detectStalePatch(process.cwd(), result.targetFiles);
    if (staleResult.stale) {
      console.error(`❌ Patch Stale: ${staleResult.reason || staleResult.error}`);
      process.exit(1);
    }
    console.log(`✔ Patch Valid and Fresh. Target file(s): ${result.targetFiles.join(', ')}`);
  } catch (err) {
    console.error('Error validating patch:', err.message);
    process.exit(1);
  }
}


