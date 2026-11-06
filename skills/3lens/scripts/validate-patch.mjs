#!/usr/bin/env node
/**
 * validate-patch.mjs
 * Validates unified diff patch syntax, checks Patch Jail perimeter,
 * detects stale baselines, and applies candidate patches into sandbox workspaces.
 */

import fs from 'node:fs';
import path from 'node:path';
import { runSafeGit, getHardenedGitProvenance, resolveGitCommitRef } from './safe-git.mjs';
import { isPathContained, validateVoteEvidence } from './finalize-scan.mjs';

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

  // Option injection defense: resolve revision safely to commit hash
  let resolvedBase;
  try {
    resolvedBase = resolveGitCommitRef(repoRoot, baseRevision);
  } catch (err) {
    return {
      stale: true,
      modifiedFiles: [],
      error: `Invalid or unsafe baseRevision parameter: ${baseRevision} (${err.message})`
    };
  }

  const modifiedFiles = [];

  for (const file of targetFiles) {
    const diffRes = runSafeGit(repoRoot, ['diff', '--name-only', '--no-ext-diff', '--no-textconv', resolvedBase, '--', file]);
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
 * Validates candidate remediation against the full 3-Lens panel under Default-Deny (P1-03, R1-P0-02).
 * Requires all 3 lenses (DEFENSES, REACHABILITY, IMPACT).
 * Missing votes fail verification fail-closed (silence is not approval).
 * All 3 REFUTES votes must provide verifiable evidence binding inside the patched tree.
 */
export function verifyRemediation(finding, verifierVotes = [], repoRoot = null, options = {}) {
  if (!finding || typeof finding !== 'object') {
    return { verified: false, reason: 'Invalid finding object' };
  }

  // Under Default-Deny, verification strictly requires concrete repository root
  if (!repoRoot || typeof repoRoot !== 'string' || repoRoot.trim().length === 0) {
    return { verified: false, reason: 'Verification requires concrete repository root under default-deny' };
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

  // 2. Unresolved Reachability / Impact Evidence Check: any lens voting SUPPORTS/CONFIRMED immediately rejects
  for (const v of [defensesVote, reachabilityVote, impactVote]) {
    const dec = String(v.decision || v.verdict || '').toUpperCase();
    if (['CONFIRMED', 'SUPPORTS', 'REPORTABLE'].includes(dec)) {
      return {
        verified: false,
        reason: `${String(v.lens).toUpperCase()} lens confirms unresolved reachability/impact evidence despite patch`
      };
    }
    if (!['REFUTES', 'FALSE_POSITIVE', 'SUPPRESSED'].includes(dec)) {
      return {
        verified: false,
        reason: `${String(v.lens).toUpperCase()} lens decision '${dec}' does not refute vulnerability under default-deny`
      };
    }
  }

  // 3. Evidence Validation for all 3 REFUTES ballots (R1-P0-02)
  for (const v of [defensesVote, reachabilityVote, impactVote]) {
    const evCheck = validateVoteEvidence(v, finding, repoRoot);
    if (!evCheck.valid) {
      return {
        verified: false,
        reason: `Unverified refutation: ${String(v.lens).toUpperCase()} lens refuted remediation without valid evidence binding (${evCheck.reason}); deferred under default-deny`
      };
    }
    v._validatedEvidence = evCheck.evidence;
  }

  // 4. Scratch Tree Isolation Guard (R1-P0-02)
  if (options.scratchTree && path.resolve(repoRoot) !== path.resolve(options.scratchTree)) {
    return {
      verified: false,
      reason: 'Verification must be executed against isolated scratch tree, not unpatched repository root'
    };
  }
  if (options.originalTree) {
    const origAbs = path.resolve(options.originalTree);
    const repoAbs = path.resolve(repoRoot);
    if (origAbs === repoAbs) {
      return {
        verified: false,
        reason: 'Verification rejected: repository root points to original unpatched tree instead of isolated scratch tree'
      };
    }
  }

  // 5. Target Correlation Guard (R1-P0-02)
  const targetUri = finding.location?.uri || finding.location?.path;
  const defEv = defensesVote._validatedEvidence || [];
  const reachEv = reachabilityVote._validatedEvidence || [];
  const impactEv = impactVote._validatedEvidence || [];

  if (targetUri) {
    const normTarget = targetUri.replace(/\\/g, '/').replace(/^\.\//, '');
    const allEv = [defEv, reachEv, impactEv].flat();
    const touchesTarget = allEv.some(e => e.path.replace(/\\/g, '/').replace(/^\.\//, '') === normTarget);
    if (!touchesTarget) {
      return {
        verified: false,
        reason: `Evidence does not correlate with vulnerability target file: '${targetUri}'`
      };
    }
  }

  // 6. Specific Lens Proof Assertions:
  // DEFENSES: must prove mitigation/guard
  const hasDefProof = defEv.some(e => ['guard', 'control', 'defense', 'mitigation'].includes(e.role)) ||
    Boolean(defensesVote.mitigationProofLine);
  const defReason = defensesVote.mitigationReason || defensesVote.reason;
  if (!hasDefProof || !defReason) {
    return {
      verified: false,
      reason: 'DEFENSES lens must provide verified mitigation proof (mitigationProofLine / guard role and reason)'
    };
  }

  // REACHABILITY: must prove route/flow blocked with role and rationale
  const reachReason = reachabilityVote.reason || reachabilityVote.justification || reachabilityVote.mitigationReason;
  const hasReachProof = reachEv.some(e => ['dead-path', 'blocked', 'unreachable', 'guard', 'control', 'entrypoint'].includes(e.role)) ||
    Boolean(reachabilityVote.unreachableProofLine);
  if (!hasReachProof || !reachReason) {
    return {
      verified: false,
      reason: 'REACHABILITY lens must provide verified evidence and rationale that attack path is blocked'
    };
  }

  // IMPACT: must prove consequence neutralized with role and rationale
  const impactReason = impactVote.reason || impactVote.justification || impactVote.mitigationReason;
  const hasImpactProof = impactEv.some(e => ['impact-boundary', 'containment', 'neutralized', 'guard', 'control', 'defense'].includes(e.role)) ||
    Boolean(impactVote.containmentProofLine);
  if (!hasImpactProof || !impactReason) {
    return {
      verified: false,
      reason: 'IMPACT lens must provide verified evidence and rationale that security consequence is neutralized'
    };
  }

  return {
    verified: true,
    reason: 'Full 3-Lens panel (DEFENSES, REACHABILITY, IMPACT) unanimously verifies remediation with validated evidence bindings',
    mitigationProofLine: defensesVote.mitigationProofLine || `${defEv[0]?.path}:${defEv[0]?.line}`,
    mitigationReason: defReason
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


