/**
 * safe-git.mjs
 * Hardened Git operations avoiding malicious .git/config execution vectors
 * (diff.external, core.fsmonitor, textconv, pager, hooks).
 */

import path from 'node:path';
import crypto from 'node:crypto';
import { spawnSync } from 'node:child_process';

export const HARDENED_GIT_ENV = Object.freeze({
  ...process.env,
  GIT_CONFIG_GLOBAL: process.platform === 'win32' ? 'NUL' : '/dev/null',
  GIT_CONFIG_SYSTEM: process.platform === 'win32' ? 'NUL' : '/dev/null',
  GIT_TERMINAL_PROMPT: '0',
  GIT_PAGER: 'cat',
  PAGER: 'cat',
  GIT_EXTERNAL_DIFF: '',
  GIT_OPTIONAL_LOCKS: '0'
});

/**
 * Executes git safely with hardened environment and flags.
 */
export function runSafeGit(repoRoot, args) {
  if (!repoRoot || typeof repoRoot !== 'string') {
    throw new Error('Invalid repoRoot supplied to runSafeGit');
  }

  const safeArgs = [
    '-c', 'core.fsmonitor=false',
    '-c', `core.hooksPath=${process.platform === 'win32' ? 'NUL' : '/dev/null'}`,
    '-c', 'diff.external=',
    '-C', repoRoot,
    ...args
  ];


  const result = spawnSync('git', safeArgs, {
    cwd: repoRoot,
    shell: false,
    env: HARDENED_GIT_ENV,
    stdio: ['ignore', 'pipe', 'pipe'],
    encoding: 'utf8',
    maxBuffer: 10 * 1024 * 1024
  });

  return result;
}

/**
 * Extracts hardened Git provenance (HEAD revision SHA40, SHA12, branch, dirty status).
 */
export function getHardenedGitProvenance(repoRoot) {
  try {
    const revRes = runSafeGit(repoRoot, ['rev-parse', 'HEAD']);
    if (revRes.status !== 0 || !revRes.stdout) {
      return getFallbackProvenance();
    }
    const sha40 = revRes.stdout.trim();

    const branchRes = runSafeGit(repoRoot, ['rev-parse', '--abbrev-ref', 'HEAD']);
    const branch = (branchRes.status === 0 && branchRes.stdout) ? branchRes.stdout.trim() : 'unknown';

    const statusRes = runSafeGit(repoRoot, ['status', '--porcelain']);
    const statusOut = (statusRes.status === 0 && statusRes.stdout) ? statusRes.stdout.trim() : '';

    const isDirty = statusOut.length > 0;
    let dirtyDiffSha256 = null;
    let dirtyFiles = [];

    if (isDirty) {
      const diffRes = runSafeGit(repoRoot, ['diff', '--no-ext-diff', '--no-textconv', 'HEAD']);
      const diffOut = (diffRes.status === 0 && diffRes.stdout) ? diffRes.stdout : '';
      dirtyDiffSha256 = crypto.createHash('sha256').update(diffOut).digest('hex');
      dirtyFiles = statusOut
        .split('\n')
        .filter(line => line.length >= 4)
        .map(line => line.substring(3).trim())
        .filter(Boolean);
    }

    const relUri = repoRoot.split(path.sep).join('/');
    return {
      repositoryUri: 'file://' + relUri,
      revisionId: sha40,
      branch,
      properties: {
        sha12: sha40.substring(0, 12),
        isDirty,
        dirtyDiffSha256,
        dirtyFiles
      }
    };
  } catch {
    return getFallbackProvenance();
  }
}

/**
 * Safely reads a file content from a specific git revision (e.g. baseline for deleted files).
 */
export function readGitFileAtRevision(repoRoot, revision, filePath) {
  if (!repoRoot || !revision || !filePath) return null;
  const normalizedPath = filePath.replace(/\\/g, '/').replace(/^\/+/, '');
  const refSpec = `${revision}:${normalizedPath}`;
  const res = runSafeGit(repoRoot, ['show', refSpec]);
  if (res.status === 0 && res.stdout !== null) {
    return res.stdout;
  }
  return null;
}

export function getFallbackProvenance() {
  return {
    repositoryUri: 'unknown',
    revisionId: '0000000000000000000000000000000000000000',
    branch: 'unknown',
    properties: {
      sha12: '000000000000',
      isDirty: false,
      dirtyDiffSha256: null,
      dirtyFiles: []
    }
  };
}


