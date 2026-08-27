#!/usr/bin/env node
/**
 * build-inventory.mjs
 * Deterministic repository accounting and inventory generator for review & scan jobs.
 * - In 'scan' mode: Derives directory reconciliation manifest directly from filesystem facts.
 * - In 'review' mode: Extracts changed and deleted files from Git diff for 100% changed-file accounting.
 */

import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { runSafeGit, getHardenedGitProvenance } from './safe-git.mjs';

/**
 * Categorizes a directory path based on standard conventions.
 */
export function categorizeDirectory(dirName) {
  const raw = dirName.toLowerCase().replace(/[/\\]+$/, '');
  const trimmed = raw.replace(/^[./\\]+/, '');

  if (['node_modules', 'vendor', 'third_party', 'bower_components'].includes(trimmed)) {
    return { status: 'EXCLUDED_VENDORED', reason: 'Third-party vendor dependencies' };
  }
  if (['dist', 'build', 'out', 'target', '.next', '.nuxt', 'coverage', '.cache'].includes(raw) ||
      ['dist', 'build', 'out', 'target', 'coverage'].includes(trimmed)) {
    return { status: 'EXCLUDED_GENERATED', reason: 'Compiler or build output artifacts' };
  }
  if (['.git', '.vscode', '.idea', 'docs', 'assets', 'images', 'static', 'reports', 'scratch'].includes(raw) ||
      ['docs', 'assets', 'images', 'static', 'reports', 'scratch'].includes(trimmed)) {
    return { status: 'EXCLUDED_NON_CODE', reason: 'Metadata, documentation, or non-code assets' };
  }
  if (['test', 'tests', 'spec', 'specs', '__tests__', 'fixtures'].includes(trimmed)) {
    return { status: 'EXCLUDED_TEST', reason: 'Test suites and test fixtures' };
  }

  if (raw === '.github') {
    return { status: 'SCANNED', reason: 'CI/CD workflow definitions and automation scripts' };
  }
  if (trimmed === 'packages') {
    return { status: 'SCANNED', reason: 'Monorepo workspace packages and first-party modules' };
  }
  if (trimmed === 'bin') {
    return { status: 'SCANNED', reason: 'CLI entrypoint source scripts' };
  }
  if (trimmed === 'agents') {
    return { status: 'SCANNED', reason: 'Plugin custom subagents and security personas' };
  }

  return { status: 'SCANNED', reason: 'Core application source code' };
}


/**
 * Counts total files inside a directory recursively up to maxDepth with cycle detection.
 */
export function countFiles(dirPath, maxDepth = 20, currentDepth = 0, visited = new Set()) {
  if (currentDepth > maxDepth || !fs.existsSync(dirPath)) return 0;
  let count = 0;
  try {
    const realPath = fs.realpathSync(dirPath);
    if (visited.has(realPath)) return 0;
    visited.add(realPath);

    const entries = fs.readdirSync(dirPath, { withFileTypes: true });
    for (const entry of entries) {
      const fullEntryPath = path.join(dirPath, entry.name);
      let isFile = entry.isFile();
      let isDir = entry.isDirectory();

      if (entry.isSymbolicLink()) {
        try {
          const stat = fs.statSync(fullEntryPath);
          isFile = stat.isFile();
          isDir = stat.isDirectory();
        } catch {
          continue;
        }
      }

      if (isFile) {
        count++;
      } else if (isDir) {
        const lowerName = entry.name.toLowerCase();
        if (lowerName === '.git' || lowerName === 'node_modules') {
          continue;
        }
        count += countFiles(fullEntryPath, maxDepth, currentDepth + 1, visited);
      }
    }
  } catch {
    // Ignore unreadable entries
  }
  return count;
}

/**
 * Builds Directory Reconciliation Manifest from real filesystem entries in repoRoot.
 */
export function buildDirectoryManifest(repoRoot) {
  const rootResolved = path.resolve(repoRoot);
  const entries = [];

  const dirItems = fs.readdirSync(rootResolved, { withFileTypes: true });

  // Account for root-level files
  let rootFileCount = 0;
  for (const item of dirItems) {
    if (item.isFile()) {
      rootFileCount++;
    } else if (item.isSymbolicLink()) {
      try {
        if (fs.statSync(path.join(rootResolved, item.name)).isFile()) rootFileCount++;
      } catch {}
    }
  }

  entries.push({
    path: './',
    status: 'SCANNED',
    fileCount: rootFileCount,
    reason: 'Root configuration, entrypoints, and manifest files'
  });

  for (const item of dirItems) {
    let isDir = item.isDirectory();
    if (item.isSymbolicLink()) {
      try {
        if (fs.statSync(path.join(rootResolved, item.name)).isDirectory()) isDir = true;
      } catch {}
    }

    if (isDir) {
      const dirName = item.name;
      const relPath = dirName + '/';
      const { status, reason } = categorizeDirectory(dirName);
      const fullPath = path.join(rootResolved, dirName);
      const fileCount = status === 'EXCLUDED_VENDORED' ? 0 : countFiles(fullPath);

      entries.push({
        path: relPath,
        status,
        fileCount,
        reason
      });
    }
  }

  // Sort entries for deterministic output
  entries.sort((a, b) => a.path.localeCompare(b.path));

  return { entries };
}

/**
 * Extracts changed and deleted files for review mode via safe git (Fail-Closed).
 */
export function extractChangedFiles(repoRoot, options = {}) {
  const { base = null, head = null } = options;
  const provenance = getHardenedGitProvenance(repoRoot);

  if (provenance.revisionId === '0000000000000000000000000000000000000000') {
    throw new Error('GIT_ACCOUNTING_ERROR: Cannot perform review mode in non-git workspace or uninitialized repository.');
  }

  const changedFiles = [];
  const deletedFiles = [];

  const diffArgs = ['diff', '--name-status', '--no-ext-diff', '--no-textconv'];
  if (base && head) {
    diffArgs.push(`${base}...${head}`);
  } else if (base) {
    diffArgs.push(base);
  } else {
    diffArgs.push('HEAD');
  }

  const diffRes = runSafeGit(repoRoot, diffArgs);
  if (diffRes.status !== 0) {
    throw new Error(`GIT_ACCOUNTING_ERROR: Failed to extract git diff: ${diffRes.stderr || 'unknown git error'}`);
  }

  if (diffRes.stdout) {
    const lines = diffRes.stdout.trim().split('\n').map(l => l.trim()).filter(Boolean);
    for (const line of lines) {
      const parts = line.split('\t');
      const statusCode = parts[0] ? parts[0].trim() : 'M';
      const file1 = parts[1] ? parts[1].trim() : '';

      if (!file1) continue;

      if (statusCode.startsWith('R') || statusCode.startsWith('C')) {
        // Rename/Copy: parts[1] = old path, parts[2] = new path
        const file2 = parts[2] ? parts[2].trim() : file1;
        changedFiles.push({
          path: file2,
          status: statusCode.startsWith('R') ? 'RENAMED' : 'COPIED',
          originalPath: file1
        });
        deletedFiles.push({
          path: file1,
          status: 'RENAMED_FROM',
          baselineRevision: base || provenance.revisionId
        });
      } else if (statusCode.startsWith('D')) {
        deletedFiles.push({
          path: file1,
          status: 'DELETED',
          baselineRevision: base || provenance.revisionId
        });
      } else {
        changedFiles.push({
          path: file1,
          status: statusCode.startsWith('A') ? 'ADDED' : 'MODIFIED'
        });
      }
    }
  }

  // Use -uall so untracked directories expand into individual files
  const statusRes = runSafeGit(repoRoot, ['status', '--porcelain', '-uall']);
  if (statusRes.status !== 0) {
    throw new Error(`GIT_ACCOUNTING_ERROR: Failed to extract git status: ${statusRes.stderr || 'unknown git error'}`);
  }

  if (statusRes.stdout) {
    const lines = statusRes.stdout.split('\n').filter(l => l.length >= 4);
    for (const line of lines) {
      const code = line.substring(0, 2);
      const untrackedPath = line.substring(3).trim();
      if (code === '??' && untrackedPath) {
        if (!changedFiles.some(f => f.path === untrackedPath)) {
          changedFiles.push({
            path: untrackedPath,
            status: 'UNTRACKED'
          });
        }
      }
    }
  }

  return {
    provenance,
    changedFiles,
    deletedFiles,
    totalAccounted: changedFiles.length + deletedFiles.length
  };
}

/**
 * Builds canonical scan-manifest adhering to Section 31 Schema.
 */
export function buildScanManifest({
  mode = 'scan',
  repoRoot = process.cwd(),
  scope = [],
  effort = 'medium',
  policy = 'paranoid',
  trustMode = 'trusted-workspace',
  directoryManifest = null,
  reviewInventory = null
}) {
  const provenance = getHardenedGitProvenance(repoRoot);
  const timestamp = new Date().toISOString();
  const scanId = `${mode.toUpperCase()}-${crypto.randomBytes(4).toString('hex')}`;

  const manifest = {
    schemaVersion: '1',
    scanId,
    mode,
    target: {
      root: repoRoot,
      scope: Array.isArray(scope) ? scope : [],
      revision: provenance.revisionId,
      branch: provenance.branch,
      dirty: provenance.properties.isDirty,
      diffBase: mode === 'review' ? (provenance.properties.isDirty ? 'HEAD' : null) : null,
      diffHead: mode === 'review' ? (provenance.properties.isDirty ? 'WORKING_TREE' : null) : null
    },
    effort,
    policy,
    trustMode,
    createdAt: timestamp,
    completedAt: null,
    complete: false
  };

  if (mode === 'scan' && directoryManifest) {
    manifest.directoryManifest = directoryManifest;
  }
  if (mode === 'review' && reviewInventory) {
    manifest.reviewInventory = reviewInventory;
  }

  return manifest;
}

// -----------------------------------------------------------------------------
// CLI Dispatch
// -----------------------------------------------------------------------------
const isDirectExecution = process.argv[1] && process.argv[1].endsWith('build-inventory.mjs');

if (isDirectExecution) {
  const args = process.argv.slice(2);
  function getArg(name) {
    const idx = args.indexOf(name);
    if (idx !== -1 && idx + 1 < args.length) return args[idx + 1];
    return null;
  }

  const mode = getArg('--mode') || 'scan';
  const root = getArg('--root') || process.cwd();
  const base = getArg('--base');
  const head = getArg('--head');
  const outputManifest = getArg('--output-manifest');
  const outputDirectoryManifest = getArg('--output-dir-manifest');

  try {
    let dirManifest = null;
    let reviewInventory = null;

    if (mode === 'scan') {
      dirManifest = buildDirectoryManifest(root);
      if (outputDirectoryManifest) {
        fs.mkdirSync(path.dirname(outputDirectoryManifest), { recursive: true });
        fs.writeFileSync(outputDirectoryManifest, JSON.stringify(dirManifest, null, 2), 'utf8');
        console.log(`✔ Generated Directory Manifest: ${outputDirectoryManifest} (${dirManifest.entries.length} entries)`);
      }
    } else if (mode === 'review') {
      reviewInventory = extractChangedFiles(root, { base, head });
      console.log(`✔ Review Mode: Accounted for ${reviewInventory.totalAccounted} changed/deleted files.`);
    }

    const scanManifest = buildScanManifest({
      mode,
      repoRoot: root,
      directoryManifest: dirManifest,
      reviewInventory
    });


    if (outputManifest) {
      fs.mkdirSync(path.dirname(outputManifest), { recursive: true });
      fs.writeFileSync(outputManifest, JSON.stringify(scanManifest, null, 2), 'utf8');
      console.log(`✔ Generated Scan Manifest: ${outputManifest}`);
    }
  } catch (err) {
    console.error('Error in build-inventory:', err.message);
    process.exit(1);
  }
}

