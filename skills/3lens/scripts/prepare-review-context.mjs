#!/usr/bin/env node
/**
 * Context Preparation & Pre-Context Secret Protection Engine (R5-P0-01).
 *
 * Enforces the deterministic preparation of model-facing review context:
 * 1. Reads repository source files locally.
 * 2. Neutralizes terminal escape codes, ANSI sequences, and Unicode Bidi overrides.
 * 3. Tokenizes all secret patterns via tokenizeSecretsForContext() into structured placeholders:
 *    <SECRET:class=${type}:hash=${hash}>
 * 4. Preserves 100% exact line counts and offsets.
 * 5. Writes sanitized files into scratch/context/<relativePath>.
 * 6. Guarantees that raw plaintext credentials NEVER reach the agent / LLM review context.
 * 7. Keeps secretsMap in memory; never serializes plaintext credentials into agent-accessible files.
 *
 * Zero external npm dependencies.
 */

import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
import { tokenizeSecretsForContext } from './finalize-scan.mjs';

const CONTROL_CHARS_REGEX = /[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g;
const ANSI_REGEX = /\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])/g;
const BIDI_REGEX = /[\u202A-\u202E\u2066-\u2069]/g;

/**
 * Sanitizes dangerous control characters and injections from source code while preserving line structure.
 */
export function sanitizeSourceText(sourceText) {
  if (!sourceText || typeof sourceText !== 'string') return '';
  return sourceText
    .replace(ANSI_REGEX, '')
    .replace(BIDI_REGEX, '')
    .replace(CONTROL_CHARS_REGEX, '');
}

import {
  isPathContained,
  isRealPathContained,
  assertContainedPath,
  safeReadFileContained
} from './path-containment.mjs';

export {
  isPathContained,
  isRealPathContained,
  assertContainedPath,
  safeReadFileContained
};

/**
 * Prepares review context for a repository, producing a sanitized shadow bundle under scratch/context/.
 *
 * @param {string} repoRoot - Target repository root directory.
 * @param {object} options - Options including targetFiles, outputDir, and fileExtensions.
 * @returns {object} Context preparation manifest and statistics.
 */
export function prepareReviewContext(repoRoot = process.cwd(), options = {}) {
  const resolvedRepoRoot = path.resolve(repoRoot);
  const contextOutputDir = options.outputDir
    ? path.resolve(options.outputDir)
    : path.resolve(resolvedRepoRoot, 'scratch/context');

  if (!fs.existsSync(resolvedRepoRoot)) {
    return {
      success: false,
      manifest: {
        schemaVersion: '1.0.0',
        generatedAt: new Date().toISOString(),
        repoRoot: resolvedRepoRoot,
        contextRoot: contextOutputDir,
        scannedFilesCount: 0,
        preparedFilesCount: 0,
        tokenizedFilesCount: 0,
        totalSecretsTokenized: 0,
        preparedFiles: []
      },
      contextRoot: contextOutputDir,
      error: 'Repository root does not exist'
    };
  }

  const supportedExtensions = options.extensions || [
    '.js', '.mjs', '.cjs', '.ts', '.tsx', '.jsx', '.py', '.go', '.rs',
    '.java', '.c', '.cpp', '.h', '.hpp', '.cs', '.php', '.rb', '.sh',
    '.bash', '.json', '.yaml', '.yml', '.toml', '.xml', '.html', '.css',
    '.sql', '.env', '.config', '.pem', '.key', '.crt', '.cert', '.md', '.txt'
  ];

  const excludedDirNames = new Set([
    'node_modules', '.git', '.svn', '.hg', 'scratch', 'reports', 'dist', 'build', 'out',
    'codeql-db', '.semgrep', 'coverage', '.nyc_output', '.sonar', '.scannerwork'
  ]);

  const targetFiles = [];

  if (Array.isArray(options.targetFiles) && options.targetFiles.length > 0) {
    for (const rel of options.targetFiles) {
      const full = path.resolve(resolvedRepoRoot, rel);
      if (isPathContained(resolvedRepoRoot, full) && fs.existsSync(full) && fs.statSync(full).isFile()) {
        targetFiles.push(path.relative(resolvedRepoRoot, full).replace(/\\/g, '/'));
      }
    }
  } else {
    function walk(dir) {
      if (!fs.existsSync(dir)) return;
      const entries = fs.readdirSync(dir, { withFileTypes: true });
      for (const entry of entries) {
        if (entry.name.startsWith('.') && entry.name !== '.env') continue;
        if (entry.isDirectory()) {
          if (!excludedDirNames.has(entry.name)) {
            walk(path.join(dir, entry.name));
          }
        } else if (entry.isFile()) {
          const ext = path.extname(entry.name).toLowerCase();
          if (supportedExtensions.includes(ext) || entry.name.startsWith('.env')) {
            const rel = path.relative(resolvedRepoRoot, path.join(dir, entry.name)).replace(/\\/g, '/');
            targetFiles.push(rel);
          }
        }
      }
    }
    walk(resolvedRepoRoot);
  }

  fs.mkdirSync(contextOutputDir, { recursive: true });

  const preparedFiles = [];
  let totalSecrets = 0;
  let tokenizedFilesCount = 0;
  const inMemorySecretsMap = new Map();

  for (const relPath of targetFiles) {
    const originalFullPath = path.resolve(resolvedRepoRoot, relPath);
    const destFullPath = path.resolve(contextOutputDir, relPath);

    if (!isPathContained(resolvedRepoRoot, originalFullPath) || !isPathContained(contextOutputDir, destFullPath)) {
      continue;
    }

    const readResult = safeReadFileContained(resolvedRepoRoot, originalFullPath, { allowSymlinks: false });
    if (!readResult.ok) {
      if (readResult.error && readResult.error.includes('symbolic link')) {
        console.warn(`[PREPARE-CONTEXT] Warning: skipped ${relPath} -- symlinks are not followed into the review context.`);
      } else if (readResult.error && (readResult.error.includes('escapes') || readResult.error.includes('realpath'))) {
        console.warn(`[PREPARE-CONTEXT] Warning: skipped ${relPath} -- resolved path escapes repository root.`);
      }
      continue;
    }

    try {
      const rawContent = readResult.content;
      const sanitizedContent = sanitizeSourceText(rawContent);
      const tokenResult = tokenizeSecretsForContext(sanitizedContent);

      const rawLines = rawContent.split(/\r?\n/).length;
      const tokenizedLines = tokenResult.tokenizedText.split(/\r?\n/).length;
      if (rawLines !== tokenizedLines) {
        throw new Error(`Line drift detected during context preparation for ${relPath}: raw=${rawLines}, tokenized=${tokenizedLines}`);
      }

      fs.mkdirSync(path.dirname(destFullPath), { recursive: true });
      fs.writeFileSync(destFullPath, tokenResult.tokenizedText, 'utf8');

      if (tokenResult.secretCount > 0) {
        tokenizedFilesCount++;
        totalSecrets += tokenResult.secretCount;
        for (const [tokenKey, meta] of tokenResult.secretsMap.entries()) {
          inMemorySecretsMap.set(tokenKey, {
            ...meta,
            file: relPath
          });
        }
      }

      preparedFiles.push({
        relativePath: relPath,
        sanitizedContextPath: destFullPath,
        secretCount: tokenResult.secretCount,
        lineCount: tokenizedLines,
        contentHash: crypto.createHash('sha256').update(tokenResult.tokenizedText, 'utf8').digest('hex')
      });
    } catch (err) {
      console.warn(`[PREPARE-CONTEXT] Warning: skipped ${relPath} due to: ${err.message}`);
    }
  }

  const digestPayload = preparedFiles.map(f => `${f.relativePath}:${f.contentHash}`).sort().join('\n');
  const manifestDigest = crypto.createHash('sha256').update(digestPayload, 'utf8').digest('hex');

  const manifest = {
    schemaVersion: '1.0.0',
    generatedAt: new Date().toISOString(),
    manifestDigest,
    repoRoot: resolvedRepoRoot,
    contextRoot: contextOutputDir,
    scannedFilesCount: targetFiles.length,
    preparedFilesCount: preparedFiles.length,
    tokenizedFilesCount,
    totalSecretsTokenized: totalSecrets,
    preparedFiles
  };

  const manifestPath = path.join(contextOutputDir, 'context-manifest.json');
  fs.writeFileSync(manifestPath, JSON.stringify(manifest, null, 2), 'utf8');

  return {
    success: true,
    manifest,
    inMemorySecretsMap,
    contextRoot: contextOutputDir,
    manifestPath
  };
}

export function getPreparedContextFilePath(repoRoot, relativePath, options = {}) {
  if (!repoRoot || !relativePath) return null;
  const contextOutputDir = options.outputDir
    ? path.resolve(options.outputDir)
    : path.resolve(repoRoot, 'scratch/context');
  const candidate = path.resolve(contextOutputDir, relativePath);
  if (isPathContained(contextOutputDir, candidate) && fs.existsSync(candidate)) {
    return candidate;
  }
  return null;
}

export function readPreparedFile(repoRoot, relativePath, options = {}) {
  const preparedPath = getPreparedContextFilePath(repoRoot, relativePath, options);
  if (preparedPath && fs.existsSync(preparedPath)) {
    return fs.readFileSync(preparedPath, 'utf8');
  }
  return null;
}

if (process.argv[1] && process.argv[1].endsWith('prepare-review-context.mjs')) {
  const args = process.argv.slice(2);
  let repoRootArg = process.cwd();
  let outputDirArg = null;

  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--repo-root' && i + 1 < args.length) repoRootArg = args[++i];
    if (args[i] === '--output-dir' && i + 1 < args.length) outputDirArg = args[++i];
  }

  console.log(`Preparing sanitized review context for: ${repoRootArg}`);
  const res = prepareReviewContext(repoRootArg, { outputDir: outputDirArg });
  console.log(`✔ Context prepared successfully:`);
  console.log(`  - Files Scanned: ${res.manifest.scannedFilesCount}`);
  console.log(`  - Files Tokenized: ${res.manifest.tokenizedFilesCount}`);
  console.log(`  - Secrets Tokenized: ${res.manifest.totalSecretsTokenized}`);
  console.log(`  - Context Directory: ${res.contextRoot}`);
}