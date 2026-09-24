/**
 * quickstart-safe / index.js
 * Track D Tier 2 Micro-Corpus: Clear Safe Control (CWE-22 Defense Barrier).
 *
 * Demonstrates an explicit boundary containment barrier neutralizing path traversal:
 * - Entrypoint: serveUserAsset(publicDir, userPath)
 * - Barrier: path.resolve() boundary enclosure verification
 * - Sink: fs.readFileSync(targetFile, 'utf8') strictly confined within publicDir.
 */

import fs from 'node:fs';
import path from 'node:path';

export function serveUserAsset(publicDir, userPath) {
  if (typeof publicDir !== 'string' || typeof userPath !== 'string') {
    throw new TypeError('Invalid arguments: publicDir and userPath must be strings');
  }

  const resolvedBase = path.resolve(publicDir);
  const targetFile = path.resolve(resolvedBase, userPath);

  // Defense Barrier: Enforce strict directory containment
  const relative = path.relative(resolvedBase, targetFile);
  if (relative.startsWith('..') || path.isAbsolute(relative)) {
    throw new Error('ACCESS_DENIED: Path escapes authorized base directory');
  }

  return fs.readFileSync(targetFile, 'utf8');
}
