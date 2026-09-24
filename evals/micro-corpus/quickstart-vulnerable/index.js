/**
 * quickstart-vulnerable / index.js
 * Track D Tier 2 Micro-Corpus: Clear Vulnerable Control (CWE-22 Path Traversal).
 *
 * Demonstrates a direct, unconstrained path concatenation sink:
 * - Entrypoint: serveUserAsset(publicDir, userPath)
 * - Sink: fs.readFileSync(path.join(publicDir, userPath))
 * - Flaw: User-supplied path containing '../' traverses outside publicDir.
 */

import fs from 'node:fs';
import path from 'node:path';

export function serveUserAsset(publicDir, userPath) {
  if (typeof publicDir !== 'string' || typeof userPath !== 'string') {
    throw new TypeError('Invalid arguments: publicDir and userPath must be strings');
  }

  // Vulnerable Sink: Direct path.join without directory confinement verification
  const targetFile = path.join(publicDir, userPath);
  return fs.readFileSync(targetFile, 'utf8');
}
