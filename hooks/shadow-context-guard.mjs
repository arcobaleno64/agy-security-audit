#!/usr/bin/env node
/**
 * shadow-context-guard.mjs
 * PreToolUse Lifecycle Hook for Antigravity (AGY).
 *
 * Enforces runtime containment and transparent redirection of view_file
 * to sanitized shadow context under scratch/context/.
 *
 * Subprocess Calling Contract Compliance:
 * 1. Non-blocking stdin read with unref'd timer (fails safe on empty pipe).
 * 2. Explicit LF-only JSON output (no CRLF).
 * 3. Strict schema adherence (only decision, reason, and optional overwrite).
 *
 * Zero external npm dependencies.
 */

import fs from 'node:fs';
import path from 'node:path';
import { isRealPathContained, isPathContained } from '../skills/security-audit/scripts/path-containment.mjs';

// Emits result with strict LF line ending, avoiding CRLF conversion issues on Windows
function emit(obj) {
  process.stdout.write(JSON.stringify(obj) + '\n');
}

// Reads stdin with timeout to guard against open-but-empty pipes (Contract Rule 1)
function readStdinWithTimeout(timeoutMs = 1500) {
  return new Promise((resolve) => {
    let data = '';
    const timer = setTimeout(() => {
      resolve(data);
    }, timeoutMs);
    if (timer.unref) timer.unref();

    process.stdin.setEncoding('utf8');
    process.stdin.on('data', (chunk) => {
      data += chunk;
    });
    process.stdin.on('end', () => {
      clearTimeout(timer);
      resolve(data);
    });
    process.stdin.on('error', () => {
      clearTimeout(timer);
      resolve(data);
    });
    process.stdin.resume();
  });
}

// Discovers active scratch/context/context-manifest.json
function findContextManifest(workspacePaths, targetFilePath) {
  const candidates = [];
  if (Array.isArray(workspacePaths)) {
    for (const ws of workspacePaths) {
      if (typeof ws === 'string' && ws.trim()) {
        candidates.push(path.resolve(ws, 'scratch/context/context-manifest.json'));
      }
    }
  }

  if (targetFilePath && typeof targetFilePath === 'string') {
    let currentDir = path.dirname(path.resolve(targetFilePath));
    while (true) {
      candidates.push(path.resolve(currentDir, 'scratch/context/context-manifest.json'));
      const parent = path.dirname(currentDir);
      if (parent === currentDir) break;
      currentDir = parent;
    }
  }

  for (const candidate of candidates) {
    try {
      if (fs.existsSync(candidate)) {
        const raw = fs.readFileSync(candidate, 'utf8');
        const parsed = JSON.parse(raw);
        if (parsed && typeof parsed === 'object') {
          return {
            manifest: parsed,
            manifestPath: candidate,
            contextRoot: path.resolve(parsed.contextRoot || path.dirname(candidate)),
            repoRoot: path.resolve(parsed.repoRoot || path.resolve(path.dirname(candidate), '../..'))
          };
        }
      }
    } catch {}
  }

  return null;
}

async function main() {
  let rawInput = '';
  try {
    rawInput = await readStdinWithTimeout(1500);
  } catch {
    return emit({ decision: 'allow' });
  }

  if (!rawInput || !rawInput.trim()) {
    return emit({ decision: 'allow' });
  }

  let payload = null;
  try {
    payload = JSON.parse(rawInput);
  } catch {
    return emit({ decision: 'allow' });
  }

  const toolName = payload?.toolCall?.name;
  if (toolName !== 'view_file') {
    return emit({ decision: 'allow' });
  }

  const targetPathArg = payload?.toolCall?.args?.AbsolutePath;
  if (!targetPathArg || typeof targetPathArg !== 'string') {
    return emit({ decision: 'allow' });
  }

  const resolvedTarget = path.resolve(targetPathArg);
  const contextInfo = findContextManifest(payload?.workspacePaths, resolvedTarget);

  // If no shadow context is active for this workspace, allow direct access
  if (!contextInfo) {
    return emit({ decision: 'allow' });
  }

  const { contextRoot, repoRoot } = contextInfo;

  // 1. If path is already inside contextRoot, allow immediately
  if (isRealPathContained(contextRoot, resolvedTarget)) {
    return emit({ decision: 'allow' });
  }

  // 2. If path is inside repoRoot, check if a sanitized shadow file exists
  if (isRealPathContained(repoRoot, resolvedTarget)) {
    const relPath = path.relative(repoRoot, resolvedTarget);
    const shadowFile = path.resolve(contextRoot, relPath);

    if (fs.existsSync(shadowFile)) {
      // Record guard audit event
      const event = {
        timestamp: new Date().toISOString(),
        tool: 'view_file',
        originalPath: resolvedTarget.replace(/\\/g, '/'),
        shadowPath: shadowFile.replace(/\\/g, '/'),
        action: 'REDIRECT'
      };

      try {
        const eventsFile = path.resolve(contextRoot, 'guard-events.jsonl');
        fs.appendFileSync(eventsFile, JSON.stringify(event) + '\n', 'utf8');
      } catch {}

      return emit({
        decision: 'allow',
        reason: `Shadow Context: Transparently redirected to sanitized review context (${relPath.replace(/\\/g, '/')}).`,
        overwrite: {
          AbsolutePath: shadowFile.replace(/\\/g, '/')
        }
      });
    }
  }

  // Not a shadowed file; pass through
  return emit({ decision: 'allow' });
}

main().catch(() => {
  emit({ decision: 'allow' });
});