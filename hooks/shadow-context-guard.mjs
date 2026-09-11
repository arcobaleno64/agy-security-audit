#!/usr/bin/env node
/**
 * shadow-context-guard.mjs
 * PreToolUse Lifecycle Hook for Antigravity (AGY).
 *
 * Enforces runtime containment and Fail-Closed Default-Deny on repository reads,
 * directing agents to sanitized shadow context under scratch/context/.
 *
 * Subprocess Calling Contract Compliance:
 * 1. Non-blocking stdin read with unref'd timer (fails safe on empty pipe).
 * 2. Explicit LF-only JSON output (no CRLF).
 * 3. Strict schema adherence (only decision, reason, permissionOverrides).
 *
 * Supported Tools:
 * - view_file (AbsolutePath)
 * - grep_search (SearchPath)
 * - list_dir (DirectoryPath)
 * - find_by_name (SearchDirectory)
 *
 * Zero external npm dependencies.
 */

import fs from 'node:fs';
import path from 'node:path';
import { isRealPathContained, isPathContained } from '../skills/security-audit/scripts/path-containment.mjs';

const SUPPORTED_TOOLS = new Set(['view_file', 'grep_search', 'list_dir', 'find_by_name']);

// Emits result with strict LF line ending, avoiding CRLF conversion issues on Windows
function emit(obj) {
  process.stdout.write(JSON.stringify(obj) + '\n');
}

// Extracts target path parameter based on tool definition
export function extractTargetParam(toolName, args) {
  if (!args || typeof args !== 'object') return null;
  switch (toolName) {
    case 'view_file':
      return typeof args.AbsolutePath === 'string' ? args.AbsolutePath : null;
    case 'grep_search':
      return typeof args.SearchPath === 'string' ? args.SearchPath : null;
    case 'list_dir':
      return typeof args.DirectoryPath === 'string' ? args.DirectoryPath : null;
    case 'find_by_name':
      return typeof args.SearchDirectory === 'string' ? args.SearchDirectory : null;
    default:
      return null;
  }
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

// Records structured audit telemetry to trusted location and contextRoot mirror
function recordTelemetry(contextInfo, payload, toolName, targetPath, decision, action, reason) {
  try {
    const event = {
      timestamp: new Date().toISOString(),
      conversationId: payload?.conversationId || 'UNKNOWN',
      stepIdx: typeof payload?.stepIdx === 'number' ? payload.stepIdx : null,
      modelName: payload?.modelName || 'UNKNOWN',
      manifestDigest: contextInfo?.manifest?.manifestDigest || null,
      tool: toolName,
      targetPath: (targetPath || '').replace(/\\/g, '/'),
      decision,
      action,
      reason
    };
    const eventLine = JSON.stringify(event) + '\n';

    // Trusted execution-side location (artifactDirectoryPath)
    if (payload?.artifactDirectoryPath && typeof payload.artifactDirectoryPath === 'string') {
      try {
        if (fs.existsSync(payload.artifactDirectoryPath)) {
          const trustedPath = path.join(payload.artifactDirectoryPath, 'shadow-guard-telemetry.jsonl');
          fs.appendFileSync(trustedPath, eventLine, 'utf8');
        }
      } catch {}
    }

    // Target contextRoot mirror (backward compatibility)
    if (contextInfo?.contextRoot) {
      try {
        if (fs.existsSync(contextInfo.contextRoot)) {
          const eventsFile = path.resolve(contextInfo.contextRoot, 'guard-events.jsonl');
          fs.appendFileSync(eventsFile, eventLine, 'utf8');
        }
      } catch {}
    }
  } catch {}
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
  if (!toolName || !SUPPORTED_TOOLS.has(toolName)) {
    return emit({ decision: 'allow' });
  }

  const targetPathArg = extractTargetParam(toolName, payload?.toolCall?.args);
  const candidateResolved = targetPathArg && typeof targetPathArg === 'string' ? path.resolve(targetPathArg) : null;
  const contextInfo = findContextManifest(payload?.workspacePaths, candidateResolved);

  // If no shadow context is active for this workspace, allow direct access
  if (!contextInfo) {
    return emit({ decision: 'allow' });
  }

  // Active shadow context is present! Strict Fail-Closed enforcement applies.
  if (!targetPathArg || typeof targetPathArg !== 'string' || !targetPathArg.trim()) {
    recordTelemetry(contextInfo, payload, toolName, '', 'deny', 'DENIED_MALFORMED', 'Tool call rejected: missing required path argument.');
    return emit({
      decision: 'deny',
      reason: `[SHADOW_CONTEXT_ENFORCEMENT] Tool call '${toolName}' rejected: missing required path argument.`
    });
  }

  const resolvedTarget = path.resolve(targetPathArg);
  const { contextRoot, repoRoot } = contextInfo;

  // 1. If path is already inside contextRoot, allow sanitized inspection
  if (isRealPathContained(contextRoot, resolvedTarget) || isPathContained(contextRoot, resolvedTarget)) {
    recordTelemetry(contextInfo, payload, toolName, resolvedTarget, 'allow', 'ALLOWED_SHADOW', 'Access to sanitized shadow context permitted.');
    return emit({ decision: 'allow' });
  }

  // 2. If path escapes repoRoot (traversal or symlink escape), strictly deny
  if (!isRealPathContained(repoRoot, resolvedTarget) || !isPathContained(repoRoot, resolvedTarget)) {
    recordTelemetry(contextInfo, payload, toolName, resolvedTarget, 'deny', 'DENIED_ESCAPE', 'Path containment violation: path escapes repository boundary.');
    return emit({
      decision: 'deny',
      reason: `[SHADOW_CONTEXT_ENFORCEMENT] Path containment violation: '${targetPathArg}' escapes repository boundary (CWE-59 defense).`
    });
  }

  // 3. Path is within repoRoot (raw repository path).
  // Check if sanitized shadow counterpart exists.
  const relPath = path.relative(repoRoot, resolvedTarget);
  const shadowEquivalent = path.resolve(contextRoot, relPath);
  const shadowRel = path.relative(repoRoot, shadowEquivalent).replace(/\\/g, '/');
  const rawRel = relPath.replace(/\\/g, '/');

  if (fs.existsSync(shadowEquivalent)) {
    recordTelemetry(contextInfo, payload, toolName, resolvedTarget, 'deny', 'DENIED_RAW', `Direct access to raw repository path blocked; sanitized shadow copy exists at '${shadowRel}'.`);
    return emit({
      decision: 'deny',
      reason: `[SHADOW_CONTEXT_ENFORCEMENT] Direct access to raw repository path '${rawRel}' is blocked. You MUST inspect the sanitized shadow copy at '${shadowRel}'.`
    });
  }

  // 4. Path is unshadowed within repoRoot: strictly deny under Default-Deny (Fail-Closed)
  recordTelemetry(contextInfo, payload, toolName, resolvedTarget, 'deny', 'DENIED_UNSHADOWED', `Direct access to raw repository path blocked; path '${rawRel}' is absent from sanitized shadow context.`);
  return emit({
    decision: 'deny',
    reason: `[SHADOW_CONTEXT_ENFORCEMENT] Direct access to raw repository path '${rawRel}' is blocked. This path is not present in the sanitized shadow context.`
  });
}

main().catch(() => {
  emit({ decision: 'allow' });
});