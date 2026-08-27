#!/usr/bin/env node
/**
 * validate-attack-path.mjs
 * Validates candidate attack paths against Section 21 schema and detects proof gaps.
 */

import fs from 'node:fs';
import path from 'node:path';

/**
 * Validates a single location node (source, sink, step).
 */
export function validatePathLocation(node, repoRoot = process.cwd(), label = 'node') {
  if (!node || typeof node !== 'object') {
    return { valid: false, error: `${label} must be a valid object` };
  }

  const uri = node.uri || node.path;
  const line = Number(node.line || node.startLine);

  if (!uri || typeof uri !== 'string' || uri.trim().length === 0) {
    return { valid: false, error: `${label} missing required 'uri'` };
  }

  if (!Number.isInteger(line) || line < 1) {
    return { valid: false, error: `${label} invalid line number: ${node.line || node.startLine}` };
  }

  // Reject raw traversal patterns across platforms
  if (uri.includes('..\\') || uri.includes('../') || uri === '..' || uri.startsWith('../') || uri.startsWith('..\\')) {
    return { valid: false, error: `${label} contains directory traversal sequence: ${uri}` };
  }

  // Prevent directory traversal escaping repoRoot
  const rootResolved = path.resolve(repoRoot);
  const rootReal = fs.existsSync(rootResolved) ? fs.realpathSync(rootResolved) : rootResolved;
  const resolved = path.resolve(repoRoot, uri);
  const rel = path.relative(rootResolved, resolved);

  if (rel.startsWith('..') || path.isAbsolute(rel)) {
    return { valid: false, error: `${label} escapes repository root: ${uri}` };
  }

  // R1-P1-01: Physical verification against disk and line count bounds
  const locationType = node.locationType || 'current-tree';

  if (locationType === 'current-tree' || locationType === 'generated-validation-artifact') {
    if (!fs.existsSync(resolved)) {
      return { valid: false, error: `${label} file does not exist: '${uri}'` };
    }

    let stat;
    try {
      stat = fs.statSync(resolved);
    } catch (err) {
      return { valid: false, error: `${label} cannot stat file: '${uri}' (${err.message})` };
    }

    if (!stat.isFile()) {
      return { valid: false, error: `${label} target is not a regular file: '${uri}'` };
    }

    // Verify symlink resolution does not escape repoRoot
    try {
      const real = fs.realpathSync(resolved);
      const relReal = path.relative(rootReal, real);
      if (relReal.startsWith('..') || path.isAbsolute(relReal)) {
        return { valid: false, error: `${label} symlink target escapes repository root: '${uri}'` };
      }
    } catch (err) {
      return { valid: false, error: `${label} failed resolving realpath: '${uri}' (${err.message})` };
    }

    // Verify line <= actual file line count (empty file has lineCount 0)
    try {
      const content = fs.readFileSync(resolved, 'utf8');
      const lineCount = content.length === 0 ? 0 : content.split('\n').length;
      if (line > lineCount) {
        return { valid: false, error: `${label} line ${line} exceeds file line count (${lineCount}) in '${uri}'` };
      }
    } catch (err) {
      return { valid: false, error: `${label} cannot read file content: '${uri}' (${err.message})` };
    }
  } else if (locationType === 'baseline-preimage') {
    // Under Default-Deny, baseline-preimage strictly requires non-empty preimageContent
    if (typeof node.preimageContent !== 'string' || node.preimageContent.length === 0) {
      return { valid: false, error: `${label} baseline-preimage requires non-empty 'preimageContent' for '${uri}'` };
    }
    const lineCount = node.preimageContent.split('\n').length;
    if (line > lineCount) {
      return { valid: false, error: `${label} line ${line} exceeds baseline preimage line count (${lineCount}) in '${uri}'` };
    }
  } else {
    return { valid: false, error: `${label} unknown locationType '${locationType}'` };
  }

  return { valid: true, uri: uri.trim(), line, description: node.description || '', locationType };
}

/**
 * Validates candidate attack path schema conforming to Section 21.
 */
export function validateAttackPath(attackPath, repoRoot = process.cwd()) {
  if (!attackPath || typeof attackPath !== 'object') {
    return { valid: false, error: 'Attack path payload must be an object' };
  }

  // 1. Validate Source
  const sourceValidation = validatePathLocation(attackPath.source, repoRoot, 'Source');
  if (!sourceValidation.valid) {
    return { valid: false, error: sourceValidation.error };
  }

  // 2. Validate Sink
  const sinkValidation = validatePathLocation(attackPath.sink, repoRoot, 'Sink');
  if (!sinkValidation.valid) {
    return { valid: false, error: sinkValidation.error };
  }

  // 3. Validate Intermediate Steps (if present)
  const steps = [];
  if (attackPath.steps !== undefined) {
    if (!Array.isArray(attackPath.steps)) {
      return { valid: false, error: "'steps' must be an array" };
    }
    for (let i = 0; i < attackPath.steps.length; i++) {
      const stepVal = validatePathLocation(attackPath.steps[i], repoRoot, `Step[${i}]`);
      if (!stepVal.valid) {
        return { valid: false, error: stepVal.error };
      }
      steps.push(stepVal);
    }
  }

  // 4. Validate Preconditions & Exploitability
  const preconditions = Array.isArray(attackPath.preconditions)
    ? attackPath.preconditions.map(String)
    : [];
  const exploitabilityPrerequisites = Array.isArray(attackPath.exploitabilityPrerequisites)
    ? attackPath.exploitabilityPrerequisites.map(String)
    : [];

  // 5. Validate Unmitigated Invariant
  const unmitigatedInvariant = typeof attackPath.unmitigatedInvariant === 'string' && attackPath.unmitigatedInvariant.trim().length > 0
    ? attackPath.unmitigatedInvariant.trim()
    : null;

  return {
    valid: true,
    attackPathId: attackPath.attackPathId || attackPath.id || 'AP-UNKNOWN',
    source: sourceValidation,
    sink: sinkValidation,
    steps,
    preconditions,
    exploitabilityPrerequisites,
    unmitigatedInvariant,
    error: null
  };
}

const SPECULATIVE_REGEX = /(?:assumed|hypothetical|unproven|unverified|presumed|speculative|todo)/i;

/**
 * Identifies unproven dataflow steps or missing assertions (Proof Gaps).
 */
export function detectProofGaps(attackPath) {
  const gaps = [];
  if (!attackPath || typeof attackPath !== 'object') {
    return { hasGaps: true, proofGaps: [{ target: 'payload', unprovenProperty: 'Malformed attack path payload' }] };
  }

  const srcDesc = typeof attackPath.source?.description === 'string' ? attackPath.source.description.trim() : '';
  if (!srcDesc || SPECULATIVE_REGEX.test(srcDesc)) {
    gaps.push({
      target: 'source',
      unprovenProperty: 'Source ingress lacks verifiable controllability proof'
    });
  }

  if (Array.isArray(attackPath.steps)) {
    for (let i = 0; i < attackPath.steps.length; i++) {
      const step = attackPath.steps[i] || {};
      const desc = typeof step.description === 'string' ? step.description.trim() : '';
      if (step.unproven || !desc || SPECULATIVE_REGEX.test(desc)) {
        gaps.push({
          stepIndex: i,
          location: `${step.uri || 'unknown'}:${step.line || '?'}`,
          unprovenProperty: step.unprovenReason || 'Intermediate propagation step is unverified hypothesis'
        });
      }
    }
  }

  const sinkDesc = typeof attackPath.sink?.description === 'string' ? attackPath.sink.description.trim() : '';
  if (!sinkDesc || SPECULATIVE_REGEX.test(sinkDesc) || attackPath.sink?.unproven) {
    gaps.push({
      target: 'sink',
      unprovenProperty: 'Sink invocation lacks verifiable execution proof'
    });
  }

  const inv = typeof attackPath.unmitigatedInvariant === 'string' ? attackPath.unmitigatedInvariant.trim() : '';
  if (!inv || SPECULATIVE_REGEX.test(inv)) {
    gaps.push({
      target: 'mitigation',
      unprovenProperty: 'Missing explicit proof that no intermediate sanitizer or defensive barrier neutralizes flow'
    });
  }

  return {
    hasGaps: gaps.length > 0,
    proofGaps: gaps
  };
}


// -----------------------------------------------------------------------------
// CLI Dispatch
// -----------------------------------------------------------------------------
const isDirectExecution = process.argv[1] && process.argv[1].endsWith('validate-attack-path.mjs');

if (isDirectExecution) {
  const args = process.argv.slice(2);
  const inputPath = args[0];
  if (!inputPath) {
    console.error('Usage: node validate-attack-path.mjs <attack-path.json>');
    process.exit(1);
  }

  try {
    const raw = JSON.parse(fs.readFileSync(inputPath, 'utf8'));
    const result = validateAttackPath(raw);
    if (!result.valid) {
      console.error(`❌ Attack Path Invalid: ${result.error}`);
      process.exit(1);
    }
    const gaps = detectProofGaps(raw);
    console.log(`✔ Attack Path Valid (${result.steps.length} steps). Proof gaps: ${gaps.proofGaps.length}`);
  } catch (err) {
    console.error('Error validating attack path:', err.message);
    process.exit(1);
  }
}

