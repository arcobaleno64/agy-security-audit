#!/usr/bin/env node
/**
 * project-context.mjs
 * Project Security Context loader, validator, drift detector, and intake generator (R9-P1-01 through R9-P1-04).
 * Enforces evidence-bound component decomposition, verified actors, and context drift policies.
 */

import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { isPathContained } from './path-containment.mjs';
import { detectRepositoryInventory } from './build-threat-model.mjs';

/**
 * Computes deterministic SHA-256 fingerprint for project context.
 */
export function computeProjectContextFingerprint(context) {
  if (!context) return null;
  const canonicalData = {
    projectId: context.project?.projectId || 'unknown',
    projectType: context.project?.projectType || 'generic',
    languages: (context.project?.languages || []).slice().sort(),
    entrypoints: (context.project?.entrypoints || []).slice().sort(),
    dataStores: (context.project?.dataStores || []).slice().sort(),
    externalServices: (context.project?.externalServices || []).slice().sort(),
    actors: (context.actors || []).map(a => ({ id: a.id, trustLevel: a.trustLevel, source: a.source })).sort((a, b) => a.id.localeCompare(b.id)),
    components: (context.trustModel?.components || []).map(c => ({ id: c.id || c.name, evidence: (c.evidence || []).slice().sort() })).sort((a, b) => (a.id || '').localeCompare(b.id || '')),
    trustBoundaries: (context.trustModel?.trustBoundaries || []).map(b => ({ boundary: b.boundary || b.name, from: b.from, to: b.to })).sort((a, b) => (a.boundary || '').localeCompare(b.boundary || ''))
  };
  return crypto.createHash('sha256').update(JSON.stringify(canonicalData)).digest('hex');
}

/**
 * Computes deterministic SHA-256 fingerprint for security properties.
 */
export function computeSecurityPropertiesFingerprint(properties) {
  if (!Array.isArray(properties) || properties.length === 0) return null;
  const sorted = properties.map(p => ({
    id: p.id,
    property: p.property || p.description,
    component: p.component || ''
  })).sort((a, b) => a.id.localeCompare(b.id));
  return crypto.createHash('sha256').update(JSON.stringify(sorted)).digest('hex');
}

/**
 * Loads and validates Project Security Context from .security-audit/ (R9-P1-01 & R9-P1-02).
 */
export function loadProjectSecurityContext(repoRoot = process.cwd()) {
  const resolvedRoot = path.resolve(repoRoot);
  const contextDir = path.join(resolvedRoot, '.security-audit');

  if (!fs.existsSync(contextDir) || !fs.statSync(contextDir).isDirectory()) {
    return {
      status: 'ABSENT',
      context: null,
      qualityGate: {
        valid: true,
        warnings: ['Project Security Context (.security-audit/) is absent. Bounded clean assurance cannot be certified; defaulting to CONTEXT_LIMITED.'],
        errors: []
      },
      projectContextFingerprint: null,
      securityPropertiesFingerprint: null,
      assuranceLevel: 'CONTEXT_LIMITED'
    };
  }

  function readJsonSafe(fileName) {
    const filePath = path.join(contextDir, fileName);
    if (!fs.existsSync(filePath)) return null;
    try {
      return JSON.parse(fs.readFileSync(filePath, 'utf8'));
    } catch {
      return null;
    }
  }

  const project = readJsonSafe('project.json') || {};
  const actors = readJsonSafe('actors.json') || [];
  const trustModel = readJsonSafe('trust-model.json') || {};
  const securityProperties = readJsonSafe('security-properties.json') || [];
  const assumptions = readJsonSafe('assumptions.json') || [];
  const acceptedRisks = readJsonSafe('accepted-risks.json') || [];

  const warnings = [];
  const errors = [];

  // Quality Gate Check 1: Components must have valid repository evidence (R9-T09)
  const components = Array.isArray(trustModel.components) ? trustModel.components : [];
  if (components.length === 0) {
    errors.push('Threat model contains 0 evidenced components');
  }

  for (const comp of components) {
    const compId = comp.id || comp.name;
    const evidenceList = Array.isArray(comp.evidence) ? comp.evidence : (comp.evidence ? [comp.evidence] : []);
    if (evidenceList.length === 0) {
      errors.push(`Component '${compId}' has no repository evidence and cannot become authoritative (R9-T09)`);
      comp.isAuthoritative = false;
    } else {
      let foundEvidence = false;
      for (const ev of evidenceList) {
        const evPath = typeof ev === 'string' ? ev : (ev.path || '');
        if (evPath && isPathContained(resolvedRoot, path.resolve(resolvedRoot, evPath)) && fs.existsSync(path.resolve(resolvedRoot, evPath))) {
          foundEvidence = true;
          break;
        }
      }
      if (!foundEvidence) {
        errors.push(`Component '${compId}' references non-existent physical evidence: ${JSON.stringify(evidenceList)}`);
        comp.isAuthoritative = false;
      } else {
        comp.isAuthoritative = true;
      }
    }
  }

  // Quality Gate Check 2: Actors must be evidenced or confirmed (R9-T08)
  const safeActors = Array.isArray(actors) ? actors : [];
  for (const actor of safeActors) {
    const isGeneric = ['user', 'admin', 'attacker', 'generic-user'].includes(String(actor.id).toLowerCase());
    const hasEvidence = actor.source === 'REPOSITORY_EVIDENCE' || actor.source === 'USER_CONFIRMED' || (actor.evidence && Object.keys(actor.evidence).length > 0);
    if (isGeneric && !hasEvidence) {
      warnings.push(`Actor '${actor.id}' is a generic unverified actor without repository evidence (R9-T08)`);
      actor.status = 'ASSUMPTION';
    } else {
      actor.status = actor.status || (hasEvidence ? 'FACT' : 'ASSUMPTION');
    }
  }

  const context = {
    project,
    actors: safeActors,
    trustModel: {
      ...trustModel,
      components
    },
    securityProperties: Array.isArray(securityProperties) ? securityProperties : [],
    assumptions: Array.isArray(assumptions) ? assumptions : [],
    acceptedRisks: Array.isArray(acceptedRisks) ? acceptedRisks : []
  };

  const projectContextFingerprint = computeProjectContextFingerprint(context);
  const securityPropertiesFingerprint = computeSecurityPropertiesFingerprint(context.securityProperties);

  const isValid = errors.length === 0;

  return {
    status: isValid ? 'CONFIRMED' : 'INVALID',
    context,
    qualityGate: {
      valid: isValid,
      warnings,
      errors
    },
    projectContextFingerprint,
    securityPropertiesFingerprint,
    assuranceLevel: isValid ? 'BOUNDED_CLEAN' : 'CONTEXT_LIMITED'
  };
}

/**
 * Detects security context drift against baseline (R9-P1-04, R9-T12, R9-T13).
 */
export function detectContextDrift(currentContext, baselineContext) {
  if (!currentContext || !baselineContext) {
    return {
      hasDrift: false,
      driftType: 'NO_DRIFT',
      status: 'STABLE',
      reasons: []
    };
  }

  const reasons = [];

  // 1. Entrypoint additions (R9-T12)
  const baseEntries = new Set(baselineContext.project?.entrypoints || []);
  const currEntries = currentContext.project?.entrypoints || [];
  for (const ep of currEntries) {
    if (!baseEntries.has(ep)) {
      reasons.push({ type: 'NEW_ENTRYPOINT', detail: `New entrypoint detected: ${ep}` });
    }
  }

  // 2. Privileged operations / sensitive operations additions (R9-T13)
  const basePrivs = new Set(baselineContext.project?.privilegedOperations || baselineContext.trustModel?.sensitiveOperations || []);
  const currPrivs = currentContext.project?.privilegedOperations || currentContext.trustModel?.sensitiveOperations || [];
  for (const priv of currPrivs) {
    if (!basePrivs.has(priv)) {
      reasons.push({ type: 'NEW_PRIVILEGED_OPERATION', detail: `New privileged operation detected: ${priv}` });
    }
  }

  // 3. New actors or roles
  const baseActors = new Set((baselineContext.actors || []).map(a => a.id));
  for (const act of (currentContext.actors || [])) {
    if (!baseActors.has(act.id)) {
      reasons.push({ type: 'NEW_ACTOR', detail: `New actor role detected: ${act.id}` });
    }
  }

  // 4. New trust boundaries
  const baseBoundaries = new Set((baselineContext.trustModel?.trustBoundaries || []).map(b => b.boundary || b.name));
  for (const b of (currentContext.trustModel?.trustBoundaries || [])) {
    const bName = b.boundary || b.name;
    if (!baseBoundaries.has(bName)) {
      reasons.push({ type: 'NEW_TRUST_BOUNDARY', detail: `New trust boundary detected: ${bName}` });
    }
  }

  const hasDrift = reasons.length > 0;
  let status = 'STABLE';
  let driftType = 'NO_DRIFT';

  if (hasDrift) {
    const hasPrivileged = reasons.some(r => r.type === 'NEW_PRIVILEGED_OPERATION');
    const hasBoundaryOrEntry = reasons.some(r => r.type === 'NEW_ENTRYPOINT' || r.type === 'NEW_TRUST_BOUNDARY');
    if (hasPrivileged) {
      status = 'THREAT_MODEL_REVIEW_REQUIRED';
      driftType = 'THREAT_MODEL_DRIFT';
    } else if (hasBoundaryOrEntry) {
      status = 'CONTEXT_DRIFT';
      driftType = 'SURFACE_DRIFT';
    } else {
      status = 'MINOR_DRIFT';
      driftType = 'METADATA_DRIFT';
    }
  }

  return {
    hasDrift,
    driftType,
    status,
    reasons
  };
}

/**
 * Generates initial Project Security Context templates (R9-P1-03 Intake contract, R10-P1-04 Inventory-driven).
 */
export function initProjectContext(repoRoot = process.cwd(), options = {}) {
  const resolvedRoot = path.resolve(repoRoot);
  const targetDir = path.join(resolvedRoot, '.security-audit');
  if (!fs.existsSync(targetDir)) {
    fs.mkdirSync(targetDir, { recursive: true });
  }

  let inventory = { languages: [], profiles: [], entrypoints: [] };
  try {
    inventory = detectRepositoryInventory(resolvedRoot);
  } catch {}

  const projectName = options.projectId || path.basename(resolvedRoot);
  const createdFiles = [];

  let detectedLanguages = options.languages;
  if (!detectedLanguages || detectedLanguages.length === 0) {
    detectedLanguages = (inventory.languages && inventory.languages.length > 0)
      ? inventory.languages
      : ['UNKNOWN'];
  }

  let detectedRuntime = options.runtime;
  if (!detectedRuntime || detectedRuntime.length === 0) {
    detectedRuntime = [];
    const addRuntime = (value) => {
      if (!detectedRuntime.includes(value)) detectedRuntime.push(value);
    };
    try {
      const topFiles = fs.readdirSync(resolvedRoot);
      if (topFiles.includes('package.json')) addRuntime('Node.js');
      if (topFiles.includes('requirements.txt') || topFiles.includes('pyproject.toml')) addRuntime('Python');
      if (topFiles.includes('go.mod')) addRuntime('Go');
      if (topFiles.includes('pom.xml') || topFiles.includes('build.gradle') || topFiles.includes('build.gradle.kts')) addRuntime('JVM');
      if (inventory.languages?.includes('Rust')) addRuntime('Rust (native)');
      if (inventory.languages?.includes('C/C++')) addRuntime('Native / C++ (MSVC/Clang/GCC)');
      if (inventory.languages?.includes('C#')) {
        addRuntime(inventory.profiles?.includes('web-app') ? '.NET Framework / IIS' : '.NET / C#');
      }
    } catch {}
    if (detectedRuntime.length === 0) detectedRuntime.push('UNKNOWN');
  }

  let detectedFramework = options.framework;
  if (!detectedFramework) {
    try {
      const topFiles = fs.readdirSync(resolvedRoot);
      if (inventory.languages?.includes('C/C++') && inventory.profiles?.includes('native')) {
        detectedFramework = 'Native C/C++ Application / Library';
      } else if (inventory.languages?.includes('Rust') && inventory.profiles?.includes('native')) {
        detectedFramework = 'Native Rust Application / Library';
      } else if (topFiles.some(f => f.endsWith('.aspx') || f.endsWith('.asax'))) {
        detectedFramework = 'ASP.NET WebForms';
      } else if (inventory.profiles?.includes('agent-plugin')) {
        detectedFramework = 'Antigravity Plugin';
      } else if (inventory.profiles?.includes('web-api') || inventory.profiles?.includes('web-app')) {
        detectedFramework = 'Web Application';
      } else if (inventory.profiles?.includes('cli')) {
        detectedFramework = 'Command-Line Interface';
      } else if (inventory.profiles?.includes('native')) {
        detectedFramework = 'Native Application / Library';
      } else {
        detectedFramework = 'UNKNOWN';
      }
    } catch {
      detectedFramework = 'UNKNOWN';
    }
  }

  const detectedEntrypoints = (options.entrypoints && options.entrypoints.length > 0)
    ? options.entrypoints
    : (inventory.entrypoints?.map(e => e.path) || []);

  const projectJson = {
    projectId: projectName,
    projectType: options.projectType || inventory.primaryProfile || 'generic-library',
    framework: detectedFramework,
    languages: detectedLanguages,
    runtime: detectedRuntime,
    entrypoints: detectedEntrypoints,
    dataStores: options.dataStores || [],
    externalServices: options.externalServices || [],
    source: 'SUGGESTED'
  };
  fs.writeFileSync(path.join(targetDir, 'project.json'), JSON.stringify(projectJson, null, 2), 'utf8');
  createdFiles.push('.security-audit/project.json');

  const actorsJson = [
    {
      id: 'LOCAL_DEVELOPER',
      description: 'Authorized local developer executing commands in workspace',
      trustLevel: 'privileged',
      source: 'SUGGESTED',
      confidence: 'HIGH'
    }
  ];
  fs.writeFileSync(path.join(targetDir, 'actors.json'), JSON.stringify(actorsJson, null, 2), 'utf8');
  createdFiles.push('.security-audit/actors.json');

  const trustModelJson = {
    components: options.components || [],
    trustBoundaries: options.trustBoundaries || []
  };
  fs.writeFileSync(path.join(targetDir, 'trust-model.json'), JSON.stringify(trustModelJson, null, 2), 'utf8');
  createdFiles.push('.security-audit/trust-model.json');

  const secPropsJson = options.securityProperties || [];
  fs.writeFileSync(path.join(targetDir, 'security-properties.json'), JSON.stringify(secPropsJson, null, 2), 'utf8');
  createdFiles.push('.security-audit/security-properties.json');

  const assumptionsJson = [
    {
      id: 'ASM-INIT-01',
      assumption: 'Initial template generated by security-audit intake workflow.',
      source: 'MODEL_INFERRED'
    }
  ];
  fs.writeFileSync(path.join(targetDir, 'assumptions.json'), JSON.stringify(assumptionsJson, null, 2), 'utf8');
  createdFiles.push('.security-audit/assumptions.json');

  const acceptedRisksJson = [];
  fs.writeFileSync(path.join(targetDir, 'accepted-risks.json'), JSON.stringify(acceptedRisksJson, null, 2), 'utf8');
  createdFiles.push('.security-audit/accepted-risks.json');

  return {
    success: true,
    status: 'SUGGESTED',
    createdFiles
  };
}

/**
 * Loads persisted baseline context from .security-audit/baseline.json if present (R10-P1-03).
 */
export function loadBaselineContext(repoRoot = process.cwd()) {
  const baselinePath = path.join(path.resolve(repoRoot), '.security-audit', 'baseline.json');
  if (fs.existsSync(baselinePath)) {
    try {
      const data = JSON.parse(fs.readFileSync(baselinePath, 'utf8'));
      return { exists: true, path: baselinePath, baseline: data };
    } catch (err) {
      return { exists: true, path: baselinePath, baseline: null, error: err.message };
    }
  }
  return { exists: false, path: baselinePath, baseline: null };
}

/**
 * Persists current verified context as baseline to .security-audit/baseline.json (R10-P1-03).
 */
export function persistBaselineContext(repoRoot = process.cwd(), baselineData = {}) {
  const targetDir = path.join(path.resolve(repoRoot), '.security-audit');
  if (!fs.existsSync(targetDir)) {
    fs.mkdirSync(targetDir, { recursive: true });
  }
  const baselinePath = path.join(targetDir, 'baseline.json');
  fs.writeFileSync(baselinePath, JSON.stringify(baselineData, null, 2) + '\n', 'utf8');
  return { success: true, path: baselinePath };
}
