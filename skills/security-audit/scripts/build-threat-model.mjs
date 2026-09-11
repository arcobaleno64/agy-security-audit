#!/usr/bin/env node
/**
 * build-threat-model.mjs
 * Generates bounded, deterministic repository-specific threat model artifacts (R2-P0-09)
 * conforming to Section 17, Section 30, and Section 34 of the Security Hardening Plan.
 *
 * Implements 3-Stage Pipeline:
 * - Stage A: Deterministic Inventory & Multi-Profile Detection (Languages, Frameworks, Profiles, Entrypoints)
 * - Stage B: Semantic Component Discovery with Verified Physical Evidence Pointers
 * - Stage C: Strict Reconciliation (All claims evidence-bound, unevidenced claims marked ASSUMPTION)
 */

import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { getHardenedGitProvenance } from './safe-git.mjs';
import {
  loadProjectSecurityContext,
  computeProjectContextFingerprint,
  computeSecurityPropertiesFingerprint
} from './project-context.mjs';
import { isPathContained } from './path-containment.mjs';

/**
 * Stage A: Scans repository for deterministic facts: languages, manifests, frameworks, entrypoints, and profiles (R2-P0-09).
 */
export function detectRepositoryInventory(repoRoot = process.cwd()) {
  const rootResolved = path.resolve(repoRoot);
  const detectedLanguages = new Set();
  const detectedManifests = [];
  const detectedFrameworks = [];
  const detectedProfiles = new Set();
  const entrypoints = [];

  const exists = (rel) => fs.existsSync(path.join(rootResolved, rel));

  // 1. Node.js / TypeScript
  let pkg = {};
  if (exists('package.json')) {
    detectedLanguages.add('JavaScript');
    detectedManifests.push({ path: 'package.json', type: 'npm' });
    try {
      pkg = JSON.parse(fs.readFileSync(path.join(rootResolved, 'package.json'), 'utf8')) || {};
    } catch {}
    if (pkg.bin) {
      detectedProfiles.add('cli');
      if (typeof pkg.bin === 'string') {
        entrypoints.push({ path: pkg.bin, type: 'cli', evidence: { manifestOrigin: 'package.json:bin', confidence: 'high' } });
      } else if (typeof pkg.bin === 'object') {
        for (const [cmd, bPath] of Object.entries(pkg.bin)) {
          entrypoints.push({ path: bPath, type: `cli:${cmd}`, evidence: { manifestOrigin: 'package.json:bin', confidence: 'high' } });
        }
      }
    }
    if (pkg.main) {
      entrypoints.push({ path: pkg.main, type: 'library_entry', evidence: { manifestOrigin: 'package.json:main', confidence: 'high' } });
    }
  }
  if (exists('tsconfig.json')) {
    detectedLanguages.add('TypeScript');
    detectedManifests.push({ path: 'tsconfig.json', type: 'typescript' });
  }

  // 2. Python
  if (exists('requirements.txt') || exists('pyproject.toml') || exists('setup.py') || exists('Pipfile')) {
    detectedLanguages.add('Python');
    if (exists('requirements.txt')) detectedManifests.push({ path: 'requirements.txt', type: 'pip' });
    if (exists('pyproject.toml')) detectedManifests.push({ path: 'pyproject.toml', type: 'pyproject' });
    if (exists('setup.py')) detectedManifests.push({ path: 'setup.py', type: 'setuptools' });
    if (exists('main.py')) entrypoints.push({ path: 'main.py', type: 'app_entry', evidence: { manifestOrigin: 'main.py', confidence: 'high' } });
    if (exists('app.py')) entrypoints.push({ path: 'app.py', type: 'app_entry', evidence: { manifestOrigin: 'app.py', confidence: 'high' } });
  }

  // 3. Go
  if (exists('go.mod')) {
    detectedLanguages.add('Go');
    detectedManifests.push({ path: 'go.mod', type: 'go_modules' });
    if (exists('main.go')) entrypoints.push({ path: 'main.go', type: 'go_entry', evidence: { manifestOrigin: 'main.go', confidence: 'high' } });
  }

  // 4. Rust
  if (exists('Cargo.toml')) {
    detectedLanguages.add('Rust');
    detectedManifests.push({ path: 'Cargo.toml', type: 'cargo' });
    if (exists('src/main.rs')) entrypoints.push({ path: 'src/main.rs', type: 'cargo_bin', evidence: { manifestOrigin: 'src/main.rs', confidence: 'high' } });
  }

  // 5. Java / JVM
  if (exists('pom.xml') || exists('build.gradle') || exists('build.gradle.kts')) {
    detectedLanguages.add('Java');
    if (exists('pom.xml')) detectedManifests.push({ path: 'pom.xml', type: 'maven' });
    if (exists('build.gradle')) detectedManifests.push({ path: 'build.gradle', type: 'gradle' });
  }

  // 6. .NET / C#
  try {
    const rootFiles = fs.readdirSync(rootResolved);
    if (rootFiles.some(f => f.endsWith('.csproj') || f.endsWith('.sln') || f.endsWith('.fsproj') || f.endsWith('.cs') || f.endsWith('.aspx') || f.toLowerCase() === 'web.config')) {
      detectedLanguages.add('C#');
      detectedProfiles.add('web-app');
      const manifestFile = rootFiles.find(f => f.endsWith('.csproj') || f.endsWith('.sln') || f.toLowerCase() === 'web.config');
      if (manifestFile) detectedManifests.push({ path: manifestFile, type: 'dotnet' });
      const aspxFile = rootFiles.find(f => f.endsWith('.aspx'));
      if (aspxFile) entrypoints.push({ path: aspxFile, type: 'webforms_page', evidence: { manifestOrigin: 'webforms', confidence: 'high' } });
    }
  } catch {}

  // 7. C / C++
  if (exists('CMakeLists.txt') || exists('Makefile')) {
    detectedLanguages.add('C/C++');
    if (exists('CMakeLists.txt')) detectedManifests.push({ path: 'CMakeLists.txt', type: 'cmake' });
    if (exists('Makefile')) detectedManifests.push({ path: 'Makefile', type: 'make' });
  }

  // 8. Infrastructure as Code / Container
  if (exists('Dockerfile') || exists('docker-compose.yml') || exists('docker-compose.yaml')) {
    detectedProfiles.add('infra');
    if (exists('Dockerfile')) detectedManifests.push({ path: 'Dockerfile', type: 'docker' });
  }
  try {
    const rootFiles = fs.readdirSync(rootResolved);
    if (rootFiles.some(f => f.endsWith('.tf') || f.endsWith('.tfvars'))) {
      detectedLanguages.add('HCL/Terraform');
      detectedProfiles.add('infra');
      detectedManifests.push({ path: rootFiles.find(f => f.endsWith('.tf')), type: 'terraform' });
    }
  } catch {}

  // 9. Antigravity Agent Plugin Profile
  if (exists('plugin.json') || exists('skills') || exists('agents')) {
    detectedProfiles.add('agent-plugin');
    if (exists('plugin.json')) {
      entrypoints.push({ path: 'plugin.json', type: 'plugin_manifest', evidence: { manifestOrigin: 'plugin.json', confidence: 'high' } });
    }
  }

  // Check dependencies for frameworks
  const allDeps = {
    ...(pkg.dependencies || {}),
    ...(pkg.devDependencies || {})
  };
  const webDeps = ['express', 'fastify', 'koa', 'hapi', 'nest', 'next', 'nuxt', 'koa-router'];
  for (const d of webDeps) {
    if (allDeps[d]) {
      detectedFrameworks.push(d);
      detectedProfiles.add(['next', 'nuxt'].includes(d) ? 'web-app' : 'web-api');
    }
  }
  const cliDeps = ['commander', 'yargs', 'meow', 'cac', 'caporal', 'clipanion'];
  for (const d of cliDeps) {
    if (allDeps[d]) {
      detectedFrameworks.push(d);
      detectedProfiles.add('cli');
    }
  }

  // Check directory indicators
  let dirNames = [];
  try {
    dirNames = fs.readdirSync(rootResolved, { withFileTypes: true })
      .filter(i => i.isDirectory())
      .map(i => i.name.toLowerCase());
  } catch {}

  if (dirNames.includes('bin')) detectedProfiles.add('cli');
  if (dirNames.includes('api') || dirNames.includes('routes') || dirNames.includes('controllers') || dirNames.includes('handlers') || dirNames.includes('endpoints')) {
    detectedProfiles.add('web-api');
  }
  if (dirNames.includes('packages')) detectedProfiles.add('library');

  // Fallbacks if no profile detected
  if (detectedProfiles.size === 0) {
    detectedProfiles.add('library');
  }

  const primaryProfile = detectedProfiles.has('agent-plugin')
    ? 'agent-plugin'
    : (detectedProfiles.has('web-api') ? 'web-api' : (detectedProfiles.has('cli') ? 'cli' : Array.from(detectedProfiles)[0]));

  return {
    languages: Array.from(detectedLanguages),
    manifests: detectedManifests,
    frameworks: detectedFrameworks,
    entrypoints,
    profiles: Array.from(detectedProfiles),
    primaryProfile
  };
}

/**
 * Stage B: Discovers components based on verified physical facts and directory structures (R2-P0-09).
 */
export function discoverComponents(repoRoot, inventory = null) {
  const components = [];
  const rootResolved = path.resolve(repoRoot);
  const inv = inventory || detectRepositoryInventory(rootResolved);

  let pkg = {};
  const pkgPath = path.join(rootResolved, 'package.json');
  const hasPkg = fs.existsSync(pkgPath);
  if (hasPkg) {
    try {
      pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf8')) || {};
    } catch {}
  }
  const allDeps = { ...(pkg.dependencies || {}), ...(pkg.devDependencies || {}) };

  let dirNames = [];
  try {
    dirNames = fs.readdirSync(rootResolved, { withFileTypes: true })
      .filter(i => i.isDirectory())
      .map(i => i.name.toLowerCase());
  } catch {}

  // Helper to find existing matching directory
  const findDir = (candidates) => dirNames.find(d => candidates.includes(d));

  // 1. API / Web Routing Component
  const webDeps = ['express', 'fastify', 'koa', 'hapi', 'nest', 'next', 'nuxt', 'koa-router'];
  const hasWebDeps = webDeps.some(d => allDeps[d]);
  const apiDirs = ['api', 'routes', 'controllers', 'handlers', 'endpoints'];
  const matchedApiDir = findDir(apiDirs);
  if (hasWebDeps || matchedApiDir || inv.profiles.includes('web-api')) {
    const evidence = matchedApiDir
      ? { path: matchedApiDir + '/', manifestOrigin: 'directory-structure', confidence: 'high' }
      : (hasWebDeps && hasPkg ? { path: 'package.json', manifestOrigin: 'package.json:dependencies', confidence: 'high' } : { path: './', manifestOrigin: 'profile-inference', confidence: 'moderate' });

    components.push({
      name: 'API',
      description: 'HTTP / Web Service Entrypoints and Route Controllers',
      criticality: 'high',
      indicators: Object.keys(allDeps).filter(d => webDeps.includes(d)),
      evidence
    });
  }

  // 2. Auth & Identity Component
  const authDeps = ['passport', 'jsonwebtoken', 'bcrypt', 'argon2', 'auth0', 'firebase-admin', 'jose'];
  const hasAuthDeps = authDeps.some(d => allDeps[d]);
  const matchedAuthDir = findDir(['auth', 'security', 'identity']);
  if (hasAuthDeps || matchedAuthDir) {
    const evidence = hasAuthDeps && hasPkg
      ? { path: 'package.json', manifestOrigin: 'package.json:dependencies', confidence: 'high' }
      : { path: matchedAuthDir + '/', manifestOrigin: 'directory-structure', confidence: 'high' };

    components.push({
      name: 'Auth',
      description: 'Identity verification, token validation, and authorization',
      criticality: 'critical',
      indicators: Object.keys(allDeps).filter(d => authDeps.includes(d)),
      evidence
    });
  }

  // 3. Persistence & Data Storage Component
  const dbDeps = ['pg', 'mysql', 'mysql2', 'sqlite3', 'better-sqlite3', 'prisma', 'typeorm', 'mongoose', 'knex'];
  const hasDbDeps = dbDeps.some(d => allDeps[d]);
  const matchedDbDir = findDir(['db', 'database', 'models', 'migrations', 'prisma']);
  if (hasDbDeps || matchedDbDir) {
    const evidence = hasDbDeps && hasPkg
      ? { path: 'package.json', manifestOrigin: 'package.json:dependencies', confidence: 'high' }
      : { path: matchedDbDir + '/', manifestOrigin: 'directory-structure', confidence: 'high' };

    components.push({
      name: 'Persistence',
      description: 'Database storage, queries, and data models',
      criticality: 'high',
      indicators: Object.keys(allDeps).filter(d => dbDeps.includes(d)),
      evidence
    });
  }

  // 4. File & Archive Handling Component
  const fileDeps = ['multer', 'formidable', 'busboy', 'archiver', 'tar', 'adm-zip', 'unzipper'];
  const hasFileDeps = fileDeps.some(d => allDeps[d]);
  const matchedFileDir = findDir(['uploads', 'files', 'storage']);
  if (hasFileDeps || matchedFileDir) {
    const evidence = hasFileDeps && hasPkg
      ? { path: 'package.json', manifestOrigin: 'package.json:dependencies', confidence: 'high' }
      : { path: matchedFileDir + '/', manifestOrigin: 'directory-structure', confidence: 'high' };

    components.push({
      name: 'FileHandling',
      description: 'File upload, archive extraction, and filesystem operations',
      criticality: 'high',
      indicators: Object.keys(allDeps).filter(d => fileDeps.includes(d)),
      evidence
    });
  }

  // 5. Background Jobs & Asynchronous Workers Component
  const jobDeps = ['bullmq', 'bull', 'agenda', 'bree', 'node-cron', 'amqplib', 'kafkajs'];
  const hasJobDeps = jobDeps.some(d => allDeps[d]);
  const matchedJobDir = findDir(['queues', 'workers', 'jobs']);
  if (hasJobDeps || matchedJobDir) {
    const evidence = hasJobDeps && hasPkg
      ? { path: 'package.json', manifestOrigin: 'package.json:dependencies', confidence: 'high' }
      : { path: matchedJobDir + '/', manifestOrigin: 'directory-structure', confidence: 'high' };

    components.push({
      name: 'Jobs',
      description: 'Background queues, cron schedulers, and asynchronous workers',
      criticality: 'medium',
      indicators: Object.keys(allDeps).filter(d => jobDeps.includes(d)),
      evidence
    });
  }

  // 6. Administrative & Internal Tools Component
  const matchedAdminDir = findDir(['admin', 'dashboard', 'internal', 'management']);
  if (matchedAdminDir) {
    components.push({
      name: 'Admin',
      description: 'Administrative interfaces, back-office panels, and internal tools',
      criticality: 'high',
      indicators: [`${matchedAdminDir}/ directory present`],
      evidence: {
        path: matchedAdminDir + '/',
        manifestOrigin: 'directory-structure',
        confidence: 'high'
      }
    });
  }

  // 7. Import / Export Handlers Component
  const importExportDeps = ['csv-parser', 'xlsx', 'exceljs', 'fast-xml-parser', 'xml2js', 'pdfkit'];
  const hasImportExport = importExportDeps.some(d => allDeps[d]);
  if (hasImportExport) {
    components.push({
      name: 'ImportExport',
      description: 'Document parsing, spreadsheet export, and bulk data deserializers',
      criticality: 'medium',
      indicators: Object.keys(allDeps).filter(d => importExportDeps.includes(d)),
      evidence: {
        path: hasPkg ? 'package.json' : './',
        manifestOrigin: hasPkg ? 'package.json:dependencies' : 'inferred',
        confidence: 'high'
      }
    });
  }

  // 8. Plugin & Extension Architecture Component (R2-P0-09)
  const matchedPluginDir = findDir(['plugins', 'rules', 'skills', 'extensions', 'addons', 'agents']);
  const hasPluginJson = fs.existsSync(path.join(rootResolved, 'plugin.json'));
  const hasPluginNaming = (pkg.name && pkg.name.includes('plugin')) || inv.profiles.includes('agent-plugin');
  if (matchedPluginDir || hasPluginJson || hasPluginNaming) {
    let pluginEvidencePath = hasPluginJson ? 'plugin.json' : (matchedPluginDir ? matchedPluginDir + '/' : 'package.json');
    let pluginOrigin = hasPluginJson ? 'agent-plugin-manifest' : (matchedPluginDir ? 'directory-structure' : 'package.json:name');

    components.push({
      name: 'PluginSystem',
      description: 'Extensibility hooks, custom rules, agent personas, and skill definitions',
      criticality: 'high',
      indicators: ['plugins/skills/agents directories, plugin.json, or plugin naming'],
      evidence: {
        path: pluginEvidencePath,
        manifestOrigin: pluginOrigin,
        confidence: 'high'
      }
    });
  }

  // 9. Frontend Trust Boundary Component
  const frontendDeps = ['helmet', 'cors', 'csurf'];
  const hasFrontendDeps = frontendDeps.some(d => allDeps[d]);
  const matchedFrontDir = findDir(['views', 'templates', 'public', 'static']);
  if (hasFrontendDeps || matchedFrontDir) {
    const evidence = hasFrontendDeps && hasPkg
      ? { path: 'package.json', manifestOrigin: 'package.json:dependencies', confidence: 'high' }
      : { path: matchedFrontDir + '/', manifestOrigin: 'directory-structure', confidence: 'high' };

    components.push({
      name: 'FrontendBoundary',
      description: 'Client-side assets, template rendering, and browser security policies',
      criticality: 'medium',
      indicators: Object.keys(allDeps).filter(d => frontendDeps.includes(d)),
      evidence
    });
  }

  // 10. CLI Surface Component (R2-P0-09)
  if (inv.profiles.includes('cli') || dirNames.includes('bin') || pkg.bin) {
    const cliPath = pkg.bin
      ? (typeof pkg.bin === 'string' ? pkg.bin : Object.values(pkg.bin)[0])
      : (dirNames.includes('bin') ? 'bin/' : './');

    components.push({
      name: 'CLI',
      description: 'Command line interface, parameter parsing, and subshell executions',
      criticality: 'high',
      indicators: ['bin directory, package.json bin entry, or cli parser dependencies'],
      evidence: {
        path: cliPath,
        manifestOrigin: pkg.bin ? 'package.json:bin' : 'directory-structure',
        confidence: 'high'
      }
    });
  }

  // Fallback if no specific components matched
  if (components.length === 0) {
    components.push({
      name: 'CoreApp',
      description: 'General application source code',
      criticality: 'medium',
      indicators: ['standard source tree'],
      evidence: {
        path: './',
        manifestOrigin: 'directory-structure',
        confidence: 'moderate'
      }
    });
  }

  return components;
}

/**
 * Generates the active Component × Family discovery dispatch matrix.
 */
/**
 * Generates the active Component × Family discovery dispatch matrix (R9-P1-02).
 * Supports component-driven applicability filtering with explicit reasons.
 */
export function generateDiscoveryMatrix(components = [], inScopeFamilies = [], applicabilityMap = {}) {
  const matrix = [];
  for (const comp of components) {
    const compName = comp.name || comp.id;
    const applicableSet = Array.isArray(comp.applicableFamilies) ? new Set(comp.applicableFamilies) : null;
    const notApplicableMap = (comp.notApplicable && typeof comp.notApplicable === 'object') ? comp.notApplicable : {};

    for (const fam of inScopeFamilies) {
      let isNotApplicable = false;
      let reason = null;

      if (notApplicableMap[fam]) {
        isNotApplicable = true;
        reason = notApplicableMap[fam];
      } else if (applicableSet && !applicableSet.has(fam)) {
        isNotApplicable = true;
        reason = `Family '${fam}' is outside defined architectural scope for '${compName}'.`;
      } else if (applicabilityMap[compName] && applicabilityMap[compName][fam] === false) {
        isNotApplicable = true;
        reason = (applicabilityMap[compName] && applicabilityMap[compName][`${fam}:reason`]) || `Family '${fam}' is marked not applicable for '${compName}'.`;
      } else if (compName === 'ContextPreparation' && fam === 'auth/authz/tenancy') {
        isNotApplicable = true;
        reason = 'Context preparation is local filesystem sandbox; multi-tenant authz is not applicable.';
      } else if (compName === 'GitBoundary' && fam === 'network/SSRF') {
        isNotApplicable = true;
        reason = 'Git boundary isolates local git process invocations; remote SSRF is not applicable.';
      }

      matrix.push({
        component: compName,
        family: fam,
        criticality: comp.criticality || 'medium',
        status: isNotApplicable ? 'NOT_APPLICABLE' : 'PENDING',
        ...(reason ? { reason } : {})
      });
    }
  }
  return matrix;
}

/**
 * Validates a Threat Model against evidence and quality gates (R9-P1-02, R9-T08, R9-T09).
 */
export function validateThreatModel(threatModel, repoRoot = process.cwd()) {
  if (!threatModel) return { valid: false, errors: ['Threat model is null or undefined'], warnings: [] };
  const rootResolved = path.resolve(repoRoot);
  const errors = [];
  const warnings = [];

  const comps = Array.isArray(threatModel.components) ? threatModel.components : [];
  if (comps.length === 0) {
    errors.push('Threat model must contain at least 1 component');
  }

  for (const comp of comps) {
    const compName = comp.name || comp.id || 'unknown';
    const evidenceList = Array.isArray(comp.evidence) ? comp.evidence : (comp.evidence ? [comp.evidence] : []);
    if (evidenceList.length === 0) {
      errors.push(`Component '${compName}' has no repository evidence and cannot become authoritative (R9-T09)`);
      comp.isAuthoritative = false;
    } else {
      let foundValid = false;
      for (const ev of evidenceList) {
        const evPath = typeof ev === 'string' ? ev : (ev.path || '');
        if (evPath) {
          const resolved = path.resolve(rootResolved, evPath);
          if (isPathContained(rootResolved, resolved) && fs.existsSync(resolved)) {
            foundValid = true;
            break;
          }
        }
      }
      if (!foundValid) {
        errors.push(`Component '${compName}' physical evidence does not exist in repository (R9-T09)`);
        comp.isAuthoritative = false;
      } else {
        comp.isAuthoritative = true;
      }
    }
  }

  const actors = Array.isArray(threatModel.actors) ? threatModel.actors : [];
  for (const a of actors) {
    const isGeneric = ['user', 'admin', 'attacker', 'external-attacker', 'authenticated-user'].includes(String(a.id).toLowerCase());
    const hasEvidence = a.source === 'REPOSITORY_EVIDENCE' || a.source === 'USER_CONFIRMED' || (a.evidence && Object.keys(a.evidence).length > 0);
    if (isGeneric && !hasEvidence) {
      warnings.push(`Actor '${a.id}' is a generic actor without repository evidence (R9-T08)`);
    }
  }

  return {
    valid: errors.length === 0,
    errors,
    warnings
  };
}

/**
 * Stage C: Builds standard repository-specific Threat Model conforming to Section 17, 30 & 34 (R2-P0-09 & R9-P1-02).
 */
export function buildThreatModel(repoRoot = process.cwd()) {
  const rootResolved = path.resolve(repoRoot);
  const provenance = getHardenedGitProvenance(rootResolved);
  const inventory = detectRepositoryInventory(rootResolved);
  const timestamp = new Date().toISOString();
  const threatModelId = `TM-${crypto.randomBytes(4).toString('hex')}`;

  const inScopeFamilies = [
    'auth/authz/tenancy',
    'injection/query/template/eval',
    'network/SSRF',
    'filesystem/path/archive',
    'parser/deserialization',
    'secrets/crypto',
    'state/business-logic',
    'dangerous-defaults/config',
    'native-memory-safety',
    'ai/agent-trust-boundaries'
  ];

  // R9-P1-01 & R9-P1-02: Load Project Security Context (.security-audit/) if present
  const projectContextRes = loadProjectSecurityContext(rootResolved);
  const hasConfirmedContext = (projectContextRes.status === 'CONFIRMED' && projectContextRes.context);

  let components;
  let actors;
  let trustBoundaries;
  let securityProperties = [];
  let contextStatus = 'GENERIC_SECURITY_REVIEW';
  let assuranceLimitation = 'CONTEXT_LIMITED';
  let projectContextFingerprint = null;
  let securityPropertiesFingerprint = null;

  const discovered = discoverComponents(rootResolved, inventory);

  const hasCi = fs.existsSync(path.join(rootResolved, '.github')) ||
                fs.existsSync(path.join(rootResolved, '.gitlab-ci.yml')) ||
                fs.existsSync(path.join(rootResolved, 'Dockerfile'));
  const operatorEvidence = hasCi
    ? {
        path: fs.existsSync(path.join(rootResolved, '.github')) ? '.github/' : (fs.existsSync(path.join(rootResolved, '.gitlab-ci.yml')) ? '.gitlab-ci.yml' : 'Dockerfile'),
        manifestOrigin: 'ci-operator-boundary',
        confidence: 'high'
      }
    : null;

  const hasNetworkProfile = inventory.profiles.includes('web-api') || inventory.profiles.includes('web-app');
  const attackerEvidence = hasNetworkProfile
    ? { path: inventory.entrypoints[0]?.path || './', manifestOrigin: 'network-ingress-boundary', confidence: 'high' }
    : (inventory.profiles.includes('cli')
        ? { path: inventory.entrypoints[0]?.path || 'bin/', manifestOrigin: 'cli-user-boundary', confidence: 'high' }
        : null);

  const authComp = discovered.find(c => c.name === 'Auth');
  const persistenceComp = discovered.find(c => c.name === 'Persistence');

  const defaultActors = [
    {
      id: 'external-attacker',
      trustLevel: 'untrusted',
      description: 'External actor interacting via network, public APIs, or CLI parameters',
      status: attackerEvidence ? 'FACT' : 'ASSUMPTION',
      evidence: attackerEvidence
    },
    {
      id: 'authenticated-user',
      trustLevel: 'semi-trusted',
      description: 'Standard tenant user attempting horizontal or vertical privilege escalation',
      status: authComp ? 'FACT' : 'ASSUMPTION',
      evidence: authComp ? authComp.evidence : null
    },
    {
      id: 'system-operator',
      trustLevel: 'privileged',
      description: 'Authorized administrator configuring environment and deployments',
      status: operatorEvidence ? 'FACT' : 'ASSUMPTION',
      evidence: operatorEvidence
    }
  ];

  const defaultBoundaries = [
    {
      boundary: 'untrusted-ingress-to-controller',
      description: 'External data ingress passing into internal application logic',
      status: inventory.entrypoints.length > 0 ? 'FACT' : 'ASSUMPTION',
      evidence: inventory.entrypoints[0] ? { path: inventory.entrypoints[0].path, manifestOrigin: 'entrypoint-boundary', confidence: 'high' } : null
    },
    {
      boundary: 'controller-to-persistence',
      description: 'Application logic interacting with persistent datastores or external APIs',
      status: persistenceComp ? 'FACT' : 'ASSUMPTION',
      evidence: persistenceComp ? persistenceComp.evidence : null
    },
    {
      boundary: 'application-to-environment',
      description: 'Process environment, filesystem operations, and subshell executions',
      status: 'FACT',
      evidence: { path: './', manifestOrigin: 'process-environment-boundary', confidence: 'high' }
    }
  ];

  const suggestedExtensions = {
    components: [],
    actors: [],
    boundaries: []
  };

  if (hasConfirmedContext) {
    const ctx = projectContextRes.context;
    const ctxComps = (ctx.trustModel?.components || []).map(c => {
      const name = c.name || c.id;
      let evidence = c.evidence;
      if (Array.isArray(evidence) && evidence.length > 0 && typeof evidence[0] === 'string') {
        evidence = { path: evidence[0], manifestOrigin: 'project-context', confidence: 'high' };
      }
      return {
        name,
        id: c.id || name,
        description: c.description || `Evidenced component ${name}`,
        criticality: c.criticality || 'medium',
        evidence,
        source: c.source || 'REPOSITORY_EVIDENCE',
        isAuthoritative: c.isAuthoritative !== false,
        applicableFamilies: c.applicableFamilies || null,
        notApplicable: c.notApplicable || null
      };
    });

    // R10-P1-02: Quarantine auto-discovered components not explicitly confirmed in project context
    for (const d of discovered) {
      if (!ctxComps.some(c => c.name === d.name || c.id === d.id)) {
        suggestedExtensions.components.push({
          ...d,
          status: 'AUTO_DISCOVERED_UNCONFIRMED',
          isAuthoritative: false
        });
      }
    }
    components = ctxComps;

    const ctxActors = (ctx.actors || []).map(a => ({
      id: a.id,
      trustLevel: a.trustLevel || 'untrusted',
      description: a.description || '',
      status: a.status || (a.source === 'REPOSITORY_EVIDENCE' ? 'FACT' : 'ASSUMPTION'),
      evidence: a.evidence || (a.source === 'REPOSITORY_EVIDENCE' ? { manifestOrigin: a.source, confidence: 'high' } : null)
    }));

    // R10-P1-02: Quarantine default generic actors not explicitly confirmed in project context
    for (const da of defaultActors) {
      if (!ctxActors.some(a => a.id === da.id)) {
        suggestedExtensions.actors.push({
          ...da,
          status: 'AUTO_DISCOVERED_UNCONFIRMED',
          isAuthoritative: false
        });
      }
    }
    actors = ctxActors;

    const ctxBoundaries = (ctx.trustModel?.trustBoundaries || []).map(b => ({
      boundary: b.boundary || b.name,
      description: b.description || '',
      status: b.status || 'FACT',
      evidence: b.evidence || null
    }));

    // R10-P1-02: Quarantine default generic boundaries not explicitly confirmed in project context
    for (const db of defaultBoundaries) {
      if (!ctxBoundaries.some(b => b.boundary === db.boundary)) {
        suggestedExtensions.boundaries.push({
          ...db,
          status: 'AUTO_DISCOVERED_UNCONFIRMED',
          isAuthoritative: false
        });
      }
    }
    trustBoundaries = ctxBoundaries;

    securityProperties = ctx.securityProperties || [];
    contextStatus = 'CONFIRMED';
    assuranceLimitation = null;
    projectContextFingerprint = projectContextRes.projectContextFingerprint;
    securityPropertiesFingerprint = projectContextRes.securityPropertiesFingerprint;
  } else {
    components = discovered;
    actors = defaultActors;
    trustBoundaries = defaultBoundaries;
    contextStatus = 'GENERIC_SECURITY_REVIEW';
    assuranceLimitation = 'CONTEXT_LIMITED';
  }

  const discoveryMatrix = generateDiscoveryMatrix(components, inScopeFamilies);
  let pkg = {};
  try {
    const pkgContent = fs.readFileSync(path.join(rootResolved, 'package.json'), 'utf8');
    pkg = JSON.parse(pkgContent) || {};
  } catch {}

  const systemPurpose = typeof pkg.description === 'string' && pkg.description.trim().length > 0
    ? pkg.description.trim()
    : `${inventory.primaryProfile.toUpperCase()} codebase subject to multi-profile security audit`;

  return {
    schemaVersion: '1',
    threatModelId,
    target: {
      repositoryUri: provenance.repositoryUri,
      revision: provenance.revisionId,
      branch: provenance.branch,
      dirty: provenance.properties.isDirty
    },
    targetProfile: {
      primary: inventory.primaryProfile,
      detectedProfiles: inventory.profiles,
      detectedLanguages: inventory.languages,
      manifestsCount: inventory.manifests.length
    },
    systemPurpose,
    actors,
    components,
    entrypoints: inventory.entrypoints,
    trustBoundaries,
    suggestedExtensions,
    securityProperties,
    inScopeFamilies,
    discoveryMatrix,
    contextStatus,
    assuranceLimitation,
    projectContextFingerprint,
    securityPropertiesFingerprint,
    explicitAssumptions: [
      'Git operations isolated against external diff and fsmonitor overrides via safe-git wrapper.',
      'Candidate findings cannot self-assert verdicts and must achieve quorum under Default-Deny.',
      'Secrets discovered in codebase are deterministically redacted before export.',
      'Unevidenced actors and trust boundaries are strictly scoped as ASSUMPTION.'
    ],
    createdAt: timestamp
  };
}

// -----------------------------------------------------------------------------
// CLI Dispatch
// -----------------------------------------------------------------------------
const isDirectExecution = process.argv[1] && process.argv[1].endsWith('build-threat-model.mjs');

if (isDirectExecution) {
  const args = process.argv.slice(2);
  function getArg(name) {
    const idx = args.indexOf(name);
    if (idx !== -1 && idx + 1 < args.length) return args[idx + 1];
    return null;
  }

  const root = getArg('--root') || process.cwd();
  const outputPath = getArg('--output') || path.join(root, 'scratch', 'threat-model.json');

  try {
    const tm = buildThreatModel(root);
    fs.mkdirSync(path.dirname(outputPath), { recursive: true });
    fs.writeFileSync(outputPath, JSON.stringify(tm, null, 2), 'utf8');
    console.log(`✔ Generated Threat Model: ${outputPath} (${tm.components.length} components, ${tm.targetProfile.primary} profile)`);
  } catch (err) {
    console.error('Error in build-threat-model:', err.message);
    process.exit(1);
  }
}
