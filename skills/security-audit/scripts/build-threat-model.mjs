#!/usr/bin/env node
/**
 * build-threat-model.mjs
 * Generates bounded, deterministic repository-specific threat model artifacts
 * conforming to Section 17 and Section 30 of the Security Hardening Plan.
 */

import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { getHardenedGitProvenance } from './safe-git.mjs';

/**
 * Discovers components based on package.json manifests and directory structures.
 */
export function discoverComponents(repoRoot) {
  const components = [];
  const rootResolved = path.resolve(repoRoot);

  let pkg = {};
  const pkgPath = path.join(rootResolved, 'package.json');
  if (fs.existsSync(pkgPath)) {
    try {
      const parsed = JSON.parse(fs.readFileSync(pkgPath, 'utf8'));
      if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
        pkg = parsed;
      }
    } catch {}
  }

  const pkgName = typeof pkg.name === 'string' ? pkg.name : '';
  const allDeps = {
    ...(pkg.dependencies && typeof pkg.dependencies === 'object' ? pkg.dependencies : {}),
    ...(pkg.devDependencies && typeof pkg.devDependencies === 'object' ? pkg.devDependencies : {})
  };

  // Inspect directories
  const dirItems = fs.readdirSync(rootResolved, { withFileTypes: true });
  const dirNames = dirItems.filter(i => i.isDirectory()).map(i => i.name.toLowerCase());

  // 1. API / Web Routing Component
  const webDeps = ['express', 'fastify', 'koa', 'hapi', 'nest', 'next', 'nuxt', 'koa-router'];
  const hasWebFramework = webDeps.some(d => allDeps[d]);
  const hasApiDir = ['api', 'routes', 'controllers', 'handlers', 'endpoints'].some(d => dirNames.includes(d));
  if (hasWebFramework || hasApiDir) {
    components.push({
      name: 'API',
      description: 'HTTP / Web Service Entrypoints and Route Controllers',
      criticality: 'high',
      indicators: Object.keys(allDeps).filter(d => webDeps.includes(d))
    });
  }

  // 2. Auth & Identity Component
  const authDeps = ['passport', 'jsonwebtoken', 'bcrypt', 'argon2', 'auth0', 'firebase-admin', 'jose'];
  const hasAuth = authDeps.some(d => allDeps[d]) || ['auth', 'security', 'identity'].some(d => dirNames.includes(d));
  if (hasAuth) {
    components.push({
      name: 'Auth',
      description: 'Identity verification, token validation, and authorization',
      criticality: 'critical',
      indicators: Object.keys(allDeps).filter(d => authDeps.includes(d))
    });
  }

  // 3. Persistence & Data Storage Component
  const dbDeps = ['pg', 'mysql', 'mysql2', 'sqlite3', 'better-sqlite3', 'prisma', 'typeorm', 'mongoose', 'knex'];
  const hasDb = dbDeps.some(d => allDeps[d]) || ['db', 'database', 'models', 'migrations', 'prisma'].some(d => dirNames.includes(d));
  if (hasDb) {
    components.push({
      name: 'Persistence',
      description: 'Database storage, queries, and data models',
      criticality: 'high',
      indicators: Object.keys(allDeps).filter(d => dbDeps.includes(d))
    });
  }

  // 4. File & Archive Handling Component
  const fileDeps = ['multer', 'formidable', 'busboy', 'archiver', 'tar', 'adm-zip', 'unzipper'];
  const hasFileHandling = fileDeps.some(d => allDeps[d]) || ['uploads', 'files', 'storage'].some(d => dirNames.includes(d));
  if (hasFileHandling) {
    components.push({
      name: 'FileHandling',
      description: 'File upload, archive extraction, and filesystem operations',
      criticality: 'high',
      indicators: Object.keys(allDeps).filter(d => fileDeps.includes(d))
    });
  }

  // 5. Background Jobs & Asynchronous Workers Component
  const jobDeps = ['bullmq', 'bull', 'agenda', 'bree', 'node-cron', 'amqplib', 'kafkajs'];
  const hasJobs = jobDeps.some(d => allDeps[d]) || ['queues', 'workers', 'jobs'].some(d => dirNames.includes(d));
  if (hasJobs) {
    components.push({
      name: 'Jobs',
      description: 'Background queues, cron schedulers, and asynchronous workers',
      criticality: 'medium',
      indicators: Object.keys(allDeps).filter(d => jobDeps.includes(d))
    });
  }

  // 6. Administrative & Internal Tools Component
  const hasAdmin = ['admin', 'dashboard', 'internal', 'management'].some(d => dirNames.includes(d));
  if (hasAdmin) {
    components.push({
      name: 'Admin',
      description: 'Administrative interfaces, back-office panels, and internal tools',
      criticality: 'high',
      indicators: ['admin/internal directory present']
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
      indicators: Object.keys(allDeps).filter(d => importExportDeps.includes(d))
    });
  }

  // 8. Plugin & Extension Architecture Component
  const hasPluginDir = ['plugins', 'rules', 'skills', 'extensions', 'addons'].some(d => dirNames.includes(d)) ||
    pkgName.includes('plugin');
  if (hasPluginDir) {
    components.push({
      name: 'PluginSystem',
      description: 'Extensibility hooks, custom rules, and skill definitions',
      criticality: 'high',
      indicators: ['plugins/skills directories or plugin package naming']
    });
  }

  // 9. Frontend Trust Boundary Component
  const frontendDeps = ['helmet', 'cors', 'csurf'];
  const hasFrontendBoundary = frontendDeps.some(d => allDeps[d]) || ['views', 'templates', 'public', 'static'].some(d => dirNames.includes(d));
  if (hasFrontendBoundary) {
    components.push({
      name: 'FrontendBoundary',
      description: 'Client-side assets, template rendering, and browser security policies',
      criticality: 'medium',
      indicators: Object.keys(allDeps).filter(d => frontendDeps.includes(d))
    });
  }

  // Fallback if no specific components matched
  if (components.length === 0) {
    components.push({
      name: 'CoreApp',
      description: 'General application source code',
      criticality: 'medium',
      indicators: ['standard source tree']
    });
  }

  return components;
}

/**
 * Generates the active Component × Family discovery dispatch matrix.
 */
export function generateDiscoveryMatrix(components = [], inScopeFamilies = []) {
  const matrix = [];
  for (const comp of components) {
    for (const fam of inScopeFamilies) {
      matrix.push({
        component: comp.name,
        family: fam,
        criticality: comp.criticality || 'medium',
        status: 'PENDING'
      });
    }
  }
  return matrix;
}

/**
 * Builds standard repository-specific Threat Model conforming to Section 17 & 30.
 */
export function buildThreatModel(repoRoot = process.cwd()) {
  const provenance = getHardenedGitProvenance(repoRoot);
  const components = discoverComponents(repoRoot);
  const timestamp = new Date().toISOString();
  const threatModelId = `TM-${crypto.randomBytes(4).toString('hex')}`;

  let pkg = {};
  try {
    const pkgContent = fs.readFileSync(path.join(repoRoot, 'package.json'), 'utf8');
    pkg = JSON.parse(pkgContent) || {};
  } catch {}

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

  const discoveryMatrix = generateDiscoveryMatrix(components, inScopeFamilies);
  const systemPurpose = typeof pkg.description === 'string' && pkg.description.trim().length > 0
    ? pkg.description.trim()
    : 'Target codebase subject to security audit';

  return {
    schemaVersion: '1',
    threatModelId,
    target: {
      repositoryUri: provenance.repositoryUri,
      revision: provenance.revisionId,
      branch: provenance.branch,
      dirty: provenance.properties.isDirty
    },
    systemPurpose,
    actors: [
      {
        id: 'external-attacker',
        trustLevel: 'untrusted',
        description: 'Unauthenticated external actor interacting via network or public APIs'
      },
      {
        id: 'authenticated-user',
        trustLevel: 'semi-trusted',
        description: 'Standard tenant user attempting horizontal or vertical privilege escalation'
      },
      {
        id: 'system-operator',
        trustLevel: 'privileged',
        description: 'Authorized administrator configuring environment and deployments'
      }
    ],
    components,
    trustBoundaries: [
      {
        boundary: 'untrusted-ingress-to-controller',
        description: 'External data ingress passing into internal application logic'
      },
      {
        boundary: 'controller-to-persistence',
        description: 'Application logic interacting with persistent datastores or external APIs'
      },
      {
        boundary: 'application-to-environment',
        description: 'Process environment, filesystem operations, and subshell executions'
      }
    ],
    inScopeFamilies,
    discoveryMatrix,
    explicitAssumptions: [
      'Git operations isolated against external diff and fsmonitor overrides via safe-git wrapper.',
      'Candidate findings cannot self-assert verdicts and must achieve quorum under Default-Deny.',
      'Secrets discovered in codebase are deterministically redacted before export.'
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
    console.log(`✔ Generated Threat Model: ${outputPath} (${tm.components.length} components, ${tm.inScopeFamilies.length} families)`);
  } catch (err) {
    console.error('Error in build-threat-model:', err.message);
    process.exit(1);
  }
}

