#!/usr/bin/env node
/**
 * doctor.mjs
 * Track D Phase D1: deterministic, zero-dependency environment preflight.
 *
 * This script intentionally distinguishes static configuration from observed
 * runtime enforcement. It never performs network I/O and never upgrades an
 * unobserved sandbox/runtime claim to READY.
 */

import fs from 'node:fs';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { verifyToolSelfIntegrity } from '../skills/security-audit/scripts/finalize-scan.mjs';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
export const DEFAULT_REPO_ROOT = path.resolve(__dirname, '..');

export const DOCTOR_SCHEMA_ID = 'https://antigravity.google/schemas/security-audit/doctor-report.schema.json';
export const DOCTOR_SCHEMA_VERSION = '1.0.0';
export const DOCTOR_STATES = Object.freeze(['READY', 'DEGRADED', 'UNSUPPORTED', 'UNVERIFIABLE']);
export const MINIMUM_VERSIONS = Object.freeze({
  node: '20.0.0',
  git: '2.30.0',
  agy: '1.2.0',
  gh: '2.50.0'
});

const STATUS_RANK = Object.freeze({ READY: 0, DEGRADED: 1, UNVERIFIABLE: 2, UNSUPPORTED: 3 });
const SUPPORTED_PLATFORMS = new Set(['win32', 'linux', 'darwin']);

function safeErrorMessage(value) {
  if (!value) return null;
  return String(value.message || value.code || value).slice(0, 300);
}

export function parseSemver(value) {
  const text = String(value ?? '').trim();
  const match = text.match(/(?:^|[^0-9])v?(\d+)\.(\d+)\.(\d+)(?:[^0-9]|$)/);
  if (!match) return null;
  return {
    raw: `${match[1]}.${match[2]}.${match[3]}`,
    major: Number(match[1]),
    minor: Number(match[2]),
    patch: Number(match[3])
  };
}

export function compareSemver(actual, minimum) {
  const a = typeof actual === 'string' ? parseSemver(actual) : actual;
  const b = typeof minimum === 'string' ? parseSemver(minimum) : minimum;
  if (!a || !b) return null;
  for (const key of ['major', 'minor', 'patch']) {
    if (a[key] > b[key]) return 1;
    if (a[key] < b[key]) return -1;
  }
  return 0;
}

export function aggregateStatus(statuses) {
  const filtered = statuses.filter(s => DOCTOR_STATES.includes(s));
  if (filtered.length === 0) return 'UNVERIFIABLE';
  return filtered.reduce((worst, current) => STATUS_RANK[current] > STATUS_RANK[worst] ? current : worst, 'READY');
}

function executableCandidates(command, platform, env) {
  if (platform !== 'win32') return [command];
  if (path.extname(command)) return [command];
  const extSource = env.PATHEXT || env.Pathext || '.COM;.EXE;.BAT;.CMD';
  return ['', ...extSource.split(';').filter(Boolean)].map(ext => command + ext.toLowerCase());
}

export function resolveExecutablePath(command, options = {}) {
  const env = options.env || process.env;
  const platform = options.platform || process.platform;
  const pathValue = env.PATH || env.Path || env.path || '';
  if (!pathValue) return null;
  const candidates = executableCandidates(command, platform, env);
  for (const dir of pathValue.split(path.delimiter).filter(Boolean)) {
    for (const candidate of candidates) {
      const full = path.resolve(dir.replace(/^"|"$/g, ''), candidate);
      try {
        if (!fs.statSync(full).isFile()) continue;
        if (platform !== 'win32') fs.accessSync(full, fs.constants.X_OK);
        return fs.realpathSync(full);
      } catch {
        // Continue probing the PATH deterministically.
      }
    }
  }
  return null;
}

export function defaultCommandRunner(command, args = [], options = {}) {
  const result = spawnSync(command, args, {
    cwd: options.cwd || DEFAULT_REPO_ROOT,
    env: options.env || process.env,
    encoding: 'utf8',
    timeout: options.timeoutMs || 4000,
    windowsHide: true,
    shell: false,
    stdio: ['ignore', 'pipe', 'pipe']
  });
  return {
    ok: !result.error && result.status === 0,
    status: result.status,
    stdout: String(result.stdout || '').trim(),
    stderr: String(result.stderr || '').trim(),
    error: safeErrorMessage(result.error)
  };
}

export function probeExecutable(spec, options = {}) {
  const env = options.env || process.env;
  const platform = options.platform || process.platform;
  const runner = options.commandRunner || defaultCommandRunner;
  const executablePath = resolveExecutablePath(spec.command, { env, platform });
  const command = executablePath || spec.command;
  const result = runner(command, spec.args || ['--version'], {
    cwd: options.repoRoot || DEFAULT_REPO_ROOT,
    env,
    timeoutMs: spec.timeoutMs || 4000
  });

  if (!result.ok) {
    return {
      id: spec.id,
      status: spec.missingStatus || 'UNSUPPORTED',
      requiredFor: spec.requiredFor || [],
      requirement: spec.requirement,
      summary: spec.missingSummary || `${spec.label} is unavailable.`,
      observed: {
        available: false,
        executablePath,
        version: null,
        rawVersion: null,
        error: result.error || result.stderr || `exit=${result.status}`
      }
    };
  }

  const rawVersion = result.stdout || result.stderr;
  const parsed = parseSemver(rawVersion);
  if (!parsed) {
    return {
      id: spec.id,
      status: 'UNVERIFIABLE',
      requiredFor: spec.requiredFor || [],
      requirement: spec.requirement,
      summary: `${spec.label} executed, but its version could not be parsed safely.`,
      observed: { available: true, executablePath, version: null, rawVersion, error: null }
    };
  }

  const comparison = compareSemver(parsed, spec.minimumVersion);
  const below = comparison === null || comparison < 0;
  return {
    id: spec.id,
    status: below ? (spec.belowStatus || 'UNSUPPORTED') : 'READY',
    requiredFor: spec.requiredFor || [],
    requirement: spec.requirement,
    summary: below
      ? `${spec.label} ${parsed.raw} is below required ${spec.minimumVersion}.`
      : `${spec.label} ${parsed.raw} satisfies >= ${spec.minimumVersion}.`,
    observed: {
      available: true,
      executablePath,
      version: parsed.raw,
      rawVersion,
      error: null
    }
  };
}

function parseJsonFile(filePath) {
  try {
    return { ok: true, value: JSON.parse(fs.readFileSync(filePath, 'utf8')), error: null };
  } catch (error) {
    return { ok: false, value: null, error: safeErrorMessage(error) };
  }
}

export function inspectPluginLayout(repoRoot = DEFAULT_REPO_ROOT) {
  const required = ['plugin.json', 'hooks.json', 'rules/AGENTS.md'];
  const missing = required.filter(rel => !fs.existsSync(path.join(repoRoot, rel)));
  const plugin = parseJsonFile(path.join(repoRoot, 'plugin.json'));
  const hooks = parseJsonFile(path.join(repoRoot, 'hooks.json'));
  const structurallyValid = missing.length === 0
    && plugin.ok && plugin.value?.name === 'security-audit'
    && hooks.ok && Boolean(hooks.value?.['shadow-context-guard']?.PreToolUse);

  return {
    id: 'plugin-layout',
    status: structurallyValid ? 'READY' : 'UNSUPPORTED',
    requiredFor: ['TIER1', 'TIER2'],
    requirement: 'plugin.json, hooks.json, rules/AGENTS.md and security-audit hook registration',
    summary: structurallyValid
      ? 'Plugin layout and hook registration are present.'
      : 'Plugin layout is incomplete or malformed.',
    observed: {
      root: repoRoot,
      requiredFiles: required,
      missingFiles: missing,
      pluginName: plugin.ok ? plugin.value?.name || null : null,
      pluginParseError: plugin.error,
      hooksParseError: hooks.error
    }
  };
}

export function inspectTcbIntegrity(repoRoot = DEFAULT_REPO_ROOT, verifier = verifyToolSelfIntegrity) {
  const toolRoot = path.join(repoRoot, 'skills', 'security-audit');
  try {
    const result = verifier(toolRoot, repoRoot, { allowSelfAudit: true });
    return {
      id: 'tcb-integrity',
      status: result?.valid ? 'READY' : 'UNSUPPORTED',
      requiredFor: ['TIER1', 'TIER2'],
      requirement: 'critical TCB script hashes match tool-integrity-manifest.json',
      summary: result?.valid
        ? `TCB integrity verified for ${result.verifiedScriptsCount ?? 'all'} critical scripts.`
        : 'TCB integrity verification failed.',
      observed: {
        valid: Boolean(result?.valid),
        verifierStatus: result?.status || null,
        verifiedScriptsCount: result?.verifiedScriptsCount ?? null,
        manifestDigest: result?.manifestDigest || result?.toolIntegrityDigest || null,
        toolVersion: result?.toolVersion || null,
        error: result?.error || result?.warning || null
      }
    };
  } catch (error) {
    return {
      id: 'tcb-integrity',
      status: 'UNVERIFIABLE',
      requiredFor: ['TIER1', 'TIER2'],
      requirement: 'critical TCB script hashes match tool-integrity-manifest.json',
      summary: 'TCB verifier could not complete.',
      observed: { valid: false, verifierStatus: null, verifiedScriptsCount: null, manifestDigest: null, toolVersion: null, error: safeErrorMessage(error) }
    };
  }
}

export function inspectPermissionsAndSandbox(repoRoot = DEFAULT_REPO_ROOT) {
  const permissionsPath = path.join(repoRoot, 'recommended-security-audit-permissions.json');
  const hooksPath = path.join(repoRoot, 'hooks.json');
  const permissions = parseJsonFile(permissionsPath);
  const hooks = parseJsonFile(hooksPath);
  const layers = permissions.value?.defenseInDepth || {};
  const roles = permissions.value?.roles || {};
  const staticReady = permissions.ok
    && hooks.ok
    && Boolean(layers.layer1_terminal_sandbox)
    && Boolean(layers.layer2_permission_engine)
    && Boolean(layers.layer3_shadow_context_guard)
    && Boolean(layers.layer4_deterministic_tcb)
    && ['coordinator', 'discovery', 'verifiers', 'remediation'].every(role => Boolean(roles[role]))
    && Boolean(hooks.value?.['shadow-context-guard']?.PreToolUse);

  const profileCheck = {
    id: 'permissions-profile',
    status: staticReady ? 'READY' : 'UNSUPPORTED',
    requiredFor: ['TIER2'],
    requirement: 'recommended permissions profile and four-layer configuration are present',
    summary: staticReady
      ? 'Permission profile and four-layer static configuration are present.'
      : 'Permission or sandbox configuration is missing or malformed.',
    observed: {
      profilePath: permissionsPath,
      schemaVersion: permissions.value?.schemaVersion || null,
      profileVersion: permissions.value?.version || null,
      roles: Object.keys(roles).sort(),
      parseError: permissions.error || hooks.error || null
    }
  };

  const runtimeCheck = {
    id: 'sandbox-runtime-enforcement',
    status: staticReady ? 'UNVERIFIABLE' : 'UNSUPPORTED',
    requiredFor: ['TIER2'],
    requirement: 'live AGY sandbox and hook enforcement must be observed, not inferred from configuration',
    summary: staticReady
      ? 'Static sandbox configuration is present; live enforcement is intentionally unverified by Doctor.'
      : 'Sandbox configuration is incomplete, so live enforcement cannot be evaluated.',
    observed: {
      staticConfigurationPresent: staticReady,
      liveCanaryObserved: false,
      evidenceGrade: staticReady ? 'STATIC_CONFIGURATION_ONLY' : 'MISSING_CONFIGURATION'
    }
  };

  return [profileCheck, runtimeCheck];
}

export function inspectPlatform(options = {}) {
  const platform = options.platform || process.platform;
  const arch = options.arch || process.arch;
  const env = options.env || process.env;
  const shell = platform === 'win32'
    ? (env.ComSpec || env.COMSPEC || null)
    : (env.SHELL || null);
  const supported = SUPPORTED_PLATFORMS.has(platform);
  return {
    id: 'platform',
    status: supported ? 'READY' : 'UNSUPPORTED',
    requiredFor: ['TIER1', 'TIER2'],
    requirement: 'supported OS platform: win32, linux, or darwin',
    summary: supported ? `${platform}/${arch} is a declared supported platform.` : `${platform}/${arch} is not declared supported.`,
    observed: { platform, arch, shell }
  };
}

export function inspectNode(options = {}) {
  const nodeVersion = String(options.nodeVersion || process.versions.node || '').replace(/^v/, '');
  const parsed = parseSemver(nodeVersion);
  const ok = parsed && compareSemver(parsed, MINIMUM_VERSIONS.node) >= 0;
  return {
    id: 'node',
    status: ok ? 'READY' : 'UNSUPPORTED',
    requiredFor: ['TIER1', 'TIER2'],
    requirement: `Node.js >= ${MINIMUM_VERSIONS.node}`,
    summary: ok ? `Node.js ${parsed.raw} satisfies >= ${MINIMUM_VERSIONS.node}.` : `Node.js ${nodeVersion || 'UNKNOWN'} is unsupported.`,
    observed: {
      available: true,
      executablePath: process.execPath,
      version: parsed?.raw || null,
      esm: true,
      builtinCrypto: true
    }
  };
}

export function validateDoctorReportShape(report) {
  if (!report || typeof report !== 'object' || Array.isArray(report)) return false;

  const exactKeys = (value, expected) => {
    if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
    const actual = Object.keys(value).sort();
    const wanted = [...expected].sort();
    return actual.length === wanted.length && actual.every((key, index) => key === wanted[index]);
  };
  const isStatus = value => DOCTOR_STATES.includes(value);
  const isStringOrNull = value => typeof value === 'string' || value === null;

  if (!exactKeys(report, ['$schema', 'schemaVersion', 'generatedAt', 'toolVersion', 'overallStatus', 'profiles', 'environment', 'capabilities', 'checks'])) return false;
  if (report.$schema !== DOCTOR_SCHEMA_ID || report.schemaVersion !== DOCTOR_SCHEMA_VERSION) return false;
  if (typeof report.generatedAt !== 'string' || Number.isNaN(Date.parse(report.generatedAt))) return false;
  if (typeof report.toolVersion !== 'string' || report.toolVersion.length === 0) return false;
  if (!isStatus(report.overallStatus)) return false;

  if (!exactKeys(report.profiles, ['tier1', 'tier2'])) return false;
  if (!isStatus(report.profiles.tier1) || !isStatus(report.profiles.tier2)) return false;

  if (!exactKeys(report.environment, ['platform', 'arch', 'shell', 'pluginRoot'])) return false;
  if (typeof report.environment.platform !== 'string' || typeof report.environment.arch !== 'string') return false;
  if (!isStringOrNull(report.environment.shell) || typeof report.environment.pluginRoot !== 'string') return false;

  if (!exactKeys(report.capabilities, ['deterministicTier1', 'liveTier2Executable', 'strictReleaseProvenance', 'liveSandboxEnforcementObserved'])) return false;
  if (!['deterministicTier1', 'liveTier2Executable', 'strictReleaseProvenance', 'liveSandboxEnforcementObserved']
    .every(key => typeof report.capabilities[key] === 'boolean')) return false;
  if (report.capabilities.liveSandboxEnforcementObserved !== false) return false;

  if (!Array.isArray(report.checks) || report.checks.length < 8) return false;
  const ids = new Set();
  for (const check of report.checks) {
    if (!exactKeys(check, ['id', 'status', 'requiredFor', 'requirement', 'summary', 'observed'])) return false;
    if (typeof check.id !== 'string' || check.id.length === 0 || ids.has(check.id)) return false;
    ids.add(check.id);
    if (!isStatus(check.status)) return false;
    if (!Array.isArray(check.requiredFor) || new Set(check.requiredFor).size !== check.requiredFor.length) return false;
    if (!check.requiredFor.every(value => value === 'TIER1' || value === 'TIER2')) return false;
    if (typeof check.requirement !== 'string' || typeof check.summary !== 'string') return false;
    if (!check.observed || typeof check.observed !== 'object' || Array.isArray(check.observed)) return false;
  }
  return true;
}

export function runDoctor(options = {}) {
  const repoRoot = path.resolve(options.repoRoot || DEFAULT_REPO_ROOT);
  const env = options.env || process.env;
  const platform = options.platform || process.platform;
  const commandProbe = options.commandProbe || ((spec) => probeExecutable(spec, {
    repoRoot,
    env,
    platform,
    commandRunner: options.commandRunner
  }));

  const checks = [
    inspectNode({ nodeVersion: options.nodeVersion }),
    commandProbe({
      id: 'git', label: 'Git', command: platform === 'win32' ? 'git.exe' : 'git', minimumVersion: MINIMUM_VERSIONS.git,
      requiredFor: ['TIER1', 'TIER2'], requirement: `Git >= ${MINIMUM_VERSIONS.git}`,
      missingStatus: 'UNSUPPORTED', belowStatus: 'UNSUPPORTED'
    }),
    commandProbe({
      id: 'agy', label: 'Antigravity CLI', command: platform === 'win32' ? 'agy.exe' : 'agy', minimumVersion: MINIMUM_VERSIONS.agy,
      requiredFor: ['TIER2'], requirement: `Antigravity CLI >= ${MINIMUM_VERSIONS.agy}`,
      missingStatus: 'UNSUPPORTED', belowStatus: 'UNSUPPORTED',
      missingSummary: 'Antigravity CLI is unavailable; deterministic Tier 1 remains usable, but live Tier 2 reproduction is unsupported.'
    }),
    commandProbe({
      id: 'gh', label: 'GitHub CLI', command: platform === 'win32' ? 'gh.exe' : 'gh', minimumVersion: MINIMUM_VERSIONS.gh,
      requiredFor: ['TIER1'], requirement: `GitHub CLI >= ${MINIMUM_VERSIONS.gh} for strict release provenance verification`,
      missingStatus: 'DEGRADED', belowStatus: 'DEGRADED',
      missingSummary: 'GitHub CLI is unavailable; strict SLSA/release provenance verification is disabled.'
    }),
    inspectPlatform({ platform, arch: options.arch, env }),
    inspectPluginLayout(repoRoot),
    inspectTcbIntegrity(repoRoot, options.tcbVerifier || verifyToolSelfIntegrity),
    ...inspectPermissionsAndSandbox(repoRoot)
  ];

  const forTier = tier => checks.filter(c => c.requiredFor.includes(tier)).map(c => c.status);
  const profiles = {
    tier1: aggregateStatus(forTier('TIER1')),
    tier2: aggregateStatus(forTier('TIER2'))
  };

  const report = {
    $schema: DOCTOR_SCHEMA_ID,
    schemaVersion: DOCTOR_SCHEMA_VERSION,
    generatedAt: (options.now || (() => new Date()))().toISOString(),
    toolVersion: (() => {
      try { return JSON.parse(fs.readFileSync(path.join(repoRoot, 'package.json'), 'utf8')).version || 'UNKNOWN'; }
      catch { return 'UNKNOWN'; }
    })(),
    overallStatus: aggregateStatus([profiles.tier1, profiles.tier2]),
    profiles,
    environment: {
      platform,
      arch: options.arch || process.arch,
      shell: platform === 'win32' ? (env.ComSpec || env.COMSPEC || null) : (env.SHELL || null),
      pluginRoot: repoRoot
    },
    capabilities: {
      deterministicTier1: profiles.tier1 === 'READY' || profiles.tier1 === 'DEGRADED',
      liveTier2Executable: checks.find(c => c.id === 'agy')?.status === 'READY',
      strictReleaseProvenance: checks.find(c => c.id === 'gh')?.status === 'READY',
      liveSandboxEnforcementObserved: false
    },
    checks
  };

  if (!validateDoctorReportShape(report)) {
    throw new Error('DOCTOR_INTERNAL_SCHEMA_VIOLATION: generated report failed internal shape validation');
  }
  return report;
}

export function renderHumanReport(report) {
  const lines = [];
  lines.push(`agy-security-audit Doctor v${report.toolVersion}`);
  lines.push(`Overall: ${report.overallStatus}`);
  lines.push(`Tier 1 deterministic reproduction: ${report.profiles.tier1}`);
  lines.push(`Tier 2 live assurance reproduction: ${report.profiles.tier2}`);
  lines.push('');
  for (const check of report.checks) {
    lines.push(`[${check.status}] ${check.id}: ${check.summary}`);
  }
  lines.push('');
  lines.push('Note: UNVERIFIABLE is intentional when live runtime enforcement has not been observed.');
  lines.push('Doctor performs no network I/O and does not claim live sandbox enforcement from static configuration alone.');
  return `${lines.join('\n')}\n`;
}

function usage() {
  return [
    'Usage: node scripts/doctor.mjs [--json] [--help]',
    '  --json  Emit machine-readable doctor report only.',
    '  --help  Show this help.'
  ].join('\n');
}

export function runCli(args = process.argv.slice(2), io = {}) {
  const writeOut = io.writeOut || (text => process.stdout.write(text));
  const writeErr = io.writeErr || (text => process.stderr.write(text));
  const unknown = args.filter(arg => !['--json', '--help', '-h'].includes(arg));
  if (unknown.length > 0) {
    writeErr(`Unknown argument(s): ${unknown.join(', ')}\n${usage()}\n`);
    return 2;
  }
  if (args.includes('--help') || args.includes('-h')) {
    writeOut(`${usage()}\n`);
    return 0;
  }
  try {
    const report = runDoctor(io.options || {});
    if (args.includes('--json')) writeOut(`${JSON.stringify(report, null, 2)}\n`);
    else writeOut(renderHumanReport(report));
    return report.overallStatus === 'UNSUPPORTED' ? 1 : 0;
  } catch (error) {
    writeErr(`DOCTOR_FAILED: ${safeErrorMessage(error)}\n`);
    return 1;
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === path.resolve(__filename)) {
  process.exitCode = runCli();
}
