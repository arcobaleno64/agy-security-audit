#!/usr/bin/env node
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  DOCTOR_SCHEMA_ID,
  aggregateStatus,
  compareSemver,
  inspectPluginLayout,
  parseSemver,
  runDoctor,
  validateDoctorReportShape
} from './doctor.mjs';

function assert(condition, message) {
  if (!condition) throw new Error(`ASSERTION_FAILED: ${message}`);
}

function assertEqual(actual, expected, message) {
  assert(actual === expected, `${message}: expected ${JSON.stringify(expected)}, got ${JSON.stringify(actual)}`);
}

let passed = 0;
function test(name, fn) {
  fn();
  passed++;
  console.log(`PASS ${passed}: ${name}`);
}

function writeJson(filePath, value) {
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  fs.writeFileSync(filePath, `${JSON.stringify(value, null, 2)}\n`, 'utf8');
}

function makeRepo() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'agy-doctor-test-'));
  writeJson(path.join(root, 'package.json'), { name: 'fixture', version: '1.8.1', type: 'module' });
  writeJson(path.join(root, 'plugin.json'), { name: 'security-audit' });
  writeJson(path.join(root, 'hooks.json'), {
    'shadow-context-guard': { PreToolUse: [{ matcher: 'view_file', hooks: [{ type: 'command', command: 'node hooks/shadow-context-guard.mjs' }] }] }
  });
  fs.mkdirSync(path.join(root, 'rules'), { recursive: true });
  fs.writeFileSync(path.join(root, 'rules', 'AGENTS.md'), '# rules\n', 'utf8');
  writeJson(path.join(root, 'recommended-security-audit-permissions.json'), {
    schemaVersion: '1.0.0',
    version: '1.8.1',
    defenseInDepth: {
      layer1_terminal_sandbox: {},
      layer2_permission_engine: {},
      layer3_shadow_context_guard: {},
      layer4_deterministic_tcb: {}
    },
    roles: { coordinator: {}, discovery: {}, verifiers: {}, remediation: {} }
  });
  return root;
}

function commandProbeFrom(map) {
  return spec => {
    const item = map[spec.id];
    if (!item) throw new Error(`missing probe fixture for ${spec.id}`);
    return {
      id: spec.id,
      status: item.status,
      requiredFor: spec.requiredFor,
      requirement: spec.requirement,
      summary: item.summary || `${spec.id} fixture`,
      observed: { available: item.status !== 'DEGRADED', executablePath: `/fixture/${spec.id}`, version: item.version || null, rawVersion: item.version || null, error: null }
    };
  };
}

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const FIXED_NOW = () => new Date('2026-09-24T07:00:00.000Z');
const TCB_OK = () => ({ valid: true, status: 'SELF_AUDIT_MODE', verifiedScriptsCount: 10, manifestDigest: 'a'.repeat(64), toolVersion: '1.8.1' });

test('parseSemver handles CLI-formatted versions', () => {
  assertEqual(parseSemver('git version 2.50.1.windows.1').raw, '2.50.1', 'git version');
  assertEqual(parseSemver('agy 1.2.0').raw, '1.2.0', 'agy version');
  assertEqual(parseSemver('gh version 2.50.0 (2026)').raw, '2.50.0', 'gh version');
});

test('compareSemver is deterministic', () => {
  assertEqual(compareSemver('20.0.0', '20.0.0'), 0, 'equal version');
  assertEqual(compareSemver('20.1.0', '20.0.0'), 1, 'greater version');
  assertEqual(compareSemver('19.9.9', '20.0.0'), -1, 'less version');
});

test('aggregateStatus preserves fail-honest precedence', () => {
  assertEqual(aggregateStatus(['READY', 'DEGRADED']), 'DEGRADED', 'degraded dominates ready');
  assertEqual(aggregateStatus(['DEGRADED', 'UNVERIFIABLE']), 'UNVERIFIABLE', 'unverifiable dominates degraded');
  assertEqual(aggregateStatus(['UNVERIFIABLE', 'UNSUPPORTED']), 'UNSUPPORTED', 'unsupported dominates unverifiable');
});

test('plugin layout validates required files and hook registration', () => {
  const root = makeRepo();
  try {
    assertEqual(inspectPluginLayout(root).status, 'READY', 'valid layout');
    fs.unlinkSync(path.join(root, 'rules', 'AGENTS.md'));
    assertEqual(inspectPluginLayout(root).status, 'UNSUPPORTED', 'missing rules must fail');
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('healthy Tier 1 remains READY while Tier 2 sandbox stays UNVERIFIABLE', () => {
  const root = makeRepo();
  try {
    const report = runDoctor({
      repoRoot: root,
      platform: 'linux',
      arch: 'x64',
      env: { PATH: '/fixture/bin', SHELL: '/bin/bash' },
      nodeVersion: '20.11.1',
      now: FIXED_NOW,
      tcbVerifier: TCB_OK,
      commandProbe: commandProbeFrom({
        git: { status: 'READY', version: '2.50.1' },
        agy: { status: 'READY', version: '1.2.0' },
        gh: { status: 'READY', version: '2.50.0' }
      })
    });
    assertEqual(report.profiles.tier1, 'READY', 'tier1 readiness');
    assertEqual(report.profiles.tier2, 'UNVERIFIABLE', 'tier2 cannot self-certify sandbox runtime');
    assertEqual(report.overallStatus, 'UNVERIFIABLE', 'overall status');
    assertEqual(report.capabilities.liveSandboxEnforcementObserved, false, 'sandbox observation must remain false');
    assert(validateDoctorReportShape(report), 'report shape must be valid');
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('missing GitHub CLI degrades Tier 1 without making it unsupported', () => {
  const root = makeRepo();
  try {
    const report = runDoctor({
      repoRoot: root,
      platform: 'linux', arch: 'x64', env: { SHELL: '/bin/bash' }, nodeVersion: '20.0.0', now: FIXED_NOW, tcbVerifier: TCB_OK,
      commandProbe: commandProbeFrom({ git: { status: 'READY' }, agy: { status: 'READY' }, gh: { status: 'DEGRADED' } })
    });
    assertEqual(report.profiles.tier1, 'DEGRADED', 'tier1 degradation');
    assertEqual(report.capabilities.strictReleaseProvenance, false, 'strict provenance capability');
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

test('missing AGY makes live Tier 2 unsupported while leaving Tier 1 independently evaluable', () => {
  const root = makeRepo();
  try {
    const report = runDoctor({
      repoRoot: root,
      platform: 'linux', arch: 'x64', env: { SHELL: '/bin/bash' }, nodeVersion: '20.0.0', now: FIXED_NOW, tcbVerifier: TCB_OK,
      commandProbe: commandProbeFrom({ git: { status: 'READY' }, agy: { status: 'UNSUPPORTED' }, gh: { status: 'READY' } })
    });
    assertEqual(report.checks.find(c => c.id === 'agy').status, 'UNSUPPORTED', 'agy missing status');
    assertEqual(report.profiles.tier1, 'READY', 'tier1 remains independently ready');
    assertEqual(report.profiles.tier2, 'UNSUPPORTED', 'tier2 requires AGY');
    assertEqual(report.capabilities.liveTier2Executable, false, 'live execution capability');
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

test('unsupported Node fails closed', () => {
  const root = makeRepo();
  try {
    const report = runDoctor({
      repoRoot: root,
      platform: 'linux', arch: 'x64', env: { SHELL: '/bin/bash' }, nodeVersion: '18.20.0', now: FIXED_NOW, tcbVerifier: TCB_OK,
      commandProbe: commandProbeFrom({ git: { status: 'READY' }, agy: { status: 'READY' }, gh: { status: 'READY' } })
    });
    assertEqual(report.overallStatus, 'UNSUPPORTED', 'old Node must make environment unsupported');
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

test('TCB integrity mismatch fails closed', () => {
  const root = makeRepo();
  try {
    const report = runDoctor({
      repoRoot: root,
      platform: 'linux', arch: 'x64', env: { SHELL: '/bin/bash' }, nodeVersion: '20.0.0', now: FIXED_NOW,
      tcbVerifier: () => ({ valid: false, status: 'INTEGRITY_VIOLATION', error: 'digest mismatch' }),
      commandProbe: commandProbeFrom({ git: { status: 'READY' }, agy: { status: 'READY' }, gh: { status: 'READY' } })
    });
    assertEqual(report.checks.find(c => c.id === 'tcb-integrity').status, 'UNSUPPORTED', 'TCB mismatch');
    assertEqual(report.overallStatus, 'UNSUPPORTED', 'overall TCB failure');
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

test('unverifiable Tier 1 requirement does not overclaim deterministic capability', () => {
  const root = makeRepo();
  try {
    const report = runDoctor({
      repoRoot: root,
      platform: 'linux', arch: 'x64', env: { SHELL: '/bin/bash' }, nodeVersion: '20.0.0', now: FIXED_NOW,
      tcbVerifier: () => { throw new Error('manifest unavailable'); },
      commandProbe: commandProbeFrom({ git: { status: 'READY' }, agy: { status: 'READY' }, gh: { status: 'READY' } })
    });
    assertEqual(report.profiles.tier1, 'UNVERIFIABLE', 'tier1 evidence state');
    assertEqual(report.capabilities.deterministicTier1, false, 'unverifiable tier1 must not become a positive capability claim');
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

test('runtime report validator enforces the published schema contract shape', () => {
  const root = makeRepo();
  try {
    const report = runDoctor({
      repoRoot: root,
      platform: 'linux', arch: 'x64', env: { SHELL: '/bin/bash' }, nodeVersion: '20.0.0', now: FIXED_NOW,
      tcbVerifier: TCB_OK,
      commandProbe: commandProbeFrom({ git: { status: 'READY' }, agy: { status: 'READY' }, gh: { status: 'READY' } })
    });
    assert(validateDoctorReportShape(report), 'baseline report must validate');
    assert(!validateDoctorReportShape({ ...report, unexpected: true }), 'additional top-level properties must fail');
    assert(!validateDoctorReportShape({ ...report, capabilities: { ...report.capabilities, liveSandboxEnforcementObserved: true } }), 'unobserved sandbox cannot be promoted');
    assert(!validateDoctorReportShape({ ...report, checks: [...report.checks, { ...report.checks[0] }] }), 'duplicate check ids must fail');
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

test('doctor JSON schema artifact exposes required four-state vocabulary', () => {
  const schemaPath = path.resolve(__dirname, '..', 'schemas', 'doctor-report.schema.json');
  const schema = JSON.parse(fs.readFileSync(schemaPath, 'utf8'));
  assertEqual(schema.$id, DOCTOR_SCHEMA_ID, 'schema id');
  const states = schema.definitions.status.enum.slice().sort().join(',');
  assertEqual(states, ['READY', 'DEGRADED', 'UNSUPPORTED', 'UNVERIFIABLE'].sort().join(','), 'state enum');
});

test('doctor source has no network or telemetry dependencies', () => {
  const sourcePath = path.resolve(__dirname, 'doctor.mjs');
  const source = fs.readFileSync(sourcePath, 'utf8');
  for (const forbidden of ["node:http", "node:https", "node:net", "fetch(", "curl ", "wget "]) {
    assert(!source.includes(forbidden), `doctor must not contain ${forbidden}`);
  }
});

console.log(`All Doctor policy tests passed (${passed}/${passed}).`);
