#!/usr/bin/env node
/**
 * test-runtime-confinement.mjs
 * Milestone G6: Dual-Control Runtime Confinement Verification Suite.
 *
 * Deterministic test suite verifying all 5 runtime confinement controls:
 * 1. ALLOW_SHADOW_READ
 * 2. DENY_RAW_REPO_READ
 * 3. DENY_NETWORK_EXFILTRATION
 * 4. DENY_ARBITRARY_FS_WRITE
 * 5. DENY_SUBAGENT_RECURSION
 *
 * Enforces Subprocess Calling Contract (Rules 1-3) and Default-Deny assurance.
 * Zero external npm dependencies.
 */

import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { execFileSync } from 'node:child_process';
import {
  evaluateConfinementMatrix,
  renderConfinementReport,
  invokeGuardHook
} from './run-confinement-matrix.mjs';

const REPO_ROOT = process.cwd();
const HOOK_SCRIPT_PATH = path.resolve(REPO_ROOT, 'hooks/shadow-context-guard.mjs');

function assert(condition, message) {
  if (!condition) {
    throw new Error(`ASSERTION_FAILED: ${message}`);
  }
}

function runSuite() {
  console.log('================================================================');
  console.log('v1.5 Milestone G6: Runtime Confinement Matrix Test Suite');
  console.log('================================================================\n');

  // ---------------------------------------------------------------------------
  // Suite 1: Subprocess Calling Contract Compliance (Rules 1, 2, 3)
  // ---------------------------------------------------------------------------
  console.log('Suite 1: Subprocess Calling Contract Compliance');

  // 1.1 Empty Stdin (Rule 1: Non-blocking unref timer, fail-safe allow)
  const emptyOut = execFileSync(process.execPath, [HOOK_SCRIPT_PATH], {
    input: '',
    encoding: 'utf8',
    timeout: 3000
  });
  assert(!emptyOut.includes('\r'), 'Hook stdout contains CRLF on empty stdin (Rule 2 violation)');
  const parsedEmpty = JSON.parse(emptyOut.trim());
  assert(parsedEmpty.decision === 'allow', 'Empty stdin must fail-safe allow');
  console.log('  ✔ 1.1 Rule 1: Non-blocking stdin read allows safely without hanging.');

  // 1.2 No CRLF Invariant (Rule 2: Unix LF-only output across all responses)
  const dummyPayload = JSON.stringify({
    toolCall: { name: 'search_web', args: { query: 'test' } },
    workspacePaths: [REPO_ROOT]
  });
  const crlfCheck = execFileSync(process.execPath, [HOOK_SCRIPT_PATH], {
    input: dummyPayload,
    encoding: 'utf8',
    timeout: 3000
  });
  assert(!crlfCheck.includes('\r'), 'Hook stdout contains CRLF on deny response (Rule 2 violation)');
  console.log('  ✔ 1.2 Rule 2: Explicit LF-only JSON output enforced (zero CRLF byte leakage).');

  // 1.3 Strict Schema Adherence (Rule 3: Only decision, reason, permissionOverrides)
  const allowedKeys = new Set(['decision', 'reason', 'permissionOverrides']);
  const parsedDummy = JSON.parse(crlfCheck.trim());
  for (const k of Object.keys(parsedDummy)) {
    assert(allowedKeys.has(k), `Extraneous key '${k}' in hook output (Rule 3 violation)`);
  }
  console.log('  ✔ 1.3 Rule 3: Strict output schema adherence (only valid protocol keys allowed).\n');

  // ---------------------------------------------------------------------------
  // Setup Hermetic Scratch Workspace for Functional Control Testing
  // ---------------------------------------------------------------------------
  const tempWs = fs.mkdtempSync(path.join(os.tmpdir(), 'confinement-unit-'));
  const scratchContextDir = path.join(tempWs, 'scratch/context');
  const scratchDir = path.join(tempWs, 'scratch');
  const srcDir = path.join(tempWs, 'src');
  const githubDir = path.join(tempWs, '.github/workflows');

  fs.mkdirSync(scratchContextDir, { recursive: true });
  fs.mkdirSync(srcDir, { recursive: true });
  fs.mkdirSync(githubDir, { recursive: true });

  const manifest = {
    manifestVersion: '1.0.0',
    manifestDigest: 'unit-test-manifest-digest',
    contextRoot: scratchContextDir,
    repoRoot: tempWs,
    entries: [
      { relativePath: 'src/main.js', sanitizedContextPath: path.join(scratchContextDir, 'src/main.js') }
    ]
  };
  fs.writeFileSync(path.join(scratchContextDir, 'context-manifest.json'), JSON.stringify(manifest, null, 2), 'utf8');

  const shadowFile = path.join(scratchContextDir, 'src/main.js');
  const rawFile = path.join(srcDir, 'main.js');
  const unshadowedFile = path.join(srcDir, 'secret.js');
  const githubFile = path.join(githubDir, 'deploy.yml');
  const scratchFile = path.join(scratchDir, 'patch.diff');
  const escapeFile = path.resolve(tempWs, '../outside-leak.txt');

  fs.mkdirSync(path.dirname(shadowFile), { recursive: true });
  fs.writeFileSync(shadowFile, 'export const safe = true;', 'utf8');
  fs.writeFileSync(rawFile, 'export const raw = "api_key";', 'utf8');
  fs.writeFileSync(unshadowedFile, 'export const pass = "secret";', 'utf8');
  fs.writeFileSync(githubFile, 'name: Deploy', 'utf8');

  const testCtx = {
    workspacePaths: [tempWs],
    artifactDirectoryPath: path.join(tempWs, 'scratch/artifacts')
  };

  try {
    // -------------------------------------------------------------------------
    // Suite 2: ALLOW_SHADOW_READ & DENY_RAW_REPO_READ Controls
    // -------------------------------------------------------------------------
    console.log('Suite 2: Filesystem Read Confinement (ALLOW_SHADOW_READ & DENY_RAW_REPO_READ)');

    // 2.1 ALLOW_SHADOW_READ
    const shadowRes = invokeGuardHook({ name: 'view_file', args: { AbsolutePath: shadowFile } }, testCtx, HOOK_SCRIPT_PATH);
    assert(shadowRes.decision === 'allow', 'view_file on shadow context must be allowed');

    const grepShadowRes = invokeGuardHook({ name: 'grep_search', args: { SearchPath: scratchContextDir, Query: 'safe' } }, testCtx, HOOK_SCRIPT_PATH);
    assert(grepShadowRes.decision === 'allow', 'grep_search on shadow context must be allowed');
    console.log('  ✔ 2.1 ALLOW_SHADOW_READ: Reading within sanitized shadow context is permitted.');

    // 2.2 DENY_RAW_REPO_READ
    const rawRes = invokeGuardHook({ name: 'view_file', args: { AbsolutePath: rawFile } }, testCtx, HOOK_SCRIPT_PATH);
    assert(rawRes.decision === 'deny', 'view_file on raw repo file must be denied');
    assert(rawRes.reason.includes('Direct access to raw repository path'), 'Raw read denial must explain redirection');

    const unshadowedRes = invokeGuardHook({ name: 'view_file', args: { AbsolutePath: unshadowedFile } }, testCtx, HOOK_SCRIPT_PATH);
    assert(unshadowedRes.decision === 'deny', 'view_file on unshadowed raw file must be denied');

    const escapeRes = invokeGuardHook({ name: 'view_file', args: { AbsolutePath: escapeFile } }, testCtx, HOOK_SCRIPT_PATH);
    assert(escapeRes.decision === 'deny', 'view_file escaping repo boundary must be denied');
    assert(escapeRes.reason.includes('Path containment violation'), 'Escaping path must trigger containment violation');
    console.log('  ✔ 2.2 DENY_RAW_REPO_READ: Raw repository files and escaping traversals are intercepted fail-closed.\n');

    // -------------------------------------------------------------------------
    // Suite 3: DENY_NETWORK_EXFILTRATION Control
    // -------------------------------------------------------------------------
    console.log('Suite 3: Outbound Network Confinement (DENY_NETWORK_EXFILTRATION)');

    // 3.1 Network Tools Blocked
    const searchRes = invokeGuardHook({ name: 'search_web', args: { query: 'exploit' } }, testCtx, HOOK_SCRIPT_PATH);
    assert(searchRes.decision === 'deny', 'search_web must be denied');
    assert(searchRes.reason.includes('NETWORK_CONFINEMENT_ENFORCEMENT'), 'Denial reason must cite network confinement');

    const readUrlRes = invokeGuardHook({ name: 'read_url_content', args: { Url: 'http://attacker.com' } }, testCtx, HOOK_SCRIPT_PATH);
    assert(readUrlRes.decision === 'deny', 'read_url_content must be denied');

    const mcpRes = invokeGuardHook({ name: 'call_mcp_tool', args: { ServerName: 'cloudrun' } }, testCtx, HOOK_SCRIPT_PATH);
    assert(mcpRes.decision === 'deny', 'call_mcp_tool must be denied');
    console.log('  ✔ 3.1 Network tools (search_web, read_url_content, call_mcp_tool) blocked fail-closed.');

    // 3.2 Shell Network Egress Binaries Blocked
    const curlRes = invokeGuardHook({ name: 'run_command', args: { CommandLine: 'curl -s https://evil.com' } }, testCtx, HOOK_SCRIPT_PATH);
    assert(curlRes.decision === 'deny', 'curl command must be denied');
    assert(curlRes.reason.includes('prohibited outbound network egress via \'curl\''), 'curl denial must cite binary');

    const wgetRes = invokeGuardHook({ name: 'run_command', args: { CommandLine: 'wget http://leak.site' } }, testCtx, HOOK_SCRIPT_PATH);
    assert(wgetRes.decision === 'deny', 'wget command must be denied');

    const iwrRes = invokeGuardHook({ name: 'run_command', args: { CommandLine: 'Invoke-WebRequest -Uri http://sink.com' } }, testCtx, HOOK_SCRIPT_PATH);
    assert(iwrRes.decision === 'deny', 'Invoke-WebRequest must be denied');

    // Safe command must be allowed
    const safeCmdRes = invokeGuardHook({ name: 'run_command', args: { CommandLine: 'git status' } }, testCtx, HOOK_SCRIPT_PATH);
    assert(safeCmdRes.decision === 'allow', 'safe local command (git status) must be allowed');
    console.log('  ✔ 3.2 Outbound shell network egress binaries intercepted while permitting safe local commands.\n');

    // -------------------------------------------------------------------------
    // Suite 4: DENY_ARBITRARY_FS_WRITE Control
    // -------------------------------------------------------------------------
    console.log('Suite 4: Filesystem Mutation Confinement (DENY_ARBITRARY_FS_WRITE)');

    // 4.1 Raw Repository Code Writes Blocked
    const writeRawRes = invokeGuardHook({ name: 'write_to_file', args: { TargetFile: rawFile, CodeContent: 'tamper' } }, testCtx, HOOK_SCRIPT_PATH);
    assert(writeRawRes.decision === 'deny', 'write_to_file on raw repo file must be denied');
    assert(writeRawRes.reason.includes('FILESYSTEM_CONFINEMENT_ENFORCEMENT'), 'Write denial must cite filesystem confinement');

    const replaceRawRes = invokeGuardHook({ name: 'replace_file_content', args: { TargetFile: rawFile, ReplacementContent: 'tamper' } }, testCtx, HOOK_SCRIPT_PATH);
    assert(replaceRawRes.decision === 'deny', 'replace_file_content on raw repo file must be denied');

    // 4.2 CI/CD Manifest Writes Blocked
    const writeCiRes = invokeGuardHook({ name: 'write_to_file', args: { TargetFile: githubFile, CodeContent: 'tamper' } }, testCtx, HOOK_SCRIPT_PATH);
    assert(writeCiRes.decision === 'deny', 'write_to_file on CI/CD manifest must be denied');

    // 4.3 Sandbox / Scratch Writes Permitted
    const writeScratchRes = invokeGuardHook({ name: 'write_to_file', args: { TargetFile: scratchFile, CodeContent: 'diff' } }, testCtx, HOOK_SCRIPT_PATH);
    assert(writeScratchRes.decision === 'allow', 'write_to_file inside scratch must be allowed');
    console.log('  ✔ 4.1 Raw repo writes and CI/CD modifications blocked; scratch mutations permitted.\n');

    // -------------------------------------------------------------------------
    // Suite 5: DENY_SUBAGENT_RECURSION Control
    // -------------------------------------------------------------------------
    console.log('Suite 5: Subagent Recursion Confinement (DENY_SUBAGENT_RECURSION)');

    // 5.1 Subagents (depth >= 1) cannot spawn further subagents
    const recurseRes = invokeGuardHook(
      { name: 'invoke_subagent', args: { Subagents: [{ TypeName: 'research', Role: 'Nested', Prompt: 'p' }] } },
      { ...testCtx, agentRole: 'discovery-agent', subagentDepth: 1, isSubagent: true },
      HOOK_SCRIPT_PATH
    );
    assert(recurseRes.decision === 'deny', 'Subagent calling invoke_subagent must be denied');
    assert(recurseRes.reason.includes('SUBAGENT_CONFINEMENT_ENFORCEMENT'), 'Denial must cite subagent confinement');

    // 5.2 Coordinator exceeding quorum quota (> 5) is rejected
    const batchExceedRes = invokeGuardHook(
      {
        name: 'invoke_subagent',
        args: {
          Subagents: Array.from({ length: 6 }, (_, i) => ({ TypeName: 'self', Role: `Agent ${i}`, Prompt: 'p' }))
        }
      },
      { ...testCtx, agentRole: 'coordinator', subagentDepth: 0 },
      HOOK_SCRIPT_PATH
    );
    assert(batchExceedRes.decision === 'deny', 'Coordinator batch > 5 must be denied');

    // 5.3 Coordinator within quorum quota (<= 5) is permitted
    const coordOkRes = invokeGuardHook(
      {
        name: 'invoke_subagent',
        args: {
          Subagents: [
            { TypeName: 'discovery-agent', Role: 'Discovery', Prompt: 'p' },
            { TypeName: 'verifier-reachability', Role: 'Verifier', Prompt: 'p' }
          ]
        }
      },
      { ...testCtx, agentRole: 'coordinator', subagentDepth: 0 },
      HOOK_SCRIPT_PATH
    );
    assert(coordOkRes.decision === 'allow', 'Coordinator within quorum quota must be allowed');
    console.log('  ✔ 5.1 Subagent recursion (depth >= 1) and batch quota overflow blocked; coordinator quorum allowed.\n');

  } finally {
    try {
      fs.rmSync(tempWs, { recursive: true, force: true });
    } catch {}
  }

  // ---------------------------------------------------------------------------
  // Suite 6: Full Confinement Matrix Runner & Uncompressed Report
  // ---------------------------------------------------------------------------
  console.log('Suite 6: Full Confinement Matrix Runner & Uncompressed Reporting');

  const matrixRes = evaluateConfinementMatrix({ repoRoot: REPO_ROOT, hookPath: HOOK_SCRIPT_PATH });
  assert(matrixRes.overallStatus === 'ALL_CONTROLS_PASSED', 'Overall matrix status must be ALL_CONTROLS_PASSED');
  assert(matrixRes.controls.length === 5, `Expected exactly 5 controls in matrix, got ${matrixRes.controls.length}`);

  for (const c of matrixRes.controls) {
    assert(c.status === 'PASS', `Control ${c.controlId} must be PASS`);
    assert(c.verdict === c.type, `Control ${c.controlId} verdict must equal type ${c.type}`);
  }

  const report = renderConfinementReport(matrixRes);
  assert(report.includes('Dual-Control Runtime Confinement Matrix Report'), 'Report missing title');
  assert(report.includes('ALLOW_SHADOW_READ'), 'Report missing ALLOW_SHADOW_READ');
  assert(report.includes('DENY_RAW_REPO_READ'), 'Report missing DENY_RAW_REPO_READ');
  assert(report.includes('DENY_NETWORK_EXFILTRATION'), 'Report missing DENY_NETWORK_EXFILTRATION');
  assert(report.includes('DENY_ARBITRARY_FS_WRITE'), 'Report missing DENY_ARBITRARY_FS_WRITE');
  assert(report.includes('DENY_SUBAGENT_RECURSION'), 'Report missing DENY_SUBAGENT_RECURSION');
  assert(report.includes('CONFINEMENT BARRIER ASSURANCE: PASSED'), 'Report missing assurance pass badge');
  console.log('  ✔ 6.1 Dual-control matrix harness evaluates all 5 controls independently with uncompressed report.\n');

  console.log('================================================================');
  console.log('All Milestone G6 Runtime Confinement Matrix tests passed successfully.');
  console.log('================================================================');
}

runSuite();
