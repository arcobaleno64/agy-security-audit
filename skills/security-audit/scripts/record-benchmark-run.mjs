#!/usr/bin/env node
/**
 * record-benchmark-run.mjs
 * Recorded Empirical Benchmark Protocol Envelope Recorder (v1.1.0 P1).
 * Serializes agent execution passes into standardized benchmark run envelopes
 * conforming to schemas/empirical-benchmark-run.schema.json.
 */

import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { getHardenedGitProvenance } from './safe-git.mjs';
import { TOOL_VERSION, verifyToolSelfIntegrity, getToolProvenance } from './finalize-scan.mjs';

/**
 * Probes the runtime environment to extract authoritative provenance.
 */
export function probeEnvironment(repoRoot = process.cwd(), overrides = {}) {
  let agyVersion = overrides.agyVersion || process.env.AGY_VERSION || null;
  if (!agyVersion) {
    try {
      const out = execFileSync('agy', ['--version'], {
        encoding: 'utf8',
        timeout: 4000,
        stdio: ['pipe', 'pipe', 'ignore']
      }).trim();
      if (out) agyVersion = out;
    } catch {
      agyVersion = 'UNKNOWN';
    }
  }

  // Authoritative tool provenance from the security-audit tool root
  const defaultToolRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
  const toolProv = getToolProvenance(defaultToolRoot);

  return {
    agyVersion: agyVersion || 'UNKNOWN',
    modelId: overrides.modelId || process.env.AGY_MODEL || 'UNKNOWN',
    modelProvider: overrides.modelProvider || process.env.AGY_MODEL_PROVIDER || 'UNKNOWN',
    os: `${process.platform} (${process.arch})`,
    nodeVersion: process.version,
    skillRevision: toolProv.toolRevision,
    toolVersion: toolProv.toolVersion || TOOL_VERSION,
    toolRevision: toolProv.toolRevision,
    toolIntegrityDigest: toolProv.toolIntegrityDigest,
    toolDirty: toolProv.toolDirty
  };
}

/**
 * Parses and validates Antigravity CLI stream-json trace (NDJSON format).
 * Extracts raw response, first-party execution telemetry, tool usage,
 * subagent invocations, and token consumption under Default-Deny.
 *
 * @param {string} rawNdjson - Raw newline-delimited JSON stream output
 * @returns {{ success: boolean, telemetry: object|null, rawResponse: string, error: string|null }}
 */
export function parseStreamJsonTrace(rawNdjson) {
  if (typeof rawNdjson !== 'string' || !rawNdjson.trim()) {
    return {
      success: false,
      telemetry: null,
      rawResponse: '',
      error: 'NDJSON trace is empty or invalid'
    };
  }

  const telemetryDigest = crypto.createHash('sha256').update(rawNdjson, 'utf8').digest('hex');
  const lines = rawNdjson.split(/\r?\n/);

  let totalEvents = 0;
  let conversationId = null;
  let permissionMode = null;
  const availableTools = new Set();
  const toolsUsed = new Set();
  const subagentsInvoked = new Set();
  let rawResponse = '';
  let accumulatedText = '';
  let durationSeconds = null;
  let finalStatus = null;
  let hasResultEvent = false;
  let resultError = null;

  let tokenUsage = {
    inputTokens: 0,
    outputTokens: 0,
    thinkingTokens: 0,
    cacheReadTokens: 0,
    totalTokens: 0
  };
  let resultUsage = null;

  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed) continue;

    let eventObj;
    try {
      eventObj = JSON.parse(trimmed);
    } catch {
      continue;
    }

    totalEvents++;

    const evtType = eventObj.event || eventObj.type;

    // Handle init event
    if (evtType === 'init' || eventObj.init) {
      const initObj = eventObj.init || eventObj;
      if (initObj.conversation_id || initObj.conversationId) {
        conversationId = initObj.conversation_id || initObj.conversationId;
      } else if (eventObj.conversation_id || eventObj.conversationId) {
        conversationId = eventObj.conversation_id || eventObj.conversationId;
      }
      if (initObj.permission_mode || initObj.permissionMode) {
        permissionMode = initObj.permission_mode || initObj.permissionMode;
      }
      const tools = initObj.tools || initObj.available_tools || initObj.availableTools || eventObj.tools;
      if (Array.isArray(tools)) {
        for (const t of tools) {
          if (typeof t === 'string' && t.trim()) availableTools.add(t.trim());
        }
      }
    }

    // Handle step_update event
    if (evtType === 'step_update' || eventObj.step_update) {
      const step = eventObj.step_update || eventObj;
      if (!conversationId && (step.conversation_id || step.conversationId)) {
        conversationId = step.conversation_id || step.conversationId;
      }

      // Track text deltas
      if (typeof step.text_delta === 'string') {
        accumulatedText += step.text_delta;
      }

      // Track tool executions
      let toolName = null;
      if (typeof step.tool === 'string') {
        toolName = step.tool;
      } else if (typeof step.tool_name === 'string') {
        toolName = step.tool_name;
      } else if (step.tool_call) {
        toolName = typeof step.tool_call === 'string' ? step.tool_call : (step.tool_call.name || step.tool_call.tool);
      } else if (step.tool_use) {
        toolName = typeof step.tool_use === 'string' ? step.tool_use : (step.tool_use.name || step.tool_use.tool);
      } else if ((step.step_type === 'tool_use' || step.step_type === 'tool_call') && typeof step.tool === 'string') {
        toolName = step.tool;
      } else if ((step.step_type === 'tool_use' || step.step_type === 'tool_call') && typeof step.name === 'string') {
        toolName = step.name;
      }

      if (toolName && typeof toolName === 'string') {
        toolsUsed.add(toolName);
        if (toolName === 'invoke_subagent') {
          let callArgs = step.tool_call?.args ?? step.tool_call?.arguments ??
                         step.tool_use?.args ?? step.tool_use?.arguments ??
                         step.args;
          if (typeof callArgs === 'string') {
            try { callArgs = JSON.parse(callArgs); } catch {}
          }
          const subagentName = callArgs?.agent ||
                               callArgs?.subagent ||
                               callArgs?.name;
          if (subagentName && typeof subagentName === 'string') {
            subagentsInvoked.add(subagentName);
          }
        }
      }

      const directSubagent = step.subagent || step.subagent_invoked || step.subagentName;
      if (directSubagent && typeof directSubagent === 'string') {
        subagentsInvoked.add(directSubagent);
      }

      // Track token usage accumulation from step_update
      const u = step.usage || step.token_usage || eventObj.usage;
      if (u && typeof u === 'object') {
        tokenUsage.inputTokens += (u.input_tokens ?? u.inputTokens ?? 0);
        tokenUsage.outputTokens += (u.output_tokens ?? u.outputTokens ?? 0);
        tokenUsage.thinkingTokens += (u.thinking_tokens ?? u.thinkingTokens ?? 0);
        tokenUsage.cacheReadTokens += (u.cache_read_tokens ?? u.cacheReadTokens ?? 0);
        tokenUsage.totalTokens += (u.total_tokens ?? u.totalTokens ?? 0);
      }
    }

    // Handle result event
    if (evtType === 'result' || eventObj.result) {
      hasResultEvent = true;
      const res = eventObj.result || eventObj;
      if (res.conversation_id || res.conversationId) {
        conversationId = res.conversation_id || res.conversationId;
      }
      if (typeof res.response === 'string') {
        rawResponse = res.response;
      } else if (typeof res.text === 'string') {
        rawResponse = res.text;
      }
      if (typeof res.duration_seconds === 'number') {
        durationSeconds = res.duration_seconds;
      } else if (typeof res.durationSeconds === 'number') {
        durationSeconds = res.durationSeconds;
      }
      if (res.status) {
        finalStatus = res.status;
      }
      if (res.error) {
        resultError = typeof res.error === 'string' ? res.error : JSON.stringify(res.error);
      } else if (eventObj.error) {
        resultError = typeof eventObj.error === 'string' ? eventObj.error : JSON.stringify(eventObj.error);
      }
      const u = res.usage || eventObj.usage;
      if (u && typeof u === 'object') {
        resultUsage = {
          inputTokens: (u.input_tokens ?? u.inputTokens ?? 0),
          outputTokens: (u.output_tokens ?? u.outputTokens ?? 0),
          thinkingTokens: (u.thinking_tokens ?? u.thinkingTokens ?? 0),
          cacheReadTokens: (u.cache_read_tokens ?? u.cacheReadTokens ?? 0),
          totalTokens: (u.total_tokens ?? u.totalTokens ?? 0)
        };
      }
    }
  }

  if (totalEvents === 0) {
    return {
      success: false,
      telemetry: null,
      rawResponse: '',
      error: 'No valid JSON events found in trace'
    };
  }

  // Fallback to accumulated text if no result.response was provided
  if (!rawResponse && accumulatedText) {
    rawResponse = accumulatedText;
  }

  // If tokenUsage was not populated by step_update events, but resultUsage exists, use resultUsage
  if (tokenUsage.totalTokens === 0 && tokenUsage.inputTokens === 0 && tokenUsage.outputTokens === 0 && resultUsage) {
    tokenUsage = resultUsage;
  }

  // Reconcile totalTokens if 0 but components exist
  if (tokenUsage.totalTokens === 0 && (tokenUsage.inputTokens > 0 || tokenUsage.outputTokens > 0)) {
    tokenUsage.totalTokens = tokenUsage.inputTokens + tokenUsage.outputTokens + tokenUsage.thinkingTokens + tokenUsage.cacheReadTokens;
  }

  const telemetry = {
    format: 'AGY_STREAM_JSON_V1',
    conversationId: conversationId || null,
    telemetryDigest,
    totalEvents,
    availableTools: Array.from(availableTools),
    toolsUsed: Array.from(toolsUsed),
    subagentsInvoked: Array.from(subagentsInvoked),
    permissionMode: permissionMode || null,
    tokenUsage,
    durationSeconds: durationSeconds !== null ? durationSeconds : null
  };

  // Fail-Closed Validation under Default-Deny:
  if (resultError) {
    return {
      success: false,
      telemetry,
      rawResponse,
      error: `Stream execution error: ${resultError}`
    };
  }

  if (finalStatus && finalStatus !== 'SUCCESS' && finalStatus !== 'COMPLETED') {
    return {
      success: false,
      telemetry,
      rawResponse,
      error: `Stream result status indicates failure: ${finalStatus}`
    };
  }

  if (!hasResultEvent && !rawResponse.trim()) {
    return {
      success: false,
      telemetry,
      rawResponse,
      error: 'NDJSON stream terminated prematurely without result event or response text'
    };
  }

  return {
    success: true,
    telemetry,
    rawResponse,
    error: null
  };
}

/**
 * Validates an empirical benchmark run envelope against structural rules.
 */
export function validateBenchmarkRunEnvelope(envelope) {
  const errors = [];
  if (!envelope || typeof envelope !== 'object') {
    return { valid: false, errors: ['Envelope must be a non-null object'] };
  }

  if (envelope.schemaVersion !== '1.0.0' && envelope.schemaVersion !== '1') {
    errors.push(`Invalid schemaVersion: expected '1.0.0' or '1', got '${envelope.schemaVersion}'`);
  }
  if (typeof envelope.runId !== 'string' || !envelope.runId) {
    errors.push('Missing or invalid runId string');
  }
  if (typeof envelope.recordedAt !== 'string' || !envelope.recordedAt) {
    errors.push('Missing or invalid recordedAt ISO timestamp');
  }
  const VALID_MODES = ['DISCOVERY', 'AUDIT', 'VALIDATE', 'STABILITY'];
  if (!VALID_MODES.includes(envelope.benchmarkMode)) {
    errors.push(`Invalid benchmarkMode: expected one of ${VALID_MODES.join(', ')}, got '${envelope.benchmarkMode}'`);
  }
  const VALID_EVIDENCE_ORIGINS = ['MODEL_OBSERVED', 'SYNTHETIC', 'IMPORTED'];
  if (!VALID_EVIDENCE_ORIGINS.includes(envelope.evidenceOrigin)) {
    errors.push(`Invalid or missing evidenceOrigin: expected one of ${VALID_EVIDENCE_ORIGINS.join(', ')}, got '${envelope.evidenceOrigin}'`);
  }
  const VALID_EXECUTION_KINDS = ['LIVE_AGENT', 'SIMULATED_HARNESS', 'REPLAY_LOG'];
  if (envelope.executionKind !== undefined && !VALID_EXECUTION_KINDS.includes(envelope.executionKind)) {
    errors.push(`Invalid executionKind: expected one of ${VALID_EXECUTION_KINDS.join(', ')}, got '${envelope.executionKind}'`);
  }
  if (!envelope.target || typeof envelope.target !== 'object') {
    errors.push('Missing target object');
  } else {
    if (typeof envelope.target.repositoryName !== 'string') errors.push('target.repositoryName must be a string');
    if (typeof envelope.target.repositoryUri !== 'string') errors.push('target.repositoryUri must be a string');
    if (typeof envelope.target.commitSha !== 'string') errors.push('target.commitSha must be a string');
  }

  if (!envelope.environment || typeof envelope.environment !== 'object') {
    errors.push('Missing environment object');
  } else {
    if (typeof envelope.environment.agyVersion !== 'string') errors.push('environment.agyVersion must be a string');
    if (typeof envelope.environment.modelId !== 'string') errors.push('environment.modelId must be a string');
    if (typeof envelope.environment.modelProvider !== 'string') errors.push('environment.modelProvider must be a string');
    if (typeof envelope.environment.os !== 'string') errors.push('environment.os must be a string');
    if (typeof envelope.environment.nodeVersion !== 'string') errors.push('environment.nodeVersion must be a string');
  }

  if (!envelope.findings || typeof envelope.findings !== 'object') {
    errors.push('Missing findings object');
  } else {
    if (!Array.isArray(envelope.findings.candidates)) {
      errors.push('findings.candidates must be an array');
    }
  }

  if (!envelope.summary || typeof envelope.summary !== 'object') {
    errors.push('Missing summary object');
  } else {
    if (typeof envelope.summary.candidateCount !== 'number' || envelope.summary.candidateCount < 0) {
      errors.push('summary.candidateCount must be a non-negative number');
    }
  }

  if (envelope.executionTelemetry !== undefined) {
    if (!envelope.executionTelemetry || typeof envelope.executionTelemetry !== 'object') {
      errors.push('executionTelemetry must be a non-null object');
    } else {
      const telem = envelope.executionTelemetry;
      const VALID_FORMATS = ['AGY_STREAM_JSON_V1', 'SIMULATED_MOCK'];
      if (!VALID_FORMATS.includes(telem.format)) {
        errors.push(`Invalid executionTelemetry.format: expected one of ${VALID_FORMATS.join(', ')}, got '${telem.format}'`);
      }
      if (telem.conversationId !== null && typeof telem.conversationId !== 'string') {
        errors.push('executionTelemetry.conversationId must be a string or null');
      }
      if (telem.telemetryDigest !== null && typeof telem.telemetryDigest !== 'string') {
        errors.push('executionTelemetry.telemetryDigest must be a string or null');
      }
      if (typeof telem.totalEvents !== 'number' || telem.totalEvents < 0 || !Number.isInteger(telem.totalEvents)) {
        errors.push('executionTelemetry.totalEvents must be an integer >= 0');
      }
      if (!Array.isArray(telem.availableTools) || !telem.availableTools.every(t => typeof t === 'string')) {
        errors.push('executionTelemetry.availableTools must be an array of strings');
      }
      if (!Array.isArray(telem.toolsUsed) || !telem.toolsUsed.every(t => typeof t === 'string')) {
        errors.push('executionTelemetry.toolsUsed must be an array of strings');
      }
      if (!Array.isArray(telem.subagentsInvoked) || !telem.subagentsInvoked.every(t => typeof t === 'string')) {
        errors.push('executionTelemetry.subagentsInvoked must be an array of strings');
      }
      if (telem.permissionMode !== null && typeof telem.permissionMode !== 'string') {
        errors.push('executionTelemetry.permissionMode must be a string or null');
      }
      if (telem.sandboxEnabled !== undefined && telem.sandboxEnabled !== null && typeof telem.sandboxEnabled !== 'boolean') {
        errors.push('executionTelemetry.sandboxEnabled must be a boolean or null');
      }
      if (!telem.tokenUsage || typeof telem.tokenUsage !== 'object') {
        errors.push('executionTelemetry.tokenUsage must be an object');
      } else {
        const fields = ['inputTokens', 'outputTokens', 'thinkingTokens', 'cacheReadTokens', 'totalTokens'];
        for (const f of fields) {
          if (typeof telem.tokenUsage[f] !== 'number' || telem.tokenUsage[f] < 0 || !Number.isInteger(telem.tokenUsage[f])) {
            errors.push(`executionTelemetry.tokenUsage.${f} must be an integer >= 0`);
          }
        }
      }
      if (telem.durationSeconds !== null && (typeof telem.durationSeconds !== 'number' || Number.isNaN(telem.durationSeconds) || telem.durationSeconds < 0)) {
        errors.push('executionTelemetry.durationSeconds must be a non-negative number or null');
      }
    }
  }

  return {
    valid: errors.length === 0,
    errors
  };
}

/**
 * Validates a role-based permissions profile conforming to schemas/permissions-profile.schema.json
 * and enforces Default-Deny least-privilege security boundaries.
 *
 * @param {object} profile - Parsed permissions profile object
 * @returns {{ valid: boolean, errors: string[] }}
 */
export function validatePermissionsProfile(profile) {
  const errors = [];
  if (!profile || typeof profile !== 'object' || Array.isArray(profile)) {
    return { valid: false, errors: ['Permissions profile must be a non-null object'] };
  }

  if (profile.schemaVersion !== '1' && profile.schemaVersion !== '1.0.0') {
    errors.push(`Invalid or missing schemaVersion: expected '1' or '1.0.0', got '${profile.schemaVersion}'`);
  }

  if (typeof profile.profileName !== 'string' || !profile.profileName.trim()) {
    errors.push('Missing or empty profileName');
  }

  // 1. Validate defenseInDepth specification (4 layers)
  if (!profile.defenseInDepth || typeof profile.defenseInDepth !== 'object') {
    errors.push('Missing defenseInDepth specification object');
  } else {
    const did = profile.defenseInDepth;
    const requiredLayers = [
      'layer1_terminal_sandbox',
      'layer2_permission_engine',
      'layer3_shadow_context_guard',
      'layer4_deterministic_tcb'
    ];
    for (const l of requiredLayers) {
      if (!did[l] || typeof did[l] !== 'object') {
        errors.push(`Missing or invalid defenseInDepth layer: '${l}'`);
      } else {
        if (typeof did[l].boundary !== 'string' || !did[l].boundary.trim()) {
          errors.push(`defenseInDepth.${l}.boundary must be a non-empty string`);
        }
        if (typeof did[l].objective !== 'string' || !did[l].objective.trim()) {
          errors.push(`defenseInDepth.${l}.objective must be a non-empty string`);
        }
      }
    }
    if (did.layer2_permission_engine && (typeof did.layer2_permission_engine.precedence !== 'string' || !did.layer2_permission_engine.precedence.trim())) {
      errors.push('defenseInDepth.layer2_permission_engine.precedence must be a non-empty string');
    }
    if (did.layer3_shadow_context_guard && (typeof did.layer3_shadow_context_guard.hook !== 'string' || !did.layer3_shadow_context_guard.hook.trim())) {
      errors.push('defenseInDepth.layer3_shadow_context_guard.hook must be a non-empty string');
    }
    if (did.layer4_deterministic_tcb && (typeof did.layer4_deterministic_tcb.module !== 'string' || !did.layer4_deterministic_tcb.module.trim())) {
      errors.push('defenseInDepth.layer4_deterministic_tcb.module must be a non-empty string');
    }
  }

  // 2. Validate roles presence and structure
  const REQUIRED_ROLES = ['coordinator', 'discovery', 'verifiers', 'remediation'];
  if (!profile.roles || typeof profile.roles !== 'object') {
    errors.push('Missing roles object');
  } else {
    for (const roleName of REQUIRED_ROLES) {
      const role = profile.roles[roleName];
      if (!role || typeof role !== 'object') {
        errors.push(`Missing required role definition: '${roleName}'`);
        continue;
      }
      if (!Array.isArray(role.allow) || !role.allow.every(item => typeof item === 'string')) {
        errors.push(`role.${roleName}.allow must be an array of strings`);
      }
      if (!Array.isArray(role.ask) || !role.ask.every(item => typeof item === 'string')) {
        errors.push(`role.${roleName}.ask must be an array of strings`);
      }
      if (!Array.isArray(role.deny) || !role.deny.every(item => typeof item === 'string')) {
        errors.push(`role.${roleName}.deny must be an array of strings`);
      }
    }
  }

  // If structural validation failed on roles, return early before checking permissions
  if (errors.length > 0 && (!profile.roles || typeof profile.roles !== 'object')) {
    return { valid: false, errors };
  }

  const roles = profile.roles || {};

  // Helpers to test tool properties
  const isWriteTool = (perm) => perm.startsWith('write_to_file') || perm.startsWith('replace_file_content');
  const isNetworkTool = (perm) => perm === 'read_url_content' || perm === 'search_web' || perm.startsWith('read_url') || perm.startsWith('run_command:curl') || perm.startsWith('run_command:wget') || perm.includes('curl ') || perm.includes('wget ');
  const isCommandTool = (perm) => perm.startsWith('run_command');
  const isSubagentTool = (perm) => perm === 'invoke_subagent' || perm === 'manage_subagents';

  // 3. Default-Deny boundary assertions

  // Discovery Role Assertions
  const disc = roles.discovery;
  if (disc && Array.isArray(disc.allow)) {
    if (disc.allow.some(isWriteTool)) {
      errors.push("Role 'discovery' must NOT allow file write or modify tools (Default-Deny violation)");
    }
    if (disc.allow.some(isNetworkTool)) {
      errors.push("Role 'discovery' must NOT allow network or web search tools (Default-Deny violation)");
    }
    if (disc.allow.some(isCommandTool)) {
      errors.push("Role 'discovery' must NOT allow command execution (Default-Deny violation)");
    }
    if (disc.allow.some(isSubagentTool)) {
      errors.push("Role 'discovery' must NOT allow subagent management or invocation (Default-Deny violation)");
    }
  }

  // Verifiers Role Assertions
  const verifiers = roles.verifiers;
  if (verifiers && Array.isArray(verifiers.allow)) {
    if (verifiers.allow.some(isWriteTool)) {
      errors.push("Role 'verifiers' must NOT allow file write or modify tools (Default-Deny violation)");
    }
    if (verifiers.allow.some(isNetworkTool)) {
      errors.push("Role 'verifiers' must NOT allow network or web search tools (Default-Deny violation)");
    }
    if (verifiers.allow.some(isCommandTool)) {
      errors.push("Role 'verifiers' must NOT allow command execution (Default-Deny violation)");
    }
    if (verifiers.allow.some(isSubagentTool)) {
      errors.push("Role 'verifiers' must NOT allow subagent management or invocation (Default-Deny violation)");
    }
  }

  // Coordinator Role Assertions
  const coord = roles.coordinator;
  if (coord && Array.isArray(coord.allow)) {
    if (coord.allow.some(isNetworkTool)) {
      errors.push("Role 'coordinator' must NOT allow network egress tools (Default-Deny violation)");
    }
    if (coord.allow.some(isWriteTool)) {
      errors.push("Role 'coordinator' must NOT allow direct file modification tools (Default-Deny violation)");
    }
    // Assert coordinator commands are bounded, not arbitrary shell execution
    const arbitraryCommands = coord.allow.filter(perm => perm === 'run_command' || perm === 'run_command:*' || perm === 'run_command:bash *' || perm === 'run_command:sh *' || perm === 'run_command:pwsh *' || perm === 'run_command:cmd *');
    if (arbitraryCommands.length > 0) {
      errors.push("Role 'coordinator' must NOT allow arbitrary unconstrained shell commands (Default-Deny violation)");
    }
  }
  if (coord && Array.isArray(coord.deny)) {
    const coordDenySet = new Set(coord.deny);
    if (!coordDenySet.has('read_url_content') || !coordDenySet.has('search_web')) {
      errors.push("Role 'coordinator' must explicitly deny network access ('read_url_content', 'search_web')");
    }
    if (!coordDenySet.has('write_to_file') || !coordDenySet.has('replace_file_content')) {
      errors.push("Role 'coordinator' must explicitly deny write tools ('write_to_file', 'replace_file_content')");
    }
    if (!coord.deny.some(perm => perm.includes('git push'))) {
      errors.push("Role 'coordinator' must explicitly deny 'git push' commands");
    }
  }

  // Remediation Role Assertions
  const rem = roles.remediation;
  if (rem && Array.isArray(rem.deny)) {
    const deniesGithub = rem.deny.some(perm => perm.includes('.github'));
    const deniesGit = rem.deny.some(perm => perm.includes('.git'));
    const deniesGitPush = rem.deny.some(perm => perm.includes('git push'));
    const deniesNetwork = rem.deny.some(perm => perm === 'read_url_content' || perm === 'search_web' || perm.includes('curl') || perm.includes('wget'));

    if (!deniesGithub) {
      errors.push("Role 'remediation' must explicitly deny CI/CD manifest modification ('.github/*')");
    }
    if (!deniesGit) {
      errors.push("Role 'remediation' must explicitly deny git metadata modification ('.git/*')");
    }
    if (!deniesGitPush) {
      errors.push("Role 'remediation' must explicitly deny remote repository mutation ('git push')");
    }
    if (!deniesNetwork) {
      errors.push("Role 'remediation' must explicitly deny network egress (curl, wget, read_url_content)");
    }
  }
  if (rem && Array.isArray(rem.allow)) {
    if (rem.allow.some(isNetworkTool)) {
      errors.push("Role 'remediation' must NOT allow network egress tools (Default-Deny violation)");
    }
    if (rem.allow.some(perm => perm === 'run_command' || perm === 'run_command:*')) {
      errors.push("Role 'remediation' must NOT allow arbitrary command execution (Default-Deny violation)");
    }
  }

  return {
    valid: errors.length === 0,
    errors
  };
}

const VALID_FINDING_TYPES = new Set(['VULNERABILITY', 'HARDENING', 'INFORMATIONAL']);
const VALID_PROOF_KINDS = new Set([
  'STATIC_TRACE',
  'UNIT_TEST',
  'BENIGN_REPRODUCTION',
  'CONFIG_EVIDENCE',
  'DEPENDENCY_EVIDENCE',
  'EXTERNAL_SCANNER_EVIDENCE',
  'MANUAL_ATTESTATION'
]);
const VALID_SEVERITIES = new Set(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNRATED']);
const ALLOWED_ROOT_PROPERTIES = new Set(['schemaVersion', 'candidates', 'discoveryMetadata']);
const ALLOWED_CANDIDATE_PROPERTIES = new Set([
  'schemaVersion',
  'id',
  'ruleId',
  'title',
  'description',
  'securityProperty',
  'violation',
  'findingType',
  'proofKind',
  'severity',
  'location',
  'symbol',
  'proof',
  'attackPath',
  'evidence',
  'lineageId',
  'lineage',
  'component',
  'family'
]);
const ALLOWED_LOCATION_PROPERTIES = new Set(['uri', 'startLine', 'endLine', 'lineSnippet']);

/**
 * Validates candidate set structured output against candidate-set.schema.json.
 * Zero external dependencies.
 *
 * @param {any} data - Parsed candidate set object to validate.
 * @returns {{ valid: boolean, errors: string[] }}
 */
export function validateCandidateSet(data) {
  const errors = [];
  if (!data || typeof data !== 'object' || Array.isArray(data)) {
    return { valid: false, errors: ['Candidate set must be a non-null object'] };
  }

  for (const key of Object.keys(data)) {
    if (!ALLOWED_ROOT_PROPERTIES.has(key)) {
      errors.push(`Unexpected root property '${key}' (additionalProperties: false)`);
    }
  }

  if (data.schemaVersion !== undefined && data.schemaVersion !== '1' && data.schemaVersion !== '1.0.0') {
    errors.push(`Invalid schemaVersion: expected '1' or '1.0.0', got '${data.schemaVersion}'`);
  }

  if (!Array.isArray(data.candidates)) {
    errors.push('Candidate set missing required candidates array');
    return { valid: false, errors };
  }

  if (data.discoveryMetadata !== undefined && (typeof data.discoveryMetadata !== 'object' || data.discoveryMetadata === null || Array.isArray(data.discoveryMetadata))) {
    errors.push('discoveryMetadata must be an object if specified');
  }

  for (let i = 0; i < data.candidates.length; i++) {
    const cand = data.candidates[i];
    const prefix = `candidates[${i}]`;
    if (!cand || typeof cand !== 'object' || Array.isArray(cand)) {
      errors.push(`${prefix} must be a non-null object`);
      continue;
    }

    for (const key of Object.keys(cand)) {
      if (!ALLOWED_CANDIDATE_PROPERTIES.has(key)) {
        errors.push(`${prefix} has unexpected property '${key}' (additionalProperties: false)`);
      }
    }

    if (typeof cand.id !== 'string' || !cand.id.trim()) {
      errors.push(`${prefix}.id must be a non-empty string`);
    }
    if (typeof cand.ruleId !== 'string' || !cand.ruleId.trim()) {
      errors.push(`${prefix}.ruleId must be a non-empty string`);
    }
    if (typeof cand.title !== 'string' || !cand.title.trim()) {
      errors.push(`${prefix}.title must be a non-empty string`);
    }
    if (typeof cand.securityProperty !== 'string' || !cand.securityProperty.trim()) {
      errors.push(`${prefix}.securityProperty must be a non-empty string`);
    }
    if (!VALID_FINDING_TYPES.has(cand.findingType)) {
      errors.push(`${prefix}.findingType must be one of: ${Array.from(VALID_FINDING_TYPES).join(', ')} (got '${cand.findingType}')`);
    }
    if (!VALID_PROOF_KINDS.has(cand.proofKind)) {
      errors.push(`${prefix}.proofKind must be one of: ${Array.from(VALID_PROOF_KINDS).join(', ')} (got '${cand.proofKind}')`);
    }

    if (cand.severity !== undefined && !VALID_SEVERITIES.has(cand.severity)) {
      errors.push(`${prefix}.severity must be one of: ${Array.from(VALID_SEVERITIES).join(', ')} (got '${cand.severity}')`);
    }

    if (!cand.location || typeof cand.location !== 'object' || Array.isArray(cand.location)) {
      errors.push(`${prefix}.location must be an object`);
    } else {
      for (const locKey of Object.keys(cand.location)) {
        if (!ALLOWED_LOCATION_PROPERTIES.has(locKey)) {
          errors.push(`${prefix}.location has unexpected property '${locKey}' (additionalProperties: false)`);
        }
      }
      if (typeof cand.location.uri !== 'string' || !cand.location.uri.trim()) {
        errors.push(`${prefix}.location.uri must be a non-empty string`);
      }
      if (typeof cand.location.startLine !== 'number' || !Number.isInteger(cand.location.startLine) || cand.location.startLine < 1) {
        errors.push(`${prefix}.location.startLine must be an integer >= 1`);
      }
      if (cand.location.endLine !== undefined) {
        if (typeof cand.location.endLine !== 'number' || !Number.isInteger(cand.location.endLine) || cand.location.endLine < 1) {
          errors.push(`${prefix}.location.endLine must be an integer >= 1`);
        } else if (typeof cand.location.startLine === 'number' && cand.location.endLine < cand.location.startLine) {
          errors.push(`${prefix}.location.endLine (${cand.location.endLine}) cannot be less than startLine (${cand.location.startLine})`);
        }
      }
    }
  }

  return {
    valid: errors.length === 0,
    errors
  };
}

/**
 * Creates a schema-compliant empirical benchmark run envelope.
 */
export function createBenchmarkRunEnvelope(options = {}) {
  const repoRoot = options.repoRoot || process.cwd();
  const gitProv = getHardenedGitProvenance(repoRoot);

  const runId = options.runId || `run-${Date.now()}-${crypto.randomBytes(4).toString('hex')}`;
  const recordedAt = options.recordedAt || new Date().toISOString();
  const benchmarkMode = options.benchmarkMode || 'DISCOVERY';

  const target = {
    repositoryName: options.target?.repositoryName || path.basename(repoRoot) || 'unknown',
    repositoryUri: options.target?.repositoryUri || gitProv.repositoryUri || repoRoot,
    commitSha: options.target?.commitSha || gitProv.revisionId || gitProv.commitSha || 'UNKNOWN',
    corpus: options.target?.corpus || options.corpus || null
  };

  const cleanEnvOverrides = {};
  if (options.environment && typeof options.environment === 'object') {
    for (const [k, v] of Object.entries(options.environment)) {
      if (v !== undefined) cleanEnvOverrides[k] = v;
    }
  }

  const environment = {
    ...probeEnvironment(repoRoot, cleanEnvOverrides),
    ...cleanEnvOverrides
  };

  const candidates = Array.isArray(options.candidates) ? options.candidates : [];
  const verifiedFindings = Array.isArray(options.verifiedFindings)
    ? options.verifiedFindings
    : (Array.isArray(options.findings) ? options.findings : null);

  let verifiedCount = null;
  let deferredCount = null;
  let suppressedCount = null;

  if (verifiedFindings) {
    verifiedCount = verifiedFindings.filter(f => f.disposition === 'CONFIRMED' || f.disposition === 'REPORTABLE').length;
    deferredCount = verifiedFindings.filter(f => f.disposition === 'DEFERRED').length;
    suppressedCount = verifiedFindings.filter(f => f.disposition === 'FALSE_POSITIVE' || f.disposition === 'AFFIRMATIVELY_REFUTED').length;
  }

  const summary = {
    candidateCount: candidates.length,
    verifiedCount,
    deferredCount,
    suppressedCount,
    executionDurationMs: typeof options.executionDurationMs === 'number' ? options.executionDurationMs : null,
    ...(options.summary || {})
  };

  const evidenceOrigin = options.evidenceOrigin || 'MODEL_OBSERVED';
  const executionKind = options.executionKind || (evidenceOrigin === 'SYNTHETIC' ? 'SIMULATED_HARNESS' : 'LIVE_AGENT');

  const envelope = {
    schemaVersion: '1.0.0',
    runId,
    recordedAt,
    benchmarkMode,
    evidenceOrigin,
    executionKind,
    target,
    environment,
    findings: {
      candidates,
      verifiedFindings,
      unresolvedCandidates: options.unresolvedCandidates || null,
      suppressedCandidates: options.suppressedCandidates || null
    },
    summary,
    metadata: options.metadata || {}
  };

  if (options.executionTelemetry !== undefined) {
    envelope.executionTelemetry = options.executionTelemetry;
  }

  const validation = validateBenchmarkRunEnvelope(envelope);
  if (!validation.valid) {
    throw new Error(`Invalid benchmark run envelope: ${validation.errors.join('; ')}`);
  }

  return envelope;
}

// -----------------------------------------------------------------------------
// CLI Dispatch
// -----------------------------------------------------------------------------
const isDirectExecution = process.argv[1] && process.argv[1].endsWith('record-benchmark-run.mjs');
if (isDirectExecution) {
  const args = process.argv.slice(2);
  function getArg(name) {
    const idx = args.indexOf(name);
    return idx !== -1 && idx + 1 < args.length ? args[idx + 1] : null;
  }

  const candPath = getArg('--candidates') || path.resolve('scratch/candidate-findings.json');
  const findingsPath = getArg('--findings') || getArg('--canonical') || path.resolve('scratch/canonical-findings.json');
  const outPath = getArg('--output');
  const outDir = getArg('--output-dir');
  const mode = getArg('--mode') || 'DISCOVERY';
  const model = getArg('--model');
  const provider = getArg('--provider');
  const corpus = getArg('--corpus');
  const originArg = getArg('--evidence-origin') || getArg('--origin');
  const executionKindArg = getArg('--execution-kind');

  let candidates = [];
  if (fs.existsSync(candPath)) {
    try {
      candidates = JSON.parse(fs.readFileSync(candPath, 'utf8'));
    } catch (e) {
      console.error(`Failed to parse candidates at ${candPath}:`, e.message);
      process.exit(1);
    }
  }

  let verifiedFindings = null;
  if (fs.existsSync(findingsPath)) {
    try {
      verifiedFindings = JSON.parse(fs.readFileSync(findingsPath, 'utf8'));
    } catch (e) {
      console.warn(`Could not parse findings at ${findingsPath}:`, e.message);
    }
  }

  const envelope = createBenchmarkRunEnvelope({
    benchmarkMode: mode,
    candidates,
    verifiedFindings,
    corpus,
    evidenceOrigin: originArg || undefined,
    executionKind: executionKindArg || undefined,
    environment: {
      modelId: model || undefined,
      modelProvider: provider || undefined
    }
  });

  const serialized = JSON.stringify(envelope, null, 2);

  if (outPath) {
    fs.mkdirSync(path.dirname(outPath), { recursive: true });
    fs.writeFileSync(outPath, serialized, 'utf8');
    console.log(`✔ Recorded benchmark envelope written to: ${outPath}`);
  } else if (outDir) {
    fs.mkdirSync(outDir, { recursive: true });
    const targetFile = path.join(outDir, `${envelope.runId}.json`);
    fs.writeFileSync(targetFile, serialized, 'utf8');
    console.log(`✔ Recorded benchmark envelope written to: ${targetFile}`);
  } else {
    process.stdout.write(serialized + '\n');
  }
}
