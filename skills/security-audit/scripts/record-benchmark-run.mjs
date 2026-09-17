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

  const modelId = overrides.modelId || process.env.AGY_MODEL || 'UNKNOWN';
  const modelProvider = overrides.modelProvider || process.env.AGY_MODEL_PROVIDER || 'UNKNOWN';
  const modelTaxonomy = overrides.modelTaxonomy || normalizeModelTaxonomy(modelId, { modelProvider, ...overrides });

  const baseModel = overrides.baseModel || modelTaxonomy.baseModel;
  const reasoningProfile = overrides.reasoningProfile !== undefined ? overrides.reasoningProfile : modelTaxonomy.reasoningProfile;
  const identitySource = overrides.identitySource || modelTaxonomy.identitySource;

  return {
    agyVersion: agyVersion || 'UNKNOWN',
    modelId,
    modelProvider,
    baseModel,
    reasoningProfile,
    identitySource,
    modelTaxonomy,
    os: `${process.platform} (${process.arch})`,
    nodeVersion: process.version,
    skillRevision: toolProv.toolRevision,
    toolVersion: toolProv.toolVersion || TOOL_VERSION,
    toolRevision: toolProv.toolRevision,
    toolIntegrityDigest: toolProv.toolIntegrityDigest,
    toolDirty: toolProv.toolDirty
  };
}

export const VALID_IDENTITY_SOURCES = Object.freeze([
  'RUNTIME_ATTESTED',
  'CONFIG_DECLARED',
  'PARSED_INFERRED',
  'UNKNOWN'
]);

export const VALID_TAXONOMY_TIERS = Object.freeze([
  'REASONING_PROFILE_ABLATION',
  'INTRA_PROVIDER_MODEL_REPLICATION',
  'CROSS_PROVIDER_MODEL_REPLICATION',
  'CROSS_SYSTEM_REPLICATION',
  'IDENTITY_CONTROL'
]);

/**
 * Normalizes raw model ID and environment parameters into an attested model taxonomy record.
 * Supports attested identity precedence under Default-Deny.
 *
 * @param {string} rawModelId - Raw model identifier (e.g. 'gemini-3.8-flash-high')
 * @param {object} [overrides={}] - Attested identity or configuration overrides
 * @returns {object} Full taxonomy record conforming to protocol specification
 */
export function normalizeModelTaxonomy(rawModelId, overrides = {}) {
  const raw = (typeof rawModelId === 'string' && rawModelId.trim()) ? rawModelId.trim() : (overrides.rawModelId || 'UNKNOWN');

  // Determine identity source
  let identitySource = overrides.identitySource || null;
  if (!identitySource || !VALID_IDENTITY_SOURCES.includes(identitySource)) {
    if (raw === 'UNKNOWN') {
      identitySource = 'UNKNOWN';
    } else if (overrides.modelProvider && overrides.baseModel && overrides.reasoningProfile !== undefined) {
      identitySource = 'CONFIG_DECLARED';
    } else {
      identitySource = 'PARSED_INFERRED';
    }
  }

  // Determine identity confidence
  let identityConfidence = overrides.identityConfidence || null;
  if (!identityConfidence) {
    if (identitySource === 'RUNTIME_ATTESTED' || identitySource === 'CONFIG_DECLARED') {
      identityConfidence = 'HIGH';
    } else if (identitySource === 'PARSED_INFERRED') {
      identityConfidence = 'MEDIUM';
    } else {
      identityConfidence = 'NONE';
    }
  }

  // Heuristic parser for rawModelId when fields are not explicitly provided
  let parsedProvider = 'unknown';
  let parsedBaseModel = raw;
  let parsedFamily = 'unknown';
  let parsedProfile = 'standard';

  const lowerRaw = raw.toLowerCase();

  // 1. Provider & Family inference
  if (lowerRaw.includes('gemini')) {
    parsedProvider = 'google';
    parsedFamily = lowerRaw.includes('pro') ? 'gemini-pro' : 'gemini-flash';
  } else if (lowerRaw.includes('claude')) {
    parsedProvider = 'anthropic';
    if (lowerRaw.includes('opus')) parsedFamily = 'claude-opus';
    else if (lowerRaw.includes('haiku')) parsedFamily = 'claude-haiku';
    else parsedFamily = 'claude-sonnet';
  } else if (lowerRaw.includes('gpt') || lowerRaw.startsWith('o1') || lowerRaw.startsWith('o3')) {
    parsedProvider = 'openai';
    parsedFamily = (lowerRaw.startsWith('o1') || lowerRaw.startsWith('o3')) ? 'o-series' : 'gpt-4';
  }

  // 2. Reasoning profile inference (e.g. -high, -medium, -low, -thinking)
  const profileMatch = raw.match(/[-_](high|medium|low|none|thinking|default)$/i);
  if (profileMatch) {
    parsedProfile = profileMatch[1].toLowerCase();
    parsedBaseModel = raw.slice(0, profileMatch.index);
  } else {
    parsedBaseModel = raw;
  }

  const baseModel = overrides.baseModel || parsedBaseModel;
  const canonicalModelId = overrides.canonicalModelId || baseModel;
  const modelFamily = overrides.modelFamily || parsedFamily;
  const modelProvider = overrides.modelProvider || parsedProvider;
  const reasoningProfile = overrides.reasoningProfile || parsedProfile;
  const runtimeId = overrides.runtimeId || 'agy';
  const runtimeAdapter = overrides.runtimeAdapter || 'native';

  return {
    rawModelId: raw,
    canonicalModelId,
    baseModel,
    modelFamily,
    modelProvider,
    reasoningProfile,
    runtimeId,
    runtimeAdapter,
    identitySource,
    identityConfidence
  };
}

/**
 * Validates whether model independence claims for Class B/C (Tiers 2, 3, 4)
 * meet the Default-Deny attested identity threshold.
 *
 * @param {object} taxonomyA - Attested taxonomy for configuration A
 * @param {object} taxonomyB - Attested taxonomy for configuration B
 * @param {string|number} claimedTier - Claimed tier name or number
 * @returns {{ valid: boolean, error: string|null }}
 */
export function validateIndependenceAuthority(taxonomyA, taxonomyB, claimedTier) {
  const isTier1 = claimedTier === 'REASONING_PROFILE_ABLATION' || claimedTier === 1;
  const isTier2 = claimedTier === 'INTRA_PROVIDER_MODEL_REPLICATION' || claimedTier === 2;
  const isTier3 = claimedTier === 'CROSS_PROVIDER_MODEL_REPLICATION' || claimedTier === 3;
  const isTier4 = claimedTier === 'CROSS_SYSTEM_REPLICATION' || claimedTier === 4;

  if (isTier1 || isTier2 || isTier3 || isTier4) {
    const validSources = new Set(['RUNTIME_ATTESTED', 'CONFIG_DECLARED']);
    if (!validSources.has(taxonomyA?.identitySource) || !validSources.has(taxonomyB?.identitySource)) {
      return {
        valid: false,
        error: `Default-Deny Authority Violation: Tier '${claimedTier}' independence claim requires RUNTIME_ATTESTED or CONFIG_DECLARED identitySource (got A: '${taxonomyA?.identitySource}', B: '${taxonomyB?.identitySource}')`
      };
    }
  }

  return { valid: true, error: null };
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

  if (envelope.provenanceScope !== undefined) {
    if (!envelope.provenanceScope || typeof envelope.provenanceScope !== 'object' || Array.isArray(envelope.provenanceScope)) {
      errors.push('provenanceScope must be a non-null object');
    } else {
      const ps = envelope.provenanceScope;
      if (ps.appliesToVersion !== undefined && typeof ps.appliesToVersion !== 'string') {
        errors.push('provenanceScope.appliesToVersion must be a string');
      }
      if (ps.sourceRevision !== undefined && typeof ps.sourceRevision !== 'string' && ps.sourceRevision !== null) {
        errors.push('provenanceScope.sourceRevision must be a string or null');
      }
      if (ps.isHistoricalBaseline !== undefined && typeof ps.isHistoricalBaseline !== 'boolean') {
        errors.push('provenanceScope.isHistoricalBaseline must be a boolean');
      }
      if (ps.runtimeCapabilities !== undefined && (!Array.isArray(ps.runtimeCapabilities) || !ps.runtimeCapabilities.every(c => typeof c === 'string'))) {
        errors.push('provenanceScope.runtimeCapabilities must be an array of strings');
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

  if (options.provenanceScope !== undefined) {
    envelope.provenanceScope = options.provenanceScope;
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

// -----------------------------------------------------------------------------
// AGY Agent Contract Conformance & Native Frontmatter Validation
// -----------------------------------------------------------------------------

export const AGY_COMMAND_EXECUTION_POLICIES = Object.freeze(['off', 'auto', 'eager', 'sandbox']);

export const EXPECTED_COORDINATOR_FILE = 'security-audit-coordinator.md';
export const EXPECTED_COORDINATOR_NAME = 'security-audit-coordinator';
export const EXPECTED_SUBAGENT_FILES = Object.freeze([
  'discovery-agent.md',
  'threat-modeler.md',
  'verifier-reachability.md',
  'verifier-defenses.md',
  'verifier-impact.md'
]);
export const EXPECTED_SUBAGENT_NAMES = Object.freeze(
  EXPECTED_SUBAGENT_FILES.map(f => f.replace(/\.md$/, ''))
);
export const ALL_EXPECTED_AGENT_FILES = Object.freeze([
  EXPECTED_COORDINATOR_FILE,
  ...EXPECTED_SUBAGENT_FILES
].sort());

/**
 * Strips inline YAML comment while preserving '#' within quotes.
 */
function stripInlineComment(val) {
  let inQuote = null;
  for (let i = 0; i < val.length; i++) {
    const ch = val[i];
    if ((ch === '"' || ch === "'") && (i === 0 || val[i - 1] !== '\\')) {
      if (inQuote === ch) inQuote = null;
      else if (!inQuote) inQuote = ch;
    } else if (ch === '#' && !inQuote) {
      return val.slice(0, i).trim();
    }
  }
  return val.trim();
}

/**
 * Parses YAML frontmatter from an agent markdown file.
 * Returns parsed object or null if frontmatter is absent or malformed.
 */
export function parseAgentFrontmatter(content) {
  if (typeof content !== 'string') return null;
  const sanitized = content.replace(/^\uFEFF/, '');
  const match = sanitized.match(/^---\r?\n([\s\S]*?)\r?\n---/);
  if (!match) return null;
  const yamlText = match[1];
  const lines = yamlText.split(/\r?\n/);
  const result = {};
  const seenKeys = new Set();
  let currentKey = null;
  let pendingEmptyKey = null;

  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;

    // List item match: supports 0 or more leading spaces before '-'
    const listMatch = line.match(/^\s*-\s+(.*)$/);
    if (listMatch && currentKey) {
      pendingEmptyKey = null;
      if (!Array.isArray(result[currentKey])) {
        result[currentKey] = [];
      }
      let rawVal = stripInlineComment(listMatch[1]);
      if ((rawVal.startsWith('"') && rawVal.endsWith('"')) || (rawVal.startsWith("'") && rawVal.endsWith("'"))) {
        rawVal = rawVal.slice(1, -1);
      }
      result[currentKey].push(rawVal);
      continue;
    }

    const kvMatch = line.match(/^([a-zA-Z0-9_-]+):\s*(.*)$/);
    if (kvMatch) {
      const key = kvMatch[1];
      if (seenKeys.has(key)) {
        // Fail-closed on duplicate mapping keys to prevent config smuggling
        return null;
      }
      seenKeys.add(key);

      if (pendingEmptyKey && pendingEmptyKey !== key) {
        if (pendingEmptyKey !== 'tools' && Array.isArray(result[pendingEmptyKey]) && result[pendingEmptyKey].length === 0) {
          result[pendingEmptyKey] = '';
        }
        pendingEmptyKey = null;
      }

      currentKey = key;
      let rawVal = stripInlineComment(kvMatch[2]);

      // Flow sequence support: e.g. [view_file, list_dir]
      if (rawVal.startsWith('[') && rawVal.endsWith(']')) {
        const inner = rawVal.slice(1, -1).trim();
        if (!inner) {
          result[key] = [];
        } else {
          result[key] = inner.split(',').map(item => {
            let s = item.trim();
            if ((s.startsWith('"') && s.endsWith('"')) || (s.startsWith("'") && s.endsWith("'"))) {
              s = s.slice(1, -1);
            }
            return s;
          }).filter(Boolean);
        }
      } else if (rawVal === '') {
        pendingEmptyKey = key;
        result[key] = [];
      } else if (rawVal === 'true') {
        result[key] = true;
      } else if (rawVal === 'false') {
        result[key] = false;
      } else if (!isNaN(Number(rawVal)) && rawVal !== '') {
        result[key] = Number(rawVal);
      } else {
        let s = rawVal;
        if ((s.startsWith('"') && s.endsWith('"')) || (s.startsWith("'") && s.endsWith("'"))) {
          s = s.slice(1, -1);
        }
        result[key] = s;
      }
    }
  }

  if (pendingEmptyKey && pendingEmptyKey !== 'tools' && Array.isArray(result[pendingEmptyKey]) && result[pendingEmptyKey].length === 0) {
    result[pendingEmptyKey] = '';
  }

  return result;
}

/**
 * Validates a single agent contract against AGY agent specifications.
 */
export function validateAgentContract(agent, filename = '') {
  const errors = [];
  if (!agent || typeof agent !== 'object' || Array.isArray(agent)) {
    return { valid: false, errors: ['Agent contract must be a non-null object'] };
  }

  if (typeof agent.name !== 'string' || !agent.name.trim()) {
    errors.push('Missing or empty agent name');
  }

  if (!AGY_COMMAND_EXECUTION_POLICIES.includes(agent.commandExecutionPolicy)) {
    errors.push(`Invalid commandExecutionPolicy: '${agent.commandExecutionPolicy}'. Expected one of ${AGY_COMMAND_EXECUTION_POLICIES.join(', ')}`);
  }

  if (typeof agent.mainAgent !== 'boolean') {
    errors.push('agent.mainAgent must be a boolean');
  }
  if (typeof agent.subagent !== 'boolean') {
    errors.push('agent.subagent must be a boolean');
  }

  if (agent.mainAgent === agent.subagent) {
    errors.push('agent.mainAgent and agent.subagent cannot have the same boolean value');
  }

  const baseFilename = filename ? path.basename(filename) : '';
  const isCoordinator = agent.name === EXPECTED_COORDINATOR_NAME ||
    baseFilename === EXPECTED_COORDINATOR_FILE ||
    agent.mainAgent === true;

  if (isCoordinator) {
    if (agent.name !== EXPECTED_COORDINATOR_NAME) {
      errors.push(`Coordinator agent name must be '${EXPECTED_COORDINATOR_NAME}', got '${agent.name}'`);
    }
    if (baseFilename && baseFilename !== EXPECTED_COORDINATOR_FILE) {
      errors.push(`Coordinator agent file must be named '${EXPECTED_COORDINATOR_FILE}', got '${baseFilename}'`);
    }
    if (agent.mainAgent !== true || agent.subagent !== false) {
      errors.push('Coordinator agent must declare mainAgent: true and subagent: false');
    }
    if (agent.commandExecutionPolicy !== 'sandbox') {
      errors.push(`Coordinator agent must declare commandExecutionPolicy: 'sandbox', got '${agent.commandExecutionPolicy}'`);
    }
    const requiredCoordinatorTools = ['invoke_subagent', 'send_message', 'manage_subagents', 'view_file', 'list_dir', 'run_command'];
    if (!Array.isArray(agent.tools)) {
      errors.push('Coordinator agent must declare tools array');
    } else {
      for (const t of requiredCoordinatorTools) {
        if (!agent.tools.includes(t)) {
          errors.push(`Coordinator agent tools missing required tool: '${t}'`);
        }
      }
    }
  } else {
    // Subagent assertions under Default-Deny
    if (agent.mainAgent !== false || agent.subagent !== true) {
      errors.push(`Subagent '${agent.name || filename}' must declare mainAgent: false and subagent: true`);
    }
    if (agent.commandExecutionPolicy !== 'off') {
      errors.push(`Subagent '${agent.name || filename}' must declare commandExecutionPolicy: 'off' (Default-Deny)`);
    }
    if (!EXPECTED_SUBAGENT_NAMES.includes(agent.name)) {
      errors.push(`Unrecognized or unauthorized subagent name: '${agent.name}'`);
    }
    if (baseFilename) {
      if (!baseFilename.endsWith('.md')) {
        errors.push(`Subagent file must have .md extension, got '${baseFilename}'`);
      } else {
        const expectedFile = `${agent.name}.md`;
        if (baseFilename !== expectedFile) {
          errors.push(`Subagent file '${baseFilename}' does not match agent name '${agent.name}'`);
        }
      }
    }
    if (!Array.isArray(agent.tools)) {
      errors.push(`Subagent '${agent.name || filename}' must declare tools array`);
    } else {
      const allowedSubagentTools = new Set(['view_file', 'list_dir', 'grep_search', 'find_by_name']);
      for (const t of agent.tools) {
        if (!allowedSubagentTools.has(t)) {
          errors.push(`Subagent '${agent.name || filename}' allows prohibited tool: '${t}' (must be strictly read-only)`);
        }
        if (t === 'run_command' || t.startsWith('run_command') || t.includes('command') || t.includes('exec')) {
          errors.push(`Subagent '${agent.name || filename}' violates Default-Deny: command execution tool '${t}' prohibited`);
        }
        if (t === 'write_to_file' || t === 'replace_file_content' || t.includes('write') || t.includes('replace')) {
          errors.push(`Subagent '${agent.name || filename}' violates Default-Deny: write tool '${t}' prohibited`);
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
 * Validates all agent contracts within the agents directory.
 */
export function validateAllAgentContracts(agentsDir) {
  const errors = [];
  if (!fs.existsSync(agentsDir)) {
    return { valid: false, errors: [`Agents directory does not exist: ${agentsDir}`] };
  }
  const files = fs.readdirSync(agentsDir).filter(f => f.endsWith('.md')).sort();
  if (files.length === 0) {
    return { valid: false, errors: ['No agent definition files found'] };
  }

  // Completeness check: all expected agent files must be present
  for (const expected of ALL_EXPECTED_AGENT_FILES) {
    if (!files.includes(expected)) {
      errors.push(`Missing mandatory agent definition file: ${expected}`);
    }
  }

  // Authorization check: no unexpected / extraneous agent files allowed in agents/
  for (const f of files) {
    if (!ALL_EXPECTED_AGENT_FILES.includes(f)) {
      errors.push(`Unauthorized or unexpected agent definition file in agents/: ${f}`);
    }
  }

  let mainAgentCount = 0;
  let mainAgentName = null;
  const verifiedAgents = [];

  for (const f of files) {
    const filePath = path.join(agentsDir, f);
    const content = fs.readFileSync(filePath, 'utf8');
    const parsed = parseAgentFrontmatter(content);
    if (!parsed) {
      errors.push(`Failed to parse frontmatter in agent file: ${f}`);
      continue;
    }

    const singleRes = validateAgentContract(parsed, f);
    if (!singleRes.valid) {
      for (const err of singleRes.errors) {
        errors.push(`[${f}] ${err}`);
      }
    }

    if (parsed.mainAgent === true) {
      mainAgentCount++;
      mainAgentName = parsed.name || f;
    }
    verifiedAgents.push({ file: f, name: parsed.name, policy: parsed.commandExecutionPolicy });
  }

  if (mainAgentCount !== 1) {
    errors.push(`Expected exactly ONE agent with mainAgent: true, found ${mainAgentCount}`);
  }
  if (mainAgentName !== EXPECTED_COORDINATOR_NAME) {
    errors.push(`Expected mainAgent to be '${EXPECTED_COORDINATOR_NAME}', found '${mainAgentName}'`);
  }

  return {
    valid: errors.length === 0,
    errors,
    verifiedAgents
  };
}

