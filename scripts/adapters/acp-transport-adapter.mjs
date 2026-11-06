#!/usr/bin/env node
/**
 * scripts/adapters/acp-transport-adapter.mjs
 * Milestone 5.4 Phase 1 (M54-P1-F04 / R13-F04-01):
 * Native Agent Client Protocol (ACP) Transport Prioritization and Governance Adapter.
 *
 * Requirements:
 * 1. Prioritize Native ACP: Selects native `agy acp --stdio` (Antigravity ACP Server 1.5.1)
 *    as HIGHEST priority over custom bridge layers and legacy fallback.
 * 2. Fail-Closed Handshake Governance: Validates JSON-RPC 2.0 initialize handshake
 *    including protocolVersion, server identity, and required agent capabilities.
 * 3. Safe Fallback & Confinement: On handshake failure or timeout, safely terminates fail-closed
 *    or transitions to hermetic fallback only if explicitly authorized.
 *
 * Zero external npm dependencies.
 */

import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';

export const ACP_PROTOCOL_VERSION = 1;
export const ACP_PROTOCOL_NAME = 'ACP_STDIO_JSONRPC_V1';

export const TRANSPORT_PRIORITIES = Object.freeze({
  NATIVE_ACP: 1,       // Highest priority
  ISOLATED_STDIO: 2,   // Secondary fallback
  NONE: 99             // Fail-closed / Disabled
});

/**
 * Validates an ACP JSON-RPC 2.0 handshake initialization response.
 *
 * @param {object|string} rawResponse - Handshake response payload
 * @returns {{ valid: boolean, capabilities: object|null, error: string|null }}
 */
export function validateAcpHandshake(rawResponse) {
  if (!rawResponse) {
    return { valid: false, capabilities: null, error: 'Empty ACP handshake response' };
  }

  let parsed = rawResponse;
  if (typeof rawResponse === 'string') {
    try {
      parsed = JSON.parse(rawResponse.trim());
    } catch (err) {
      return { valid: false, capabilities: null, error: `Malformed JSON-RPC handshake: ${err.message}` };
    }
  }

  if (typeof parsed !== 'object' || parsed === null) {
    return { valid: false, capabilities: null, error: 'Invalid JSON-RPC payload: expected object' };
  }

  if (parsed.jsonrpc !== '2.0') {
    return { valid: false, capabilities: null, error: `Unsupported JSON-RPC version: ${parsed.jsonrpc}` };
  }

  if (parsed.error) {
    const errMsg = typeof parsed.error === 'string' ? parsed.error : (parsed.error.message || JSON.stringify(parsed.error));
    return { valid: false, capabilities: null, error: `Server returned JSON-RPC error: ${errMsg}` };
  }

  const result = parsed.result;
  if (!result || typeof result !== 'object') {
    return { valid: false, capabilities: null, error: 'Missing result object in initialize response' };
  }

  if (result.protocolVersion !== ACP_PROTOCOL_VERSION) {
    return {
      valid: false,
      capabilities: null,
      error: `Protocol version mismatch: expected ${ACP_PROTOCOL_VERSION}, got ${result.protocolVersion}`
    };
  }

  const caps = result.agentCapabilities;
  if (!caps || typeof caps !== 'object') {
    return { valid: false, capabilities: null, error: 'Missing agentCapabilities in initialize result' };
  }

  // Verify core native capabilities (session management and prompt capabilities)
  const hasPromptCaps = Boolean(caps.promptCapabilities && typeof caps.promptCapabilities === 'object');
  const hasSessionCaps = Boolean(caps.sessionCapabilities || caps.session_capabilities);
  if (!hasPromptCaps || !hasSessionCaps) {
    return { valid: false, capabilities: null, error: 'Incomplete native ACP capabilities profile' };
  }

  return {
    valid: true,
    capabilities: caps,
    agentInfo: result.agentInfo || null,
    authMethods: result.authMethods || [],
    error: null
  };
}

/**
 * Resolves the active execution transport following the Native ACP Prioritization policy.
 *
 * @param {object} [options={}]
 * @param {boolean} [options.enableNativeAcp=true] - Whether native ACP is enabled
 * @param {object|string} [options.probeResponse=null] - Pre-probed handshake response
 * @param {boolean} [options.allowFallback=false] - Whether fallback to isolated stdio is permitted on failure
 * @returns {{ transport: string, priority: number, protocol: string, status: string, error: string|null }}
 */
export function resolveTransport(options = {}) {
  const {
    enableNativeAcp = true,
    probeResponse = null,
    allowFallback = false
  } = options;

  // 1. Highest Priority: Native ACP
  if (enableNativeAcp) {
    if (probeResponse) {
      const validation = validateAcpHandshake(probeResponse);
      if (validation.valid) {
        return {
          transport: 'NATIVE_ACP',
          priority: TRANSPORT_PRIORITIES.NATIVE_ACP,
          protocol: ACP_PROTOCOL_NAME,
          status: 'ACTIVE',
          agentInfo: validation.agentInfo,
          capabilities: validation.capabilities,
          error: null
        };
      }

      // Handshake failed under Default-Deny
      if (!allowFallback) {
        return {
          transport: 'NONE',
          priority: TRANSPORT_PRIORITIES.NONE,
          protocol: 'UNKNOWN',
          status: 'FAILED',
          error: `Native ACP handshake failed: ${validation.error} (Fail-Closed)`
        };
      }

      // Fallback permitted
      return {
        transport: 'ISOLATED_STDIO',
        priority: TRANSPORT_PRIORITIES.ISOLATED_STDIO,
        protocol: 'HERMETIC_STDIO_V1',
        status: 'FALLBACK',
        fallbackReason: validation.error,
        error: null
      };
    }

    // Native ACP enabled but no probe response available -> requires probe
    if (!allowFallback) {
      return {
        transport: 'NONE',
        priority: TRANSPORT_PRIORITIES.NONE,
        protocol: 'UNKNOWN',
        status: 'FAILED',
        error: 'Native ACP enabled but unverified; handshake probe required (Fail-Closed)'
      };
    }
  }

  // 2. Secondary Fallback: Isolated Stdio
  if (allowFallback) {
    return {
      transport: 'ISOLATED_STDIO',
      priority: TRANSPORT_PRIORITIES.ISOLATED_STDIO,
      protocol: 'HERMETIC_STDIO_V1',
      status: 'ACTIVE',
      error: null
    };
  }

  // Fail-Closed
  return {
    transport: 'NONE',
    priority: TRANSPORT_PRIORITIES.NONE,
    protocol: 'UNKNOWN',
    status: 'FAILED',
    error: 'No compliant transport available (Fail-Closed)'
  };
}
