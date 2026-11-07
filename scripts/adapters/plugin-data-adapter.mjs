#!/usr/bin/env node
/**
 * scripts/adapters/plugin-data-adapter.mjs
 * Milestone 5.4 Phase 2 (RFC 0005 Workstream 3):
 * Dual-Anchor Persistent Storage and Revocation Governance Adapter.
 *
 * Requirements:
 * 1. Dual-Anchor Architecture:
 *    - Primary Anchor (Isolated State): $PLUGIN_DATA directory (cross-workspace, persistent).
 *    - Secondary Anchor (Root of Trust): Embedded static root registry and cryptographic anchors.
 * 2. Zero Workspace Pollution:
 *    - Strictly prevents writing or mutating trust artifacts inside the target repository or cwd.
 * 3. Fail-Closed Tamper-Evident Revocation Journal:
 *    - Append-only hash-chained journal (.irv-revocation-journal.jsonl) with Ed25519 support.
 * 4. Cross-Platform Path Normalization:
 *    - Handles Windows drive letters, POSIX paths, atomic rename, and directory containment.
 *
 * Zero external npm dependencies.
 */

import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import crypto from 'node:crypto';

export const ADAPTER_NAME = 'PLUGIN_DATA_DUAL_ANCHOR_ADAPTER';
export const ADAPTER_VERSION = '1.0.0';

export const REVOCATION_TYPES = Object.freeze({
  KEY_REVOCATION: 'KEY_REVOCATION',
  NONCE_REVOCATION: 'NONCE_REVOCATION',
  BALLOT_DISPUTE: 'BALLOT_DISPUTE',
  EMERGENCY_FREEZE: 'EMERGENCY_FREEZE'
});

export const DEFAULT_SUPERVISOR_KEY_ID = 'IRV-SUPERVISOR-ROOT-ED25519-v1-a2a222ec7ca28466';
export const DEFAULT_SUPERVISOR_PUBLIC_PEM =
  '-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAugD3MpoZoJb47Y2U8IRqzlyhjulIdNp+vKgfkn5tIzU=\n-----END PUBLIC KEY-----\n';
export const DEFAULT_SUPERVISOR_FINGERPRINT =
  'a2a222ec7ca284666f70554925dc8596b96e163cbc881cafdec9e0f7dabbb678';

export const EMBEDDED_ROOT_REGISTRY = Object.freeze({
  schemaVersion: '1.0.0',
  registryVersion: 1,
  authority: 'IRV_SUPERVISOR_ROOT_AUTHORITY',
  activeKeyId: DEFAULT_SUPERVISOR_KEY_ID,
  activeKeyFingerprint: DEFAULT_SUPERVISOR_FINGERPRINT,
  activePublicKeyPem: DEFAULT_SUPERVISOR_PUBLIC_PEM,
  keyType: 'ed25519',
  pinnedSince: '2026-10-16T06:55:39.565Z',
  rotationPolicy: 'SINGLE_ACTIVE_PINNED_ROOT',
  revokedKeyIds: [],
  keys: [
    {
      keyId: DEFAULT_SUPERVISOR_KEY_ID,
      keyFingerprint: DEFAULT_SUPERVISOR_FINGERPRINT,
      publicKeyPem: DEFAULT_SUPERVISOR_PUBLIC_PEM,
      status: 'ACTIVE_PINNED_ROOT',
      issuedAt: '2026-10-16T06:55:39.565Z'
    }
  ]
});

/**
 * Normalizes a path string to POSIX forward slashes while preserving drive letters.
 */
export function normalizePath(p) {
  if (typeof p !== 'string' || !p.trim()) return '';
  return p.replace(/\\/g, '/');
}

/**
 * Computes deterministic SHA-256 hex digest of string or buffer.
 */
export function sha256Digest(data) {
  return crypto.createHash('sha256').update(data).digest('hex');
}

/**
 * Deterministic JSON serialization for canonical hashing.
 */
export function canonicalJsonStringify(obj) {
  if (obj === null || typeof obj !== 'object') {
    return JSON.stringify(obj);
  }
  if (Array.isArray(obj)) {
    return '[' + obj.map(canonicalJsonStringify).join(',') + ']';
  }
  const keys = Object.keys(obj).sort();
  const pairs = keys.map(k => JSON.stringify(k) + ':' + canonicalJsonStringify(obj[k]));
  return '{' + pairs.join(',') + '}';
}

/**
 * Resolves the persistent plugin data directory location.
 *
 * Priority:
 * 1. options.pluginDataDir
 * 2. process.env.PLUGIN_DATA
 * 3. process.env.AGY_PLUGIN_DATA
 * 4. Fallback ~/.gemini/antigravity-cli/plugin_data/security-audit
 *
 * Invariant: Unless explicitly overridden with allowInWorkspace: true,
 * the resolved directory MUST NOT reside inside repoRoot or process.cwd().
 *
 * @param {object} [options={}]
 * @returns {string} Normalized absolute path to plugin data directory
 */
export function resolvePluginDataDir(options = {}) {
  let targetDir = options.pluginDataDir || process.env.PLUGIN_DATA || process.env.AGY_PLUGIN_DATA;

  if (!targetDir || typeof targetDir !== 'string' || !targetDir.trim()) {
    const homeDir = os.homedir();
    targetDir = path.join(homeDir, '.gemini', 'antigravity-cli', 'plugin_data', 'security-audit');
  }

  // Path safety: fail-closed on null bytes
  if (targetDir.includes('\0')) {
    throw new Error('Illegal null byte detected in plugin data path');
  }

  const resolved = path.resolve(targetDir);
  const normalized = normalizePath(resolved);

  // Zero Workspace Pollution Invariant Check
  if (options.allowInWorkspace !== true) {
    const repoRoot = path.resolve(options.repoRoot || process.cwd());
    const normalizedRepo = normalizePath(repoRoot);

    if (normalized === normalizedRepo || normalized.startsWith(normalizedRepo + '/')) {
      throw new Error(
        `[ZERO_WORKSPACE_POLLUTION_VIOLATION] PLUGIN_DATA (${normalized}) must not reside inside target workspace (${normalizedRepo})`
      );
    }
  }

  if (options.ensureDir !== false) {
    if (!fs.existsSync(resolved)) {
      fs.mkdirSync(resolved, { recursive: true });
    }
  }

  return normalized;
}

/**
 * Returns path to supervisor-trust-registry.json in PLUGIN_DATA.
 */
export function getTrustRegistryPath(options = {}) {
  const dir = resolvePluginDataDir(options);
  return normalizePath(path.join(dir, 'supervisor-trust-registry.json'));
}

/**
 * Returns path to .irv-revocation-journal.jsonl in PLUGIN_DATA.
 */
export function getRevocationJournalPath(options = {}) {
  const dir = resolvePluginDataDir(options);
  return normalizePath(path.join(dir, '.irv-revocation-journal.jsonl'));
}

/**
 * Validates the schema and cryptographic integrity of a trust registry object.
 *
 * @param {object} registry
 * @param {object} [options={}]
 * @returns {{ valid: boolean, error: string|null }}
 */
export function validateTrustRegistry(registry, options = {}) {
  if (!registry || typeof registry !== 'object') {
    return { valid: false, error: 'Registry must be a non-null object' };
  }

  if (typeof registry.schemaVersion !== 'string' || !registry.schemaVersion) {
    return { valid: false, error: 'Missing or invalid schemaVersion' };
  }

  if (!Number.isInteger(registry.registryVersion) || registry.registryVersion < 1) {
    return { valid: false, error: 'registryVersion must be an integer >= 1' };
  }

  if (options.minRegistryVersion && registry.registryVersion < options.minRegistryVersion) {
    return {
      valid: false,
      error: `Monotonic regression: registryVersion (${registry.registryVersion}) < min required (${options.minRegistryVersion})`
    };
  }

  if (typeof registry.activeKeyId !== 'string' || !registry.activeKeyId) {
    return { valid: false, error: 'Missing or invalid activeKeyId' };
  }

  if (typeof registry.activePublicKeyPem !== 'string' || !registry.activePublicKeyPem.includes('BEGIN PUBLIC KEY')) {
    return { valid: false, error: 'Missing or malformed activePublicKeyPem' };
  }

  const computedFp = sha256Digest(registry.activePublicKeyPem);
  if (computedFp !== registry.activeKeyFingerprint) {
    return {
      valid: false,
      error: `Fingerprint mismatch: expected ${registry.activeKeyFingerprint}, computed ${computedFp}`
    };
  }

  if (!Array.isArray(registry.keys) || registry.keys.length === 0) {
    return { valid: false, error: 'keys array must be non-empty' };
  }

  if (!Array.isArray(registry.revokedKeyIds)) {
    return { valid: false, error: 'revokedKeyIds must be an array' };
  }

  return { valid: true, error: null };
}

/**
 * Loads trust registry, adhering to dual-anchor resolution.
 * Primary: Reads from PLUGIN_DATA.
 * Secondary: Falls back to embedded static root registry.
 *
 * @param {object} [options={}]
 * @returns {{ source: 'PLUGIN_DATA'|'EMBEDDED_FALLBACK', registry: object, valid: boolean }}
 */
export function loadTrustRegistry(options = {}) {
  const regPath = getTrustRegistryPath(options);

  if (fs.existsSync(regPath)) {
    try {
      const raw = fs.readFileSync(regPath, 'utf8');
      const parsed = JSON.parse(raw);
      const validation = validateTrustRegistry(parsed, options);

      if (!validation.valid) {
        if (options.failClosed !== false) {
          throw new Error(`Corrupt trust registry at ${regPath}: ${validation.error}`);
        }
        return { source: 'PLUGIN_DATA', registry: null, valid: false, error: validation.error };
      }

      return { source: 'PLUGIN_DATA', registry: parsed, valid: true, path: regPath };
    } catch (err) {
      if (options.failClosed !== false) {
        throw new Error(`Failed to read trust registry from ${regPath}: ${err.message}`);
      }
      return { source: 'PLUGIN_DATA', registry: null, valid: false, error: err.message };
    }
  }

  // Fallback to secondary embedded anchor
  const fallback = JSON.parse(JSON.stringify(EMBEDDED_ROOT_REGISTRY));

  if (options.autoInitialize === true) {
    saveTrustRegistry(fallback, options);
    return { source: 'PLUGIN_DATA', registry: fallback, valid: true, path: regPath, initialized: true };
  }

  return { source: 'EMBEDDED_FALLBACK', registry: fallback, valid: true, path: null };
}

/**
 * Atomically writes a trust registry to PLUGIN_DATA.
 *
 * @param {object} registry
 * @param {object} [options={}]
 * @returns {{ success: boolean, path: string, registryVersion: number }}
 */
export function saveTrustRegistry(registry, options = {}) {
  const validation = validateTrustRegistry(registry, options);
  if (!validation.valid) {
    throw new Error(`Cannot save invalid trust registry: ${validation.error}`);
  }

  const regPath = getTrustRegistryPath(options);
  const dir = path.dirname(regPath);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });

  const tmpPath = path.join(dir, `.tmp.reg.${process.pid}.${Date.now()}.${crypto.randomBytes(4).toString('hex')}`);
  const serialized = JSON.stringify(registry, null, 2) + '\n';

  fs.writeFileSync(tmpPath, serialized, 'utf8');
  fs.renameSync(tmpPath, regPath);

  return {
    success: true,
    path: normalizePath(regPath),
    registryVersion: registry.registryVersion
  };
}

/**
 * Loads and validates the hash-chained revocation journal from PLUGIN_DATA.
 *
 * @param {object} [options={}]
 * @returns {{ valid: boolean, entries: Array<object>, error: string|null, count: number }}
 */
export function loadRevocationJournal(options = {}) {
  const journalPath = getRevocationJournalPath(options);

  if (!fs.existsSync(journalPath)) {
    return { valid: true, entries: [], error: null, count: 0, path: journalPath };
  }

  try {
    const content = fs.readFileSync(journalPath, 'utf8');
    const lines = content.split(/\r?\n/).filter(line => line.trim().length > 0);
    const entries = [];
    let expectedPrevDigest = '0'.repeat(64);

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      let parsed;
      try {
        parsed = JSON.parse(line);
      } catch (e) {
        const msg = `Malformed JSON in journal at line ${i + 1}`;
        if (options.failClosed !== false) throw new Error(msg);
        return { valid: false, entries: [], error: msg, count: i };
      }

      if (parsed.entryIndex !== i) {
        const msg = `Index mismatch at line ${i + 1}: expected ${i}, found ${parsed.entryIndex}`;
        if (options.failClosed !== false) throw new Error(msg);
        return { valid: false, entries: [], error: msg, count: i };
      }

      if (parsed.prevEntryDigest !== expectedPrevDigest) {
        const msg = `Tamper detected at line ${i + 1}: broken hash chain (expected ${expectedPrevDigest}, found ${parsed.prevEntryDigest})`;
        if (options.failClosed !== false) throw new Error(msg);
        return { valid: false, entries: [], error: msg, count: i };
      }

      if (!parsed.targetId || typeof parsed.targetId !== 'string') {
        const msg = `Missing targetId at line ${i + 1}`;
        if (options.failClosed !== false) throw new Error(msg);
        return { valid: false, entries: [], error: msg, count: i };
      }

      entries.push(parsed);
      // Compute hash of this entry for chaining
      expectedPrevDigest = sha256Digest(canonicalJsonStringify(parsed));
    }

    return { valid: true, entries, error: null, count: entries.length, path: journalPath };
  } catch (err) {
    if (options.failClosed !== false) {
      throw new Error(`Failed to load revocation journal: ${err.message}`);
    }
    return { valid: false, entries: [], error: err.message, count: 0 };
  }
}

/**
 * Appends an entry to the revocation journal with hash chaining and optional Ed25519 signature.
 *
 * @param {object} entryInput
 * @param {string} entryInput.revocationType
 * @param {string} entryInput.targetId
 * @param {string} [entryInput.reason='MANUAL_REVOCATION']
 * @param {object} [options={}]
 * @returns {{ success: boolean, entryIndex: number, entryDigest: string, path: string }}
 */
export function appendRevocationEntry(entryInput, options = {}) {
  if (!entryInput || typeof entryInput !== 'object') {
    throw new Error('entryInput must be an object');
  }

  if (!entryInput.revocationType || !REVOCATION_TYPES[entryInput.revocationType]) {
    throw new Error(`Invalid revocationType: ${entryInput.revocationType}`);
  }

  if (!entryInput.targetId || typeof entryInput.targetId !== 'string') {
    throw new Error('targetId must be a non-empty string');
  }

  const journal = loadRevocationJournal({ ...options, failClosed: true });
  const entryIndex = journal.entries.length;

  let prevEntryDigest = '0'.repeat(64);
  if (entryIndex > 0) {
    prevEntryDigest = sha256Digest(canonicalJsonStringify(journal.entries[entryIndex - 1]));
  }

  const record = {
    entryIndex,
    timestamp: options.timestamp || new Date().toISOString(),
    revocationType: entryInput.revocationType,
    targetId: entryInput.targetId,
    reason: entryInput.reason || 'MANUAL_REVOCATION',
    prevEntryDigest
  };

  // Optional cryptographic signature
  if (options.signerPrivateKey) {
    const signPayload = Buffer.from(`${record.targetId}:${record.entryIndex}:${record.prevEntryDigest}`, 'utf8');
    record.signature = crypto.sign(null, signPayload, options.signerPrivateKey).toString('hex');
    record.signedBy = options.signerKeyId || DEFAULT_SUPERVISOR_KEY_ID;
  }

  const journalPath = getRevocationJournalPath(options);
  const dir = path.dirname(journalPath);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });

  const line = JSON.stringify(record) + '\n';
  fs.appendFileSync(journalPath, line, 'utf8');

  const entryDigest = sha256Digest(canonicalJsonStringify(record));

  return {
    success: true,
    entryIndex,
    entryDigest,
    path: normalizePath(journalPath)
  };
}

/**
 * Checks whether an ID (keyId, nonce, or ballot fingerprint) has been revoked.
 *
 * @param {string} targetId
 * @param {object} [options={}]
 * @returns {{ revoked: boolean, reason: string|null, entry: object|null }}
 */
export function isRevoked(targetId, options = {}) {
  if (!targetId || typeof targetId !== 'string') {
    return { revoked: false, reason: null, entry: null };
  }

  // 1. Check Trust Registry revokedKeyIds
  const regLoad = loadTrustRegistry(options);
  if (regLoad.valid && regLoad.registry && Array.isArray(regLoad.registry.revokedKeyIds)) {
    if (regLoad.registry.revokedKeyIds.includes(targetId)) {
      return {
        revoked: true,
        reason: 'REVOKED_IN_TRUST_REGISTRY',
        entry: null
      };
    }
  }

  // 2. Check Revocation Journal
  let journalLoad;
  try {
    journalLoad = loadRevocationJournal({ ...options, failClosed: false });
  } catch (err) {
    journalLoad = { valid: false, error: err.message };
  }

  if (!journalLoad.valid) {
    // Fail-closed: corrupted journal treats query as revoked/untrusted
    return {
      revoked: true,
      reason: 'JOURNAL_CORRUPTED_FAIL_CLOSED',
      entry: null
    };
  }

  for (const entry of journalLoad.entries) {
    if (entry.targetId === targetId) {
      return {
        revoked: true,
        reason: entry.reason || entry.revocationType,
        entry
      };
    }
  }

  return {
    revoked: false,
    reason: null,
    entry: null
  };
}
