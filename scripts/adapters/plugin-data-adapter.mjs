#!/usr/bin/env node
/**
 * scripts/adapters/plugin-data-adapter.mjs
 * Milestone 5.4 Phase 2 (RFC 0005 Workstream 3 — R01 Hardening):
 * Dual-Anchor Persistent Storage and Root-Authorized Revocation Governance Adapter.
 *
 * Requirements & Invariants:
 * 1. Dual-Anchor Architecture with Root Authorization (F02 Closure):
 *    - Primary Anchor (Isolated State): $PLUGIN_DATA directory.
 *    - Secondary Anchor (Root of Trust): EMBEDDED_ROOT_REGISTRY with Ed25519 root key.
 *    - Mandatory Root Authorization Chain: Registry version updates (> 1) must carry a valid
 *      cryptographic authorizationProof signed by an authorized supervisor key.
 *    - Strict Monotonicity: Versions cannot regress; revokedKeyIds cannot be removed without root authority.
 * 2. Zero Workspace Pollution (F03 Closure):
 *    - Uses fs.realpathSync() to resolve symlinks and Windows junctions.
 *    - Strictly checks that resolved PLUGIN_DATA does not reside inside options.repoRoot, process.cwd(),
 *      or any active workspace directory.
 * 3. Fail-Closed Tamper-Evident Revocation Journal (F01 Closure):
 *    - Append-only hash-chained journal (.irv-revocation-journal.jsonl).
 *    - Mandatory Ed25519 signatures verified on read against trusted keys.
 *    - Root-anchored checkpoint (supervisor-revocation-checkpoint.json) to detect deletion,
 *      truncation, or rollback attacks.
 * 4. Cross-Process Mutual Exclusion (F04 Closure):
 *    - Atomic file locking (withFileLock) for concurrent registry writes and journal appends.
 *
 * Zero external npm dependencies.
 */

import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import crypto from 'node:crypto';

export const ADAPTER_NAME = 'PLUGIN_DATA_DUAL_ANCHOR_ADAPTER';
export const ADAPTER_VERSION = '1.1.0';

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
 * Resolves real physical path resolving symlinks and Windows junctions.
 * Resolves M54-P2-F03: Traverses up to the deepest existing ancestor to neutralize
 * intermediate uncreated symlink directories.
 */
export function toRealNormalizedPath(p) {
  if (typeof p !== 'string' || !p.trim()) return '';
  const abs = path.resolve(p);
  let current = abs;
  const uncreatedSuffix = [];
  while (!fs.existsSync(current)) {
    const parent = path.dirname(current);
    if (parent === current) break;
    uncreatedSuffix.unshift(path.basename(current));
    current = parent;
  }
  try {
    if (fs.existsSync(current)) {
      const realAncestor = fs.realpathSync(current);
      return normalizePath(uncreatedSuffix.length > 0 ? path.join(realAncestor, ...uncreatedSuffix) : realAncestor);
    }
  } catch {}
  return normalizePath(abs);
}

/**
 * Asserts that a target storage file is safe from symlink redirection and hard link aliasing.
 * Resolves R04-B03:
 * 1. Dangling symlink detection: calls lstatSync without guarding on existsSync().
 * 2. Hard link detection: asserts stat.nlink === 1, rejecting multi-link inode sharing.
 * 3. Zero workspace pollution: checks realpath against workspace roots.
 *
 * @param {string} targetPath - Path to target file
 * @param {object} [options={}] - Options containing repoRoot or workspacePaths
 */
export function assertSafeStorageTarget(targetPath, options = {}) {
  const forbiddenRoots = [
    options.repoRoot ? toRealNormalizedPath(options.repoRoot) : null,
    toRealNormalizedPath(process.cwd()),
    process.env.INIT_CWD ? toRealNormalizedPath(process.env.INIT_CWD) : null,
    ...(Array.isArray(options.workspacePaths) ? options.workspacePaths.map(p => toRealNormalizedPath(p)) : [])
  ].filter(Boolean);

  let stat = null;
  try {
    stat = fs.lstatSync(targetPath);
  } catch (err) {
    if (err.code !== 'ENOENT') throw err;
  }

  if (stat) {
    if (stat.isSymbolicLink()) {
      throw new Error(`[SYMLINK_POLLUTION_VIOLATION] Target file (${targetPath}) must not be a symbolic link`);
    }
    if (stat.nlink > 1 && options.allowInWorkspace !== true) {
      throw new Error(
        `[HARDLINK_POLLUTION_VIOLATION] Target file (${targetPath}) has multiple hard links (nlink: ${stat.nlink}), potential workspace inode aliasing`
      );
    }
    if (options.allowInWorkspace !== true) {
      const realFile = toRealNormalizedPath(targetPath).toLowerCase();
      for (const root of forbiddenRoots) {
        const rLower = root.toLowerCase();
        if (realFile === rLower || realFile.startsWith(rLower + '/')) {
          throw new Error(`[ZERO_WORKSPACE_POLLUTION_VIOLATION] Target file realpath (${realFile}) resides inside workspace (${root})`);
        }
      }
    }
  } else {
    // Target file does not exist yet: verify parent directory
    const parentDir = path.dirname(targetPath);
    let parentStat = null;
    try {
      parentStat = fs.lstatSync(parentDir);
    } catch (e) {
      if (e.code !== 'ENOENT') throw e;
    }
    if (parentStat) {
      if (parentStat.isSymbolicLink()) {
        throw new Error(`[SYMLINK_POLLUTION_VIOLATION] Parent directory of target file (${parentDir}) must not be a symbolic link`);
      }
      if (options.allowInWorkspace !== true) {
        const realParent = toRealNormalizedPath(parentDir).toLowerCase();
        for (const root of forbiddenRoots) {
          const rLower = root.toLowerCase();
          if (realParent === rLower || realParent.startsWith(rLower + '/')) {
            throw new Error(`[ZERO_WORKSPACE_POLLUTION_VIOLATION] Target parent directory realpath (${realParent}) resides inside workspace (${root})`);
          }
        }
      }
    }
  }
}

/**
 * Checks whether a process PID is currently alive on the host.
 * Resolves M54-P2-F04.
 */
export function isPidAlive(pid) {
  if (!pid || typeof pid !== 'number' || pid <= 0) return false;
  try {
    process.kill(pid, 0);
    return true;
  } catch (err) {
    return err.code === 'EPERM'; // EPERM means process exists but belongs to another user
  }
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
 * Cross-process file locking primitive using exclusive file creation.
 * Resolves M54-P2-F04: Lock info contains PID and unique lockId; stale lock
 * reclamation strictly verifies PID liveness; lock release verifies lockId ownership.
 *
 * @param {string} targetFile - Path to file needing mutual exclusion
 * @param {Function} fn - Operation to execute while lock is held
 * @param {object} [options={}] - Lock options
 * @returns {any} Result of fn()
 */
export function withFileLock(targetFile, fn, options = {}) {
  const lockFile = `${targetFile}.lock`;
  const timeoutMs = options.lockTimeoutMs || 5000;
  const pollIntervalMs = 15;
  const staleTimeoutMs = options.staleLockTimeoutMs || 30000;
  const start = Date.now();
  const lockId = crypto.randomBytes(8).toString('hex');

  let lockFd = null;
  while (Date.now() - start < timeoutMs) {
    try {
      lockFd = fs.openSync(lockFile, 'wx');
      const info = JSON.stringify({ pid: process.pid, timestamp: Date.now(), lockId });
      fs.writeFileSync(lockFd, info, 'utf8');
      break;
    } catch (err) {
      if (err.code === 'EEXIST') {
        try {
          const stats = fs.statSync(lockFile);
          if (Date.now() - stats.mtimeMs > staleTimeoutMs) {
            let canRecover = true;
            try {
              const content = fs.readFileSync(lockFile, 'utf8');
              const parsed = JSON.parse(content);
              if (parsed.pid && isPidAlive(parsed.pid)) {
                canRecover = false;
              }
            } catch {}
            if (canRecover) {
              fs.unlinkSync(lockFile);
              continue;
            }
          }
        } catch {}
        // Sleep briefly
        const sleepEnd = Date.now() + pollIntervalMs;
        while (Date.now() < sleepEnd) {}
      } else {
        throw err;
      }
    }
  }

  if (lockFd === null) {
    throw new Error(`[LOCK_TIMEOUT] Failed to acquire lock for ${targetFile} within ${timeoutMs}ms`);
  }

  try {
    return fn();
  } finally {
    try {
      fs.closeSync(lockFd);
    } catch {}
    try {
      if (fs.existsSync(lockFile)) {
        const content = fs.readFileSync(lockFile, 'utf8');
        const parsed = JSON.parse(content);
        if (parsed.lockId === lockId) {
          fs.unlinkSync(lockFile);
        }
      }
    } catch {}
  }
}

/**
 * Resolves the persistent plugin data directory location.
 * Resolves M54-P2-F03: Enforces realpath resolution and post-creation validation against symlink/junction bypass.
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

  if (targetDir.includes('\0')) {
    throw new Error('Illegal null byte detected in plugin data path');
  }

  const normalized = toRealNormalizedPath(targetDir);

  // Zero Workspace Pollution Invariant Check (F03: Check both repoRoot and cwd using realpaths)
  if (options.allowInWorkspace !== true) {
    const forbiddenPaths = new Set();

    if (options.repoRoot) {
      forbiddenPaths.add(toRealNormalizedPath(options.repoRoot));
    }
    forbiddenPaths.add(toRealNormalizedPath(process.cwd()));

    if (process.env.INIT_CWD) {
      forbiddenPaths.add(toRealNormalizedPath(process.env.INIT_CWD));
    }

    if (Array.isArray(options.workspacePaths)) {
      for (const ws of options.workspacePaths) {
        if (ws) forbiddenPaths.add(toRealNormalizedPath(ws));
      }
    }

    const normLower = normalized.toLowerCase();
    for (const forbidden of forbiddenPaths) {
      const fLower = forbidden.toLowerCase();
      if (forbidden && (normLower === fLower || normLower.startsWith(fLower + '/'))) {
        throw new Error(
          `[ZERO_WORKSPACE_POLLUTION_VIOLATION] PLUGIN_DATA (${normalized}) must not reside inside target workspace (${forbidden})`
        );
      }
    }
  }

  if (options.ensureDir !== false) {
    if (!fs.existsSync(normalized)) {
      fs.mkdirSync(normalized, { recursive: true });
    }
    // Post-creation physical verification (F03 Closure)
    if (options.allowInWorkspace !== true && fs.existsSync(normalized)) {
      const postReal = normalizePath(fs.realpathSync(normalized)).toLowerCase();
      const checkRoots = [
        options.repoRoot ? toRealNormalizedPath(options.repoRoot) : null,
        toRealNormalizedPath(process.cwd()),
        process.env.INIT_CWD ? toRealNormalizedPath(process.env.INIT_CWD) : null
      ].filter(Boolean);
      for (const root of checkRoots) {
        const rLower = root.toLowerCase();
        if (postReal === rLower || postReal.startsWith(rLower + '/')) {
          throw new Error(
            `[ZERO_WORKSPACE_POLLUTION_VIOLATION] Post-creation check: physical realpath (${postReal}) resides inside target workspace (${root})`
          );
        }
      }
    }
  }

  return normalized;
}

export function getTrustRegistryPath(options = {}) {
  const dir = resolvePluginDataDir(options);
  return normalizePath(path.join(dir, 'supervisor-trust-registry.json'));
}

export function getRevocationJournalPath(options = {}) {
  const dir = resolvePluginDataDir(options);
  return normalizePath(path.join(dir, '.irv-revocation-journal.jsonl'));
}

export function getRevocationCheckpointPath(options = {}) {
  const dir = resolvePluginDataDir(options);
  return normalizePath(path.join(dir, 'supervisor-revocation-checkpoint.json'));
}

/**
 * Computes canonical payload for revocation record signature.
 * Resolves M54-P2-F01: Signs all canonical fields to prevent field tampering.
 */
export function computeRevocationEntrySignPayload(record) {
  return canonicalJsonStringify({
    entryIndex: record.entryIndex,
    timestamp: record.timestamp,
    revocationType: record.revocationType,
    targetId: record.targetId,
    reason: record.reason || 'MANUAL_REVOCATION',
    prevEntryDigest: record.prevEntryDigest,
    signedBy: record.signedBy
  });
}

/**
 * Computes canonical payload for trust registry authorization signature.
 * Resolves M54-P2-F02: Enforces canonical signing over keys array as well as root identity.
 */
export function computeRegistryAuthorizationPayload(registry) {
  const normalizedKeys = Array.isArray(registry.keys)
    ? registry.keys.map(k => ({
        keyId: k.keyId,
        keyFingerprint: k.keyFingerprint,
        publicKeyPem: k.publicKeyPem,
        status: k.status,
        issuedAt: k.issuedAt || ''
      })).sort((a, b) => a.keyId.localeCompare(b.keyId))
    : [];
  return canonicalJsonStringify({
    schemaVersion: registry.schemaVersion,
    registryVersion: registry.registryVersion,
    authority: registry.authority,
    activeKeyId: registry.activeKeyId,
    activeKeyFingerprint: registry.activeKeyFingerprint,
    activePublicKeyPem: registry.activePublicKeyPem,
    keys: normalizedKeys,
    revokedKeyIds: Array.isArray(registry.revokedKeyIds) ? [...registry.revokedKeyIds].sort() : []
  });
}

/**
 * Validates the schema and cryptographic integrity of a trust registry object.
 * Resolves M54-P2-F02: Enforces root authorization chain verification.
 * - Genesis v1: keys array must contain strictly the genesis root anchor (anti-rogue injection).
 * - Version > 1: Signer public key MUST originate from root anchor or an authenticated priorRegistry (no self-signed loop).
 *
 * @param {object} registry
 * @param {object} [options={}]
 * @returns {{ valid: boolean, error: string|null }}
 */
export function validateTrustRegistry(registry, options = {}) {
  let cryptographicValidity = true;
  let monotonicValidity = true;
  let ancestryContinuity = true;

  if (!registry || typeof registry !== 'object') {
    return {
      valid: false,
      error: 'Registry must be a non-null object',
      cryptographicValidity: false,
      monotonicValidity: false,
      ancestryContinuity: false
    };
  }

  if (typeof registry.schemaVersion !== 'string' || !registry.schemaVersion) {
    return {
      valid: false,
      error: 'Missing or invalid schemaVersion',
      cryptographicValidity: false,
      monotonicValidity: false,
      ancestryContinuity: false
    };
  }

  if (!Number.isInteger(registry.registryVersion) || registry.registryVersion < 1) {
    return {
      valid: false,
      error: 'registryVersion must be an integer >= 1',
      cryptographicValidity: false,
      monotonicValidity: false,
      ancestryContinuity: false
    };
  }

  const expectedMinVersion = typeof options.minRegistryVersion === 'number'
    ? options.minRegistryVersion
    : (process.env.THREE_LENS_MIN_REGISTRY_VERSION ? parseInt(process.env.THREE_LENS_MIN_REGISTRY_VERSION, 10) : 1);

  if (registry.registryVersion < expectedMinVersion) {
    monotonicValidity = false;
    return {
      valid: false,
      error: `Monotonic regression: registryVersion (${registry.registryVersion}) < min required (${expectedMinVersion})`,
      cryptographicValidity: true,
      monotonicValidity: false,
      ancestryContinuity: true
    };
  }

  if (typeof registry.activeKeyId !== 'string' || !registry.activeKeyId) {
    return {
      valid: false,
      error: 'Missing or invalid activeKeyId',
      cryptographicValidity: false,
      monotonicValidity: true,
      ancestryContinuity: true
    };
  }

  if (typeof registry.activePublicKeyPem !== 'string' || !registry.activePublicKeyPem.includes('BEGIN PUBLIC KEY')) {
    return {
      valid: false,
      error: 'Missing or malformed activePublicKeyPem',
      cryptographicValidity: false,
      monotonicValidity: true,
      ancestryContinuity: true
    };
  }

  const computedFp = sha256Digest(registry.activePublicKeyPem);
  if (computedFp !== registry.activeKeyFingerprint) {
    return {
      valid: false,
      error: `Fingerprint mismatch: expected ${registry.activeKeyFingerprint}, computed ${computedFp}`,
      cryptographicValidity: false,
      monotonicValidity: true,
      ancestryContinuity: true
    };
  }

  if (!Array.isArray(registry.keys) || registry.keys.length === 0) {
    return {
      valid: false,
      error: 'keys array must be non-empty',
      cryptographicValidity: false,
      monotonicValidity: true,
      ancestryContinuity: true
    };
  }

  if (!Array.isArray(registry.revokedKeyIds)) {
    return {
      valid: false,
      error: 'revokedKeyIds must be an array',
      cryptographicValidity: false,
      monotonicValidity: true,
      ancestryContinuity: true
    };
  }

  // High-water mark validation if present
  if (registry.revocationHighWaterMark !== undefined && registry.revocationHighWaterMark !== null) {
    const hwm = registry.revocationHighWaterMark;
    if (
      typeof hwm !== 'object' ||
      typeof hwm.headIndex !== 'number' ||
      hwm.headIndex < 0 ||
      typeof hwm.headDigest !== 'string' ||
      !/^[0-9a-f]{64}$/i.test(hwm.headDigest)
    ) {
      return {
        valid: false,
        error: 'Malformed revocationHighWaterMark in trust registry',
        cryptographicValidity: false,
        monotonicValidity: true,
        ancestryContinuity: true
      };
    }
  }

  // F02 & R04-B02: Ancestry verification against priorRegistry
  if (options.priorRegistry && typeof options.priorRegistry === 'object') {
    if (typeof options.priorRegistry.registryVersion === 'number') {
      if (registry.registryVersion <= options.priorRegistry.registryVersion) {
        monotonicValidity = false;
        return {
          valid: false,
          error: `[REGISTRY_ROLLBACK_DETECTED] Version ${registry.registryVersion} <= priorRegistry version ${options.priorRegistry.registryVersion}`,
          cryptographicValidity: true,
          monotonicValidity: false,
          ancestryContinuity: false
        };
      }
      if (registry.registryVersion !== options.priorRegistry.registryVersion + 1) {
        ancestryContinuity = false;
        return {
          valid: false,
          error: `[ANCESTRY_CONTINUITY_VIOLATION] Non-consecutive version progression: version ${registry.registryVersion} is not consecutive successor to priorRegistry version ${options.priorRegistry.registryVersion}`,
          cryptographicValidity: true,
          monotonicValidity: true,
          ancestryContinuity: false
        };
      }
    }
  } else if (registry.registryVersion > 1 && options.requirePriorRegistry === true) {
    ancestryContinuity = false;
    return {
      valid: false,
      error: `[ANCESTRY_CONTINUITY_VIOLATION] Registry version ${registry.registryVersion} (> 1) requires verified priorRegistry for unbroken ancestry verification`,
      cryptographicValidity: true,
      monotonicValidity: true,
      ancestryContinuity: false
    };
  }

  // Root Authorization Chain Verification
  const expectedRootId = options.trustedRootKeyId || DEFAULT_SUPERVISOR_KEY_ID;
  const expectedRootFp = options.trustedRootFingerprint || DEFAULT_SUPERVISOR_FINGERPRINT;
  const expectedRootPem = options.trustedRootPublicKeyPem || DEFAULT_SUPERVISOR_PUBLIC_PEM;

  if (registry.registryVersion === 1) {
    if (registry.activeKeyId !== expectedRootId || registry.activeKeyFingerprint !== expectedRootFp) {
      return {
        valid: false,
        error: `Genesis registry (v1) activeKeyId/fingerprint must match embedded root anchor (${expectedRootId})`,
        cryptographicValidity: false,
        monotonicValidity: true,
        ancestryContinuity: true
      };
    }
    if (
      registry.keys.length !== 1 ||
      registry.keys[0].keyId !== expectedRootId ||
      registry.keys[0].keyFingerprint !== expectedRootFp ||
      registry.keys[0].publicKeyPem !== expectedRootPem ||
      registry.keys[0].status !== 'ACTIVE_PINNED_ROOT'
    ) {
      return {
        valid: false,
        error: `Genesis registry (v1) keys array must contain exactly the pinned root key (${expectedRootId}) with status ACTIVE_PINNED_ROOT and matching PEM`,
        cryptographicValidity: false,
        monotonicValidity: true,
        ancestryContinuity: true
      };
    }
  } else {
    // Version > 1 MUST carry a cryptographic authorizationProof signed by an authorized key
    if (!registry.authorizationProof || typeof registry.authorizationProof !== 'object') {
      return {
        valid: false,
        error: `Registry version ${registry.registryVersion} (> 1) requires valid authorizationProof`,
        cryptographicValidity: false,
        monotonicValidity: true,
        ancestryContinuity: ancestryContinuity
      };
    }

    const proof = registry.authorizationProof;
    if (!proof.authorizedBy || !proof.signature) {
      return {
        valid: false,
        error: 'authorizationProof missing authorizedBy or signature',
        cryptographicValidity: false,
        monotonicValidity: true,
        ancestryContinuity: ancestryContinuity
      };
    }

    let signerPem = null;
    if (proof.authorizedBy === expectedRootId) {
      signerPem = expectedRootPem;
    } else if (options.priorRegistry && typeof options.priorRegistry === 'object' && Array.isArray(options.priorRegistry.keys)) {
      const priorValidation = validateTrustRegistry(options.priorRegistry, {
        ...options,
        priorRegistry: null,
        minRegistryVersion: 1
      });
      if (!priorValidation.valid) {
        return {
          valid: false,
          error: `Unauthenticated priorRegistry rejected: ${priorValidation.error}`,
          cryptographicValidity: false,
          monotonicValidity: priorValidation.monotonicValidity,
          ancestryContinuity: false
        };
      }
      const priorKey = options.priorRegistry.keys.find(
        k => k.keyId === proof.authorizedBy && (k.status === 'ACTIVE_PINNED_ROOT' || k.status === 'ACTIVE')
      );
      if (priorKey) {
        signerPem = priorKey.publicKeyPem;
      }
    }

    if (!signerPem) {
      return {
        valid: false,
        error: `Signer key '${proof.authorizedBy}' for authorizationProof not found in trusted authority root or authenticated prior registry`,
        cryptographicValidity: false,
        monotonicValidity: true,
        ancestryContinuity: ancestryContinuity
      };
    }

    const payload = Buffer.from(computeRegistryAuthorizationPayload(registry), 'utf8');
    const isValid = crypto.verify(null, payload, signerPem, Buffer.from(proof.signature, 'hex'));
    if (!isValid) {
      return {
        valid: false,
        error: 'Cryptographic verification of authorizationProof failed',
        cryptographicValidity: false,
        monotonicValidity: true,
        ancestryContinuity: ancestryContinuity
      };
    }
  }

  return {
    valid: cryptographicValidity && monotonicValidity && ancestryContinuity,
    error: null,
    cryptographicValidity,
    monotonicValidity,
    ancestryContinuity
  };
}

/**
 * Creates an authorized registry update carrying a cryptographic authorizationProof.
 *
 * @param {object} currentRegistry
 * @param {object} updates
 * @param {string} signerKeyId
 * @param {KeyObject|string} signerPrivateKey
 * @returns {object} Updated registry with authorizationProof
 */
export function createAuthorizedRegistryUpdate(currentRegistry, updates, signerKeyId, signerPrivateKey) {
  const updated = {
    ...currentRegistry,
    ...updates,
    registryVersion: (currentRegistry.registryVersion || 1) + 1
  };
  const payload = Buffer.from(computeRegistryAuthorizationPayload(updated), 'utf8');
  const signature = crypto.sign(null, payload, signerPrivateKey).toString('hex');
  updated.authorizationProof = {
    authorizedBy: signerKeyId,
    signature,
    timestamp: new Date().toISOString()
  };
  return updated;
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
        return {
          source: 'PLUGIN_DATA',
          registry: null,
          valid: false,
          error: validation.error,
          cryptographicValidity: validation.cryptographicValidity,
          monotonicValidity: validation.monotonicValidity,
          ancestryContinuity: validation.ancestryContinuity
        };
      }

      return {
        source: 'PLUGIN_DATA',
        registry: parsed,
        valid: true,
        path: regPath,
        cryptographicValidity: validation.cryptographicValidity,
        monotonicValidity: validation.monotonicValidity,
        ancestryContinuity: validation.ancestryContinuity
      };
    } catch (err) {
      if (options.failClosed !== false) {
        throw new Error(`Failed to read trust registry from ${regPath}: ${err.message}`);
      }
      return {
        source: 'PLUGIN_DATA',
        registry: null,
        valid: false,
        error: err.message,
        cryptographicValidity: false,
        monotonicValidity: false,
        ancestryContinuity: false
      };
    }
  }

  // Disk registry missing:
  if (
    options.requirePersistentRegistry === true ||
    options.disallowFallback === true ||
    process.env.THREE_LENS_REQUIRE_PERSISTENT_REGISTRY === '1'
  ) {
    const errorMsg = `[PERSISTENT_REGISTRY_MISSING] On-disk trust registry missing from ${regPath} and fallback is disallowed`;
    if (options.failClosed !== false) {
      throw new Error(errorMsg);
    }
    return {
      source: 'EMBEDDED_FALLBACK',
      registry: null,
      valid: false,
      error: errorMsg,
      cryptographicValidity: false,
      monotonicValidity: false,
      ancestryContinuity: false
    };
  }

  const fallback = JSON.parse(JSON.stringify(EMBEDDED_ROOT_REGISTRY));
  const expectedMin = typeof options.minRegistryVersion === 'number'
    ? options.minRegistryVersion
    : (process.env.THREE_LENS_MIN_REGISTRY_VERSION ? parseInt(process.env.THREE_LENS_MIN_REGISTRY_VERSION, 10) : 1);

  if (fallback.registryVersion < expectedMin) {
    const errorMsg = `Monotonic regression: registry version ${fallback.registryVersion} < minimum expected ${expectedMin}`;
    if (options.failClosed !== false) {
      throw new Error(`[MONOTONIC_REGRESSION_FAIL_CLOSED] ${errorMsg}`);
    }
    return {
      source: 'EMBEDDED_FALLBACK',
      registry: null,
      valid: false,
      error: errorMsg,
      cryptographicValidity: true,
      monotonicValidity: false,
      ancestryContinuity: true
    };
  }

  // Validate fallback schema integrity against default root
  const fallbackValidation = validateTrustRegistry(fallback, { minRegistryVersion: 1 });
  if (!fallbackValidation.valid) {
    if (options.failClosed !== false) {
      throw new Error(`Embedded fallback registry fails schema validation: ${fallbackValidation.error}`);
    }
    return {
      source: 'EMBEDDED_FALLBACK',
      registry: null,
      valid: false,
      error: fallbackValidation.error,
      cryptographicValidity: fallbackValidation.cryptographicValidity,
      monotonicValidity: fallbackValidation.monotonicValidity,
      ancestryContinuity: fallbackValidation.ancestryContinuity
    };
  }

  if (options.autoInitialize === true) {
    saveTrustRegistry(fallback, options);
    return {
      source: 'PLUGIN_DATA',
      registry: fallback,
      valid: true,
      path: regPath,
      initialized: true,
      cryptographicValidity: true,
      monotonicValidity: true,
      ancestryContinuity: true
    };
  }

  return {
    source: 'EMBEDDED_FALLBACK',
    registry: fallback,
    valid: true,
    path: null,
    cryptographicValidity: true,
    monotonicValidity: true,
    ancestryContinuity: true
  };
}

/**
 * Atomically writes a trust registry to PLUGIN_DATA under mutual exclusion.
 * Resolves M54-P2-F02 (Monotonic check and anti-rollback) and M54-P2-F04 (withFileLock).
 *
 * @param {object} registry
 * @param {object} [options={}]
 * @returns {{ success: boolean, path: string, registryVersion: number }}
 */
export function saveTrustRegistry(registry, options = {}) {
  const regPath = getTrustRegistryPath(options);
  const dir = path.dirname(regPath);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });

  return withFileLock(regPath, () => {
    assertSafeStorageTarget(regPath, options);
    let priorRegistry = null;
    // Check against existing on-disk registry if present
    if (fs.existsSync(regPath)) {
      try {
        const existingRaw = fs.readFileSync(regPath, 'utf8');
        priorRegistry = JSON.parse(existingRaw);

        if (registry.registryVersion < priorRegistry.registryVersion) {
          throw new Error(
            `[REGISTRY_ROLLBACK_DETECTED] Cannot save version ${registry.registryVersion} over existing version ${priorRegistry.registryVersion}`
          );
        }

        // Anti-unrevocation invariant: cannot strip previously revoked keyIds
        if (Array.isArray(priorRegistry.revokedKeyIds)) {
          for (const revokedId of priorRegistry.revokedKeyIds) {
            if (!registry.revokedKeyIds.includes(revokedId)) {
              throw new Error(`[REVOCATION_STRIP_VIOLATION] Cannot un-revoke previously revoked keyId '${revokedId}'`);
            }
          }
        }
      } catch (err) {
        if (err.message.includes('REGISTRY_ROLLBACK_DETECTED') || err.message.includes('REVOCATION_STRIP_VIOLATION')) {
          throw err;
        }
        if (options.forceOverwrite !== true) {
          throw new Error(
            `[CORRUPT_PRIOR_REGISTRY_DETECTED] Cannot save registry: existing on-disk registry at ${regPath} is corrupt or unreadable (${err.message})`
          );
        }
      }
    }

    const validation = validateTrustRegistry(registry, { ...options, priorRegistry });
    if (!validation.valid) {
      throw new Error(`Cannot save invalid trust registry: ${validation.error}`);
    }

    const tmpPath = path.join(dir, `.tmp.reg.${process.pid}.${Date.now()}.${crypto.randomBytes(4).toString('hex')}`);
    assertSafeStorageTarget(tmpPath, options);
    const serialized = JSON.stringify(registry, null, 2) + '\n';

    fs.writeFileSync(tmpPath, serialized, 'utf8');
    fs.renameSync(tmpPath, regPath);

    return {
      success: true,
      path: normalizePath(regPath),
      registryVersion: registry.registryVersion
    };
  }, options);
}

/**
 * Loads and validates the hash-chained revocation journal from PLUGIN_DATA.
 * Resolves M54-P2-F01: Mandatory signature verification, root key verification,
 * and rollback/truncation detection via persistent checkpoint and trust registry high-water mark.
 *
 * @param {object} [options={}]
 * @returns {{ valid: boolean, entries: Array<object>, error: string|null, count: number }}
 */
function doLoadRevocationJournal(options = {}) {
  const journalPath = getRevocationJournalPath(options);
  const checkpointPath = getRevocationCheckpointPath(options);

  // Checkpoint audit (F01: Detect deletion / rollback)
  let checkpoint = null;
  if (fs.existsSync(checkpointPath)) {
    try {
      checkpoint = JSON.parse(fs.readFileSync(checkpointPath, 'utf8'));
      if (typeof checkpoint.headIndex !== 'number' || typeof checkpoint.headDigest !== 'string') {
        const msg = `[CHECKPOINT_CORRUPTION_DETECTED] Checkpoint file missing headIndex or headDigest at ${checkpointPath}`;
        if (options.failClosed !== false) throw new Error(msg);
        return { valid: false, entries: [], error: msg, count: 0, path: journalPath };
      }
    } catch (err) {
      const msg = `[CHECKPOINT_CORRUPTION_DETECTED] Failed to parse revocation checkpoint at ${checkpointPath}: ${err.message}`;
      if (options.failClosed !== false) throw new Error(msg);
      return { valid: false, entries: [], error: msg, count: 0, path: journalPath };
    }
  }

  // R04-B01: Query trust registry high-water mark
  const trustRegistryLoad = loadTrustRegistry({ ...options, failClosed: false });
  const registryHwm = (trustRegistryLoad.valid && trustRegistryLoad.registry?.revocationHighWaterMark)
    ? trustRegistryLoad.registry.revocationHighWaterMark
    : null;

  if (!fs.existsSync(journalPath)) {
    if (checkpoint && checkpoint.headIndex >= 0) {
      const msg = `[JOURNAL_ROLLBACK_DETECTED] Journal file missing but checkpoint records headIndex ${checkpoint.headIndex}`;
      if (options.failClosed !== false) throw new Error(msg);
      return { valid: false, entries: [], error: msg, count: 0, path: journalPath };
    }
    if (registryHwm && typeof registryHwm.headIndex === 'number' && registryHwm.headIndex >= 0) {
      const msg = `[JOURNAL_ROLLBACK_DETECTED] Journal file missing but trust registry records revocation high-water mark headIndex ${registryHwm.headIndex}`;
      if (options.failClosed !== false) throw new Error(msg);
      return { valid: false, entries: [], error: msg, count: 0, path: journalPath };
    }
    if (typeof options.minJournalEntries === 'number' && options.minJournalEntries > 0) {
      const msg = `[JOURNAL_ROLLBACK_DETECTED] Journal file missing but minJournalEntries is ${options.minJournalEntries}`;
      if (options.failClosed !== false) throw new Error(msg);
      return { valid: false, entries: [], error: msg, count: 0, path: journalPath };
    }
    return { valid: true, entries: [], error: null, count: 0, path: journalPath };
  }

  try {
    const content = fs.readFileSync(journalPath, 'utf8');
    const lines = content.split(/\r?\n/).filter(line => line.trim().length > 0);

    // Rollback detection against checkpoint
    if (checkpoint && lines.length < checkpoint.headIndex + 1) {
      const msg = `[JOURNAL_TRUNCATION_DETECTED] Journal has ${lines.length} entries but checkpoint records headIndex ${checkpoint.headIndex}`;
      if (options.failClosed !== false) throw new Error(msg);
      return { valid: false, entries: [], error: msg, count: 0, path: journalPath };
    }

    // Rollback detection against trust registry high-water mark (R04-B01)
    if (registryHwm && typeof registryHwm.headIndex === 'number' && lines.length < registryHwm.headIndex + 1) {
      const msg = `[JOURNAL_TRUNCATION_DETECTED] Journal has ${lines.length} entries but trust registry records headIndex ${registryHwm.headIndex}`;
      if (options.failClosed !== false) throw new Error(msg);
      return { valid: false, entries: [], error: msg, count: lines.length, path: journalPath };
    }

    if (typeof options.minJournalEntries === 'number' && lines.length < options.minJournalEntries) {
      const msg = `[JOURNAL_ROLLBACK_DETECTED] Journal has ${lines.length} entries, less than expected minimum ${options.minJournalEntries}`;
      if (options.failClosed !== false) throw new Error(msg);
      return { valid: false, entries: [], error: msg, count: lines.length, path: journalPath };
    }

    const trustedKeys = new Map();

    if (trustRegistryLoad.valid && trustRegistryLoad.registry) {
      const revokedSet = new Set(trustRegistryLoad.registry.revokedKeyIds || []);
      for (const k of trustRegistryLoad.registry.keys || []) {
        if (['ACTIVE_PINNED_ROOT', 'ACTIVE', 'RETIRED'].includes(k.status) && !revokedSet.has(k.keyId)) {
          trustedKeys.set(k.keyId, k.publicKeyPem);
        }
      }
    }
    // Always include genesis root anchor
    const rootId = options.trustedRootKeyId || DEFAULT_SUPERVISOR_KEY_ID;
    const rootPem = options.trustedRootPublicKeyPem || DEFAULT_SUPERVISOR_PUBLIC_PEM;
    trustedKeys.set(rootId, rootPem);

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

      // Mandatory Ed25519 signature verification on read
      if (!parsed.signature || !parsed.signedBy) {
        const msg = `Unsigned revocation record detected at line ${i + 1} (targetId: ${parsed.targetId})`;
        if (options.failClosed !== false) throw new Error(msg);
        return { valid: false, entries: [], error: msg, count: i };
      }

      const signerPem = trustedKeys.get(parsed.signedBy);
      if (!signerPem) {
        const msg = `Signer '${parsed.signedBy}' at line ${i + 1} is not a trusted supervisor key`;
        if (options.failClosed !== false) throw new Error(msg);
        return { valid: false, entries: [], error: msg, count: i };
      }

      const signPayload = Buffer.from(computeRevocationEntrySignPayload(parsed), 'utf8');
      const isValid = crypto.verify(null, signPayload, signerPem, Buffer.from(parsed.signature, 'hex'));
      if (!isValid) {
        const msg = `Signature verification failed for revocation record at line ${i + 1} (targetId: ${parsed.targetId})`;
        if (options.failClosed !== false) throw new Error(msg);
        return { valid: false, entries: [], error: msg, count: i };
      }

      entries.push(parsed);
      expectedPrevDigest = sha256Digest(canonicalJsonStringify(parsed));
    }

    // Verify head digest against checkpoint if available
    if (checkpoint && entries.length > 0 && expectedPrevDigest !== checkpoint.headDigest) {
      const msg = `[JOURNAL_HEAD_MISMATCH] Journal head digest does not match checkpoint headDigest`;
      if (options.failClosed !== false) throw new Error(msg);
      return { valid: false, entries: [], error: msg, count: entries.length, path: journalPath };
    }

    // Verify head digest against trust registry high-water mark (R04-B01)
    if (
      registryHwm &&
      typeof registryHwm.headIndex === 'number' &&
      entries.length > registryHwm.headIndex
    ) {
      const entryAtHwm = entries[registryHwm.headIndex];
      const digestAtHwm = sha256Digest(canonicalJsonStringify(entryAtHwm));
      if (digestAtHwm !== registryHwm.headDigest) {
        const msg = `[JOURNAL_HEAD_MISMATCH] Journal entry at index ${registryHwm.headIndex} digest does not match trust registry high-water mark headDigest`;
        if (options.failClosed !== false) throw new Error(msg);
        return { valid: false, entries: [], error: msg, count: entries.length, path: journalPath };
      }
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
 * Loads and validates the hash-chained revocation journal from PLUGIN_DATA.
 * Resolves M54-P2-F01 and M54-P2-F04: Reader synchronization via withFileLock,
 * mandatory signature verification, root & retired key verification, and anti-rollback.
 * Resolves R04-B05: Readers acquire mutual exclusion even on non-existent journal file.
 *
 * @param {object} [options={}]
 * @returns {{ valid: boolean, entries: Array<object>, error: string|null, count: number }}
 */
export function loadRevocationJournal(options = {}) {
  const journalPath = getRevocationJournalPath(options);
  if (options.skipLock === true) {
    return doLoadRevocationJournal(options);
  }
  return withFileLock(journalPath, () => doLoadRevocationJournal(options), {
    ...options,
    staleLockTimeoutMs: options.staleLockTimeoutMs || 10000,
    lockTimeoutMs: options.lockTimeoutMs || 15000
  });
}

/**
 * Appends an entry to the revocation journal with mandatory Ed25519 signature under mutual exclusion.
 * Resolves M54-P2-F01 and M54-P2-F04.
 * Resolves R04-B01 (Trust Registry High-Water Mark Anchor) and R04-B03 (Symlink/Hardlink Defense).
 *
 * @param {object} entryInput
 * @param {string} entryInput.revocationType
 * @param {string} entryInput.targetId
 * @param {string} [entryInput.reason='MANUAL_REVOCATION']
 * @param {object} options
 * @param {KeyObject|string} options.signerPrivateKey - Mandatory signing private key
 * @param {string} [options.signerKeyId] - Key ID of signer
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

  if (!options.signerPrivateKey) {
    throw new Error('[MANDATORY_SIGNATURE_REQUIRED] appendRevocationEntry requires options.signerPrivateKey (F01)');
  }

  const journalPath = getRevocationJournalPath(options);
  const checkpointPath = getRevocationCheckpointPath(options);
  const regPath = getTrustRegistryPath(options);
  const dir = path.dirname(journalPath);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });

  return withFileLock(journalPath, () => {
    // R04-B03: Check leaf files for symlink and hardlink pollution inside lock
    assertSafeStorageTarget(journalPath, options);
    assertSafeStorageTarget(checkpointPath, options);
    assertSafeStorageTarget(regPath, options);

    const journal = loadRevocationJournal({ ...options, failClosed: true, skipLock: true });
    const entryIndex = journal.entries.length;

    let prevEntryDigest = '0'.repeat(64);
    if (entryIndex > 0) {
      prevEntryDigest = sha256Digest(canonicalJsonStringify(journal.entries[entryIndex - 1]));
    }

    const timestamp = options.timestamp || new Date().toISOString();
    const signedBy = options.signerKeyId || DEFAULT_SUPERVISOR_KEY_ID;
    const reason = entryInput.reason || 'MANUAL_REVOCATION';

    const unsignedRecord = {
      entryIndex,
      timestamp,
      revocationType: entryInput.revocationType,
      targetId: entryInput.targetId,
      reason,
      prevEntryDigest,
      signedBy
    };

    const signPayload = Buffer.from(computeRevocationEntrySignPayload(unsignedRecord), 'utf8');
    const signature = crypto.sign(null, signPayload, options.signerPrivateKey).toString('hex');

    const record = {
      ...unsignedRecord,
      signature
    };

    const line = JSON.stringify(record) + '\n';

    // R04-B03: Safe descriptor inspection on open
    const fd = fs.openSync(journalPath, 'a+');
    try {
      const fdStat = fs.fstatSync(fd);
      if (fdStat.nlink > 1 && options.allowInWorkspace !== true) {
        throw new Error(
          `[HARDLINK_POLLUTION_VIOLATION] Target file (${journalPath}) has multiple hard links (nlink: ${fdStat.nlink})`
        );
      }
      fs.writeSync(fd, line, null, 'utf8');
    } finally {
      fs.closeSync(fd);
    }

    const entryDigest = sha256Digest(canonicalJsonStringify(record));

    // Update persistent checkpoint for anti-rollback protection (F01) via atomic write
    const checkpointData = {
      headIndex: entryIndex,
      headDigest: entryDigest,
      updatedAt: record.timestamp
    };
    const cpTmpPath = path.join(dir, `.tmp.cp.${process.pid}.${Date.now()}.${crypto.randomBytes(4).toString('hex')}`);
    assertSafeStorageTarget(cpTmpPath, options);
    fs.writeFileSync(cpTmpPath, JSON.stringify(checkpointData, null, 2) + '\n', 'utf8');
    fs.renameSync(cpTmpPath, checkpointPath);

    // R04-B01: Anchor revocation high-water mark into trust registry
    try {
      let regObj = null;
      if (fs.existsSync(regPath)) {
        regObj = JSON.parse(fs.readFileSync(regPath, 'utf8'));
      } else {
        const rootId = options.trustedRootKeyId || DEFAULT_SUPERVISOR_KEY_ID;
        const rootPem = options.trustedRootPublicKeyPem || DEFAULT_SUPERVISOR_PUBLIC_PEM;
        const rootFp = options.trustedRootFingerprint || DEFAULT_SUPERVISOR_FINGERPRINT;
        regObj = {
          schemaVersion: '1.0.0',
          registryVersion: 1,
          authority: 'IRV_SUPERVISOR_ROOT_AUTHORITY',
          activeKeyId: rootId,
          activeKeyFingerprint: rootFp,
          activePublicKeyPem: rootPem,
          keyType: 'ed25519',
          pinnedSince: new Date().toISOString(),
          rotationPolicy: 'SINGLE_ACTIVE_PINNED_ROOT',
          revokedKeyIds: [],
          keys: [
            {
              keyId: rootId,
              keyFingerprint: rootFp,
              publicKeyPem: rootPem,
              status: 'ACTIVE_PINNED_ROOT',
              issuedAt: new Date().toISOString()
            }
          ]
        };
      }
      regObj.revocationHighWaterMark = {
        headIndex: entryIndex,
        headDigest: entryDigest,
        updatedAt: record.timestamp
      };
      const regDir = path.dirname(regPath);
      if (!fs.existsSync(regDir)) fs.mkdirSync(regDir, { recursive: true });
      const regTmpPath = path.join(regDir, `.tmp.reg.${process.pid}.${Date.now()}.${crypto.randomBytes(4).toString('hex')}`);
      assertSafeStorageTarget(regTmpPath, options);
      fs.writeFileSync(regTmpPath, JSON.stringify(regObj, null, 2) + '\n', 'utf8');
      fs.renameSync(regTmpPath, regPath);
    } catch (regErr) {
      if (regErr.message && regErr.message.includes('_VIOLATION')) {
        throw regErr;
      }
    }

    return {
      success: true,
      entryIndex,
      entryDigest,
      path: normalizePath(journalPath)
    };
  }, options);
}

/**
 * Checks whether an ID (keyId, nonce, or ballot fingerprint) has been revoked.
 * Resolves R04-B01: Seamlessly anchors revocation high-water mark from trust registry
 * so dual-file deletion of journal and checkpoint fails closed.
 *
 * @param {string} targetId
 * @param {object} [options={}]
 * @returns {{ revoked: boolean, reason: string|null, entry: object|null }}
 */
export function isRevoked(targetId, options = {}) {
  if (!targetId || typeof targetId !== 'string') {
    return { revoked: false, reason: null, entry: null };
  }

  const regLoad = loadTrustRegistry({ ...options, failClosed: false });
  if (!regLoad.valid) {
    return {
      revoked: true,
      reason: `REGISTRY_CORRUPTED_FAIL_CLOSED: ${regLoad.error || 'unknown error'}`,
      entry: null
    };
  }

  if (regLoad.registry && Array.isArray(regLoad.registry.revokedKeyIds)) {
    if (regLoad.registry.revokedKeyIds.includes(targetId)) {
      return {
        revoked: true,
        reason: 'REVOKED_IN_TRUST_REGISTRY',
        entry: null
      };
    }
  }

  const journalOpts = { ...options, failClosed: false };
  if (
    regLoad.valid &&
    regLoad.registry?.revocationHighWaterMark &&
    typeof regLoad.registry.revocationHighWaterMark.headIndex === 'number'
  ) {
    journalOpts.minJournalEntries = regLoad.registry.revocationHighWaterMark.headIndex + 1;
    journalOpts.expectedHeadDigest = regLoad.registry.revocationHighWaterMark.headDigest;
  }

  let journalLoad;
  try {
    journalLoad = loadRevocationJournal(journalOpts);
  } catch (err) {
    journalLoad = { valid: false, error: err.message };
  }

  if (!journalLoad.valid) {
    return {
      revoked: true,
      reason: `JOURNAL_CORRUPTED_FAIL_CLOSED: ${journalLoad.error || 'unknown error'}`,
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
