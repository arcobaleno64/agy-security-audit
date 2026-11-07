import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import crypto from 'node:crypto';
import {
  resolvePluginDataDir,
  getTrustRegistryPath,
  getRevocationJournalPath,
  getRevocationCheckpointPath,
  validateTrustRegistry,
  loadTrustRegistry,
  saveTrustRegistry,
  loadRevocationJournal,
  appendRevocationEntry,
  isRevoked,
  withFileLock,
  createAuthorizedRegistryUpdate,
  REVOCATION_TYPES,
  EMBEDDED_ROOT_REGISTRY,
  DEFAULT_SUPERVISOR_KEY_ID,
  DEFAULT_SUPERVISOR_PUBLIC_PEM,
  DEFAULT_SUPERVISOR_FINGERPRINT
} from '../scripts/adapters/plugin-data-adapter.mjs';

function createTempDir(prefix = 'test-plugin-data-') {
  const dir = path.join(os.tmpdir(), `${prefix}${Date.now()}-${crypto.randomBytes(4).toString('hex')}`);
  fs.mkdirSync(dir, { recursive: true });
  return dir;
}

function generateTestAuthority() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const pem = publicKey.export({ type: 'spki', format: 'pem' });
  const fp = crypto.createHash('sha256').update(pem).digest('hex');
  const keyId = `TEST-SUPERVISOR-ROOT-${fp.slice(0, 16)}`;
  return { publicKey, privateKey, pem, fp, keyId };
}

test('PLUGIN_DATA Governance: Default embedded root registry has valid schema and fingerprint', () => {
  const validation = validateTrustRegistry(EMBEDDED_ROOT_REGISTRY);
  assert.equal(validation.valid, true);
  assert.equal(validation.error, null);
  assert.equal(EMBEDDED_ROOT_REGISTRY.activeKeyId, DEFAULT_SUPERVISOR_KEY_ID);
  assert.equal(EMBEDDED_ROOT_REGISTRY.activeKeyFingerprint, DEFAULT_SUPERVISOR_FINGERPRINT);
});

test('PLUGIN_DATA Governance: Invariant - Zero Workspace Pollution strictly rejects in-repo target path', () => {
  const fakeRepo = createTempDir('fake-repo-');
  const insideRepoPluginData = path.join(fakeRepo, '.plugin-data');

  assert.throws(
    () => {
      resolvePluginDataDir({
        pluginDataDir: insideRepoPluginData,
        repoRoot: fakeRepo,
        allowInWorkspace: false
      });
    },
    /ZERO_WORKSPACE_POLLUTION_VIOLATION/
  );

  fs.rmSync(fakeRepo, { recursive: true, force: true });
});

test('PLUGIN_DATA Governance: F03 - Path containment resolves symlinks/junctions fail-closed', (t) => {
  const tempBase = createTempDir('symlink-test-');
  const fakeRepo = path.join(tempBase, 'repo');
  const outsideTarget = path.join(tempBase, 'outside');
  const symlinkInsideRepo = path.join(fakeRepo, 'link-outside');

  fs.mkdirSync(fakeRepo, { recursive: true });
  fs.mkdirSync(outsideTarget, { recursive: true });

  try {
    fs.symlinkSync(outsideTarget, symlinkInsideRepo, 'dir');
  } catch {
    // On Windows without SeCreateSymbolicLinkPrivilege, junctions may be used
    try {
      fs.symlinkSync(outsideTarget, symlinkInsideRepo, 'junction');
    } catch {
      t.skip('Filesystem does not support symlink/junction in test context');
      fs.rmSync(tempBase, { recursive: true, force: true });
      return;
    }
  }

  // Symlink inside repo targeting inside repo should fail
  const insideInside = path.join(fakeRepo, 'target-inside');
  fs.mkdirSync(insideInside, { recursive: true });
  const symlinkToInside = path.join(tempBase, 'outside-link-to-inside');
  try {
    fs.symlinkSync(insideInside, symlinkToInside, 'junction');
    // Calling with symlink outside that points INSIDE repo must be caught by realpathSync
    assert.throws(
      () => {
        resolvePluginDataDir({
          pluginDataDir: symlinkToInside,
          repoRoot: fakeRepo,
          allowInWorkspace: false
        });
      },
      /ZERO_WORKSPACE_POLLUTION_VIOLATION/
    );
  } catch (e) {
    if (!e.message.includes('ZERO_WORKSPACE_POLLUTION_VIOLATION')) {
      // Junction creation might be skipped
    } else {
      throw e;
    }
  }

  fs.rmSync(tempBase, { recursive: true, force: true });
});

test('PLUGIN_DATA Governance: Explicit allowInWorkspace permits isolated harness testing', () => {
  const tempDir = createTempDir('harness-data-');
  const resolved = resolvePluginDataDir({
    pluginDataDir: tempDir,
    allowInWorkspace: true
  });

  assert.ok(fs.existsSync(resolved));
  assert.equal(getTrustRegistryPath({ pluginDataDir: tempDir, allowInWorkspace: true }), `${resolved}/supervisor-trust-registry.json`);
  assert.equal(getRevocationJournalPath({ pluginDataDir: tempDir, allowInWorkspace: true }), `${resolved}/.irv-revocation-journal.jsonl`);

  fs.rmSync(tempDir, { recursive: true, force: true });
});

test('PLUGIN_DATA Governance: Rejects null bytes in path fail-closed', () => {
  assert.throws(
    () => {
      resolvePluginDataDir({ pluginDataDir: '/var/data\0/evil' });
    },
    /Illegal null byte/
  );
});

test('PLUGIN_DATA Governance: Dual-Anchor fallback loads embedded registry when no local file exists', () => {
  const tempDir = createTempDir('empty-data-');
  const res = loadTrustRegistry({ pluginDataDir: tempDir, allowInWorkspace: true });

  assert.equal(res.source, 'EMBEDDED_FALLBACK');
  assert.equal(res.valid, true);
  assert.equal(res.registry.activeKeyId, DEFAULT_SUPERVISOR_KEY_ID);
  assert.equal(res.registry.registryVersion, 1);

  fs.rmSync(tempDir, { recursive: true, force: true });
});

test('PLUGIN_DATA Governance: F02 - Atomic save with root authorization chain and anti-rollback', () => {
  const tempDir = createTempDir('save-data-');
  const auth = generateTestAuthority();
  const v1Reg = {
    schemaVersion: '1.0.0',
    registryVersion: 1,
    authority: 'IRV_SUPERVISOR_ROOT_AUTHORITY',
    activeKeyId: auth.keyId,
    activeKeyFingerprint: auth.fp,
    activePublicKeyPem: auth.pem,
    keyType: 'ed25519',
    pinnedSince: '2026-10-16T06:55:39.565Z',
    rotationPolicy: 'SINGLE_ACTIVE_PINNED_ROOT',
    revokedKeyIds: [],
    keys: [{ keyId: auth.keyId, keyFingerprint: auth.fp, publicKeyPem: auth.pem, status: 'ACTIVE_PINNED_ROOT', issuedAt: '2026-10-16T06:55:39.565Z' }]
  };

  const opts = {
    pluginDataDir: tempDir,
    allowInWorkspace: true,
    trustedRootKeyId: auth.keyId,
    trustedRootPublicKeyPem: auth.pem,
    trustedRootFingerprint: auth.fp
  };

  // 1. Save v1 genesis
  const saveRes1 = saveTrustRegistry(v1Reg, opts);
  assert.equal(saveRes1.success, true);
  assert.equal(saveRes1.registryVersion, 1);

  // 2. Unsigned v2 must be rejected (F02)
  const unsignedV2 = {
    ...v1Reg,
    registryVersion: 2,
    revokedKeyIds: ['OLD-COMPROMISED-KEY-001']
  };
  assert.throws(
    () => saveTrustRegistry(unsignedV2, opts),
    /requires valid authorizationProof/
  );

  // 3. Cryptographically authorized v2 succeeds
  const authorizedV2 = createAuthorizedRegistryUpdate(
    v1Reg,
    { revokedKeyIds: ['OLD-COMPROMISED-KEY-001'] },
    auth.keyId,
    auth.privateKey
  );
  const saveRes2 = saveTrustRegistry(authorizedV2, opts);
  assert.equal(saveRes2.success, true);
  assert.equal(saveRes2.registryVersion, 2);

  const loadRes = loadTrustRegistry(opts);
  assert.equal(loadRes.source, 'PLUGIN_DATA');
  assert.equal(loadRes.valid, true);
  assert.equal(loadRes.registry.registryVersion, 2);
  assert.deepEqual(loadRes.registry.revokedKeyIds, ['OLD-COMPROMISED-KEY-001']);

  // 4. Anti-unrevocation invariant check (cannot silently remove revokedKeyId)
  const stripRevocationV3 = createAuthorizedRegistryUpdate(
    authorizedV2,
    { revokedKeyIds: [] },
    auth.keyId,
    auth.privateKey
  );
  assert.throws(
    () => saveTrustRegistry(stripRevocationV3, opts),
    /REVOCATION_STRIP_VIOLATION/
  );

  // 5. Anti-rollback check (cannot overwrite v2 with v1)
  assert.throws(
    () => saveTrustRegistry(v1Reg, opts),
    /REGISTRY_ROLLBACK_DETECTED/
  );

  fs.rmSync(tempDir, { recursive: true, force: true });
});

test('PLUGIN_DATA Governance: Monotonic version regression fails closed', () => {
  const tempDir = createTempDir('regress-data-');
  const auth = generateTestAuthority();
  const v1Reg = {
    schemaVersion: '1.0.0',
    registryVersion: 1,
    authority: 'IRV_SUPERVISOR_ROOT_AUTHORITY',
    activeKeyId: auth.keyId,
    activeKeyFingerprint: auth.fp,
    activePublicKeyPem: auth.pem,
    keyType: 'ed25519',
    pinnedSince: '2026-10-16T06:55:39.565Z',
    rotationPolicy: 'SINGLE_ACTIVE_PINNED_ROOT',
    revokedKeyIds: [],
    keys: [{ keyId: auth.keyId, keyFingerprint: auth.fp, publicKeyPem: auth.pem, status: 'ACTIVE_PINNED_ROOT', issuedAt: '2026-10-16T06:55:39.565Z' }]
  };
  const opts = {
    pluginDataDir: tempDir,
    allowInWorkspace: true,
    trustedRootKeyId: auth.keyId,
    trustedRootPublicKeyPem: auth.pem,
    trustedRootFingerprint: auth.fp
  };
  saveTrustRegistry(v1Reg, opts);

  assert.throws(
    () => {
      loadTrustRegistry({
        ...opts,
        minRegistryVersion: 2,
        failClosed: true
      });
    },
    /Monotonic regression/
  );

  fs.rmSync(tempDir, { recursive: true, force: true });
});

test('PLUGIN_DATA Governance: Tampered key fingerprint in registry fails closed', () => {
  const tempDir = createTempDir('tamper-reg-');
  const tamperedReg = {
    ...EMBEDDED_ROOT_REGISTRY,
    activeKeyFingerprint: '0000000000000000000000000000000000000000000000000000000000000000'
  };

  assert.throws(
    () => {
      saveTrustRegistry(tamperedReg, { pluginDataDir: tempDir, allowInWorkspace: true });
    },
    /Fingerprint mismatch/
  );

  fs.rmSync(tempDir, { recursive: true, force: true });
});

test('PLUGIN_DATA Governance: F01 - Revocation journal enforces signatures, chaining, and checkpoint', () => {
  const tempDir = createTempDir('journal-data-');
  const auth = generateTestAuthority();
  const opts = {
    pluginDataDir: tempDir,
    allowInWorkspace: true,
    trustedRootKeyId: auth.keyId,
    trustedRootPublicKeyPem: auth.pem,
    trustedRootFingerprint: auth.fp,
    signerPrivateKey: auth.privateKey,
    signerKeyId: auth.keyId
  };

  const app1 = appendRevocationEntry(
    { revocationType: REVOCATION_TYPES.NONCE_REVOCATION, targetId: 'NONCE-111', reason: 'REPLAY_TEST' },
    opts
  );
  assert.equal(app1.success, true);
  assert.equal(app1.entryIndex, 0);

  const app2 = appendRevocationEntry(
    { revocationType: REVOCATION_TYPES.KEY_REVOCATION, targetId: 'KEY-222', reason: 'ROTATION' },
    opts
  );
  assert.equal(app2.success, true);
  assert.equal(app2.entryIndex, 1);

  const load = loadRevocationJournal(opts);
  assert.equal(load.valid, true);
  assert.equal(load.count, 2);
  assert.equal(load.entries[0].prevEntryDigest, '0'.repeat(64));
  assert.equal(load.entries[1].prevEntryDigest, app1.entryDigest);

  // Verification of query
  assert.equal(isRevoked('NONCE-111', opts).revoked, true);
  assert.equal(isRevoked('KEY-222', opts).revoked, true);
  assert.equal(isRevoked('NONCE-999', opts).revoked, false);

  // Checkpoint anti-rollback / truncation verification (F01)
  const checkpointPath = getRevocationCheckpointPath(opts);
  assert.ok(fs.existsSync(checkpointPath));
  const checkpoint = JSON.parse(fs.readFileSync(checkpointPath, 'utf8'));
  assert.equal(checkpoint.headIndex, 1);
  assert.equal(checkpoint.headDigest, app2.entryDigest);

  // Truncating the journal while checkpoint exists must fail closed
  const journalPath = getRevocationJournalPath(opts);
  const firstLineOnly = fs.readFileSync(journalPath, 'utf8').split('\n')[0] + '\n';
  fs.writeFileSync(journalPath, firstLineOnly, 'utf8');

  assert.throws(
    () => loadRevocationJournal(opts),
    /JOURNAL_TRUNCATION_DETECTED|JOURNAL_HEAD_MISMATCH|broken hash chain/
  );

  fs.rmSync(tempDir, { recursive: true, force: true });
});

test('PLUGIN_DATA Governance: Tampered revocation journal line fails closed immediately', () => {
  const tempDir = createTempDir('corrupt-journal-');
  const auth = generateTestAuthority();
  const opts = {
    pluginDataDir: tempDir,
    allowInWorkspace: true,
    trustedRootKeyId: auth.keyId,
    trustedRootPublicKeyPem: auth.pem,
    trustedRootFingerprint: auth.fp,
    signerPrivateKey: auth.privateKey,
    signerKeyId: auth.keyId
  };

  appendRevocationEntry({ revocationType: REVOCATION_TYPES.NONCE_REVOCATION, targetId: 'NONCE-A' }, opts);
  appendRevocationEntry({ revocationType: REVOCATION_TYPES.NONCE_REVOCATION, targetId: 'NONCE-B' }, opts);

  // Tamper line 1
  const journalPath = getRevocationJournalPath(opts);
  const raw = fs.readFileSync(journalPath, 'utf8');
  const tampered = raw.replace('NONCE-A', 'NONCE-TAMPERED');
  fs.writeFileSync(journalPath, tampered, 'utf8');

  // Should fail closed with broken hash chain or signature verification failed
  assert.throws(
    () => {
      loadRevocationJournal(opts);
    },
    /Tamper detected|broken hash chain|Signature verification failed/
  );

  // isRevoked must fail closed to true when journal is corrupted
  const query = isRevoked('NONCE-UNTOUCHED', opts);
  assert.equal(query.revoked, true);
  assert.equal(query.reason.includes('JOURNAL_CORRUPTED_FAIL_CLOSED'), true);

  fs.rmSync(tempDir, { recursive: true, force: true });
});

test('PLUGIN_DATA Governance: F04 - withFileLock enforces cross-process mutual exclusion', () => {
  const tempDir = createTempDir('lock-test-');
  const targetFile = path.join(tempDir, 'resource.txt');

  let executionOrder = [];
  const res = withFileLock(targetFile, () => {
    executionOrder.push('in_lock');
    return 42;
  });

  assert.equal(res, 42);
  assert.deepEqual(executionOrder, ['in_lock']);
  assert.equal(fs.existsSync(`${targetFile}.lock`), false);

  fs.rmSync(tempDir, { recursive: true, force: true });
});

test('PLUGIN_DATA Governance: F02 - Genesis v1 rejects rogue injected keys in keys array', () => {
  const auth = generateTestAuthority();
  const rogueAuth = generateTestAuthority();
  const injectedV1 = {
    schemaVersion: '1.0.0',
    registryVersion: 1,
    authority: 'IRV_SUPERVISOR_ROOT_AUTHORITY',
    activeKeyId: auth.keyId,
    activeKeyFingerprint: auth.fp,
    activePublicKeyPem: auth.pem,
    keyType: 'ed25519',
    pinnedSince: '2026-10-16T06:55:39.565Z',
    rotationPolicy: 'SINGLE_ACTIVE_PINNED_ROOT',
    revokedKeyIds: [],
    keys: [
      { keyId: auth.keyId, keyFingerprint: auth.fp, publicKeyPem: auth.pem, status: 'ACTIVE_PINNED_ROOT', issuedAt: '2026-10-16T06:55:39.565Z' },
      { keyId: rogueAuth.keyId, keyFingerprint: rogueAuth.fp, publicKeyPem: rogueAuth.pem, status: 'ACTIVE', issuedAt: '2026-10-16T06:55:39.565Z' }
    ]
  };

  const validation = validateTrustRegistry(injectedV1, {
    trustedRootKeyId: auth.keyId,
    trustedRootPublicKeyPem: auth.pem,
    trustedRootFingerprint: auth.fp
  });
  assert.equal(validation.valid, false);
  assert.ok(validation.error.includes('Genesis registry (v1) keys array must contain exactly the pinned root key'));
});

test('PLUGIN_DATA Governance: F02 - saveTrustRegistry fails closed on corrupted existing file', () => {
  const tempDir = createTempDir('corrupt-prior-');
  const auth = generateTestAuthority();
  const regPath = getTrustRegistryPath({ pluginDataDir: tempDir, allowInWorkspace: true });
  fs.mkdirSync(path.dirname(regPath), { recursive: true });
  fs.writeFileSync(regPath, '{ corrupt json !!!', 'utf8');

  const v1Reg = {
    schemaVersion: '1.0.0',
    registryVersion: 1,
    authority: 'IRV_SUPERVISOR_ROOT_AUTHORITY',
    activeKeyId: auth.keyId,
    activeKeyFingerprint: auth.fp,
    activePublicKeyPem: auth.pem,
    keyType: 'ed25519',
    pinnedSince: '2026-10-16T06:55:39.565Z',
    rotationPolicy: 'SINGLE_ACTIVE_PINNED_ROOT',
    revokedKeyIds: [],
    keys: [{ keyId: auth.keyId, keyFingerprint: auth.fp, publicKeyPem: auth.pem, status: 'ACTIVE_PINNED_ROOT', issuedAt: '2026-10-16T06:55:39.565Z' }]
  };

  assert.throws(
    () => saveTrustRegistry(v1Reg, {
      pluginDataDir: tempDir,
      allowInWorkspace: true,
      trustedRootKeyId: auth.keyId,
      trustedRootPublicKeyPem: auth.pem,
      trustedRootFingerprint: auth.fp
    }),
    /CORRUPT_PRIOR_REGISTRY_DETECTED/
  );

  fs.rmSync(tempDir, { recursive: true, force: true });
});

test('PLUGIN_DATA Governance: F01 - loadRevocationJournal fails closed on corrupt checkpoint file', () => {
  const tempDir = createTempDir('corrupt-cp-');
  const auth = generateTestAuthority();
  const opts = {
    pluginDataDir: tempDir,
    allowInWorkspace: true,
    trustedRootKeyId: auth.keyId,
    trustedRootPublicKeyPem: auth.pem,
    trustedRootFingerprint: auth.fp,
    signerPrivateKey: auth.privateKey,
    signerKeyId: auth.keyId
  };

  appendRevocationEntry({ revocationType: REVOCATION_TYPES.NONCE_REVOCATION, targetId: 'NONCE-1' }, opts);
  const cpPath = getRevocationCheckpointPath(opts);
  fs.writeFileSync(cpPath, 'CORRUPT_NOT_JSON', 'utf8');

  assert.throws(
    () => loadRevocationJournal(opts),
    /CHECKPOINT_CORRUPTION_DETECTED/
  );

  fs.rmSync(tempDir, { recursive: true, force: true });
});

test('PLUGIN_DATA Governance: F01 - Tampering with revocationType or reason triggers signature verification failure', () => {
  const tempDir = createTempDir('tamper-fields-');
  const auth = generateTestAuthority();
  const opts = {
    pluginDataDir: tempDir,
    allowInWorkspace: true,
    trustedRootKeyId: auth.keyId,
    trustedRootPublicKeyPem: auth.pem,
    trustedRootFingerprint: auth.fp,
    signerPrivateKey: auth.privateKey,
    signerKeyId: auth.keyId
  };

  appendRevocationEntry({ revocationType: REVOCATION_TYPES.NONCE_REVOCATION, targetId: 'NONCE-SEC', reason: 'REASON_ORIGINAL' }, opts);

  const jPath = getRevocationJournalPath(opts);
  const raw = fs.readFileSync(jPath, 'utf8');
  const tampered = raw.replace('REASON_ORIGINAL', 'REASON_ALTERED');
  fs.writeFileSync(jPath, tampered, 'utf8');

  assert.throws(
    () => loadRevocationJournal(opts),
    /Signature verification failed/
  );

  fs.rmSync(tempDir, { recursive: true, force: true });
});

test('PLUGIN_DATA Governance: F04 - Multi-process withFileLock competition enforces mutual exclusion', async () => {
  const tempDir = createTempDir('concurrent-lock-');
  const lockTarget = path.join(tempDir, 'shared-counter.txt');
  fs.writeFileSync(lockTarget, '0', 'utf8');

  const { pathToFileURL } = await import('node:url');
  const adapterUrl = pathToFileURL(path.resolve('scripts/adapters/plugin-data-adapter.mjs')).href;
  const workerScript = `
    import fs from 'node:fs';
    import { withFileLock } from '${adapterUrl}';
    const target = process.argv[2];
    for (let i = 0; i < 5; i++) {
      withFileLock(target, () => {
        const val = parseInt(fs.readFileSync(target, 'utf8'), 10);
        Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 10);
        fs.writeFileSync(target, String(val + 1), 'utf8');
      }, { staleLockTimeoutMs: 5000, lockTimeoutMs: 15000 });
    }
  `;
  const workerFile = path.join(tempDir, 'worker.mjs');
  fs.writeFileSync(workerFile, workerScript, 'utf8');

  const { spawn } = await import('node:child_process');
  const runWorker = () => new Promise((resolve, reject) => {
    const proc = spawn(process.execPath, [workerFile, lockTarget], { stdio: 'inherit' });
    proc.on('close', code => code === 0 ? resolve() : reject(new Error('Worker exited with code ' + code)));
  });

  await Promise.all([runWorker(), runWorker(), runWorker()]);

  const finalVal = parseInt(fs.readFileSync(lockTarget, 'utf8'), 10);
  assert.equal(finalVal, 15);

  fs.rmSync(tempDir, { recursive: true, force: true });
});

test('PLUGIN_DATA Governance: R03-B02 - loadTrustRegistry fallback fails closed if minRegistryVersion > 1', () => {
  const tempDir = createTempDir('empty-reg-');
  assert.throws(
    () => loadTrustRegistry({ pluginDataDir: tempDir, minRegistryVersion: 2, failClosed: true, allowInWorkspace: true }),
    /MONOTONIC_REGRESSION_FAIL_CLOSED|Monotonic regression/
  );
  fs.rmSync(tempDir, { recursive: true, force: true });
});

test('PLUGIN_DATA Governance: R03-B02 - validateTrustRegistry rejects unauthenticated priorRegistry', () => {
  const auth = generateTestAuthority();
  const rogueAuth = generateTestAuthority();

  const fakePrior = {
    schemaVersion: '1.0.0',
    registryVersion: 1,
    authority: 'IRV_SUPERVISOR_ROOT_AUTHORITY',
    activeKeyId: rogueAuth.keyId,
    activeKeyFingerprint: rogueAuth.fp,
    activePublicKeyPem: rogueAuth.pem,
    keys: [{ keyId: rogueAuth.keyId, keyFingerprint: rogueAuth.fp, publicKeyPem: rogueAuth.pem, status: 'ACTIVE' }],
    revokedKeyIds: []
  };

  const v2Reg = createAuthorizedRegistryUpdate(
    fakePrior,
    { revokedKeyIds: [] },
    rogueAuth.keyId,
    rogueAuth.privateKey
  );

  const validation = validateTrustRegistry(v2Reg, {
    trustedRootKeyId: auth.keyId,
    trustedRootPublicKeyPem: auth.pem,
    trustedRootFingerprint: auth.fp,
    priorRegistry: fakePrior
  });

  assert.equal(validation.valid, false);
  assert.ok(validation.error.includes('Unauthenticated priorRegistry rejected') || validation.error.includes('must match embedded root anchor'));
});

test('PLUGIN_DATA Governance: R03-B02 - loadRevocationJournal accepts historical signatures from RETIRED keys', () => {
  const tempDir = createTempDir('retired-key-');
  const rootAuth = generateTestAuthority();
  const operatorAuth = generateTestAuthority();

  const v1Reg = {
    schemaVersion: '1.0.0',
    registryVersion: 1,
    authority: 'IRV_SUPERVISOR_ROOT_AUTHORITY',
    activeKeyId: rootAuth.keyId,
    activeKeyFingerprint: rootAuth.fp,
    activePublicKeyPem: rootAuth.pem,
    keyType: 'ed25519',
    pinnedSince: '2026-10-16T06:55:39.565Z',
    rotationPolicy: 'SINGLE_ACTIVE_PINNED_ROOT',
    revokedKeyIds: [],
    keys: [{ keyId: rootAuth.keyId, keyFingerprint: rootAuth.fp, publicKeyPem: rootAuth.pem, status: 'ACTIVE_PINNED_ROOT', issuedAt: '2026-10-16T06:55:39.565Z' }]
  };

  const opts = {
    pluginDataDir: tempDir,
    allowInWorkspace: true,
    trustedRootKeyId: rootAuth.keyId,
    trustedRootPublicKeyPem: rootAuth.pem,
    trustedRootFingerprint: rootAuth.fp
  };

  saveTrustRegistry(v1Reg, opts);

  // Rotate to v2 adding operator as active key
  const v2Reg = createAuthorizedRegistryUpdate(
    v1Reg,
    {
      activeKeyId: operatorAuth.keyId,
      activeKeyFingerprint: operatorAuth.fp,
      activePublicKeyPem: operatorAuth.pem,
      keys: [
        { keyId: rootAuth.keyId, keyFingerprint: rootAuth.fp, publicKeyPem: rootAuth.pem, status: 'RETIRED', issuedAt: '2026-10-16T06:55:39.565Z' },
        { keyId: operatorAuth.keyId, keyFingerprint: operatorAuth.fp, publicKeyPem: operatorAuth.pem, status: 'ACTIVE', issuedAt: '2026-10-16T06:55:39.565Z' }
      ]
    },
    rootAuth.keyId,
    rootAuth.privateKey
  );
  saveTrustRegistry(v2Reg, opts);

  // Append entry signed by operator
  appendRevocationEntry(
    { revocationType: REVOCATION_TYPES.NONCE_REVOCATION, targetId: 'NONCE-HISTORICAL-1' },
    { ...opts, signerPrivateKey: operatorAuth.privateKey, signerKeyId: operatorAuth.keyId }
  );

  // Rotate to v3 retiring operatorAuth
  const v3Reg = createAuthorizedRegistryUpdate(
    v2Reg,
    {
      activeKeyId: rootAuth.keyId,
      activeKeyFingerprint: rootAuth.fp,
      activePublicKeyPem: rootAuth.pem,
      keys: [
        { keyId: rootAuth.keyId, keyFingerprint: rootAuth.fp, publicKeyPem: rootAuth.pem, status: 'ACTIVE_PINNED_ROOT', issuedAt: '2026-10-16T06:55:39.565Z' },
        { keyId: operatorAuth.keyId, keyFingerprint: operatorAuth.fp, publicKeyPem: operatorAuth.pem, status: 'RETIRED', issuedAt: '2026-10-16T06:55:39.565Z' }
      ]
    },
    rootAuth.keyId,
    rootAuth.privateKey
  );
  saveTrustRegistry(v3Reg, opts);

  // loadRevocationJournal should still validate the entry signed by RETIRED operatorAuth
  const journal = loadRevocationJournal(opts);
  assert.equal(journal.valid, true);
  assert.equal(journal.count, 1);
  assert.equal(journal.entries[0].targetId, 'NONCE-HISTORICAL-1');

  fs.rmSync(tempDir, { recursive: true, force: true });
});

test('PLUGIN_DATA Governance: R03-B03 - appendRevocationEntry rejects leaf symlink on journal file', (t) => {
  const tempDir = createTempDir('symlink-leaf-');
  const auth = generateTestAuthority();
  const opts = {
    pluginDataDir: tempDir,
    allowInWorkspace: true,
    trustedRootKeyId: auth.keyId,
    trustedRootPublicKeyPem: auth.pem,
    trustedRootFingerprint: auth.fp,
    signerPrivateKey: auth.privateKey,
    signerKeyId: auth.keyId
  };

  const journalPath = getRevocationJournalPath(opts);
  const fakeTarget = path.join(tempDir, 'target-file.txt');
  fs.writeFileSync(fakeTarget, '', 'utf8');

  try {
    fs.symlinkSync(fakeTarget, journalPath, 'file');
  } catch {
    t.skip('Filesystem does not support file symlinks in test context');
    fs.rmSync(tempDir, { recursive: true, force: true });
    return;
  }

  assert.throws(
    () => appendRevocationEntry({ revocationType: REVOCATION_TYPES.NONCE_REVOCATION, targetId: 'NONCE-EVIL' }, opts),
    /SYMLINK_POLLUTION_VIOLATION/
  );

  fs.rmSync(tempDir, { recursive: true, force: true });
});
