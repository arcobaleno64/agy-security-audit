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
  validateTrustRegistry,
  loadTrustRegistry,
  saveTrustRegistry,
  loadRevocationJournal,
  appendRevocationEntry,
  isRevoked,
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

test('PLUGIN_DATA Governance: Atomic save and reload maintains primary state in PLUGIN_DATA', () => {
  const tempDir = createTempDir('save-data-');
  const updatedReg = {
    ...EMBEDDED_ROOT_REGISTRY,
    registryVersion: 2,
    revokedKeyIds: ['OLD-COMPROMISED-KEY-001']
  };

  const saveRes = saveTrustRegistry(updatedReg, { pluginDataDir: tempDir, allowInWorkspace: true });
  assert.equal(saveRes.success, true);
  assert.equal(saveRes.registryVersion, 2);

  const loadRes = loadTrustRegistry({ pluginDataDir: tempDir, allowInWorkspace: true });
  assert.equal(loadRes.source, 'PLUGIN_DATA');
  assert.equal(loadRes.valid, true);
  assert.equal(loadRes.registry.registryVersion, 2);
  assert.deepEqual(loadRes.registry.revokedKeyIds, ['OLD-COMPROMISED-KEY-001']);

  fs.rmSync(tempDir, { recursive: true, force: true });
});

test('PLUGIN_DATA Governance: Monotonic version regression fails closed', () => {
  const tempDir = createTempDir('regress-data-');
  const staleReg = {
    ...EMBEDDED_ROOT_REGISTRY,
    registryVersion: 1
  };
  saveTrustRegistry(staleReg, { pluginDataDir: tempDir, allowInWorkspace: true });

  assert.throws(
    () => {
      loadTrustRegistry({
        pluginDataDir: tempDir,
        allowInWorkspace: true,
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

test('PLUGIN_DATA Governance: Revocation journal enforces tamper-evident hash chaining', () => {
  const tempDir = createTempDir('journal-data-');
  const opts = { pluginDataDir: tempDir, allowInWorkspace: true };

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

  fs.rmSync(tempDir, { recursive: true, force: true });
});

test('PLUGIN_DATA Governance: Tampered revocation journal line fails closed immediately', () => {
  const tempDir = createTempDir('corrupt-journal-');
  const opts = { pluginDataDir: tempDir, allowInWorkspace: true };

  appendRevocationEntry({ revocationType: REVOCATION_TYPES.NONCE_REVOCATION, targetId: 'NONCE-A' }, opts);
  appendRevocationEntry({ revocationType: REVOCATION_TYPES.NONCE_REVOCATION, targetId: 'NONCE-B' }, opts);

  // Tamper line 1
  const journalPath = getRevocationJournalPath(opts);
  const raw = fs.readFileSync(journalPath, 'utf8');
  const tampered = raw.replace('NONCE-A', 'NONCE-TAMPERED');
  fs.writeFileSync(journalPath, tampered, 'utf8');

  // Should fail closed with broken hash chain
  assert.throws(
    () => {
      loadRevocationJournal(opts);
    },
    /Tamper detected|broken hash chain/
  );

  // isRevoked must fail closed to true when journal is corrupted
  const query = isRevoked('NONCE-UNTOUCHED', opts);
  assert.equal(query.revoked, true);
  assert.equal(query.reason, 'JOURNAL_CORRUPTED_FAIL_CLOSED');

  fs.rmSync(tempDir, { recursive: true, force: true });
});

test('PLUGIN_DATA Governance: Ed25519 signature verification on revocation entry', () => {
  const tempDir = createTempDir('ed25519-journal-');
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const opts = {
    pluginDataDir: tempDir,
    allowInWorkspace: true,
    signerPrivateKey: privateKey,
    signerKeyId: 'TEST-SIGNER-KEY-1'
  };

  const app = appendRevocationEntry(
    { revocationType: REVOCATION_TYPES.BALLOT_DISPUTE, targetId: 'BALLOT-NONCE-XYZ', reason: 'COUNTEREVIDENCE' },
    opts
  );

  const load = loadRevocationJournal(opts);
  const entry = load.entries[0];
  assert.equal(entry.signedBy, 'TEST-SIGNER-KEY-1');
  assert.ok(typeof entry.signature === 'string' && entry.signature.length > 0);

  // Verify signature cryptographically using public key
  const signPayload = Buffer.from(`${entry.targetId}:${entry.entryIndex}:${entry.prevEntryDigest}`, 'utf8');
  const validSig = crypto.verify(null, signPayload, publicKey, Buffer.from(entry.signature, 'hex'));
  assert.equal(validSig, true);

  fs.rmSync(tempDir, { recursive: true, force: true });
});
