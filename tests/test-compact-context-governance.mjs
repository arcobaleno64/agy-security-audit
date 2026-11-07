import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import {
  createCompactedStateEnvelope,
  serializeCompactedAuditHeader,
  extractCompactedAuditHeader,
  validateCompactedStateEnvelope,
  assertCompactSafe,
  sha256Digest,
  canonicalJsonStringify,
  COMPACT_SCHEMA_VERSION,
  COMPACT_ENVELOPE_TYPE,
  COMPACT_HEADER_DELIMITER_START,
  COMPACT_HEADER_DELIMITER_END
} from '../skills/3lens/scripts/compact-guard.mjs';
import { finalizeScan } from '../skills/3lens/scripts/finalize-scan.mjs';

const VALID_SAMPLE_STATE = Object.freeze({
  scanRunId: 'scan-run-20261107-1530-abc',
  executionNonce: 'NONCE-SEC-777-XYZ-888',
  toolManifestDigest: '0e8304a3977f26417792906eb4e34edfbad60b4832ba4832311f986fd7e35f95',
  repoRootFingerprint: 'repo-sha256-112233445566',
  persistedState: {
    targetDirectories: ['src', 'lib', 'packages'],
    scannedFilesCount: 42,
    activeCandidates: ['VULN-001', 'VULN-002']
  }
});

test('Compact Governance: createCompactedStateEnvelope builds canonical envelope with valid stateDigest', () => {
  const env = createCompactedStateEnvelope(VALID_SAMPLE_STATE);

  assert.equal(env.schemaVersion, COMPACT_SCHEMA_VERSION);
  assert.equal(env.envelopeType, COMPACT_ENVELOPE_TYPE);
  assert.equal(env.scanRunId, VALID_SAMPLE_STATE.scanRunId);
  assert.equal(env.executionNonce, VALID_SAMPLE_STATE.executionNonce);
  assert.equal(env.toolManifestDigest, VALID_SAMPLE_STATE.toolManifestDigest);
  assert.ok(typeof env.stateDigest === 'string' && env.stateDigest.length === 64);

  const validation = validateCompactedStateEnvelope(env);
  assert.equal(validation.valid, true);
  assert.equal(validation.error, null);
});

test('Compact Governance: Missing scanRunId or executionNonce strictly throws error', () => {
  assert.throws(
    () => createCompactedStateEnvelope({ executionNonce: 'NONCE-123' }),
    /Missing or empty scanRunId/
  );

  assert.throws(
    () => createCompactedStateEnvelope({ scanRunId: 'RUN-123' }),
    /Missing or empty executionNonce/
  );
});

test('Compact Governance: Serialization and extraction preserves exact cryptographic fidelity', () => {
  const env = createCompactedStateEnvelope(VALID_SAMPLE_STATE);
  const serialized = serializeCompactedAuditHeader(env);

  assert.ok(serialized.includes(COMPACT_HEADER_DELIMITER_START));
  assert.ok(serialized.includes(COMPACT_HEADER_DELIMITER_END));

  const surroundingChatTranscript = [
    'User requested full security audit of repository.',
    'Inventory generated: 42 files discovered.',
    serialized,
    'Threat model built: 3 trust boundaries identified.',
    'Awaiting verifier ballots.'
  ].join('\n\n');

  const extracted = extractCompactedAuditHeader(surroundingChatTranscript);
  assert.equal(extracted.valid, true);
  assert.equal(extracted.error, null);
  assert.equal(extracted.envelope.scanRunId, VALID_SAMPLE_STATE.scanRunId);
  assert.equal(extracted.envelope.executionNonce, VALID_SAMPLE_STATE.executionNonce);
  assert.equal(extracted.envelope.stateDigest, env.stateDigest);
});

test('Compact Governance: Tampering with state fields in extracted envelope fails closed', () => {
  const env = createCompactedStateEnvelope(VALID_SAMPLE_STATE);
  const serialized = serializeCompactedAuditHeader(env);

  // Tamper executionNonce inside serialized text
  const tamperedText = serialized.replace(VALID_SAMPLE_STATE.executionNonce, 'TAMPERED-NONCE-999');

  const extracted = extractCompactedAuditHeader(tamperedText);
  assert.equal(extracted.valid, false);
  assert.ok(extracted.error.includes('Tamper detected') || extracted.error.includes('stateDigest'));
});

test('Compact Governance: Truncated delimiter block fails closed', () => {
  const env = createCompactedStateEnvelope(VALID_SAMPLE_STATE);
  const serialized = serializeCompactedAuditHeader(env);

  // Remove end delimiter to simulate truncation
  const truncatedText = serialized.replace(COMPACT_HEADER_DELIMITER_END, '');

  const extracted = extractCompactedAuditHeader(truncatedText);
  assert.equal(extracted.valid, false);
  assert.ok(extracted.error.includes('Missing or truncated'));
});

test('Compact Governance: Ed25519 cryptographic signing and verification', () => {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const env = createCompactedStateEnvelope(VALID_SAMPLE_STATE, {
    signerPrivateKey: privateKey,
    signerKeyId: 'ED25519-SUPERVISOR-ROOT-TEST'
  });

  assert.equal(env.signedBy, 'ED25519-SUPERVISOR-ROOT-TEST');
  assert.ok(typeof env.signature === 'string' && env.signature.length > 0);

  // Verification with valid public key
  const validCheck = validateCompactedStateEnvelope(env, {}, { verifierPublicKey: publicKey });
  assert.equal(validCheck.valid, true);

  // Verification with wrong public key fails closed
  const { publicKey: wrongKey } = crypto.generateKeyPairSync('ed25519');
  const wrongCheck = validateCompactedStateEnvelope(env, {}, { verifierPublicKey: wrongKey });
  assert.equal(wrongCheck.valid, false);
  assert.ok(wrongCheck.error.includes('signature verification failed'));
});

test('Compact Governance: assertCompactSafe verifies uncompromised compaction transition', () => {
  const env = createCompactedStateEnvelope(VALID_SAMPLE_STATE);
  const serialized = serializeCompactedAuditHeader(env);

  const compactedTranscript = [
    '### Conversation History Compacted by /compact',
    'Previous analysis concluded inventory mapping.',
    serialized,
    'Continuing to 3-lens verifier consensus.'
  ].join('\n\n');

  const result = assertCompactSafe(VALID_SAMPLE_STATE, compactedTranscript);
  assert.equal(result.safe, true);
  assert.equal(result.error, null);
  assert.equal(result.envelope.scanRunId, VALID_SAMPLE_STATE.scanRunId);
});

test('Compact Governance: assertCompactSafe rejects when compaction strips envelope', () => {
  const strippedTranscript = [
    '### Conversation History Compacted by /compact',
    'All details summarized: audit in progress.',
    'Continuing to 3-lens verifier consensus.'
  ].join('\n\n');

  const result = assertCompactSafe(VALID_SAMPLE_STATE, strippedTranscript);
  assert.equal(result.safe, false);
  assert.ok(result.error.includes('Compaction stripped audit state envelope'));
});

test('Compact Governance: assertCompactSafe rejects executionNonce replay divergence', () => {
  const olderState = {
    ...VALID_SAMPLE_STATE,
    executionNonce: 'REPLAY-OLD-NONCE-111'
  };
  const env = createCompactedStateEnvelope(olderState);
  const serialized = serializeCompactedAuditHeader(env);

  const replayTranscript = [
    '### Conversation History Compacted',
    serialized
  ].join('\n\n');

  // Verify against current expected state
  const result = assertCompactSafe(VALID_SAMPLE_STATE, replayTranscript);
  assert.equal(result.safe, false);
  assert.ok(result.error.includes('Nonce mismatch') || result.error.includes('invariant violation'));
});

test('Compact Governance: F05 - assertCompactSafe catches mutated persistedState via deep comparison', () => {
  const originalState = {
    ...VALID_SAMPLE_STATE,
    persistedState: {
      candidatesReviewed: 5,
      ballotCounts: { pass: 5, fail: 0 }
    }
  };
  const env = createCompactedStateEnvelope(originalState);

  // Attacker crafts transcript with altered persistedState and recomputed stateDigest
  const tamperedEnv = JSON.parse(JSON.stringify(env));
  tamperedEnv.persistedState.ballotCounts.pass = 99; // Forged votes
  tamperedEnv.persistedStateDigest = sha256Digest(canonicalJsonStringify(tamperedEnv.persistedState));
  const tamperedPayload = {
    scanRunId: tamperedEnv.scanRunId,
    executionNonce: tamperedEnv.executionNonce,
    toolManifestDigest: tamperedEnv.toolManifestDigest,
    repoRootFingerprint: tamperedEnv.repoRootFingerprint,
    persistedStateDigest: tamperedEnv.persistedStateDigest,
    persistedState: tamperedEnv.persistedState
  };
  tamperedEnv.stateDigest = sha256Digest(canonicalJsonStringify(tamperedPayload));

  const serializedTampered = serializeCompactedAuditHeader(tamperedEnv);

  const compactedTranscript = [
    '### Conversation History Compacted by /compact',
    serializedTampered,
    'Proceeding to report.'
  ].join('\n\n');

  const result = assertCompactSafe(originalState, compactedTranscript);
  assert.equal(result.safe, false);
  assert.ok(result.error.includes('persistedState tamper detected') || result.error.includes('deep immutable comparison failed'));
});

test('Compact Governance: F05 - Mandatory signature enforcement fails closed when unsigned', () => {
  const env = createCompactedStateEnvelope(VALID_SAMPLE_STATE); // unsigned
  const serialized = serializeCompactedAuditHeader(env);
  const transcript = `### History\n${serialized}\nDone.`;

  const result = assertCompactSafe(VALID_SAMPLE_STATE, transcript, { requireSignature: true });
  assert.equal(result.safe, false);
  assert.ok(result.error.includes('missing required cryptographic signature'));
});

test('Compact Governance: F06 - finalizeScan wires CASE guard and fails closed to UNCHECKABLE on corrupted envelope', () => {
  const corruptedContent = '<!-- THREE_LENS_COMPACT_STATE_START -->\n```json\n{"invalid":"data"}\n```\n<!-- THREE_LENS_COMPACT_STATE_END -->';

  const res = finalizeScan({
    repoRoot: process.cwd(),
    compactedAuditContent: corruptedContent
  });

  assert.equal(res.coverageStatus, 'UNCHECKABLE');
  assert.equal(res.summary.assuranceLabel, 'UNCHECKABLE');
  assert.equal(res.summary.canDeclareClean, false);
  assert.equal(res.summary.gates.compactGate, false);
  assert.equal(res.compactGuard.valid, false);
  assert.equal(res.compactGuard.status, 'UNCHECKABLE');
});

test('Compact Governance: F06 - finalizeScan accepts valid CASE envelope', () => {
  const scanRunId = 'scan-run-valid-999';
  const executionNonce = 'NONCE-LEGAL-777';
  const validEnvelope = createCompactedStateEnvelope({
    scanRunId,
    executionNonce,
    toolManifestDigest: '',
    repoRootFingerprint: ''
  });

  const res = finalizeScan({
    repoRoot: process.cwd(),
    scanRunId,
    nonce: executionNonce,
    compactedAuditEnvelope: validEnvelope
  });

  assert.equal(res.summary.gates.compactGate, true);
  assert.equal(res.compactGuard.valid, true);
  assert.equal(res.compactGuard.status, 'VERIFIED');
});
