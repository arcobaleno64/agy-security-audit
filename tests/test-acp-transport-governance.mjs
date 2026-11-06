import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import {
  validateAcpHandshake,
  resolveTransport,
  probeNativeAcpServer,
  TRANSPORT_PRIORITIES,
  ACP_PROTOCOL_VERSION,
  ACP_PROTOCOL_NAME
} from '../scripts/adapters/acp-transport-adapter.mjs';

const VALID_HANDSHAKE_RESPONSE = {
  jsonrpc: '2.0',
  id: 1,
  result: {
    protocolVersion: 1,
    agentInfo: { name: 'Antigravity ACP Server', version: '1.5.1' },
    agentCapabilities: {
      loadSession: true,
      promptCapabilities: { image: true, embeddedContext: true },
      sessionCapabilities: { resume: {}, close: {}, load: {} }
    },
    authMethods: [{ id: 'oauth-personal', name: 'Log in with Google' }]
  }
};

test('ACP Governance: Native ACP is assigned Priority 1 (Highest)', () => {
  assert.equal(TRANSPORT_PRIORITIES.NATIVE_ACP, 1);
  assert.ok(TRANSPORT_PRIORITIES.NATIVE_ACP < TRANSPORT_PRIORITIES.ISOLATED_STDIO);
});

test('ACP Governance: Valid ACP JSON-RPC handshake resolves to NATIVE_ACP transport', () => {
  const resolution = resolveTransport({
    enableNativeAcp: true,
    probeResponse: VALID_HANDSHAKE_RESPONSE
  });

  assert.equal(resolution.status, 'ACTIVE');
  assert.equal(resolution.transport, 'NATIVE_ACP');
  assert.equal(resolution.priority, 1);
  assert.equal(resolution.protocol, ACP_PROTOCOL_NAME);
  assert.equal(resolution.agentInfo.name, 'Antigravity ACP Server');
  assert.equal(resolution.error, null);
});

test('ACP Governance: Corrupt or malformed JSON-RPC payload fails closed', () => {
  const malformed = '{ invalid json }}}';
  const val = validateAcpHandshake(malformed);
  assert.equal(val.valid, false);
  assert.match(val.error, /Malformed JSON-RPC handshake/);

  const resolution = resolveTransport({
    enableNativeAcp: true,
    probeResponse: malformed,
    allowFallback: false
  });
  assert.equal(resolution.status, 'FAILED');
  assert.equal(resolution.transport, 'NONE');
  assert.match(resolution.error, /Native ACP handshake failed.*Fail-Closed/);
});

test('ACP Governance: Protocol version mismatch fails closed under Default-Deny', () => {
  const futureVersion = JSON.parse(JSON.stringify(VALID_HANDSHAKE_RESPONSE));
  futureVersion.result.protocolVersion = 99;

  const val = validateAcpHandshake(futureVersion);
  assert.equal(val.valid, false);
  assert.match(val.error, /Protocol version mismatch/);

  const resolution = resolveTransport({
    enableNativeAcp: true,
    probeResponse: futureVersion,
    allowFallback: false
  });
  assert.equal(resolution.status, 'FAILED');
  assert.match(resolution.error, /Protocol version mismatch.*Fail-Closed/);
});

test('ACP Governance: Incomplete agentCapabilities fails closed under Default-Deny', () => {
  const incompleteCaps = JSON.parse(JSON.stringify(VALID_HANDSHAKE_RESPONSE));
  delete incompleteCaps.result.agentCapabilities.promptCapabilities;

  const val = validateAcpHandshake(incompleteCaps);
  assert.equal(val.valid, false);
  assert.match(val.error, /Incomplete native ACP capabilities profile/);
});

test('ACP Governance: R14-F04-02 counterexample missing agentInfo and empty capabilities fails closed', () => {
  // Exact counterexample provided by ChatGPT reviewer in R14
  const counterexample = {
    jsonrpc: '2.0',
    id: 999,
    result: {
      protocolVersion: 1,
      agentCapabilities: {
        promptCapabilities: {},
        sessionCapabilities: {}
      }
    }
  };

  const val = validateAcpHandshake(counterexample);
  assert.equal(val.valid, false, 'Counterexample must fail validation');
  assert.match(val.error, /agentInfo|capabilities/i);

  const resolution = resolveTransport({
    enableNativeAcp: true,
    probeResponse: counterexample,
    allowFallback: false
  });
  assert.equal(resolution.status, 'FAILED');
  assert.equal(resolution.transport, 'NONE');
});

test('ACP Governance: Response ID mismatch fails closed under Default-Deny', () => {
  const mismatchedId = JSON.parse(JSON.stringify(VALID_HANDSHAKE_RESPONSE));
  mismatchedId.id = 999;

  const val = validateAcpHandshake(mismatchedId, { expectedId: 1 });
  assert.equal(val.valid, false);
  assert.match(val.error, /JSON-RPC response ID mismatch/);

  const resolution = resolveTransport({
    enableNativeAcp: true,
    probeResponse: mismatchedId,
    expectedId: 1,
    allowFallback: false
  });
  assert.equal(resolution.status, 'FAILED');
  assert.equal(resolution.transport, 'NONE');
});

test('ACP Governance: Missing agentInfo name or version fails closed', () => {
  const noName = JSON.parse(JSON.stringify(VALID_HANDSHAKE_RESPONSE));
  delete noName.result.agentInfo.name;
  const val1 = validateAcpHandshake(noName);
  assert.equal(val1.valid, false);
  assert.match(val1.error, /agentInfo/);

  const emptyVersion = JSON.parse(JSON.stringify(VALID_HANDSHAKE_RESPONSE));
  emptyVersion.result.agentInfo.version = '  ';
  const val2 = validateAcpHandshake(emptyVersion);
  assert.equal(val2.valid, false);
  assert.match(val2.error, /agentInfo/);
});

test('ACP Governance: Handshake failure with allowFallback false strictly terminates fail-closed', () => {
  const errorHandshake = {
    jsonrpc: '2.0',
    id: 1,
    error: { code: -32600, message: 'Invalid Request' }
  };

  const resolution = resolveTransport({
    enableNativeAcp: true,
    probeResponse: errorHandshake,
    allowFallback: false
  });

  assert.equal(resolution.status, 'FAILED');
  assert.equal(resolution.transport, 'NONE');
  assert.match(resolution.error, /Server returned JSON-RPC error.*Fail-Closed/);
});

test('ACP Governance: Handshake failure with allowFallback true transitions safely to ISOLATED_STDIO', () => {
  const errorHandshake = {
    jsonrpc: '2.0',
    id: 1,
    error: { code: -32603, message: 'Internal Server Error' }
  };

  const resolution = resolveTransport({
    enableNativeAcp: true,
    probeResponse: errorHandshake,
    allowFallback: true
  });

  assert.equal(resolution.status, 'FALLBACK');
  assert.equal(resolution.transport, 'ISOLATED_STDIO');
  assert.equal(resolution.priority, 2);
  assert.match(resolution.fallbackReason, /Server returned JSON-RPC error/);
  assert.equal(resolution.error, null);
});

test('ACP Governance: Physical probe record evals/protocols/acp-stdio-probe-record.json replay verification', () => {
  const probeFile = path.resolve('evals/protocols/acp-stdio-probe-record.json');
  assert.ok(fs.existsSync(probeFile), 'Physical probe record file must exist on disk');

  const content = JSON.parse(fs.readFileSync(probeFile, 'utf8'));
  assert.equal(content.protocol, 'ACP_STDIO_JSONRPC_V1');
  assert.equal(content.provenance.serverName, 'Antigravity ACP Server');
  assert.equal(content.provenance.serverVersion, '1.5.1');

  // Extract Step 2 server initialize response
  const initStep = content.probeTranscript.find(s => s.step === 2 && s.direction === 'SERVER_TO_CLIENT');
  assert.ok(initStep, 'Step 2 initialize response must exist in transcript');

  const validation = validateAcpHandshake(initStep.message);
  assert.equal(validation.valid, true);
  assert.equal(validation.agentInfo.name, 'Antigravity ACP Server');
  assert.equal(validation.agentInfo.version, '1.5.1');

  const resolution = resolveTransport({
    enableNativeAcp: true,
    probeResponse: initStep.message
  });
  assert.equal(resolution.status, 'ACTIVE');
  assert.equal(resolution.transport, 'NATIVE_ACP');
  assert.equal(resolution.priority, 1);
});

test('ACP Governance: probeNativeAcpServer handles binary probe failure safely under Default-Deny', () => {
  // Test with non-existent binary to verify fail-closed and fallback transitions
  const failClosed = probeNativeAcpServer({
    agyBin: 'non_existent_binary_xyz_12345',
    allowFallback: false
  });
  assert.equal(failClosed.status, 'FAILED');
  assert.equal(failClosed.transport, 'NONE');

  const fallback = probeNativeAcpServer({
    agyBin: 'non_existent_binary_xyz_12345',
    allowFallback: true
  });
  assert.equal(fallback.status, 'FALLBACK');
  assert.equal(fallback.transport, 'ISOLATED_STDIO');
  assert.equal(fallback.priority, 2);
});
