import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import {
  validateAcpHandshake,
  resolveTransport,
  probeNativeAcpServer,
  probeNativeAcpServerAsync,
  connectNativeAcpTransport,
  TRANSPORT_PRIORITIES,
  TRANSPORT_STATUS,
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

// Gate 0 (R15-F04-01 / R16-F04-01): Persistent Mock ACP Server script code
const MOCK_PERSISTENT_SERVER_CODE = `
process.stdin.setEncoding('utf8');
let buffer = '';
process.stdin.on('data', (chunk) => {
  buffer += chunk;
  const lines = buffer.split('\\n');
  buffer = lines.pop();

  for (const line of lines) {
    if (!line.trim()) continue;
    let req;
    try { req = JSON.parse(line.trim()); } catch { continue; }

    if (req.method === 'initialize') {
      const response = {
        jsonrpc: '2.0',
        id: req.id,
        result: {
          protocolVersion: 1,
          agentInfo: { name: 'Antigravity ACP Persistent Server', version: '1.5.1' },
          agentCapabilities: {
            loadSession: true,
            promptCapabilities: { image: true, embeddedContext: true },
            sessionCapabilities: { resume: {}, close: {}, load: {} }
          },
          authMethods: [{ id: 'oauth-personal', name: 'Log in with Google' }]
        }
      };
      process.stdout.write(JSON.stringify(response) + '\\n');
    } else if (req.method === 'ping') {
      const response = {
        jsonrpc: '2.0',
        id: req.id,
        result: { pong: true, echo: req.params?.echo || 'ok' }
      };
      process.stdout.write(JSON.stringify(response) + '\\n');
    } else if (req.method === 'ping_unverified_noise') {
      // Counterexample R17-F04-01: missing jsonrpc version
      process.stdout.write(JSON.stringify({ id: req.id, noise: 'unverified' }) + '\\n');
    } else if (req.method === 'ping_wrong_version') {
      // Counterexample R17-F04-01: invalid jsonrpc 1.0 version
      process.stdout.write(JSON.stringify({ jsonrpc: '1.0', id: req.id, result: { pong: true } }) + '\\n');
    } else if (req.method === 'exit') {
      process.exit(0);
    }
  }
});
setInterval(() => {}, 1000000);
`;

test('ACP Governance (R15-F04-01): probeNativeAcpServer succeeds with PROBE_VERIFIED on persistent daemon without requiring process exit', () => {
  // Simulates a persistent ACP server that responds to initialize and stays alive, causing timeout on spawnSync.
  // The probe must parse the stdout response and succeed as PROBE_VERIFIED without failing.
  const probe = probeNativeAcpServer({
    agyBin: process.execPath,
    args: ['-e', MOCK_PERSISTENT_SERVER_CODE],
    timeoutMs: 1000,
    allowFallback: false
  });

  assert.equal(probe.transport, 'NATIVE_ACP');
  assert.equal(probe.priority, 1);
  assert.equal(probe.status, TRANSPORT_STATUS.PROBE_VERIFIED);
  assert.equal(probe.agentInfo.name, 'Antigravity ACP Persistent Server');
  assert.equal(probe.agentInfo.version, '1.5.1');
  assert.equal(probe.error, null);
});

test('ACP Governance (R15-F04-01): probeNativeAcpServerAsync completes non-blocking stream probe without waiting for timeout', async () => {
  const start = Date.now();
  const probe = await probeNativeAcpServerAsync({
    agyBin: process.execPath,
    args: ['-e', MOCK_PERSISTENT_SERVER_CODE],
    timeoutMs: 5000,
    allowFallback: false
  });
  const elapsed = Date.now() - start;

  assert.ok(elapsed < 2000, `Async probe must complete quickly without waiting for timeout (took ${elapsed}ms)`);
  assert.equal(probe.transport, 'NATIVE_ACP');
  assert.equal(probe.priority, 1);
  assert.equal(probe.status, TRANSPORT_STATUS.PROBE_VERIFIED);
  assert.equal(probe.agentInfo.name, 'Antigravity ACP Persistent Server');
  assert.equal(probe.error, null);
});

test('ACP Governance (R15-F04-01): connectNativeAcpTransport establishes persistent ACTIVE session with bidirectional channel', async () => {
  const session = await connectNativeAcpTransport({
    agyBin: process.execPath,
    args: ['-e', MOCK_PERSISTENT_SERVER_CODE],
    timeoutMs: 5000,
    allowFallback: false
  });

  try {
    assert.equal(session.transport, 'NATIVE_ACP');
    assert.equal(session.priority, 1);
    assert.equal(session.status, TRANSPORT_STATUS.ACTIVE);
    assert.equal(session.agentInfo.name, 'Antigravity ACP Persistent Server');
    assert.ok(session.process, 'Active session must retain child process reference');
    assert.equal(typeof session.send, 'function', 'Active session must provide send function');
    assert.equal(typeof session.request, 'function', 'Active session must provide request dispatcher');
    assert.equal(typeof session.close, 'function', 'Active session must provide close function');
    assert.equal(session.error, null);
    assert.equal(session.isActive(), true);
  } finally {
    session.close();
  }
});

test('ACP Governance (R16-F04-01): Active session successfully executes subsequent JSON-RPC request-response exchange', async () => {
  const session = await connectNativeAcpTransport({
    agyBin: process.execPath,
    args: ['-e', MOCK_PERSISTENT_SERVER_CODE],
    timeoutMs: 5000,
    allowFallback: false
  });

  try {
    assert.equal(session.status, TRANSPORT_STATUS.ACTIVE);
    const res = await session.request('ping', { echo: 'governance_verify' });
    assert.equal(res.pong, true);
    assert.equal(res.echo, 'governance_verify');
  } finally {
    session.close();
  }
});

test('ACP Governance (R16-F04-01): Server exit immediately invalidates ACTIVE session to TERMINATED and fails subsequent requests fail-closed', async () => {
  const session = await connectNativeAcpTransport({
    agyBin: process.execPath,
    args: ['-e', MOCK_PERSISTENT_SERVER_CODE],
    timeoutMs: 5000,
    allowFallback: false
  });

  assert.equal(session.status, TRANSPORT_STATUS.ACTIVE);
  assert.equal(session.isActive(), true);

  // Trigger server clean exit via JSON-RPC exit method
  const closedPromise = new Promise((resolve) => session.onClose(resolve));
  session.send({ jsonrpc: '2.0', id: 99, method: 'exit' });

  await closedPromise;

  // Verify dynamic state transition
  assert.equal(session.status, TRANSPORT_STATUS.TERMINATED);
  assert.equal(session.isActive(), false);

  // Subsequent send() must throw fail-closed
  assert.throws(
    () => session.send({ jsonrpc: '2.0', method: 'ping' }),
    /Cannot send message: ACP transport is not active/
  );

  // Subsequent request() must reject fail-closed
  await assert.rejects(
    async () => session.request('ping'),
    /Cannot send request: ACP transport is not active/
  );
});

test('ACP Governance (R17-F04-01): Active session response dispatcher strictly rejects non-JSON-RPC 2.0 payloads and wrong protocol versions', async () => {
  const session = await connectNativeAcpTransport({
    agyBin: process.execPath,
    args: ['-e', MOCK_PERSISTENT_SERVER_CODE],
    timeoutMs: 5000,
    allowFallback: false
  });

  try {
    assert.equal(session.status, TRANSPORT_STATUS.ACTIVE);

    // Negative Counterexample 1: Missing jsonrpc entirely (noise payload {"id":2, "noise":"unverified"})
    await assert.rejects(
      async () => session.request('ping_unverified_noise'),
      /Invalid JSON-RPC protocol version in response: expected '2.0', got 'undefined'/
    );

    // Negative Counterexample 2: Invalid JSON-RPC protocol version {"jsonrpc":"1.0", ...}
    await assert.rejects(
      async () => session.request('ping_wrong_version'),
      /Invalid JSON-RPC protocol version in response: expected '2.0', got '1.0'/
    );

    // Positive Control: Valid JSON-RPC 2.0 response succeeds
    const validRes = await session.request('ping', { echo: 'valid_2.0' });
    assert.equal(validRes.pong, true);
    assert.equal(validRes.echo, 'valid_2.0');
  } finally {
    session.close();
  }
});

test('ACP Governance (R17-F04-02): onClose listeners receive consistent at-most-once notification across all termination pathways', async () => {
  // Pathway 1: Client explicit session.close()
  const session1 = await connectNativeAcpTransport({
    agyBin: process.execPath,
    args: ['-e', MOCK_PERSISTENT_SERVER_CODE],
    timeoutMs: 5000,
    allowFallback: false
  });

  let closeCount1 = 0;
  let closeEvent1 = null;
  session1.onClose((evt) => {
    closeCount1++;
    closeEvent1 = evt;
  });

  session1.close('explicit_test');
  // Wait a small tick to allow any potential duplicate exit events
  await new Promise(r => setTimeout(r, 50));

  assert.equal(closeCount1, 1, 'Client close must trigger onClose exactly once');
  assert.equal(closeEvent1.origin, 'client');
  assert.equal(session1.status, TRANSPORT_STATUS.TERMINATED);

  // Pathway 2: Server exit
  const session2 = await connectNativeAcpTransport({
    agyBin: process.execPath,
    args: ['-e', MOCK_PERSISTENT_SERVER_CODE],
    timeoutMs: 5000,
    allowFallback: false
  });

  let closeCount2 = 0;
  let closeEvent2 = null;
  session2.onClose((evt) => {
    closeCount2++;
    closeEvent2 = evt;
  });

  const exitPromise = new Promise(r => session2.onClose(r));
  session2.send({ jsonrpc: '2.0', id: 101, method: 'exit' });
  await exitPromise;
  await new Promise(r => setTimeout(r, 50));

  assert.equal(closeCount2, 1, 'Server exit must trigger onClose exactly once');
  assert.equal(closeEvent2.origin, 'exit');
  assert.equal(session2.status, TRANSPORT_STATUS.TERMINATED);
});
