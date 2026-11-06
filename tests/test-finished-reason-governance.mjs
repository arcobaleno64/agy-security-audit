import test from 'node:test';
import assert from 'node:assert/strict';
import { parseStreamJsonTrace } from '../skills/3lens/scripts/record-benchmark-run.mjs';
import { parseClaudeStreamJsonTrace } from '../scripts/run-cross-provider-benchmark.mjs';

test('finished_reason lifecycle governance: omitted finished_reason on exit 0 is clean', () => {
  const normalTrace = [
    JSON.stringify({ event: 'init', init: { tools: ['view_file'] } }),
    JSON.stringify({
      event: 'result',
      result: {
        status: 'SUCCESS',
        response: JSON.stringify({ candidates: [] }),
        duration_seconds: 1.2
      }
    })
  ].join('\n');

  const trace = parseStreamJsonTrace(normalTrace, { exitCode: 0 });
  assert.equal(trace.success, true);
  assert.equal(trace.telemetry.finishedReason, null);
  assert.equal(trace.error, null);
});

test('finished_reason lifecycle governance: explicit stop finished_reason is clean', () => {
  const normalTrace = [
    JSON.stringify({ event: 'init', init: { tools: ['view_file'] } }),
    JSON.stringify({
      event: 'result',
      result: {
        status: 'SUCCESS',
        finished_reason: 'stop',
        response: JSON.stringify({ candidates: [] }),
        duration_seconds: 1.2
      }
    })
  ].join('\n');

  const trace = parseStreamJsonTrace(normalTrace);
  assert.equal(trace.success, true);
  assert.equal(trace.telemetry.finishedReason, 'stop');
  assert.equal(trace.error, null);
});

test('finished_reason lifecycle governance: safety filter fails closed as CENSORED_EXPOSURE', () => {
  const censoredTrace = [
    JSON.stringify({ event: 'init', init: { tools: ['view_file'] } }),
    JSON.stringify({
      event: 'result',
      result: {
        status: 'SUCCESS',
        finished_reason: 'safety',
        response: '',
        duration_seconds: 0.5
      }
    })
  ].join('\n');

  const trace = parseStreamJsonTrace(censoredTrace);
  assert.equal(trace.success, false);
  assert.equal(trace.telemetry.finishedReason, 'safety');
  assert.match(trace.error, /CENSORED_EXPOSURE.*safety/);
});

test('finished_reason lifecycle governance: token truncation fails closed as CENSORED_EXPOSURE', () => {
  const truncatedTrace = [
    JSON.stringify({ event: 'init', init: { tools: ['view_file'] } }),
    JSON.stringify({
      event: 'result',
      result: {
        status: 'SUCCESS',
        finished_reason: 'max_tokens',
        response: '{"candidates":[{"id":"SEC-01"',
        duration_seconds: 4.8
      }
    })
  ].join('\n');

  const trace = parseStreamJsonTrace(truncatedTrace);
  assert.equal(trace.success, false);
  assert.equal(trace.telemetry.finishedReason, 'max_tokens');
  assert.match(trace.error, /CENSORED_EXPOSURE.*token limit/);
});

test('finished_reason lifecycle governance: accumulated text without final result event fails closed as CENSORED_EXPOSURE', () => {
  const noResultTrace = [
    JSON.stringify({ event: 'init', init: { tools: ['view_file'] } }),
    JSON.stringify({
      event: 'step_update',
      step_update: {
        text_delta: '{"candidates":[{"id":"SEC-01"}]}'
      }
    })
    // No result event!
  ].join('\n');

  const trace = parseStreamJsonTrace(noResultTrace);
  assert.equal(trace.success, false);
  assert.match(trace.error, /CENSORED_EXPOSURE.*without final result event/);
});

test('finished_reason lifecycle governance: empty response on result event fails closed as CENSORED_EXPOSURE', () => {
  const emptyResTrace = [
    JSON.stringify({ event: 'init', init: { tools: ['view_file'] } }),
    JSON.stringify({
      event: 'result',
      result: {
        status: 'SUCCESS',
        response: '   '
      }
    })
  ].join('\n');

  const trace = parseStreamJsonTrace(emptyResTrace);
  assert.equal(trace.success, false);
  assert.match(trace.error, /CENSORED_EXPOSURE.*empty response text/);
});

test('finished_reason lifecycle governance: delta fallback bypass counterexample F02 (Fail-Closed Invariant)', () => {
  // Counterexample identified by ChatGPT R3:
  // Even if accumulated text was received via step_update, if result.response is empty, it MUST NOT fall back to accumulated text!
  const deltaFallbackTrace = [
    JSON.stringify({ event: 'init', init: { tools: ['view_file'] } }),
    JSON.stringify({
      event: 'step_update',
      step_update: {
        text_delta: '{"candidates":[{"id":"SEC-01"}]}'
      }
    }),
    JSON.stringify({
      event: 'result',
      result: {
        status: 'SUCCESS',
        response: '' // Empty response in result!
      }
    })
  ].join('\n');

  const trace = parseStreamJsonTrace(deltaFallbackTrace);
  assert.equal(trace.success, false, 'Empty result.response must not be rescued by accumulated delta text');
  assert.match(trace.error, /CENSORED_EXPOSURE.*empty response text/);
});

test('finished_reason lifecycle governance: non-allowlisted finished_reason interrupted (Fail-Closed Invariant)', () => {
  const interruptedTrace = [
    JSON.stringify({ event: 'init', init: { tools: ['view_file'] } }),
    JSON.stringify({
      event: 'result',
      result: {
        status: 'SUCCESS',
        finished_reason: 'interrupted',
        response: '{"candidates":[]}'
      }
    })
  ].join('\n');

  const trace = parseStreamJsonTrace(interruptedTrace);
  assert.equal(trace.success, false);
  assert.match(trace.error, /CENSORED_EXPOSURE.*non-allowlisted finished_reason: 'interrupted'/);
});

test('finished_reason lifecycle governance: non-allowlisted finished_reason print_timeout (Fail-Closed Invariant)', () => {
  const timeoutTrace = [
    JSON.stringify({ event: 'init', init: { tools: ['view_file'] } }),
    JSON.stringify({
      event: 'result',
      result: {
        status: 'SUCCESS',
        finished_reason: 'print_timeout',
        response: '{"candidates":[]}'
      }
    })
  ].join('\n');

  const trace = parseStreamJsonTrace(timeoutTrace);
  assert.equal(trace.success, false);
  assert.match(trace.error, /CENSORED_EXPOSURE.*non-allowlisted finished_reason: 'print_timeout'/);
});

test('finished_reason lifecycle governance: allowlist completion reasons (stop, end_turn, complete)', () => {
  for (const reason of ['stop', 'end_turn', 'complete', 'completed', 'eos', 'stop_sequence']) {
    const traceString = [
      JSON.stringify({ event: 'init', init: { tools: ['view_file'] } }),
      JSON.stringify({
        event: 'result',
        result: {
          status: 'SUCCESS',
          finished_reason: reason,
          response: '{"candidates":[]}'
        }
      })
    ].join('\n');

    const trace = parseStreamJsonTrace(traceString);
    assert.equal(trace.success, true, `Reason '${reason}' should be accepted in allowlist`);
    assert.equal(trace.telemetry.finishedReason, reason);
  }
});

test('finished_reason lifecycle governance: non-zero exit code 1 fails closed (Exit Code + Result Event + Schema triple contract)', () => {
  const normalTrace = [
    JSON.stringify({ event: 'init', init: { tools: ['view_file'] } }),
    JSON.stringify({
      event: 'result',
      result: {
        status: 'SUCCESS',
        response: JSON.stringify({ candidates: [] }),
        duration_seconds: 1.2
      }
    })
  ].join('\n');

  const trace = parseStreamJsonTrace(normalTrace, { exitCode: 1 });
  assert.equal(trace.success, false);
  assert.match(trace.error, /^CENSORED_EXPOSURE: Process terminated with non-zero exit code: 1/);
  assert.equal(trace.telemetry.finishedReason, 'CENSORED_EXPOSURE');
});

test('finished_reason lifecycle governance: non-zero exit code 137 (SIGKILL/OOM) fails closed', () => {
  const normalTrace = [
    JSON.stringify({ event: 'init', init: { tools: ['view_file'] } }),
    JSON.stringify({
      event: 'result',
      result: {
        status: 'SUCCESS',
        response: JSON.stringify({ candidates: [] }),
        duration_seconds: 1.2
      }
    })
  ].join('\n');

  const trace = parseStreamJsonTrace(normalTrace, 137);
  assert.equal(trace.success, false);
  assert.match(trace.error, /^CENSORED_EXPOSURE: Process terminated with non-zero exit code: 137/);
  assert.equal(trace.telemetry.finishedReason, 'CENSORED_EXPOSURE');
});

test('finished_reason lifecycle governance: non-zero exit code unconditionally overrides pre-existing finished_reason to CENSORED_EXPOSURE', () => {
  const stoppedTrace = [
    JSON.stringify({ event: 'init', init: { tools: ['view_file'] } }),
    JSON.stringify({
      event: 'result',
      result: {
        status: 'SUCCESS',
        response: JSON.stringify({ candidates: [] }),
        finished_reason: 'stop',
        duration_seconds: 1.2
      }
    })
  ].join('\n');

  const trace = parseStreamJsonTrace(stoppedTrace, { exitCode: 1 });
  assert.equal(trace.success, false);
  assert.match(trace.error, /^CENSORED_EXPOSURE: Process terminated with non-zero exit code: 1/);
  assert.equal(trace.telemetry.finishedReason, 'CENSORED_EXPOSURE');
});

test('finished_reason lifecycle governance: signal termination (SIGTERM/SIGKILL with status null) fails closed as CENSORED_EXPOSURE', () => {
  const normalTrace = [
    JSON.stringify({ event: 'init', init: { tools: ['view_file'] } }),
    JSON.stringify({
      event: 'result',
      result: {
        status: 'SUCCESS',
        response: JSON.stringify({ candidates: [] }),
        duration_seconds: 1.2
      }
    })
  ].join('\n');

  // Exact R15-F02-01 counterexample: status is null, signal is SIGTERM
  const trace = parseStreamJsonTrace(normalTrace, { exitCode: 0, signal: 'SIGTERM' });
  assert.equal(trace.success, false);
  assert.match(trace.error, /^CENSORED_EXPOSURE: Process terminated by signal: SIGTERM/);
  assert.equal(trace.telemetry.finishedReason, 'CENSORED_EXPOSURE');
});

test('finished_reason lifecycle governance: Claude stream missing result event fails closed as CENSORED_EXPOSURE (R15-F02-02)', () => {
  // Exact R15-F02-02 counterexample: assistant events produce text, but stream ends without result event
  const truncatedClaudeTrace = [
    JSON.stringify({ type: 'system', session_id: 'test-session-1' }),
    JSON.stringify({
      type: 'assistant',
      message: {
        model: 'claude-sonnet-5',
        content: [{ type: 'text', text: '{"candidates":[{"ruleId":"CWE-79"}]}' }]
      }
    })
  ].join('\n');

  const trace = parseClaudeStreamJsonTrace(truncatedClaudeTrace, { exitCode: 0 });
  assert.equal(trace.success, false, 'Claude trace without result event must fail closed');
  assert.match(trace.error, /^CENSORED_EXPOSURE: NDJSON stream terminated prematurely without final result event/);
});

test('finished_reason lifecycle governance: Live benchmark runner signal normalization counterexample R16-F02-01 (SIGTERM with status null fails closed)', () => {
  // Replays R16-F02-01 counterexample: spawnSync returns status: null, signal: 'SIGTERM'
  // Live benchmark caller exitCode calculation and signal propagation must fail closed
  const normalTrace = [
    JSON.stringify({ event: 'init', init: { tools: ['view_file'] } }),
    JSON.stringify({
      event: 'result',
      result: {
        status: 'SUCCESS',
        response: JSON.stringify({ candidates: [{ ruleId: 'CWE-89' }] }),
        duration_seconds: 1.2
      }
    })
  ].join('\n');

  // Simulated child process result from spawnSync:
  const mockChildResult = {
    status: null,
    signal: 'SIGTERM',
    stdout: normalTrace,
    stderr: '',
    error: undefined
  };

  // Live benchmark normalization logic (R16-F02-01):
  const procSignal = mockChildResult.signal || null;
  const exitCode = mockChildResult.status !== null
    ? mockChildResult.status
    : (mockChildResult.signal ? 128 : (mockChildResult.error ? 1 : 0));

  assert.equal(exitCode, 128, 'Signal termination must not normalize to 0');

  const trace = parseStreamJsonTrace(mockChildResult.stdout, { exitCode, signal: procSignal });
  assert.equal(trace.success, false, 'Trace with SIGTERM must fail closed even with valid result event');
  assert.match(trace.error, /CENSORED_EXPOSURE: Process terminated by signal: SIGTERM/);
  assert.equal(trace.telemetry.finishedReason, 'CENSORED_EXPOSURE');
});

