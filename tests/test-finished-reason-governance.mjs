import test from 'node:test';
import assert from 'node:assert/strict';
import { parseStreamJsonTrace } from '../skills/security-audit/scripts/record-benchmark-run.mjs';

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

  const trace = parseStreamJsonTrace(normalTrace);
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
