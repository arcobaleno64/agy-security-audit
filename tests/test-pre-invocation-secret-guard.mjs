#!/usr/bin/env node
/**
 * test-pre-invocation-secret-guard.mjs
 * Verification suite for PreInvocation zero-token secret guard hook (M54-P1-F01).
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { scanForSecrets } from '../hooks/pre-invocation-secret-guard.mjs';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const HOOK_SCRIPT = path.resolve(__dirname, '../hooks/pre-invocation-secret-guard.mjs');

function runHook(payloadString) {
  const result = spawnSync(process.execPath, [HOOK_SCRIPT], {
    input: payloadString,
    encoding: 'utf8',
    timeout: 3000
  });

  assert.equal(result.status, 0, `Hook process exited with code ${result.status}, stderr: ${result.stderr}`);
  assert.ok(!result.stdout.includes('\r\n'), 'CRLF violation: hook output must be strictly LF-only');

  const parsed = JSON.parse(result.stdout.trim());
  return parsed;
}

test('PreInvocation Secret Guard - scanForSecrets unit checks', () => {
  assert.equal(scanForSecrets('audit src/controllers/user.js'), null);
  assert.equal(scanForSecrets('here is a key: AKIAIOSFODNN7EXAMPLE for AWS'), 'AWS_ACCESS_KEY');
  const dummyGh = ['ghp', '_', 'abcdefghijklmnopqrstuvwxyz0123456789'].join('');
  assert.equal(scanForSecrets(`token: ${dummyGh}`), 'GITHUB_TOKEN');
  assert.equal(scanForSecrets('-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0...'), 'PRIVATE_KEY');
  const dummySlack = ['xoxb', '-1234567890-1234567890123-abcdefghijklmnopqrstuvwx'].join('');
  assert.equal(scanForSecrets(dummySlack), 'SLACK_TOKEN');
});

test('PreInvocation Secret Guard - Clean Prompt (Allow Turn)', () => {
  const payload = {
    conversationId: 'test-clean',
    lastUserInput: 'Please review evals/semantic-benchmark/safe/01-authz-bypass.js for CWE-862'
  };
  const response = runHook(JSON.stringify(payload));
  assert.deepEqual(response, {}, 'Clean input must emit empty object (proceed normally)');
});

test('PreInvocation Secret Guard - Private Key Detection (Fail-Closed Terminate)', () => {
  const payload = {
    conversationId: 'test-private-key',
    lastUserInput: 'Check this configuration: -----BEGIN OPENSSH PRIVATE KEY----- b3BlbnNza...'
  };
  const response = runHook(JSON.stringify(payload));
  assert.equal(response.terminationBehavior, 'terminate');
  assert.ok(Array.isArray(response.injectSteps));
  assert.ok(response.injectSteps[0].errorMessage.userMessage.includes('PRIVATE_KEY'));
});

test('PreInvocation Secret Guard - AWS Key Detection in Messages Array', () => {
  const payload = {
    conversationId: 'test-aws-key',
    messages: [
      { role: 'user', content: 'Deploy with AWS_ACCESS_KEY_ID=AKIA1234567890ABCDEF now' }
    ]
  };
  const response = runHook(JSON.stringify(payload));
  assert.equal(response.terminationBehavior, 'terminate');
  assert.ok(response.injectSteps[0].errorMessage.userMessage.includes('AWS_ACCESS_KEY'));
});

test('PreInvocation Secret Guard - Malformed JSON Payload (Fail-Closed Invariant)', () => {
  const response = runHook('MALFORMED_NON_JSON_CONTENT');
  assert.equal(response.terminationBehavior, 'terminate');
  assert.ok(response.injectSteps[0].errorMessage.userMessage.includes('Fail-Closed'));
});
