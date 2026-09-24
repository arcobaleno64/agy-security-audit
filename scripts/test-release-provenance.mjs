#!/usr/bin/env node
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import { parseSha256Sums, verifyIntegrity, collectVerifiedSubjects, verifyAttestations, runCli } from './verify-release-provenance.mjs';

function assert(condition, message) {
  if (!condition) throw new Error(`ASSERTION_FAILED: ${message}`);
}
function sha(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
}
function expectThrow(fn, expected) {
  let matched = false;
  try { fn(); } catch (err) { matched = String(err.message).includes(expected); }
  assert(matched, `expected failure containing '${expected}'`);
}

let testsRun = 0;
const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'provenance-policy-test-'));
try {
  fs.writeFileSync(path.join(temp, 'a.txt'), 'alpha');
  fs.writeFileSync(path.join(temp, 'b.txt'), 'beta');
  const sums = `${sha(Buffer.from('alpha'))}  a.txt\n${sha(Buffer.from('beta'))}  b.txt\n`;
  fs.writeFileSync(path.join(temp, 'SHA256SUMS.txt'), sums);

  const integrity = verifyIntegrity(temp);
  assert(integrity.releaseFiles.length === 3, 'R contains two payloads plus SHA256SUMS.txt');
  testsRun++;

  const parsed = parseSha256Sums(sums);
  assert(parsed.size === 2 && parsed.get('a.txt') === sha(Buffer.from('alpha')), 'checksum manifest parses deterministically');
  testsRun++;

  expectThrow(() => parseSha256Sums(`${'0'.repeat(64)}  ../evil\n`), 'basename');
  testsRun++;

  fs.writeFileSync(path.join(temp, 'extra.txt'), 'extra');
  expectThrow(() => verifyIntegrity(temp), 'R != S');
  fs.unlinkSync(path.join(temp, 'extra.txt'));
  testsRun++;

  const statement = [{
    verificationResult: {
      statement: {
        predicateType: 'https://slsa.dev/provenance/v1',
        subject: [
          { name: 'a.txt', digest: { sha256: sha(Buffer.from('alpha')) } },
          { name: 'b.txt', digest: { sha256: sha(Buffer.from('beta')) } },
          { name: 'SHA256SUMS.txt', digest: { sha256: sha(Buffer.from(sums)) } }
        ]
      }
    }
  }];
  const subjects = collectVerifiedSubjects(statement);
  assert(subjects.size === 3, 'verified SLSA statement yields three canonical subjects');
  testsRun++;

  const traversalSubject = [{
    verificationResult: {
      statement: {
        predicateType: 'https://slsa.dev/provenance/v1',
        subject: [{ name: '../a.txt', digest: { sha256: sha(Buffer.from('alpha')) } }]
      }
    }
  }];
  expectThrow(() => collectVerifiedSubjects(traversalSubject), 'basename');
  testsRun++;

  let ghCalls = 0;
  const ghRunner = () => {
    ghCalls++;
    return JSON.stringify(statement);
  };
  const verified = verifyAttestations(integrity, {
    repo: 'arcobaleno64/agy-security-audit',
    signerWorkflow: 'arcobaleno64/agy-security-audit/.github/workflows/release.yml',
    sourceRef: 'refs/tags/v1.8.0',
    sourceDigest: '1'.repeat(40)
  }, ghRunner);
  assert(verified.attestedSubjects.size === 3 && ghCalls === 3, 'strict verification establishes R=S=A');
  testsRun++;

  const incomplete = [{
    verificationResult: {
      statement: {
        predicateType: 'https://slsa.dev/provenance/v1',
        subject: [{ name: 'a.txt', digest: { sha256: sha(Buffer.from('alpha')) } }]
      }
    }
  }];
  expectThrow(() => verifyAttestations(integrity, {
    repo: 'arcobaleno64/agy-security-audit',
    signerWorkflow: 'arcobaleno64/agy-security-audit/.github/workflows/release.yml',
    sourceRef: 'refs/tags/v1.8.0',
    sourceDigest: '1'.repeat(40)
  }, () => JSON.stringify(incomplete)), 'matching subject digest');
  testsRun++;

  expectThrow(() => runCli([
    '--dir', temp,
    '--repo', 'arcobaleno64/agy-security-audit',
    '--signer-workflow', 'arcobaleno64/agy-security-audit/.github/workflows/release.yml',
    '--source-ref', 'refs/tags/v1.8.0',
    '--source-digest', '1'.repeat(40)
  ], { PATH: '' }), 'Unable to execute gh');
  testsRun++;

  console.log(`All provenance policy tests passed (${testsRun}/${testsRun}).`);
} finally {
  fs.rmSync(temp, { recursive: true, force: true });
}
