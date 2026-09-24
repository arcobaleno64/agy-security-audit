#!/usr/bin/env node
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);

const PREDICATE_TYPE = 'https://slsa.dev/provenance/v1';

function fail(message) {
  throw new Error(message);
}

function sha256File(filePath) {
  return crypto.createHash('sha256').update(fs.readFileSync(filePath)).digest('hex');
}

function assertSafeBasename(name, context = 'asset') {
  if (typeof name !== 'string' || name.length === 0) fail(`${context} name must be a non-empty string`);
  if (name.includes('\0')) fail(`${context} name contains NUL: ${JSON.stringify(name)}`);
  const normalized = name.replace(/\\/g, '/');
  if (normalized.includes('/')) fail(`${context} must be a basename without directories: ${name}`);
  if (normalized === '.' || normalized === '..') fail(`${context} uses forbidden traversal basename: ${name}`);
  return normalized;
}

export function parseSha256Sums(content) {
  const entries = new Map();
  const lines = content.split(/\r?\n/).filter(Boolean);
  if (lines.length === 0) fail('SHA256SUMS.txt contains no checksum entries');

  for (const line of lines) {
    const match = /^([0-9a-fA-F]{64})  (.+)$/.exec(line);
    if (!match) fail(`Malformed SHA256SUMS.txt line: ${line}`);
    const digest = match[1].toLowerCase();
    const name = assertSafeBasename(match[2], 'checksum entry');
    if (name === 'SHA256SUMS.txt') fail('SHA256SUMS.txt must not list itself');
    if (entries.has(name)) fail(`Duplicate checksum basename: ${name}`);
    entries.set(name, digest);
  }
  return entries;
}

function listRegularAssetFiles(dir) {
  const entries = fs.readdirSync(dir, { withFileTypes: true });
  const names = [];
  for (const entry of entries) {
    const name = assertSafeBasename(entry.name, 'release asset');
    const full = path.join(dir, name);
    const stat = fs.lstatSync(full);
    if (stat.isSymbolicLink()) fail(`Symlink release asset is forbidden: ${name}`);
    if (!stat.isFile()) fail(`Release asset directory contains non-file entry: ${name}`);
    names.push(name);
  }
  names.sort();
  return names;
}

function setDiff(a, b) {
  return [...a].filter(x => !b.has(x)).sort();
}

function assertSetEqual(a, b, labelA, labelB) {
  const missingFromB = setDiff(a, b);
  const missingFromA = setDiff(b, a);
  if (missingFromB.length || missingFromA.length) {
    fail(`${labelA} != ${labelB}; only in ${labelA}: [${missingFromB.join(', ')}]; only in ${labelB}: [${missingFromA.join(', ')}]`);
  }
}

export function verifyIntegrity(dir) {
  const root = path.resolve(dir);
  if (!fs.existsSync(root) || !fs.statSync(root).isDirectory()) fail(`Release asset directory not found: ${root}`);
  const sumsPath = path.join(root, 'SHA256SUMS.txt');
  if (!fs.existsSync(sumsPath) || !fs.statSync(sumsPath).isFile()) fail(`Missing SHA256SUMS.txt in ${root}`);

  const checksums = parseSha256Sums(fs.readFileSync(sumsPath, 'utf8'));
  const releaseFiles = listRegularAssetFiles(root);
  const releaseSet = new Set(releaseFiles);
  const manifestSet = new Set([...checksums.keys(), 'SHA256SUMS.txt']);
  assertSetEqual(releaseSet, manifestSet, 'R', 'S');

  for (const [name, expected] of checksums) {
    const actual = sha256File(path.join(root, name));
    if (actual !== expected) fail(`SHA-256 mismatch for ${name}: expected ${expected}, actual ${actual}`);
  }

  return { root, checksums, releaseFiles, releaseSet, manifestSet };
}

function normalizeVerifiedSubject(subject) {
  if (!subject || typeof subject !== 'object') fail('Verified attestation subject is not an object');
  const name = assertSafeBasename(path.basename(String(subject.name ?? '')), 'attestation subject');
  const digest = subject.digest?.sha256;
  if (typeof digest !== 'string' || !/^[0-9a-fA-F]{64}$/.test(digest)) {
    fail(`Attestation subject ${name} lacks a valid sha256 digest`);
  }
  return { name, digest: digest.toLowerCase() };
}

export function collectVerifiedSubjects(verificationJson) {
  if (!Array.isArray(verificationJson) || verificationJson.length === 0) fail('gh attestation verify returned no verified attestations');
  const subjects = new Map();

  for (const item of verificationJson) {
    const statement = item?.verificationResult?.statement;
    if (!statement || statement.predicateType !== PREDICATE_TYPE || !Array.isArray(statement.subject)) {
      fail('Verified attestation result lacks the expected SLSA v1 statement subject array');
    }
    for (const raw of statement.subject) {
      const { name, digest } = normalizeVerifiedSubject(raw);
      const existing = subjects.get(name);
      if (existing && existing !== digest) fail(`Conflicting attestation digests for subject ${name}`);
      subjects.set(name, digest);
    }
  }
  return subjects;
}

function runGh(args, options = {}) {
  const result = spawnSync('gh', args, {
    encoding: 'utf8',
    shell: false,
    env: options.env ?? process.env,
    stdio: ['ignore', 'pipe', 'pipe']
  });
  if (result.error) fail(`Unable to execute gh: ${result.error.message}`);
  if (result.status !== 0) fail(`gh ${args.slice(0, 3).join(' ')} failed (${result.status}): ${(result.stderr || result.stdout || '').trim()}`);
  return result.stdout;
}

export function verifyAttestations(integrity, policy, ghRunner = runGh) {
  const required = ['repo', 'signerWorkflow', 'sourceRef', 'sourceDigest'];
  for (const key of required) {
    if (!policy[key] || typeof policy[key] !== 'string') fail(`Strict provenance verification requires policy.${key}`);
  }
  if (!/^[0-9a-fA-F]{40}$/.test(policy.sourceDigest)) fail('sourceDigest must be a 40-character Git commit SHA');

  const attestedSubjects = new Map();
  for (const name of integrity.releaseFiles) {
    const assetPath = path.join(integrity.root, name);
    const stdout = ghRunner([
      'attestation', 'verify', assetPath,
      '--repo', policy.repo,
      '--signer-workflow', policy.signerWorkflow,
      '--source-ref', policy.sourceRef,
      '--source-digest', policy.sourceDigest,
      '--predicate-type', PREDICATE_TYPE,
      '--deny-self-hosted-runners',
      '--format', 'json'
    ], { env: policy.env });

    let parsed;
    try { parsed = JSON.parse(stdout); } catch (err) { fail(`Invalid JSON from gh attestation verify for ${name}: ${err.message}`); }
    const subjects = collectVerifiedSubjects(parsed);
    const localDigest = sha256File(assetPath);
    if (subjects.get(name) !== localDigest) {
      fail(`Verified attestation does not contain matching subject digest for ${name}`);
    }
    for (const [subjectName, digest] of subjects) {
      const existing = attestedSubjects.get(subjectName);
      if (existing && existing !== digest) fail(`Conflicting verified digests for attested subject ${subjectName}`);
      attestedSubjects.set(subjectName, digest);
    }
  }

  const attestedSet = new Set(attestedSubjects.keys());
  assertSetEqual(integrity.manifestSet, attestedSet, 'S', 'A');
  for (const name of integrity.releaseFiles) {
    const expected = sha256File(path.join(integrity.root, name));
    if (attestedSubjects.get(name) !== expected) fail(`Digest inequality for ${name}: local != attestation`);
    if (name !== 'SHA256SUMS.txt' && integrity.checksums.get(name) !== expected) fail(`Digest inequality for ${name}: manifest != local`);
  }

  return { attestedSubjects };
}

function usage() {
  console.log('Usage: node scripts/verify-release-provenance.mjs [options]');
  console.log('  --dir <path>              Directory containing the 18 release assets');
  console.log('  --repo <owner/repo>       Expected GitHub repository');
  console.log('  --signer-workflow <path>  Expected signer workflow identity');
  console.log('  --source-ref <ref>        Expected source ref, e.g. refs/tags/v1.8.0');
  console.log('  --source-digest <sha>     Expected 40-char source commit SHA');
  console.log('  --expected-assets <n>     Require exact total asset count');
  console.log('  --integrity-only          Verify local SHA-256 integrity only (UNATTESTED)');
  console.log('  -h, --help                Show help');
}

function parseArgs(args) {
  const out = { dir: '.', integrityOnly: false };
  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (arg === '--integrity-only') out.integrityOnly = true;
    else if (arg === '--help' || arg === '-h') out.help = true;
    else if (['--dir','--repo','--signer-workflow','--source-ref','--source-digest','--expected-assets'].includes(arg)) {
      if (i + 1 >= args.length) fail(`${arg} requires a value`);
      const key = { '--dir':'dir','--repo':'repo','--signer-workflow':'signerWorkflow','--source-ref':'sourceRef','--source-digest':'sourceDigest','--expected-assets':'expectedAssets' }[arg];
      out[key] = args[++i];
    } else fail(`Unknown argument: ${arg}`);
  }
  return out;
}

export function runCli(args = process.argv.slice(2), env = process.env) {
  const opts = parseArgs(args);
  if (opts.help) { usage(); return 0; }
  const integrity = verifyIntegrity(opts.dir);
  if (opts.expectedAssets !== undefined) {
    const expectedAssets = Number(opts.expectedAssets);
    if (!Number.isInteger(expectedAssets) || expectedAssets < 1) fail('--expected-assets must be a positive integer');
    if (integrity.releaseFiles.length !== expectedAssets) fail(`Expected exactly ${expectedAssets} release assets, found ${integrity.releaseFiles.length}`);
  }
  if (opts.integrityOnly) {
    console.log(`INTEGRITY_ONLY (UNATTESTED): ${integrity.releaseFiles.length} assets; ${integrity.checksums.size}/${integrity.checksums.size} checksums verified.`);
    return 0;
  }

  const policy = {
    repo: opts.repo ?? env.GITHUB_REPOSITORY,
    signerWorkflow: opts.signerWorkflow ?? (env.GITHUB_REPOSITORY ? `${env.GITHUB_REPOSITORY}/.github/workflows/release.yml` : undefined),
    sourceRef: opts.sourceRef ?? env.GITHUB_REF,
    sourceDigest: opts.sourceDigest ?? env.GITHUB_SHA,
    env
  };
  verifyAttestations(integrity, policy);
  console.log(`PROVENANCE_VERIFIED (SLSA Build L2): R=S=A=${integrity.releaseFiles.length}; strict GitHub attestation policy satisfied.`);
  return 0;
}

if (process.argv[1] && path.resolve(process.argv[1]) === path.resolve(__filename)) {
  try { process.exitCode = runCli(); }
  catch (err) { console.error(`PROVENANCE_VERIFICATION_FAILED: ${err.message}`); process.exitCode = 1; }
}
