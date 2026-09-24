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
  if (result.status !== 0) fail(`gh ${args.slice(0, 3).join(' ')} failed (${resultİ]\ßJNˆ	Ê™\İ[œİ\œˆ™\İ[œİİ]	ÉÊKš[J
_X
NÂˆ™]\›ˆ™\İ[œİİ]ÂŸB‚™^Ü[˜İ[Ûˆ™\šYP]\İ][ÛœÊ[YÜš]KÛXŞKÚ[›™\ˆH[‘Ú
HÂˆÛÛœİ™\]Z\™YHÉÜ™\ÉË	ÜÚYÛ™\•ÛÜšÙ›İÉË	ÜÛİ\˜ÙT™Y‰Ë	ÜÛİ\˜ÙQYÙ\İ	×NÂˆ›Üˆ
ÛÛœİÙ^HÙˆ™\]Z\™Y
HÂˆYˆ
\ÛXŞVÚÙ^WH\[ÙˆÛXŞVÚÙ^WHOOH	Üİš[™ÉÊH˜Z[
İšXİ›İ™[˜[˜ÙH™\šYšXØ][Ûˆ™\]Z\™\ÈÛXŞK‰ÚÙ^_X
NÂˆBˆYˆ
K×–ÌNXKYKQ—^ÍIË\İ
ÛXŞKœÛİ\˜ÙQYÙ\İ
JH˜Z[
	ÜÛİ\˜ÙQYÙ\İ]\İ™HHXÚ\˜Xİ\ˆÚ]ÛÛ[Z]ÒIÊNÂ‚ˆÛÛœİ]\İYİXš™XİÈH™]ÈX\

NÂˆ›Üˆ
ÛÛœİ˜[YHÙˆ[YÜš]Kœ™[X\ÙQš[\ÊHÂˆÛÛœİ\ÜÙ]]H]š›Ú[Š[YÜš]Kœ›Ûİ˜[YJNÂˆÛÛœİİİ]HÚ[›™\ŠÂˆ	Ø]\İ][Û‰Ë	İ™\šYIË\ÜÙ]]ˆ	ËK\™\ÉËÛXŞKœ™\Ëˆ	ËK\ÚYÛ™\‹]ÛÜšÙ›İÉËÛXŞKœÚYÛ™\•ÛÜšÙ›İËˆ	ËK\Ûİ\˜ÙK\™Y‰ËÛXŞKœÛİ\˜ÙT™Y‹ˆ	ËK\Ûİ\˜ÙKYYÙ\İ	ËÛXŞKœÛİ\˜ÙQYÙ\İˆ	ËK\™YXØ]K]\IË‘QPĞUWÕTKˆ	ËKY[K\Ù[‹ZÜİY\[›™\œÉËˆ	ËKY›Ü›X]	Ë	ÚœÛÛ‰ÂˆKÈ[ˆÛXŞK™[ˆJNÂ‚ˆ]\œÙYÂˆHÈ\œÙYH”ÓÓ‹œ\œÙJİİ]
NÈHØ]Ú
\œŠHÈ˜Z[
[˜[Y”ÓÓˆœ›ÛHÚ]\İ][Ûˆ™\šYH›Üˆ	Û˜[Y_Nˆ	Ù\œ‹›Y\ÜØYÙ_X
NÈBˆÛÛœİİXš™XİÈHÛÛXİ™\šYšYYİXš™XİÊ\œÙY
NÂˆÛÛœİØØ[YÙ\İHÚLM‘š[J\ÜÙ]]
NÂˆYˆ
İXš™XİË™Ù]
˜[YJHOOHØØ[YÙ\İ
HÂˆ˜Z[
™\šYšYY]\İ][ÛˆÙ\È›İÛÛZ[ˆX]Ú[™ÈİXš™XİYÙ\İ›Üˆ	Û˜[Y_X
NÂˆBˆ›Üˆ
ÛÛœİÜİXš™Xİ˜[YKYÙ\İHÙˆİXš™XİÊHÂˆÛÛœİ^\İ[™ÈH]\İYİXš™XİË™Ù]
İXš™Xİ˜[YJNÂˆYˆ
^\İ[™È	‰ˆ^\İ[™ÈOOHYÙ\İ
H˜Z[
ÛÛ™›Xİ[™È™\šYšYYYÙ\İÈ›Üˆ]\İYİXš™Xİ	ÜİXš™Xİ˜[Y_X
NÂˆ]\İYİXš™XİËœÙ]
İXš™Xİ˜[YKYÙ\İ
NÂˆBˆB‚ˆÛÛœİ]\İYÙ]H™]ÈÙ]
]\İYİXš™XİËšÙ^\Ê
JNÂˆ\ÜÙ\Ù]\]X[
[YÜš]K›X[šY™\İÙ]]\İYÙ]	ÔÉË	ĞIÊNÂˆ›Üˆ
ÛÛœİ˜[YHÙˆ[YÜš]Kœ™[X\ÙQš[\ÊHÂˆÛÛœİ^XİYHÚLM‘š[J]š›Ú[Š[YÜš]Kœ›Ûİ˜[YJJNÂˆYˆ
]\İYİXš™XİË™Ù]
˜[YJHOOH^XİY
H˜Z[
YÙ\İ[™\]X[]H›Üˆ	Û˜[Y_NˆØØ[OH]\İ][Û˜
NÂˆYˆ
˜[YHOOH	ÔÒLM”ÕSTË	È	‰ˆ[YÜš]K˜ÚXÚÜİ[\Ë™Ù]
˜[YJHOOH^XİY
H˜Z[
YÙ\İ[™\]X[]H›Üˆ	Û˜[Y_NˆX[šY™\İOHØØ[
NÂˆB‚ˆ™]\›ˆÈ]\İYİXš™XİÈNÂŸB‚™[˜İ[Ûˆ\ØYÙJ
HÂˆÛÛœÛÛK›ÙÊ	Õ\ØYÙNˆ›ÙHØÜš\Ëİ™\šYK\™[X\ÙK\›İ™[˜[˜ÙK›ZœÈÛÜ[Ûœ×IÊNÂˆÛÛœÛÛK›ÙÊ	ÈKY\ˆ]ˆ\™XİÜHÛÛZ[š[™ÈHN™[X\ÙH\ÜÙ]ÉÊNÂˆÛÛœÛÛK›ÙÊ	ÈK\™\ÈİÛ™\‹Ü™\Ïˆ^XİYÚ]Xˆ™\ÜÚ]ÜIÊNÂˆÛÛœÛÛK›ÙÊ	ÈK\ÚYÛ™\‹]ÛÜšÙ›İÈ]ˆ^XİYÚYÛ™\ˆÛÜšÙ›İÈY[]IÊNÂˆÛÛœÛÛK›ÙÊ	ÈK\Ûİ\˜ÙK\™Yˆ™Yˆ^XİYÛİ\˜ÙH™Y‹K™Ëˆ™YœËİYÜËİŒKŒ	ÊNÂˆÛÛœÛÛK›ÙÊ	ÈK\Ûİ\˜ÙKYYÙ\İÚOˆ^XİYXÚ\ˆÛİ\˜ÙHÛÛ[Z]ÒIÊNÂˆÛÛœÛÛK›ÙÊ	ÈKY^XİYX\ÜÙ]Èˆ™\]Z\™H^Xİİ[\ÜÙ]Ûİ[	ÊNÂˆÛÛœÛÛK›ÙÊ	ÈKZ[YÜš]K[Û›H™\šYHØØ[ÒKLMˆ[YÜš]HÛ›H
SUTÕQ
IÊNÂˆÛÛœÛÛK›ÙÊ	ÈZKZ[ÚİÈ[	ÊNÂŸB‚™[˜İ[Ûˆ\œÙP\™ÜÊ\™ÜÊHÂˆÛÛœİİ]HÈ\ˆ	Ë‰Ë[YÜš]SÛ›Nˆ˜[ÙHNÂˆ›Üˆ
]HHÈH\™ÜË›[™İÈJÊÊHÂˆÛÛœİ\™ÈH\™ÜÖÚWNÂˆYˆ
\™ÈOOH	ËKZ[YÜš]K[Û›IÊHİ]š[YÜš]SÛ›HHYNÂˆ[ÙHYˆ
\™ÈOOH	ËKZ[	È\™ÈOOH	ËZ	ÊHİ]š[HYNÂˆ[ÙHYˆ
ÉËKY\‰Ë	ËK\™\ÉË	ËK\ÚYÛ™\‹]ÛÜšÙ›İÉË	ËK\Ûİ\˜ÙK\™Y‰Ë	ËK\Ûİ\˜ÙKYYÙ\İ	Ë	ËKY^XİYX\ÜÙ]É×Kš[˜ÛY\Ê\™ÊJHÂˆYˆ
H
ÈHH\™ÜË›[™İ
H˜Z[
	Ø\™ßH™\]Z\™\ÈH˜[YX
NÂˆÛÛœİÙ^HHÈ	ËKY\‰Î‰Ù\‰Ë	ËK\™\ÉÎ‰Ü™\ÉË	ËK\ÚYÛ™\‹]ÛÜšÙ›İÉÎ‰ÜÚYÛ™\•ÛÜšÙ›İÉË	ËK\Ûİ\˜ÙK\™Y‰Î‰ÜÛİ\˜ÙT™Y‰Ë	ËK\Ûİ\˜ÙKYYÙ\İ	Î‰ÜÛİ\˜ÙQYÙ\İ	Ë	ËKY^XİYX\ÜÙ]ÉÎ‰Ù^XİY\ÜÙ]ÉÈVØ\™×NÂˆİ]ÚÙ^WHH\™ÜÖÊÊÚWNÂˆH[ÙH˜Z[
[šÛ›İÛˆ\™İ[Y[ˆ	Ø\™ßX
NÂˆBˆ™]\›ˆİ]ÂŸB‚™^Ü[˜İ[Ûˆ[ÛJ\™ÜÈH›ØÙ\ÜË˜\™İ‹œÛXÙJŠK[ˆH›ØÙ\ÜË™[ŠHÂˆÛÛœİÜÈH\œÙP\™ÜÊ\™ÜÊNÂˆYˆ
ÜËš[
HÈ\ØYÙJ
NÈ™]\›ˆÈBˆÛÛœİ[YÜš]HH™\šYR[YÜš]JÜË™\ŠNÂˆYˆ
ÜË™^XİY\ÜÙ]ÈOOH[™Yš[™Y
HÂˆÛÛœİ^XİY\ÜÙ]ÈH[X™\ŠÜË™^XİY\ÜÙ]ÊNÂˆYˆ
S[X™\‹š\Ò[YÙ\Š^XİY\ÜÙ]ÊH^XİY\ÜÙ]ÈJH˜Z[
	ËKY^XİYX\ÜÙ]È]\İ™HHÜÚ]]™H[YÙ\‰ÊNÂˆYˆ
[YÜš]Kœ™[X\ÙQš[\Ë›[™İOOH^XİY\ÜÙ]ÊH˜Z[
^XİY^XİH	Ù^XİY\ÜÙ]ßH™[X\ÙH\ÜÙ]Ë›İ[™	Ú[YÜš]Kœ™[X\ÙQš[\Ë›[™İX
NÂˆBˆYˆ
ÜËš[YÜš]SÛ›JHÂˆÛÛœÛÛK›ÙÊS•QÔ’UWÓÓ“H
SUTÕQ
Nˆ	Ú[YÜš]Kœ™[X\ÙQš[\Ë›[™İH\ÜÙ]ÎÈ	Ú[YÜš]K˜ÚXÚÜİ[\ËœÚ^™_KÉÚ[YÜš]K˜ÚXÚÜİ[\ËœÚ^™_HÚXÚÜİ[\È™\šYšYY˜
NÂˆ™]\›ˆÂˆB‚ˆÛÛœİÛXŞHHÂˆ™\ÎˆÜËœ™\ÈÏÈ[‹‘ÒUP—Ô‘TÔÒUÔ–KˆÚYÛ™\•ÛÜšÙ›İÎˆÜËœÚYÛ™\•ÛÜšÙ›İÈÏÈ
[‹‘ÒUP—Ô‘TÔÒUÔ–HÈ	Ù[‹‘ÒUP—Ô‘TÔÒUÔ–_KË™Ú]X‹İÛÜšÙ›İÜËÜ™[X\ÙK[[ˆ[™Yš[™Y
KˆÛİ\˜ÙT™YˆÜËœÛİ\˜ÙT™YˆÏÈ[‹‘ÒUP—Ô‘Q‹ˆÛİ\˜ÙQYÙ\İˆÜËœÛİ\˜ÙQYÙ\İÏÈ[‹‘ÒUP—ÔÒKˆ[‚ˆNÂˆ™\šYP]\İ][ÛœÊ[YÜš]KÛXŞJNÂˆÛÛœÛÛK›ÙÊ“Õ‘SSÑWÕ‘T’Q’QQ
ÓĞHZ[ŠNˆTÏPOIÚ[YÜš]Kœ™[X\ÙQš[\Ë›[™İNÈİšXİÚ]Xˆ]\İ][ÛˆÛXŞHØ]\ÙšYY˜
NÂˆ™]\›ˆÂŸB‚šYˆ
›ØÙ\ÜË˜\™İ–ÌWH	‰ˆ]œ™\ÛÛ™J›ØÙ\ÜË˜\™İ–ÌWJHOOH]œ™\ÛÛ™J×Ùš[[˜[YJJHÂˆHÈ›ØÙ\ÜË™^]ÛÙHH[ÛJ
NÈBˆØ]Ú
\œŠHÈÛÛœÛÛK™\œ›ÜŠ“Õ‘SSÑWÕ‘T’Q’PĞUSÓ—ÑRSQˆ	Ù\œ‹›Y\ÜØYÙ_X
NÈ›ØÙ\ÜË™^]ÛÙHHNÈBŸB