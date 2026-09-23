#!/usr/bin/env node
/**
 * test-cross-model-protocol.mjs
 * Deterministic Test Suite for v1.5 Cross-Model Comparative Validation Protocol.
 * Validates 4-tier taxonomy separation, dual-tier Jaccard with empty-set semantics,
 * consensus lineage dispositions, dual-level matching, and protocol digest integrity.
 *
 * Zero external dependencies.
 */

import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { auditStreamIsolation } from './run-live-oss-transfer.mjs';
import {
  normalizeModelTaxonomy,
  validateIndependenceAuthority,
  VALID_IDENTITY_SOURCES,
  VALID_TAXONOMY_TIERS
} from '../skills/security-audit/scripts/record-benchmark-run.mjs';
import {
  classifyComparisonExperiment,
  computeComparativeJaccard,
  computeConsensusLineages,
  computeComparativeSpecificity,
  dispositionConsensusLineage,
  computeLevel1Fingerprint,
  computeLevel2SemanticKey,
  extractFixtureIdFromUri,
  loadAndValidateProtocol,
  computeProtocolDigest,
  renderComparativeReport,
  compareRunMatrix,
  isCweCompatible,
  CWE_EQUIVALENCE_FAMILIES
} from './compare-model-benchmarks.mjs';

const __filename = fileURLToPath(import.meta.url);
const REPO_ROOT = path.resolve(path.dirname(__filename), '..');

function assert(condition, message) {
  if (!condition) {
    throw new Error(`ASSERTION_FAILED: ${message}`);
  }
}

function runSuite() {
  console.log('================================================================');
  console.log('v1.5 Cross-Model Comparative Validation Protocol Test Suite');
  console.log('================================================================\n');

  // ---------------------------------------------------------------------------
  // Suite 1: Epistemological Taxonomy Separation & Fail-Closed Authority
  // ---------------------------------------------------------------------------
  console.log('Suite 1: Epistemological Taxonomy Separation & Attested Authority');

  const taxGeminiHigh = normalizeModelTaxonomy('gemini-3.8-flash-high', {
    identitySource: 'RUNTIME_ATTESTED',
    identityConfidence: 'HIGH'
  });
  const taxGeminiLow = normalizeModelTaxonomy('gemini-3.8-flash-low', {
    identitySource: 'RUNTIME_ATTESTED',
    identityConfidence: 'HIGH'
  });
  const taxGeminiPro = normalizeModelTaxonomy('gemini-3.8-pro', {
    identitySource: 'RUNTIME_ATTESTED',
    identityConfidence: 'HIGH'
  });
  const taxClaudeSonnet = normalizeModelTaxonomy('claude-3-7-sonnet', {
    identitySource: 'RUNTIME_ATTESTED',
    identityConfidence: 'HIGH'
  });
  const taxClaudeCode = normalizeModelTaxonomy('claude-3-7-sonnet', {
    identitySource: 'RUNTIME_ATTESTED',
    identityConfidence: 'HIGH',
    runtimeId: 'claude-code',
    runtimeAdapter: 'acp'
  });

  // 1.1 Tier 1: REASONING_PROFILE_ABLATION
  const t1 = classifyComparisonExperiment(taxGeminiHigh, taxGeminiLow);
  assert(t1.tier === 1, `Expected Tier 1, got ${t1.tier}`);
  assert(t1.name === 'REASONING_PROFILE_ABLATION', `Expected REASONING_PROFILE_ABLATION, got ${t1.name}`);
  assert(t1.publishable === true, 'Tier 1 should be publishable');
  console.log('  ✔ 1.1 Tier 1: REASONING_PROFILE_ABLATION (same base model, different reasoning profile).');

  // 1.2 Tier 2: INTRA_PROVIDER_MODEL_REPLICATION
  const t2 = classifyComparisonExperiment(taxGeminiHigh, taxGeminiPro);
  assert(t2.tier === 2, `Expected Tier 2, got ${t2.tier}`);
  assert(t2.name === 'INTRA_PROVIDER_MODEL_REPLICATION', `Expected INTRA_PROVIDER_MODEL_REPLICATION, got ${t2.name}`);
  assert(t2.publishable === true, 'Tier 2 should be publishable');
  console.log('  ✔ 1.2 Tier 2: INTRA_PROVIDER_MODEL_REPLICATION (same provider, different architecture).');

  // 1.3 Tier 3: CROSS_PROVIDER_MODEL_REPLICATION
  const t3 = classifyComparisonExperiment(taxGeminiHigh, taxClaudeSonnet);
  assert(t3.tier === 3, `Expected Tier 3, got ${t3.tier}`);
  assert(t3.name === 'CROSS_PROVIDER_MODEL_REPLICATION', `Expected CROSS_PROVIDER_MODEL_REPLICATION, got ${t3.name}`);
  assert(t3.publishable === true, 'Tier 3 should be publishable');
  console.log('  ✔ 1.3 Tier 3: CROSS_PROVIDER_MODEL_REPLICATION (distinct model providers).');

  // 1.4 Tier 4: CROSS_SYSTEM_REPLICATION
  const t4 = classifyComparisonExperiment(taxClaudeSonnet, taxClaudeCode);
  assert(t4.tier === 4, `Expected Tier 4, got ${t4.tier}`);
  assert(t4.name === 'CROSS_SYSTEM_REPLICATION', `Expected CROSS_SYSTEM_REPLICATION, got ${t4.name}`);
  assert(t4.publishable === true, 'Tier 4 should be publishable');
  console.log('  ✔ 1.4 Tier 4: CROSS_SYSTEM_REPLICATION (model + runtime change simultaneously).');

  // 1.5 Non-Publication Control: IDENTITY_CONTROL
  const t0a = classifyComparisonExperiment(taxGeminiHigh, taxGeminiHigh, { identityControl: true });
  assert(t0a.tier === 0, `Expected Tier 0, got ${t0a.tier}`);
  assert(t0a.name === 'IDENTITY_CONTROL', `Expected IDENTITY_CONTROL, got ${t0a.name}`);
  assert(t0a.publishable === false, 'IDENTITY_CONTROL must be marked non-publishable');

  const runEnvelopeSelf = { runId: 'run-identical-001', environment: { modelId: 'gemini-3.8-flash-high' } };
  const t0b = classifyComparisonExperiment(runEnvelopeSelf, runEnvelopeSelf);
  assert(t0b.tier === 0 && t0b.name === 'IDENTITY_CONTROL' && t0b.publishable === false, 'Matching runId must classify as IDENTITY_CONTROL');

  const runPassHigh = { runId: 'run-pass-1', environment: { modelId: 'gemini-3.8-flash-high', reasoningProfile: 'high', baseModel: 'gemini-3.8-flash', identitySource: 'CONFIG_DECLARED' } };
  const runPassMed = { runId: 'run-pass-1', environment: { modelId: 'gemini-3.8-flash-medium', reasoningProfile: 'medium', baseModel: 'gemini-3.8-flash', identitySource: 'CONFIG_DECLARED' } };
  const t1SameRunId = classifyComparisonExperiment(runPassHigh, runPassMed);
  assert(t1SameRunId.tier === 1 && t1SameRunId.name === 'REASONING_PROFILE_ABLATION' && t1SameRunId.publishable === true, 'Matching pass runId across different reasoning profiles must classify as Tier 1 REASONING_PROFILE_ABLATION');
  console.log('  ✔ 1.5 Verification Control: IDENTITY_CONTROL strictly marked non-publishable.');

  // 1.6 Default-Deny Authority Invariant: PARSED_INFERRED cannot establish Tier 2/3/4 independence
  const unverifiedA = normalizeModelTaxonomy('gemini-3.8-flash', { identitySource: 'PARSED_INFERRED' });
  const unverifiedB = normalizeModelTaxonomy('claude-3-7-sonnet', { identitySource: 'PARSED_INFERRED' });
  let failClosedTriggered = false;
  try {
    classifyComparisonExperiment(unverifiedA, unverifiedB, { failClosed: true });
  } catch (err) {
    if (err.message.includes('DEFAULT_DENY_TAXONOMY_VIOLATION')) {
      failClosedTriggered = true;
    }
  }
  assert(failClosedTriggered, 'Default-Deny must fail closed when Tier 3 claimed with PARSED_INFERRED');

  // CONFIG_DECLARED is accepted as valid authority
  const declaredA = normalizeModelTaxonomy('gemini-3.8-flash', { identitySource: 'CONFIG_DECLARED' });
  const declaredB = normalizeModelTaxonomy('claude-3-7-sonnet', { identitySource: 'CONFIG_DECLARED' });
  const t3Declared = classifyComparisonExperiment(declaredA, declaredB, { failClosed: true });
  assert(t3Declared.tier === 3, 'CONFIG_DECLARED must satisfy independence authority');
  console.log('  ✔ 1.6 Default-Deny Authority Invariant: PARSED_INFERRED rejected fail-closed on cross-model claims.');

  // 1.7 Default-Deny Tier 1 Authority Invariant: PARSED_INFERRED cannot establish Tier 1 ablation
  const unverifiedTier1A = normalizeModelTaxonomy('gemini-3.8-flash-high', { identitySource: 'PARSED_INFERRED' });
  const unverifiedTier1B = normalizeModelTaxonomy('gemini-3.8-flash-low', { identitySource: 'PARSED_INFERRED' });
  let tier1FailClosedTriggered = false;
  try {
    classifyComparisonExperiment(unverifiedTier1A, unverifiedTier1B, { failClosed: true });
  } catch (err) {
    if (err.message.includes('DEFAULT_DENY_TAXONOMY_VIOLATION')) {
      tier1FailClosedTriggered = true;
    }
  }
  assert(tier1FailClosedTriggered, 'Default-Deny must fail closed when Tier 1 claimed with PARSED_INFERRED');

  // CONFIG_DECLARED satisfies Tier 1 authority
  const declaredTier1A = normalizeModelTaxonomy('gemini-3.8-flash-high', { identitySource: 'CONFIG_DECLARED', baseModel: 'gemini-3.8-flash', reasoningProfile: 'high' });
  const declaredTier1B = normalizeModelTaxonomy('gemini-3.8-flash-low', { identitySource: 'CONFIG_DECLARED', baseModel: 'gemini-3.8-flash', reasoningProfile: 'low' });
  const t1Declared = classifyComparisonExperiment(declaredTier1A, declaredTier1B, { failClosed: true });
  assert(t1Declared.tier === 1, 'CONFIG_DECLARED must satisfy Tier 1 ablation authority');
  console.log('  ✔ 1.7 Default-Deny Tier 1 Authority Invariant: PARSED_INFERRED rejected fail-closed on Tier 1 ablation.\n');

  // ---------------------------------------------------------------------------
  // Suite 2: Dual-Tier Jaccard & Explicit Empty-Set Semantics
  // ---------------------------------------------------------------------------
  console.log('Suite 2: Dual-Tier Jaccard ($J_{any}$ vs $J_{strict}$) & Empty Sets');

  // 2.1 Empty-Set Semantics (Safe Controls)
  const emptyRunsA = [
    { findings: { candidates: [] } },
    { findings: { candidates: [] } },
    { findings: { candidates: [] } }
  ];
  const emptyRunsB = [
    { findings: { candidates: [] } },
    { findings: { candidates: [] } },
    { findings: { candidates: [] } }
  ];

  const emptyRes = computeComparativeJaccard(emptyRunsA, emptyRunsB, 0.60);
  assert(emptyRes.jAny.jaccard === null, 'Empty set J_any must be null');
  assert(emptyRes.jAny.bothEmpty === true, 'Empty set J_any bothEmpty must be true');
  assert(emptyRes.jAny.display === 'N/A', 'Empty set J_any display must be N/A (not 100.0%)');
  assert(emptyRes.jStrict.jaccard === null, 'Empty set J_strict must be null');
  assert(emptyRes.jStrict.bothEmpty === true, 'Empty set J_strict bothEmpty must be true');
  assert(emptyRes.jStrict.display === 'N/A', 'Empty set J_strict display must be N/A (not 100.0%)');
  console.log('  ✔ 2.1 Empty-Set Semantics: S_A = ∅ and S_B = ∅ emits null and "N/A" (never falsified 1.0).');

  // 2.2 Strict Recurrence Threshold ceil(0.60 * N)
  // For N=3: ceil(0.60 * 3) = ceil(1.8) = 2 passes required
  const candL1 = { ruleId: 'CWE-89', location: { uri: 'src/db.js', startLine: 10 }, symbol: 'query' };
  const candL2 = { ruleId: 'CWE-79', location: { uri: 'src/view.js', startLine: 20 }, symbol: 'render' };

  // Model A: L1 seen in 3/3, L2 seen in 1/3
  const runsWithRecurrenceA = [
    { findings: { candidates: [candL1, candL2] } },
    { findings: { candidates: [candL1] } },
    { findings: { candidates: [candL1] } }
  ];
  // Model B: L1 seen in 2/3, L2 seen in 2/3
  const runsWithRecurrenceB = [
    { findings: { candidates: [candL1, candL2] } },
    { findings: { candidates: [candL1, candL2] } },
    { findings: { candidates: [] } }
  ];

  const jRes = computeComparativeJaccard(runsWithRecurrenceA, runsWithRecurrenceB, 0.60);
  assert(jRes.requiredCountA === 2, `Expected required count 2 for N=3, got ${jRes.requiredCountA}`);
  assert(jRes.requiredCountB === 2, `Expected required count 2 for N=3, got ${jRes.requiredCountB}`);

  // In A: L1 count=3 (>=2, strict), L2 count=1 (<2, NOT strict)
  // In B: L1 count=2 (>=2, strict), L2 count=2 (>=2, strict)
  // Any: SetA = {L1, L2}, SetB = {L1, L2} -> J_any = 2/2 = 1.0 (100.0%)
  assert(jRes.jAny.jaccard === 1.0, `Expected J_any = 1.0, got ${jRes.jAny.jaccard}`);
  // Strict: StableSetA = {L1}, StableSetB = {L1, L2} -> J_strict = 1/2 = 0.5 (50.0%)
  assert(jRes.jStrict.jaccard === 0.5, `Expected J_strict = 0.5, got ${jRes.jStrict.jaccard}`);
  assert(jRes.jStrict.display === '50.0%', `Expected J_strict display 50.0%, got ${jRes.jStrict.display}`);
  console.log('  ✔ 2.2 Strict Threshold ceil(0.60 * N): separates transient 1/3 lineages from stable consensus (J_any=100%, J_strict=50%).');

  // 2.3 Disjoint lineage sets
  const candL3 = { ruleId: 'CWE-22', location: { uri: 'src/fs.js', startLine: 5 }, symbol: 'readFile' };
  const disjointRunsA = [{ findings: { candidates: [candL1] } }];
  const disjointRunsB = [{ findings: { candidates: [candL3] } }];
  const disjointJ = computeComparativeJaccard(disjointRunsA, disjointRunsB, 0.60);
  assert(disjointJ.jAny.jaccard === 0.0, 'Disjoint sets must have J_any = 0.0');
  assert(disjointJ.jStrict.jaccard === 0.0, 'Disjoint sets must have J_strict = 0.0');
  console.log('  ✔ 2.3 Disjoint Finding Sets: produces exact 0.0% Jaccard score.\n');

  // ---------------------------------------------------------------------------
  // Suite 3: Consensus Lineage Dispositions & Ground-Truth Oracle
  // ---------------------------------------------------------------------------
  console.log('Suite 3: Consensus Lineage Dispositions (TP vs FP vs UNRESOLVED)');

  const mockGroundTruth = new Map([
    ['HLD-01', { id: 'HLD-01', cwe: 'CWE-1336', expectedVerdict: 'VULNERABLE', file: '01-ssti-template-injection.js' }],
    ['HLD-02', { id: 'HLD-02', cwe: 'CWE-611', expectedVerdict: 'VULNERABLE', file: '02-xxe-entity-expansion.js' }],
    ['HLD-01-SAFE', { id: 'HLD-01-SAFE', cwe: 'CWE-1336', expectedVerdict: 'SAFE', file: 'safe/01-ssti-template-injection.js' }],
    ['HLD-08-SAFE', {
      id: 'HLD-08-SAFE',
      cwe: 'CWE-918',
      file: 'safe/08-ssrf-dns-rebinding.js',
      expectedVerdict: 'DISPUTED',
      oracleStatus: 'DISPUTED_INVALIDATED',
      originalVerdict: 'SAFE',
      disputeMetadata: {
        reason: 'Verified benchmark oracle defect: unpinned DNS lookup followed by http.get (CWE-918 SSRF / DNS rebinding TOCTOU).'
      }
    }]
  ]);

  // 3.1 Replicated True Positive (Consensus matches ground truth vuln)
  const tpCandidate = {
    ruleId: 'CWE-1336',
    location: { uri: 'evals/holdout-benchmark/01-ssti-template-injection.js', startLine: 18 },
    symbol: 'evalTemplate'
  };
  const tpDisp = dispositionConsensusLineage(tpCandidate, mockGroundTruth);
  assert(tpDisp.disposition === 'REPLICATED_TRUE_POSITIVE', `Expected REPLICATED_TRUE_POSITIVE, got ${tpDisp.disposition}`);
  assert(tpDisp.groundTruthId === 'HLD-01', `Expected groundTruthId HLD-01, got ${tpDisp.groundTruthId}`);
  console.log('  ✔ 3.1 REPLICATED_TRUE_POSITIVE: consensus lineage correctly corroborates vulnerable fixture.');

  // 3.2 Replicated False Positive (Consensus spurious finding on safe control)
  const fpCandidate = {
    ruleId: 'CWE-1336',
    location: { uri: 'evals/holdout-benchmark/safe/01-ssti-template-injection.js', startLine: 20 },
    symbol: 'sanitizeTemplate'
  };
  const fpDisp = dispositionConsensusLineage(fpCandidate, mockGroundTruth);
  assert(fpDisp.disposition === 'REPLICATED_FALSE_POSITIVE', `Expected REPLICATED_FALSE_POSITIVE, got ${fpDisp.disposition}`);
  console.log('  ✔ 3.2 REPLICATED_FALSE_POSITIVE: consensus spurious finding on safe control classified as FP.');

  // 3.3 Replicated Unresolved (Consensus on un-oracled fixture/repo)
  const unresCandidate = {
    ruleId: 'CWE-89',
    location: { uri: 'external/oss-repo/db.js', startLine: 50 },
    symbol: 'rawQuery'
  };
  const unresDisp = dispositionConsensusLineage(unresCandidate, mockGroundTruth);
  assert(unresDisp.disposition === 'REPLICATED_UNRESOLVED', `Expected REPLICATED_UNRESOLVED, got ${unresDisp.disposition}`);
  console.log('  ✔ 3.3 REPLICATED_UNRESOLVED: consensus finding on un-oracled fixture correctly categorized without hallucinated verdict.');

  // 3.4 Ground Truth Dispute (Disputed benchmark fixture with authentic vulnerability)
  const disputeCandidate = {
    ruleId: 'CWE-918',
    location: { uri: 'evals/holdout-benchmark/safe/08-ssrf-dns-rebinding.js', startLine: 15 },
    symbol: 'checkDnsRebinding'
  };
  const disputeDisp = dispositionConsensusLineage(disputeCandidate, mockGroundTruth);
  assert(disputeDisp.disposition === 'GROUND_TRUTH_DISPUTE', `Expected GROUND_TRUTH_DISPUTE, got ${disputeDisp.disposition}`);
  console.log('  ✔ 3.4 GROUND_TRUTH_DISPUTE: finding on disputed benchmark fixture categorized without false FP penalty.\n');

  // ---------------------------------------------------------------------------
  // Suite 4: Dual-Level Matching (Exact Lineage vs Semantic Ground-Truth)
  // ---------------------------------------------------------------------------
  console.log('Suite 4: Dual-Level Lineage Matching');

  const matchCandA = {
    ruleId: 'CWE-1336',
    location: { uri: 'evals/holdout-benchmark/01-ssti-template-injection.js', startLine: 18 },
    symbol: 'compileDynamicTemplate',
    securityProperty: 'unrestricted-template-execution'
  };
  const matchCandB = {
    ruleId: 'CWE-1336',
    location: { uri: 'evals/holdout-benchmark/01-ssti-template-injection.js', startLine: 24 },
    symbol: 'renderTemplateString',
    securityProperty: 'unrestricted-template-execution'
  };

  // Level 1: Exact cryptographic fingerprint differentiates due to distinct symbol
  const l1A = computeLevel1Fingerprint(matchCandA);
  const l1B = computeLevel1Fingerprint(matchCandB);
  assert(l1A !== l1B, 'Level 1 fingerprints must differ when symbols are distinct');

  // Level 2: Ground-truth semantic key matches on fixture + CWE + property
  const l2A = computeLevel2SemanticKey(matchCandA, 'HLD-01');
  const l2B = computeLevel2SemanticKey(matchCandB, 'HLD-01');
  assert(l2A === l2B, `Level 2 semantic keys must match (got A='${l2A}', B='${l2B}')`);
  console.log('  ✔ 4.1 Level 1 differentiates syntactic symbol variation, while Level 2 unifies semantic ground truth.');

  // URI Fixture Extractor Test
  assert(extractFixtureIdFromUri('evals/holdout-benchmark/01-ssti-template-injection.js') === 'HLD-01', 'Extract HLD-01 failed');
  assert(extractFixtureIdFromUri('evals/holdout-benchmark/safe/08-ssrf-dns-rebinding.js') === 'HLD-08-SAFE', 'Extract HLD-08-SAFE failed');
  assert(extractFixtureIdFromUri('evals/semantic-benchmark/03-prototype-pollution.js') === 'SEM-03', 'Extract SEM-03 failed');
  console.log('  ✔ 4.2 extractFixtureIdFromUri accurately extracts HLD/SEM fixture identities.');

  // 4.3 CWE Family Equivalence (Level 2 unifies CWE-94 and CWE-1336 on HLD-01)
  assert(isCweCompatible('CWE-94', 'CWE-1336') === true, 'CWE-94 and CWE-1336 must be compatible under SSTI family');
  const candSsti94 = {
    ruleId: 'CWE-94',
    location: { uri: 'evals/holdout-benchmark/01-ssti-template-injection.js', startLine: 8 },
    symbol: 'renderDynamicTemplate',
    securityProperty: 'isolation'
  };
  const candSsti1336 = {
    ruleId: 'CWE-1336',
    location: { uri: 'evals/holdout-benchmark/01-ssti-template-injection.js', startLine: 18 },
    symbol: 'evalTemplate',
    securityProperty: 'isolation'
  };
  const l2Key94 = computeLevel2SemanticKey(candSsti94);
  const l2Key1336 = computeLevel2SemanticKey(candSsti1336);
  assert(l2Key94 === l2Key1336, `Level 2 semantic keys must match across equivalent CWE family (got '${l2Key94}' vs '${l2Key1336}')`);

  const disp94 = dispositionConsensusLineage(candSsti94, mockGroundTruth);
  assert(disp94.disposition === 'REPLICATED_TRUE_POSITIVE', `Expected REPLICATED_TRUE_POSITIVE for CWE-94 on HLD-01, got ${disp94.disposition}`);
  console.log('  ✔ 4.3 Level 2 unifies semantic CWE equivalence families (CWE-94 <-> CWE-1336 SSTI) into True Positive.\n');

  // ---------------------------------------------------------------------------
  // Suite 5: Protocol Freeze & Digest Integrity Verification
  // ---------------------------------------------------------------------------
  console.log('Suite 5: Protocol Freeze & Canonical Digest Integrity');

  const protoPath = 'evals/protocols/v1.5-cross-model-protocol.json';
  const proto = loadAndValidateProtocol(protoPath, REPO_ROOT);

  assert(proto.protocolId === 'v1.5-cross-model-1', `Expected protocolId v1.5-cross-model-1, got ${proto.protocolId}`);
  assert(proto.status === 'FROZEN', `Expected status FROZEN, got ${proto.status}`);
  assert(proto.targetVersion === '1.5.0', `Expected targetVersion 1.5.0, got ${proto.targetVersion}`);
  assert(typeof proto.protocolDigest === 'string' && proto.protocolDigest.length === 64, 'Invalid protocolDigest format');

  // 5.1 Verification of computed canonical digest against declared digest
  const computedDigest = computeProtocolDigest(proto);
  assert(computedDigest === proto.protocolDigest, `Digest mismatch: computed ${computedDigest} != declared ${proto.protocolDigest}`);
  console.log(`  ✔ 5.1 Protocol canonical SHA-256 digest verified (${proto.protocolDigest}).`);

  // 5.2 Tampering detection (Fail-Closed)
  const tampered1 = JSON.parse(JSON.stringify(proto));
  tampered1.metrics.strictThreshold = 0.50; // Tamper threshold from 0.60 to 0.50
  assert(computeProtocolDigest(tampered1) !== proto.protocolDigest, 'Tampered strictThreshold must alter digest');

  const tampered2 = JSON.parse(JSON.stringify(proto));
  tampered2.taxonomy.tiers.TIER_1_REASONING_PROFILE_ABLATION.description = 'Hacked description';
  assert(computeProtocolDigest(tampered2) !== proto.protocolDigest, 'Tampered tier description must alter digest');
  console.log('  ✔ 5.2 Tamper-evident binding rejects unauthorized modifications fail-closed.');

  // 5.3 Verification of G5 Medium ablation execution protocol integrity and digest
  const ablationProtoPath = 'evals/protocols/v1.5-g5-ablation-execution-1.json';
  const ablationProto = loadAndValidateProtocol(ablationProtoPath, REPO_ROOT);

  assert(ablationProto.protocolId === 'v1.5-g5-ablation-1', `Expected protocolId v1.5-g5-ablation-1, got ${ablationProto.protocolId}`);
  assert(ablationProto.status === 'FROZEN', `Expected status FROZEN, got ${ablationProto.status}`);
  assert(typeof ablationProto.protocolDigest === 'string' && ablationProto.protocolDigest.length === 64, 'Invalid protocolDigest format');

  const computedAblationDigest = computeProtocolDigest(ablationProto);
  assert(computedAblationDigest === ablationProto.protocolDigest, `Digest mismatch: computed ${computedAblationDigest} != declared ${ablationProto.protocolDigest}`);

  // Tampering detection on ablation execution protocol
  const tamperedAblation = JSON.parse(JSON.stringify(ablationProto));
  tamperedAblation.executionParameters.throttleDelayMs = 1000;
  assert(computeProtocolDigest(tamperedAblation) !== ablationProto.protocolDigest, 'Tampered throttleDelayMs must alter digest');

  console.log(`  ✔ 5.3 G5 Medium Ablation Execution Protocol canonical SHA-256 digest verified fail-closed (${ablationProto.protocolDigest}).\n`);

  // ---------------------------------------------------------------------------
  // Suite 6: Comparative Specificity & Report Rendering
  // ---------------------------------------------------------------------------
  console.log('Suite 6: Safe Control Specificity & Publication Report Rendering');

  // 6.1 Specificity parity test
  const cleanRuns = [
    { findings: { candidates: [] } },
    { findings: { candidates: [] } }
  ];
  const specRes = computeComparativeSpecificity(cleanRuns, cleanRuns);
  assert(specRes.fpCountA === 0 && specRes.fpCountB === 0, 'Clean runs must have 0 FPs');
  assert(specRes.safeControlSuppressionAgreement === 1.0, 'Clean runs must have 100% suppression agreement');
  console.log('  ✔ 6.1 Safe control suppression agreement correctly computes 100% on zero-FP runs.');

  // 6.2 Report rendering integration test
  const testConsensus = computeConsensusLineages(runsWithRecurrenceA, runsWithRecurrenceB, mockGroundTruth, { threshold: 0.60 });
  const mdReport = renderComparativeReport({
    classification: t1,
    consensus: testConsensus,
    specificity: specRes,
    protocol: proto
  });
  assert(mdReport.includes('Cross-Model & Ablation Comparative Validation Report'), 'Report missing title');
  assert(mdReport.includes('TIER 1 (REASONING_PROFILE_ABLATION)'), 'Report missing Tier 1 banner');
  assert(mdReport.includes('Dual-Tier Jaccard Lineage Stability Matrix'), 'Report missing Jaccard table');
  assert(mdReport.includes('Safe Control Specificity'), 'Report missing specificity section');
  console.log('  ✔ 6.2 Publication-grade comparative Markdown report rendered cleanly with all sections.');

  // 6.3 Multi-Configuration Comparison Matrix (compareRunMatrix)
  const dummyRun1 = [{ environment: { modelId: 'gemini-3.8-flash-high', identitySource: 'RUNTIME_ATTESTED' }, findings: { candidates: [candL1] } }];
  const dummyRun2 = [{ environment: { modelId: 'gemini-3.8-flash-low', identitySource: 'RUNTIME_ATTESTED' }, findings: { candidates: [candL2] } }];
  const dummyRun3 = [{ environment: { modelId: 'claude-3-7-sonnet', modelProvider: 'anthropic', identitySource: 'RUNTIME_ATTESTED' }, findings: { candidates: [candL1] } }];

  const matrixOutput = compareRunMatrix([dummyRun1, dummyRun2, dummyRun3], { repoRoot: REPO_ROOT });
  assert(matrixOutput.configurations.length === 3, `Expected 3 configs, got ${matrixOutput.configurations.length}`);
  assert(matrixOutput.pairwiseResults.length === 3, `Expected 3 pairwise comparisons (C(3,2)), got ${matrixOutput.pairwiseResults.length}`);
  assert(matrixOutput.pairwiseResults[0].classification.tier === 1, 'Pair 1 vs 2 should be Tier 1 REASONING_PROFILE_ABLATION');
  assert(matrixOutput.pairwiseResults[1].classification.tier === 3, 'Pair 1 vs 3 should be Tier 3 CROSS_PROVIDER_MODEL_REPLICATION');
  assert(matrixOutput.pairwiseResults[2].classification.tier === 3, 'Pair 2 vs 3 should be Tier 3 CROSS_PROVIDER_MODEL_REPLICATION');
  assert(matrixOutput.report.includes('Multi-Configuration Cross-Model Comparative Matrix Report'), 'Matrix report missing title');
  assert(matrixOutput.report.includes('Pairwise Comparison Matrix'), 'Matrix report missing matrix table');
  console.log('  ✔ 6.3 Multi-configuration matrix comparison (compareRunMatrix) verified with full pairwise matrix report.\n');

  // ---------------------------------------------------------------------------
  // Suite 7: Live Benchmark Hermetic Stream Isolation Invariant (Milestone G7-R)
  // ---------------------------------------------------------------------------
  console.log('Suite 7: Live Benchmark Stream Isolation Invariant');
  // 7.1 Clean isolated stream passes
  const cleanTarget = { name: 'ini-post' };
  const cleanStream = 'view_file ini.js\nInspecting functions\n{"schemaVersion":"1.0.0","candidates":[]}';
  const cleanAudit = auditStreamIsolation(cleanStream, cleanTarget);
  assert(cleanAudit.isolated === true, 'Clean stream must pass isolation audit');
  assert(cleanAudit.violations.length === 0, 'Clean stream must have 0 violations');

  // 7.2 Sibling checkout leakage fails closed
  const siblingLeakStream = 'git diff --no-index evals/oss-checkouts/ini-pre/ini.js ini.js';
  const siblingAudit = auditStreamIsolation(siblingLeakStream, cleanTarget);
  assert(siblingAudit.isolated === false, 'Sibling leakage must fail isolation audit');
  assert(siblingAudit.violations.some(v => v.includes('ini-pre') || v.includes('git diff')), 'Must detect sibling leakage violation');

  // 7.3 Parent repository path leakage fails closed
  const parentLeakStream = 'view_file C:/Users/arcobaleno/Documents/Code/agy-security-audit/package.json';
  const parentAudit = auditStreamIsolation(parentLeakStream, cleanTarget);
  assert(parentAudit.isolated === false, 'Parent repository leakage must fail isolation audit');
  assert(parentAudit.violations.some(v => v.includes('parent repository')), 'Must detect parent repository leakage violation');

  console.log('  ✔ 7.1 Live benchmark stream isolation invariant enforces Default-Deny on sibling/parent/oracle leakage.\n');

  console.log('================================================================');
  console.log('All cross-model comparative validation protocol tests passed successfully.');
  console.log('================================================================');
}

runSuite();
