#!/usr/bin/env node
/**
 * run-e2e-coordinator-evidence.mjs
 * End-to-End Live AGY Runtime Coordinator Assurance Harness (v1.4.0-dev).
 *
 * Exercises the native Antigravity CLI executing `security-audit-coordinator`
 * to orchestrate threat modeling, discovery, and 3-lens verification against
 * a controlled fixture, producing reproducible, integrity-hashed evidence envelopes.
 *
 * Canonicalization Specification:
 *   - Algorithm: AGY-SA-C14N-v1
 *   - Recursive lexicographical key sorting across all nested objects and arrays.
 *   - SHA-256 cryptographic binding over normalized JSON representation.
 *
 * Evidence Claim Hierarchy:
 *   - COORDINATOR_ORCHESTRATION_OBSERVED: Proves coordinator native mount and initial dispatch (Smoke).
 *   - FULL_PIPELINE_E2E_OBSERVED: Proves complete pipeline: threat modeling, discovery,
 *     conditional 3-lens verifier panel, and verified finalizer execution.
 */

import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import {
  probeEnvironment,
  parseStreamJsonTrace
} from '../skills/security-audit/scripts/record-benchmark-run.mjs';
import { TOOL_VERSION } from '../skills/security-audit/scripts/finalize-scan.mjs';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const DEFAULT_REPO_ROOT = path.resolve(__dirname, '..');

export const CANONICALIZATION_ALGORITHM = 'AGY-SA-C14N-v1';

export const CLAIM_TYPES = {
  ORCHESTRATION: 'COORDINATOR_ORCHESTRATION_OBSERVED',
  FULL_PIPELINE: 'FULL_PIPELINE_E2E_OBSERVED'
};

export const EXECUTION_LANES = {
  FUNCTIONAL: 'FUNCTIONAL_SKIP_PERMISSIONS',
  POLICY: 'POLICY_ENFORCED'
};

/**
 * Recursively canonicalizes an object or array by sorting all keys lexicographically (AGY-SA-C14N-v1).
 * @param {*} value - Target data to canonicalize.
 * @returns {*} Canonical deep copy with sorted keys.
 */
export function canonicalize(value) {
  if (value === null || typeof value !== 'object') {
    return value;
  }
  if (Array.isArray(value)) {
    return value.map(canonicalize);
  }
  const sortedKeys = Object.keys(value).sort();
  const result = {};
  for (const key of sortedKeys) {
    result[key] = canonicalize(value[key]);
  }
  return result;
}

/**
 * Computes deterministic SHA-256 digest of canonicalized envelope data.
 * @param {object} envelopeData - Envelope object excluding envelopeDigest itself.
 * @returns {string} Hex SHA-256 hash.
 */
export function computeEnvelopeDigest(envelopeData) {
  const { envelopeDigest, ...rest } = envelopeData;
  const canonicalObj = canonicalize(rest);
  const canonicalJson = JSON.stringify(canonicalObj, null, 2);
  return crypto.createHash('sha256').update(canonicalJson, 'utf8').digest('hex');
}

/**
 * Validates whether an AGY stream-json trace or transcript demonstrates coordinator orchestration.
 * @param {Array<object>|string} input - Parsed events array or raw NDJSON string.
 * @param {string|null} conversationId - Optional conversation ID to probe disk transcript.
 * @param {string} targetClaim - Targeted claim type (ORCHESTRATION or FULL_PIPELINE).
 * @param {number|null} candidateCount - Optional candidate finding count for conditional 3-lens check.
 * @param {string} repoRoot - Target repository root for checking finalizer artifacts.
 * @returns {object} Validation result and detailed audit metrics.
 */
export function validateCoordinatorTrace(
  input,
  conversationId = null,
  targetClaim = CLAIM_TYPES.FULL_PIPELINE,
  candidateCount = null,
  repoRoot = DEFAULT_REPO_ROOT
) {
  let events = [];
  let rawNdjson = '';

  if (typeof input === 'string') {
    rawNdjson = input;
    const lines = input.split(/\r?\n/).filter(l => l.trim().length > 0);
    for (const l of lines) {
      try { events.push(JSON.parse(l)); } catch {}
    }
  } else if (Array.isArray(input)) {
    events = input;
    rawNdjson = events.map(e => JSON.stringify(e)).join('\n');
  } else {
    return {
      valid: false,
      reason: 'Input must be a valid NDJSON string or array of events.',
      metrics: {}
    };
  }

  const subagentInvocations = [];
  const toolsUsed = new Set();
  let coordinatorDispatched = false;
  let discoveredConversationId = conversationId;
  let observedPermissionMode = null;

  let finalizerInvoked = false;
  let finalizerCompleted = false;
  let finalizerArtifactPath = null;
  let finalizerArtifactDigest = null;
  let finalizerExitStatus = null;

  // 1. Process stream events
  for (const ev of events) {
    if (ev.event === 'init' || ev.init) {
      const initObj = ev.init || ev;
      if (initObj.agent === 'security-audit-coordinator') {
        coordinatorDispatched = true;
      }
      if (!discoveredConversationId && (initObj.conversation_id || initObj.conversationId)) {
        discoveredConversationId = initObj.conversation_id || initObj.conversationId;
      }
      if (initObj.permission_mode || initObj.permissionMode) {
        observedPermissionMode = initObj.permission_mode || initObj.permissionMode;
      }
    }

    if (ev.type === 'agent_init' || ev.agent === 'security-audit-coordinator') {
      coordinatorDispatched = true;
    }

    const step = ev.step_update || ev;
    const rawCalls = step.tool_calls || (step.tool_call ? [step.tool_call] : (step.tool_use ? [step.tool_use] : (step.toolName ? [step] : [])));

    for (const toolCall of rawCalls) {
      const toolName = toolCall.name || toolCall.tool || toolCall.toolName;
      if (toolName) toolsUsed.add(toolName);

      let callArgs = toolCall.args ?? toolCall.arguments ?? {};
      if (typeof callArgs === 'string') {
        try { callArgs = JSON.parse(callArgs); } catch {}
      }

      if (toolName === 'invoke_subagent') {
        let subagents = callArgs?.Subagents || callArgs?.subagents || [];
        if (typeof subagents === 'string') {
          try { subagents = JSON.parse(subagents); } catch {}
        }
        if (Array.isArray(subagents)) {
          for (const sub of subagents) {
            const name = sub?.TypeName || sub?.name || sub?.Role || sub?.role;
            if (name && !subagentInvocations.includes(String(name))) {
              subagentInvocations.push(String(name));
            }
          }
        } else {
          const directName = callArgs?.agent || callArgs?.subagent || callArgs?.TypeName;
          if (directName && !subagentInvocations.includes(String(directName))) {
            subagentInvocations.push(String(directName));
          }
        }
      }

      // Finalizer tracking
      if (toolName === 'run_command') {
        const cmd = callArgs?.CommandLine || callArgs?.command || '';
        if (typeof cmd === 'string' && cmd.includes('finalize-scan.mjs')) {
          finalizerInvoked = true;
          // Inspect if tool execution step explicitly signaled error
          if (step.state === 'DONE' && step.status !== 'ERROR') {
            finalizerExitStatus = 0;
          }
        }
      }
    }
  }

  // 2. Supplement from disk transcript if conversationId is available
  if (discoveredConversationId) {
    const transcriptPath = path.join(
      os.homedir(),
      '.gemini',
      'antigravity-cli',
      'brain',
      discoveredConversationId,
      '.system_generated',
      'logs',
      'transcript.jsonl'
    );

    if (fs.existsSync(transcriptPath)) {
      try {
        const logLines = fs.readFileSync(transcriptPath, 'utf8').split(/\r?\n/).filter(Boolean);
        for (const line of logLines) {
          try {
            const stepObj = JSON.parse(line);
            if (stepObj.tool_calls && Array.isArray(stepObj.tool_calls)) {
              for (const tc of stepObj.tool_calls) {
                const name = tc.name || tc.tool;
                if (name) toolsUsed.add(name);

                let args = tc.args || tc.arguments || {};
                if (typeof args === 'string') {
                  try { args = JSON.parse(args); } catch {}
                }

                if (name === 'invoke_subagent') {
                  let subs = args.Subagents || args.subagents || [];
                  if (typeof subs === 'string') {
                    try { subs = JSON.parse(subs); } catch {}
                  }
                  if (Array.isArray(subs)) {
                    for (const s of subs) {
                      const subName = s.TypeName || s.name || s.Role;
                      if (subName && !subagentInvocations.includes(String(subName))) {
                        subagentInvocations.push(String(subName));
                      }
                    }
                  }
                }

                if (name === 'run_command') {
                  const cmd = args.CommandLine || args.command || '';
                  if (typeof cmd === 'string' && cmd.includes('finalize-scan.mjs')) {
                    finalizerInvoked = true;
                    if (stepObj.status === 'DONE') {
                      finalizerExitStatus = 0;
                    }
                  }
                }
              }
            }
          } catch {}
        }
      } catch {}
    }
  }

  // 3. Check for physical canonical finalizer artifact on disk
  const candidateArtifactPaths = [
    path.join(repoRoot, 'scratch', 'scan-manifest.json'),
    path.join(repoRoot, 'scratch', 'security-audit.sarif'),
    path.join(repoRoot, 'scratch', 'canonical-findings.json')
  ];

  for (const artPath of candidateArtifactPaths) {
    if (fs.existsSync(artPath)) {
      try {
        const content = fs.readFileSync(artPath, 'utf8');
        const parsed = JSON.parse(content);
        // Ensure manifest is complete if scan-manifest
        if (artPath.endsWith('scan-manifest.json') && parsed.complete !== true) {
          continue;
        }
        finalizerArtifactPath = path.relative(repoRoot, artPath).replace(/\\/g, '/');
        finalizerArtifactDigest = crypto.createHash('sha256').update(content, 'utf8').digest('hex');
        if (finalizerInvoked) {
          finalizerCompleted = true;
        }
        break;
      } catch {}
    }
  }

  // 4. Evaluate criteria based on target claim tier
  let valid = false;
  let missingSubagents = [];
  let matchedRequired = [];
  let threeLensRequired = false;

  if (targetClaim === CLAIM_TYPES.ORCHESTRATION) {
    // Smoke tier: coordinator dispatched and at least one subagent initiated
    matchedRequired = subagentInvocations.filter(inv =>
      inv.toLowerCase().includes('threat-modeler') || inv.toLowerCase().includes('discovery-agent')
    );
    valid = coordinatorDispatched && matchedRequired.length >= 1;
    missingSubagents = matchedRequired.length === 0 ? ['threat-modeler-or-discovery'] : [];
  } else {
    // Full Pipeline tier: threat-modeler + discovery-agent + conditional 3-lens + verified finalizer completion
    const baseRoles = ['threat-modeler', 'discovery-agent'];
    const matchedBase = baseRoles.filter(req =>
      subagentInvocations.some(inv => inv && inv.toLowerCase().includes(req))
    );

    const isCleanComponent = candidateCount === 0;
    threeLensRequired = !isCleanComponent;

    let verifierRoles = [];
    let matchedVerifiers = [];

    if (threeLensRequired) {
      verifierRoles = ['verifier-reachability', 'verifier-defenses', 'verifier-impact'];
      matchedVerifiers = verifierRoles.filter(req =>
        subagentInvocations.some(inv => inv && inv.toLowerCase().includes(req))
      );
    }

    const allRequiredRoles = [...baseRoles, ...verifierRoles];
    matchedRequired = [...matchedBase, ...matchedVerifiers];
    missingSubagents = allRequiredRoles.filter(r => !matchedRequired.includes(r));

    valid = coordinatorDispatched &&
            missingSubagents.length === 0 &&
            finalizerCompleted === true;
  }

  const traceDigest = crypto.createHash('sha256').update(rawNdjson, 'utf8').digest('hex');

  return {
    valid,
    targetClaim,
    coordinatorDispatched,
    conversationId: discoveredConversationId,
    observedPermissionMode,
    toolsUsed: Array.from(toolsUsed),
    subagentInvocations,
    matchedRequiredSubagents: matchedRequired,
    missingSubagents,
    threeLensRequired,
    finalizer: {
      invoked: finalizerInvoked,
      completed: finalizerCompleted,
      exitStatus: finalizerExitStatus,
      artifactPath: finalizerArtifactPath,
      artifactDigest: finalizerArtifactDigest
    },
    traceDigest
  };
}

/**
 * Creates an integrity-hashed E2E Coordinator Evidence Envelope with AGY-SA-C14N-v1.
 */
export function createCoordinatorEvidenceEnvelope({
  fixtureId,
  environment,
  traceSummary,
  validation,
  rawTraceDigest,
  rawTraceRelativePath = null,
  targetClaim = CLAIM_TYPES.FULL_PIPELINE,
  executionLane = EXECUTION_LANES.FUNCTIONAL,
  extraMetadata = {}
}) {
  const isPublicationGrade = !environment.toolDirty && validation.valid;

  const envelope = {
    schemaVersion: '1.0.0',
    envelopeType: 'E2E_COORDINATOR_EVIDENCE',
    targetClaim,
    evidenceGrade: isPublicationGrade ? 'PUBLICATION_GRADE' : 'DEVELOPMENT_SMOKE',
    publicationEligible: isPublicationGrade,
    executionLane,
    canonicalizationAlgorithm: CANONICALIZATION_ALGORITHM,
    recordedAt: new Date().toISOString(),
    environment,
    fixture: {
      fixtureId,
      ...extraMetadata.fixture
    },
    traceSummary: {
      coordinatorDispatched: traceSummary.coordinatorDispatched,
      conversationId: traceSummary.conversationId,
      observedPermissionMode: traceSummary.observedPermissionMode || null,
      toolsUsed: traceSummary.toolsUsed,
      subagentInvocations: traceSummary.subagentInvocations,
      tokenUsage: traceSummary.tokenUsage || {},
      durationSeconds: traceSummary.durationSeconds || null
    },
    finalizer: validation.finalizer || {
      invoked: false,
      completed: false,
      exitStatus: null,
      artifactPath: null,
      artifactDigest: null
    },
    traceArtifact: {
      relativePath: rawTraceRelativePath,
      sha256Digest: rawTraceDigest
    },
    validation: {
      valid: validation.valid,
      targetClaim: validation.targetClaim,
      matchedRequiredSubagents: validation.matchedRequiredSubagents,
      missingSubagents: validation.missingSubagents,
      threeLensRequired: validation.threeLensRequired
    }
  };

  envelope.envelopeDigest = computeEnvelopeDigest(envelope);
  return envelope;
}

/**
 * Resolves a model ID cleanly from CLI args, environment, or default fallback.
 */
export function resolveModelId(specifiedModel = null) {
  if (specifiedModel) return specifiedModel;
  if (process.env.AGY_MODEL) return process.env.AGY_MODEL;
  return 'gemini-3.8-flash-high';
}

/**
 * Executes live AGY Coordinator against a fixture.
 */
export function executeLiveCoordinatorAudit({
  fixtureId = 'SEM-03',
  targetClaim = CLAIM_TYPES.ORCHESTRATION,
  repoRoot = DEFAULT_REPO_ROOT,
  modelId = null,
  timeoutMs = 420000,
  sandbox = true,
  policyEnforcement = false,
  outDir = path.join(DEFAULT_REPO_ROOT, 'evals', 'live-runs', 'e2e-coordinator')
}) {
  const resolvedModel = resolveModelId(modelId);
  const env = probeEnvironment(repoRoot, { modelId: resolvedModel, modelProvider: 'google' });
  const executionLane = policyEnforcement ? EXECUTION_LANES.POLICY : EXECUTION_LANES.FUNCTIONAL;

  console.log(`[E2E-COORDINATOR] Launching Live Coordinator Audit: Fixture=${fixtureId}, Claim=${targetClaim}, Model=${env.modelId}, Lane=${executionLane}`);

  // Resolve fixture file
  const semanticGtPath = path.join(repoRoot, 'evals', 'semantic-benchmark', 'ground-truth.json');
  let fixtureInfo = null;
  if (fs.existsSync(semanticGtPath)) {
    try {
      const gt = JSON.parse(fs.readFileSync(semanticGtPath, 'utf8'));
      fixtureInfo = gt.find(f => f.id === fixtureId);
    } catch {}
  }

  const fixtureRelPath = fixtureInfo?.file || `evals/semantic-benchmark/03-confused-deputy.js`;
  const fixtureAbsPath = path.join(repoRoot, fixtureRelPath);

  if (!fs.existsSync(fixtureAbsPath)) {
    throw new Error(`Fixture file not found: ${fixtureAbsPath}`);
  }

  // Prepare isolated target in scratch
  const targetDir = path.join(repoRoot, 'scratch', 'e2e-audit-target');
  fs.mkdirSync(targetDir, { recursive: true });
  const targetFile = path.join(targetDir, 'service.js');
  fs.copyFileSync(fixtureAbsPath, targetFile);

  const normalizedRepoRoot = repoRoot.replace(/\\/g, '/');
  const normalizedTargetFile = path.relative(repoRoot, targetFile).replace(/\\/g, '/');

  // Construct audit prompt for coordinator with explicit paths
  const prompt = [
    `Perform an authoritative, end-to-end security audit on the codebase located at ${normalizedTargetFile}.`,
    `The project repository root is ${normalizedRepoRoot}.`,
    `Strictly follow your 5-stage orchestration protocol:`,
    `1. Derive inventory via build-inventory.mjs for scratch/e2e-audit-target.`,
    `2. Prepare sanitized review context via prepare-review-context.mjs.`,
    `3. Dispatch threat modeling to threat-modeler subagent.`,
    `4. Dispatch vulnerability discovery to discovery-agent subagent.`,
    `5. Dispatch 3-lens verifier subagents (reachability, defenses, impact).`,
    `6. Finalize the audit via finalize-scan.mjs.`,
    `Do not skip any stage or self-certify without evidence.`
  ].join('\n');

  const agyArgs = [
    '--agent', 'security-audit-coordinator',
    '--add-dir', repoRoot,
    '--output-format', 'stream-json'
  ];
  if (sandbox) agyArgs.push('--sandbox');
  if (!policyEnforcement) {
    agyArgs.push('--dangerously-skip-permissions');
  }
  agyArgs.push('--model', resolvedModel);
  agyArgs.push('--print', prompt);

  console.log(`[E2E-COORDINATOR] Executing command: agy ${agyArgs.slice(0, 6).join(' ')} ... (timeout ${timeoutMs}ms)`);

  const agyBin = process.platform === 'win32' ? 'agy.exe' : 'agy';
  const startTs = Date.now();

  const proc = spawnSync(agyBin, agyArgs, {
    cwd: repoRoot,
    encoding: 'utf8',
    timeout: timeoutMs,
    env: { ...process.env, PAGER: 'cat' },
    stdio: ['pipe', 'pipe', 'pipe']
  });

  const durationSeconds = (Date.now() - startTs) / 1000;
  const stdout = proc.stdout || '';
  const stderr = proc.stderr || '';

  console.log(`[E2E-COORDINATOR] Process completed with exit code ${proc.status ?? (proc.error ? 1 : 0)} in ${durationSeconds.toFixed(1)}s`);

  // Detect candidates from scratch if available
  let candidateCount = null;
  const manifestPath = path.join(repoRoot, 'scratch', 'scan-manifest.json');
  if (fs.existsSync(manifestPath)) {
    try {
      const parsedManifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
      candidateCount = parsedManifest.findings?.length ?? parsedManifest.candidateCount ?? null;
    } catch {}
  }

  // Parse telemetry
  const parsedTrace = parseStreamJsonTrace(stdout);
  const discoveredConvId = parsedTrace.telemetry?.conversationId || null;
  const validation = validateCoordinatorTrace(stdout, discoveredConvId, targetClaim, candidateCount, repoRoot);

  fs.mkdirSync(outDir, { recursive: true });
  const timestamp = new Date().toISOString().replace(/[:.]/g, '-');

  // Persist raw trace artifact for independent cryptographic verification
  const traceFilename = `trace-${fixtureId}-${timestamp}.ndjson`;
  const tracePath = path.join(outDir, traceFilename);
  fs.writeFileSync(tracePath, stdout, 'utf8');
  const rawTraceDigest = crypto.createHash('sha256').update(stdout, 'utf8').digest('hex');

  const envelopeFilename = `evidence-${fixtureId}-${timestamp}.json`;
  const envelopePath = path.join(outDir, envelopeFilename);

  const envelope = createCoordinatorEvidenceEnvelope({
    fixtureId,
    environment: env,
    traceSummary: {
      coordinatorDispatched: validation.coordinatorDispatched,
      conversationId: validation.conversationId || discoveredConvId,
      observedPermissionMode: validation.observedPermissionMode,
      toolsUsed: validation.toolsUsed,
      subagentInvocations: validation.subagentInvocations,
      tokenUsage: parsedTrace.telemetry?.tokenUsage || {},
      durationSeconds
    },
    validation,
    rawTraceDigest,
    rawTraceRelativePath: path.join('evals', 'live-runs', 'e2e-coordinator', traceFilename).replace(/\\/g, '/'),
    targetClaim,
    executionLane,
    extraMetadata: { fixture: fixtureInfo }
  });

  fs.writeFileSync(envelopePath, JSON.stringify(envelope, null, 2), 'utf8');
  console.log(`✔ [E2E-COORDINATOR] Raw trace preserved at: ${tracePath}`);
  console.log(`✔ [E2E-COORDINATOR] Evidence envelope saved to: ${envelopePath}`);

  return {
    success: validation.valid,
    envelopePath,
    tracePath,
    validation,
    durationSeconds,
    stderr: stderr ? stderr.slice(0, 500) : ''
  };
}

/**
 * CLI Entrypoint
 */
export function main(args = process.argv.slice(2)) {
  const isHelp = args.includes('--help') || args.includes('-h');
  const isDryRun = args.includes('--dry-run');
  const fixtureArg = args.find(a => a.startsWith('--fixture='))?.split('=')[1] || 'SEM-03';
  const modelArg = args.find(a => a.startsWith('--model='))?.split('=')[1] || null;
  const claimArg = args.find(a => a.startsWith('--claim='))?.split('=')[1] || 'orchestration';
  const policyEnforcement = args.includes('--policy-enforcement');
  const timeoutArg = Number(args.find(a => a.startsWith('--timeout='))?.split('=')[1]) || 420000;

  const targetClaim = claimArg === 'full-pipeline' ? CLAIM_TYPES.FULL_PIPELINE : CLAIM_TYPES.ORCHESTRATION;

  if (isHelp) {
    console.log(`
Usage: node scripts/run-e2e-coordinator-evidence.mjs [options]

Options:
  --fixture=<id>          Target fixture to audit (default: SEM-03)
  --claim=<type>          Target claim: 'orchestration' (smoke) or 'full-pipeline' (default: orchestration)
  --policy-enforcement    Run under policy enforcement lane (no skip permissions)
  --dry-run               Verify harness logic, trace parser, and envelope hashing
  --model=<id>            Specify LLM model ID for AGY CLI (default: gemini-3.8-flash-high)
  --timeout=<ms>          Timeout per run in milliseconds (default: 420000)
  --help, -h              Show this help message
`);
    process.exit(0);
  }

  const env = probeEnvironment(DEFAULT_REPO_ROOT, { modelId: resolveModelId(modelArg), modelProvider: 'google' });
  console.log(`[E2E-COORDINATOR] Runtime Environment: AGY=${env.agyVersion}, Node=${env.nodeVersion}, Tool=${env.toolVersion}, Model=${env.modelId}`);

  if (isDryRun) {
    console.log('[E2E-COORDINATOR] Running dry-run harness self-test...');

    // 1. Test Orchestration Claim (Smoke)
    const smokeTrace = [
      { event: 'init', init: { agent: 'security-audit-coordinator', conversation_id: 'dry-run-smoke' } },
      {
        step_update: {
          tool_calls: [
            {
              name: 'invoke_subagent',
              args: { Subagents: JSON.stringify([{ TypeName: 'threat-modeler' }]) }
            }
          ]
        }
      }
    ];

    const smokeVal = validateCoordinatorTrace(smokeTrace, null, CLAIM_TYPES.ORCHESTRATION);
    if (!smokeVal.valid) {
      console.error('❌ Dry-run smoke validation failed:', smokeVal);
      process.exit(1);
    }

    // 2. Test Finalizer Invoked vs Completed distinction
    const invOnlyTrace = [
      { event: 'init', init: { agent: 'security-audit-coordinator', conversation_id: 'dry-run-inv-only' } },
      {
        step_update: {
          tool_calls: [
            {
              name: 'run_command',
              args: { CommandLine: 'node skills/security-audit/scripts/finalize-scan.mjs --manifest scratch/scan-manifest.json' }
            }
          ]
        }
      }
    ];
    // With non-existent artifact, finalizerCompleted must be false
    const invOnlyVal = validateCoordinatorTrace(invOnlyTrace, null, CLAIM_TYPES.FULL_PIPELINE, 1, path.join(DEFAULT_REPO_ROOT, 'scratch', 'non-existent-dir'));
    if (!invOnlyVal.finalizer.invoked) {
      console.error('❌ Dry-run: finalizerInvoked was false');
      process.exit(1);
    }
    if (invOnlyVal.finalizer.completed) {
      console.error('❌ Dry-run regression: finalizer completed was true without valid artifact');
      process.exit(1);
    }

    // 3. Test Full Pipeline Claim with Valid 3-Lens and Artifact Simulation
    const fullTrace = [
      { event: 'init', init: { agent: 'security-audit-coordinator', conversation_id: 'dry-run-full' } },
      {
        step_update: {
          tool_calls: [
            {
              name: 'invoke_subagent',
              args: {
                Subagents: JSON.stringify([
                  { TypeName: 'threat-modeler' },
                  { TypeName: 'discovery-agent' },
                  { TypeName: 'verifier-reachability' },
                  { TypeName: 'verifier-defenses' },
                  { TypeName: 'verifier-impact' }
                ])
              }
            },
            {
              name: 'run_command',
              args: { CommandLine: 'node skills/security-audit/scripts/finalize-scan.mjs --manifest scratch/scan-manifest.json' }
            }
          ]
        }
      }
    ];

    // Mock artifact on scratch
    const mockScratch = path.join(DEFAULT_REPO_ROOT, 'scratch', 'mock-test-harness');
    fs.mkdirSync(mockScratch, { recursive: true });
    const mockManifest = path.join(mockScratch, 'scratch', 'scan-manifest.json');
    fs.mkdirSync(path.dirname(mockManifest), { recursive: true });
    fs.writeFileSync(mockManifest, JSON.stringify({ complete: true, findings: [] }));

    const fullVal = validateCoordinatorTrace(fullTrace, null, CLAIM_TYPES.FULL_PIPELINE, 1, mockScratch);
    if (!fullVal.valid || !fullVal.finalizer.completed) {
      console.error('❌ Dry-run full pipeline validation failed:', fullVal);
      process.exit(1);
    }

    // 4. Test AGY-SA-C14N-v1 Recursive Mutation Resistance
    const baseEnvelope = createCoordinatorEvidenceEnvelope({
      fixtureId: 'SEM-03-SYNTHETIC',
      environment: env,
      traceSummary: {
        coordinatorDispatched: fullVal.coordinatorDispatched,
        conversationId: fullVal.conversationId,
        toolsUsed: fullVal.toolsUsed,
        subagentInvocations: fullVal.subagentInvocations
      },
      validation: fullVal,
      rawTraceDigest: fullVal.traceDigest,
      rawTraceRelativePath: 'evals/live-runs/e2e-coordinator/trace-synthetic.ndjson',
      targetClaim: CLAIM_TYPES.FULL_PIPELINE
    });

    const d0 = baseEnvelope.envelopeDigest;
    const dModelMut = computeEnvelopeDigest({ ...baseEnvelope, environment: { ...baseEnvelope.environment, modelId: 'MUTATED_MODEL' } });
    const dTraceMut = computeEnvelopeDigest({ ...baseEnvelope, traceArtifact: { ...baseEnvelope.traceArtifact, sha256Digest: 'MUTATED_DIGEST' } });
    const dFinalizerMut = computeEnvelopeDigest({ ...baseEnvelope, finalizer: { ...baseEnvelope.finalizer, artifactDigest: 'MUTATED_ART_DIGEST' } });

    if (d0 === dModelMut) {
      console.error('❌ C14N Mutation Failed: Mutating environment.modelId did NOT alter envelopeDigest');
      process.exit(1);
    }
    if (d0 === dTraceMut) {
      console.error('❌ C14N Mutation Failed: Mutating traceArtifact.sha256Digest did NOT alter envelopeDigest');
      process.exit(1);
    }
    if (d0 === dFinalizerMut) {
      console.error('❌ C14N Mutation Failed: Mutating finalizer.artifactDigest did NOT alter envelopeDigest');
      process.exit(1);
    }

    console.log('✔ Dry-run harness self-test passed successfully across all claim tiers & C14N mutation tests:', {
      smokeClaim: smokeVal.valid,
      finalizerInvokedVsCompletedVerified: !invOnlyVal.finalizer.completed && fullVal.finalizer.completed,
      fullPipelineClaim: fullVal.valid,
      c14nMutationResistant: true,
      canonicalizationAlgorithm: baseEnvelope.canonicalizationAlgorithm,
      envelopeDigest: baseEnvelope.envelopeDigest,
      evidenceGrade: baseEnvelope.evidenceGrade
    });
    process.exit(0);
  }

  try {
    const result = executeLiveCoordinatorAudit({
      fixtureId: fixtureArg,
      targetClaim,
      modelId: modelArg,
      policyEnforcement,
      timeoutMs: timeoutArg
    });
    if (!result.success) {
      console.error('❌ Live Coordinator Audit failed validation.');
      process.exit(1);
    }
    console.log('✔ Live Coordinator Audit completed successfully!');
    process.exit(0);
  } catch (err) {
    console.error('❌ Error executing live coordinator audit:', err.message);
    process.exit(1);
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === path.resolve(__filename)) {
  main();
}
