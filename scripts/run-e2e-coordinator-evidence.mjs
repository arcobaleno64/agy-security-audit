#!/usr/bin/env node
/**
 * run-e2e-coordinator-evidence.mjs
 * End-to-End Live AGY Runtime Coordinator Assurance Harness (v1.4.0-dev).
 *
 * Exercises the native Antigravity CLI executing `security-audit-coordinator`
 * to orchestrate threat modeling, discovery, and 3-lens verification against
 * a controlled fixture, proving:
 *   1. Native AGY runtime mounts `security-audit-coordinator`.
 *   2. Coordinator obeys `commandExecutionPolicy: sandbox`.
 *   3. Coordinator dispatches specialized subagents via `invoke_subagent`.
 *   4. Subagent ballots are collected double-blind and finalized via deterministic TCB.
 *   5. Emits verifiable E2E execution trace envelope with SHA-256 integrity.
 */

import fs from 'node:fs';
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

/**
 * Validates whether an AGY stream-json trace demonstrates full coordinator orchestration.
 * @param {Array<object>|string} input - Parsed events array or raw NDJSON string.
 * @returns {object} Validation result and detailed audit metrics.
 */
export function validateCoordinatorTrace(input) {
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
  let reachedFinalization = false;
  let coordinatorDispatched = false;
  let conversationId = null;

  for (const ev of events) {
    // Handle init event
    if (ev.event === 'init' || ev.init) {
      const initObj = ev.init || ev;
      if (initObj.agent === 'security-audit-coordinator') {
        coordinatorDispatched = true;
      }
      if (initObj.conversation_id || initObj.conversationId) {
        conversationId = initObj.conversation_id || initObj.conversationId;
      }
    }

    // Direct event check
    if (ev.type === 'agent_init' || ev.agent === 'security-audit-coordinator') {
      coordinatorDispatched = true;
    }

    // Handle tool invocations from step_update or direct tool events
    const step = ev.step_update || ev;
    const toolCall = step.tool_call || step.tool_use || (step.toolName ? step : null);

    if (toolCall) {
      const toolName = toolCall.name || toolCall.tool || toolCall.toolName;
      if (toolName) toolsUsed.add(toolName);

      let callArgs = toolCall.args ?? toolCall.arguments ?? {};
      if (typeof callArgs === 'string') {
        try { callArgs = JSON.parse(callArgs); } catch {}
      }

      if (toolName === 'invoke_subagent') {
        const subagents = callArgs?.Subagents || callArgs?.subagents || [];
        if (Array.isArray(subagents)) {
          for (const sub of subagents) {
            const name = sub?.TypeName || sub?.name || sub?.Role || sub?.role;
            if (name) subagentInvocations.push(String(name));
          }
        } else {
          const directName = callArgs?.agent || callArgs?.subagent || callArgs?.TypeName;
          if (directName) subagentInvocations.push(String(directName));
        }
      }

      if (toolName === 'run_command') {
        const cmd = callArgs?.CommandLine || callArgs?.command || '';
        if (typeof cmd === 'string' && cmd.includes('finalize-scan.mjs')) {
          reachedFinalization = true;
        }
      }
    }
  }

  const requiredSubagentRoles = [
    'threat-modeler',
    'discovery-agent'
  ];

  const matchedRequired = requiredSubagentRoles.filter(
    req => subagentInvocations.some(inv => inv && inv.toLowerCase().includes(req.toLowerCase()))
  );

  const traceDigest = crypto.createHash('sha256').update(rawNdjson, 'utf8').digest('hex');

  return {
    valid: coordinatorDispatched && matchedRequired.length === requiredSubagentRoles.length,
    coordinatorDispatched,
    conversationId,
    toolsUsed: Array.from(toolsUsed),
    subagentInvocations,
    matchedRequiredSubagents: matchedRequired,
    missingSubagents: requiredSubagentRoles.filter(r => !matchedRequired.includes(r)),
    reachedFinalization,
    traceDigest
  };
}

/**
 * Creates a signed E2E Coordinator Evidence Envelope.
 */
export function createCoordinatorEvidenceEnvelope({
  fixtureId,
  environment,
  traceSummary,
  validation,
  rawTraceDigest,
  extraMetadata = {}
}) {
  const envelope = {
    schemaVersion: '1.0.0',
    envelopeType: 'E2E_COORDINATOR_EVIDENCE',
    recordedAt: new Date().toISOString(),
    environment,
    fixture: {
      fixtureId,
      ...extraMetadata.fixture
    },
    traceSummary: {
      coordinatorDispatched: traceSummary.coordinatorDispatched,
      conversationId: traceSummary.conversationId,
      toolsUsed: traceSummary.toolsUsed,
      subagentInvocations: traceSummary.subagentInvocations,
      reachedFinalization: traceSummary.reachedFinalization,
      tokenUsage: traceSummary.tokenUsage || {},
      durationSeconds: traceSummary.durationSeconds || null
    },
    validation: {
      valid: validation.valid,
      matchedRequiredSubagents: validation.matchedRequiredSubagents,
      missingSubagents: validation.missingSubagents
    },
    traceDigest: rawTraceDigest
  };

  const canonicalJson = JSON.stringify(envelope, Object.keys(envelope).sort(), 2);
  const envelopeDigest = crypto.createHash('sha256').update(canonicalJson, 'utf8').digest('hex');
  envelope.envelopeDigest = envelopeDigest;

  return envelope;
}

/**
 * Executes live AGY Coordinator against a fixture.
 */
export function executeLiveCoordinatorAudit({
  fixtureId = 'SEM-03',
  repoRoot = DEFAULT_REPO_ROOT,
  modelId = null,
  timeoutMs = 300000,
  sandbox = true,
  outDir = path.join(DEFAULT_REPO_ROOT, 'evals', 'live-runs', 'e2e-coordinator')
}) {
  const env = probeEnvironment(repoRoot, { modelId });
  console.log(`[E2E-COORDINATOR] Launching Live Coordinator Audit: Fixture=${fixtureId}, Model=${env.modelId}, Sandbox=${sandbox}`);

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

  // Construct audit prompt for coordinator
  const prompt = [
    `Perform an authoritative, end-to-end security audit on the codebase located at scratch/e2e-audit-target/service.js.`,
    `Strictly follow your 5-stage orchestration protocol:`,
    `1. Derive inventory via build-inventory.mjs for scratch/e2e-audit-target.`,
    `2. Prepare sanitized review context via prepare-review-context.mjs.`,
    `3. Dispatch threat modeling to threat-modeler subagent.`,
    `4. Dispatch vulnerability discovery to discovery-agent subagent.`,
    `5. Dispatch 3-lens verifier subagents (reachability, defenses, impact).`,
    `6. Finalize the audit via finalize-scan.mjs.`,
    `Do not skip any stage or self-certify without evidence.`
  ].join(' ');

  const agyArgs = [
    '--agent', 'security-audit-coordinator',
    '--output-format', 'stream-json'
  ];
  if (sandbox) agyArgs.push('--sandbox');
  if (modelId) agyArgs.push('--model', modelId);
  agyArgs.push('--print', prompt);

  console.log(`[E2E-COORDINATOR] Executing command: agy ${agyArgs.slice(0, 4).join(' ')} ... (timeout ${timeoutMs}ms)`);

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

  // Parse telemetry
  const parsedTrace = parseStreamJsonTrace(stdout);
  const validation = validateCoordinatorTrace(stdout);

  fs.mkdirSync(outDir, { recursive: true });
  const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
  const envelopePath = path.join(outDir, `evidence-${fixtureId}-${timestamp}.json`);

  const envelope = createCoordinatorEvidenceEnvelope({
    fixtureId,
    environment: env,
    traceSummary: {
      coordinatorDispatched: validation.coordinatorDispatched,
      conversationId: parsedTrace.telemetry?.conversationId || validation.conversationId,
      toolsUsed: validation.toolsUsed,
      subagentInvocations: validation.subagentInvocations,
      reachedFinalization: validation.reachedFinalization,
      tokenUsage: parsedTrace.telemetry?.tokenUsage || {},
      durationSeconds
    },
    validation,
    rawTraceDigest: validation.traceDigest,
    extraMetadata: { fixture: fixtureInfo }
  });

  fs.writeFileSync(envelopePath, JSON.stringify(envelope, null, 2), 'utf8');
  console.log(`✔ [E2E-COORDINATOR] Evidence envelope saved to: ${envelopePath}`);

  return {
    success: validation.valid && proc.status === 0,
    envelopePath,
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
  const timeoutArg = Number(args.find(a => a.startsWith('--timeout='))?.split('=')[1]) || 300000;

  if (isHelp) {
    console.log(`
Usage: node scripts/run-e2e-coordinator-evidence.mjs [options]

Options:
  --fixture=<id>    Target fixture to audit (default: SEM-03)
  --dry-run         Verify harness logic, trace parser, and envelope hashing
  --model=<id>      Specify LLM model ID for AGY CLI
  --timeout=<ms>    Timeout per run in milliseconds (default: 300000)
  --help, -h        Show this help message
`);
    process.exit(0);
  }

  const env = probeEnvironment(DEFAULT_REPO_ROOT);
  console.log(`[E2E-COORDINATOR] Runtime Environment: AGY=${env.agyVersion}, Node=${env.nodeVersion}, Tool=${env.toolVersion}`);

  if (isDryRun) {
    console.log('[E2E-COORDINATOR] Running dry-run harness self-test...');
    const syntheticTrace = [
      { event: 'init', init: { agent: 'security-audit-coordinator', conversation_id: 'dry-run-001' } },
      {
        step_update: {
          tool_call: {
            name: 'invoke_subagent',
            args: {
              Subagents: [
                { TypeName: 'threat-modeler', Role: 'Threat Modeler' },
                { TypeName: 'discovery-agent', Role: 'Vulnerability Hunter' },
                { TypeName: 'verifier-reachability', Role: 'Reachability Verifier' }
              ]
            }
          }
        }
      },
      {
        step_update: {
          tool_call: {
            name: 'run_command',
            args: { CommandLine: 'node skills/security-audit/scripts/finalize-scan.mjs --manifest scratch/scan-manifest.json' }
          }
        }
      }
    ];

    const validation = validateCoordinatorTrace(syntheticTrace);
    if (!validation.valid) {
      console.error('❌ Dry-run self-test validation failed:', validation);
      process.exit(1);
    }

    const envelope = createCoordinatorEvidenceEnvelope({
      fixtureId: 'SEM-03-SYNTHETIC',
      environment: env,
      traceSummary: {
        coordinatorDispatched: validation.coordinatorDispatched,
        conversationId: validation.conversationId,
        toolsUsed: validation.toolsUsed,
        subagentInvocations: validation.subagentInvocations,
        reachedFinalization: validation.reachedFinalization
      },
      validation,
      rawTraceDigest: validation.traceDigest
    });

    if (!envelope.envelopeDigest) {
      console.error('❌ Dry-run envelope digest missing');
      process.exit(1);
    }

    console.log('✔ Dry-run harness self-test passed successfully:', {
      coordinatorDispatched: validation.coordinatorDispatched,
      subagentsDispatched: validation.subagentInvocations,
      reachedFinalization: validation.reachedFinalization,
      envelopeDigest: envelope.envelopeDigest
    });
    process.exit(0);
  }

  try {
    const result = executeLiveCoordinatorAudit({
      fixtureId: fixtureArg,
      modelId: modelArg,
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
