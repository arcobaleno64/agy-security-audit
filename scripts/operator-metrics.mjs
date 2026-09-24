#!/usr/bin/env node
/**
 * operator-metrics.mjs
 * Track D Phase D3: Quantitative Operator Usability & Friction Observability.
 *
 * Conforming to RFC 0002 §7:
 * - Rejects subjective Likert surveys in favor of observable friction metrics.
 * - Enforces schema validation against schemas/operator-metrics.schema.json.
 * - Implements RFC 0002 §7.2 Interface Decision Gate (CLI vs TUI vs GUI).
 * - Zero external npm dependencies (pure Node.js built-ins).
 */

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
export const DEFAULT_REPO_ROOT = path.resolve(__dirname, '..');

export const OPERATOR_METRICS_SCHEMA_ID = 'https://antigravity.google/schemas/security-audit/operator-metrics.schema.json';

export const INTERFACE_RECOMMENDATIONS = Object.freeze([
  'CLI_SUFFICIENT',
  'CLI_WORKFLOW_IMPROVEMENT_RECOMMENDED',
  'TUI_RECOMMENDED',
  'STATUS_VOCABULARY_CLARIFICATION_RECOMMENDED',
  'GUI_REJECTED_BY_OCCAMS_RAZOR'
]);

/**
 * Validates operator metrics shape against schemas/operator-metrics.schema.json
 * without external dependencies.
 */
export function validateOperatorMetricsShape(metrics) {
  if (!metrics || typeof metrics !== 'object' || Array.isArray(metrics)) return false;

  const requiredKeys = [
    '$schema',
    'timeToInstallSeconds',
    'timeToFirstSuccessfulAuditSeconds',
    'timeToFirstUnderstoodFindingSeconds',
    'manualFilesOpenedCount',
    'rerunsRequiredCount',
    'commandsRetriedCount',
    'helpRequestsCount',
    'misinterpretedStatusesCount',
    'findingAdjudicationSeconds',
    'evidenceFilesManuallyInspectedCount',
    'operatorFrictionNotes'
  ];

  const optionalKeys = [
    'schemaVersion',
    'recordedAt',
    'operatorClass',
    'targetRepository',
    'evaluatedInterfaceRecommendation'
  ];

  const allowedKeys = new Set([...requiredKeys, ...optionalKeys]);
  for (const k of Object.keys(metrics)) {
    if (!allowedKeys.has(k)) return false;
  }
  for (const r of requiredKeys) {
    if (!(r in metrics)) return false;
  }

  if (metrics.$schema !== OPERATOR_METRICS_SCHEMA_ID) return false;

  const isNonNegativeNumber = (val) => typeof val === 'number' && Number.isFinite(val) && val >= 0;
  const isNonNegativeInteger = (val) => Number.isInteger(val) && val >= 0;

  if (!isNonNegativeNumber(metrics.timeToInstallSeconds)) return false;
  if (!isNonNegativeNumber(metrics.timeToFirstSuccessfulAuditSeconds)) return false;
  if (!isNonNegativeNumber(metrics.timeToFirstUnderstoodFindingSeconds)) return false;
  if (!isNonNegativeNumber(metrics.findingAdjudicationSeconds)) return false;

  if (!isNonNegativeInteger(metrics.manualFilesOpenedCount)) return false;
  if (!isNonNegativeInteger(metrics.rerunsRequiredCount)) return false;
  if (!isNonNegativeInteger(metrics.commandsRetriedCount)) return false;
  if (!isNonNegativeInteger(metrics.helpRequestsCount)) return false;
  if (!isNonNegativeInteger(metrics.misinterpretedStatusesCount)) return false;
  if (!isNonNegativeInteger(metrics.evidenceFilesManuallyInspectedCount)) return false;

  if (!Array.isArray(metrics.operatorFrictionNotes)) return false;
  for (const note of metrics.operatorFrictionNotes) {
    if (typeof note !== 'string') return false;
  }

  if ('schemaVersion' in metrics) {
    if (!/^1\.[0-9]+\.[0-9]+$/.test(String(metrics.schemaVersion))) return false;
  }
  if ('recordedAt' in metrics && metrics.recordedAt !== null) {
    if (typeof metrics.recordedAt !== 'string' || Number.isNaN(Date.parse(metrics.recordedAt))) return false;
  }
  if ('operatorClass' in metrics && metrics.operatorClass !== null) {
    if (!['MAINTAINER', 'CONTRIBUTOR', 'INDEPENDENT_OPERATOR', 'AUTOMATED_CI'].includes(metrics.operatorClass)) {
      return false;
    }
  }
  if ('targetRepository' in metrics && metrics.targetRepository !== null) {
    if (typeof metrics.targetRepository !== 'string') return false;
  }
  if ('evaluatedInterfaceRecommendation' in metrics && metrics.evaluatedInterfaceRecommendation !== null) {
    if (!INTERFACE_RECOMMENDATIONS.includes(metrics.evaluatedInterfaceRecommendation)) {
      return false;
    }
  }

  return true;
}

/**
 * Derives interface recommendations strictly adhering to RFC 0002 §7.2:
 * - If manualFilesOpenedCount > 5 or findingAdjudicationSeconds > 300 due to raw JSON/SARIF navigation -> TUI_RECOMMENDED
 * - If rerunsRequiredCount > 1 or commandsRetriedCount > 2 due to invocation friction -> CLI_WORKFLOW_IMPROVEMENT_RECOMMENDED
 * - If misinterpretedStatusesCount > 0 -> STATUS_VOCABULARY_CLARIFICATION_RECOMMENDED
 * - High friction on both invocation and navigation without TUI -> GUI_REJECTED_BY_OCCAMS_RAZOR (Occam's razor rejects GUI before CLI/TUI refinement)
 * - Otherwise -> CLI_SUFFICIENT
 */
export function evaluateInterfaceRecommendation(metrics) {
  if (!validateOperatorMetricsShape(metrics)) {
    throw new Error('INVALID_OPERATOR_METRICS: Input does not conform to operator-metrics.schema.json');
  }

  const recommendations = [];

  if (metrics.misinterpretedStatusesCount > 0) {
    recommendations.push('STATUS_VOCABULARY_CLARIFICATION_RECOMMENDED');
  }

  if (metrics.manualFilesOpenedCount > 5 || metrics.findingAdjudicationSeconds > 300) {
    recommendations.push('TUI_RECOMMENDED');
  }

  if (metrics.rerunsRequiredCount > 1 || metrics.commandsRetriedCount > 2) {
    recommendations.push('CLI_WORKFLOW_IMPROVEMENT_RECOMMENDED');
  }

  if (recommendations.length === 0) {
    return 'CLI_SUFFICIENT';
  }

  // RFC 0002 §7.2: Occam's razor priority order:
  // Status vocabulary clarification > CLI workflow fix > TUI viewer > (GUI is never built first)
  if (recommendations.includes('STATUS_VOCABULARY_CLARIFICATION_RECOMMENDED')) {
    return 'STATUS_VOCABULARY_CLARIFICATION_RECOMMENDED';
  }
  if (recommendations.includes('TUI_RECOMMENDED')) {
    return 'TUI_RECOMMENDED';
  }
  return 'CLI_WORKFLOW_IMPROVEMENT_RECOMMENDED';
}

/**
 * Formats operator metrics for human-readable terminal display.
 */
export function formatOperatorMetricsSummary(metrics) {
  const rec = evaluateInterfaceRecommendation(metrics);
  const lines = [
    '============================================================',
    '       OPERATOR READINESS & FRICTION OBSERVABILITY          ',
    '============================================================',
    ` Schema:                              ${metrics.$schema}`,
    ` Operator Class:                      ${metrics.operatorClass || 'UNSPECIFIED'}`,
    ` Target Repository:                   ${metrics.targetRepository || 'UNSPECIFIED'}`,
    ` Time to Install:                     ${metrics.timeToInstallSeconds}s`,
    ` Time to First Audit:                 ${metrics.timeToFirstSuccessfulAuditSeconds}s`,
    ` Time to Understood Finding:          ${metrics.timeToFirstUnderstoodFindingSeconds}s`,
    ` Finding Adjudication Time:           ${metrics.findingAdjudicationSeconds}s`,
    '------------------------------------------------------------',
    ` Manual Files Opened:                 ${metrics.manualFilesOpenedCount}`,
    ` Evidence Files Inspected:            ${metrics.evidenceFilesManuallyInspectedCount}`,
    ` Audit Reruns Required:               ${metrics.rerunsRequiredCount}`,
    ` Commands Retried:                    ${metrics.commandsRetriedCount}`,
    ` Help Requests:                       ${metrics.helpRequestsCount}`,
    ` Misinterpreted Statuses:             ${metrics.misinterpretedStatusesCount}`,
    '------------------------------------------------------------',
    ` Interface Recommendation:            ${rec}`,
    '============================================================'
  ];

  if (metrics.operatorFrictionNotes && metrics.operatorFrictionNotes.length > 0) {
    lines.push(' Operator Friction Notes:');
    for (const note of metrics.operatorFrictionNotes) {
      lines.push(`   - ${note}`);
    }
    lines.push('============================================================');
  }

  return lines.join('\n');
}

export function createBlankMetricsTemplate() {
  return {
    $schema: OPERATOR_METRICS_SCHEMA_ID,
    schemaVersion: '1.0.0',
    recordedAt: new Date().toISOString(),
    operatorClass: 'INDEPENDENT_OPERATOR',
    targetRepository: 'example/target-repo',
    timeToInstallSeconds: 0,
    timeToFirstSuccessfulAuditSeconds: 0,
    timeToFirstUnderstoodFindingSeconds: 0,
    manualFilesOpenedCount: 0,
    rerunsRequiredCount: 0,
    commandsRetriedCount: 0,
    helpRequestsCount: 0,
    misinterpretedStatusesCount: 0,
    findingAdjudicationSeconds: 0,
    evidenceFilesManuallyInspectedCount: 0,
    operatorFrictionNotes: []
  };
}

function printUsage() {
  console.log('Usage: node scripts/operator-metrics.mjs [options] [file.json]');
  console.log('Options:');
  console.log('  --check <file>     Validate metrics JSON against schema (exit 0 on success, 1 on fail)');
  console.log('  --template         Output a blank JSON template to stdout');
  console.log('  --help, -h         Show this help message');
}

if (process.argv[1] && path.resolve(process.argv[1]) === path.resolve(__filename)) {
  const args = process.argv.slice(2);
  if (args.includes('--help') || args.includes('-h')) {
    printUsage();
    process.exit(0);
  }

  if (args.includes('--template')) {
    console.log(JSON.stringify(createBlankMetricsTemplate(), null, 2));
    process.exit(0);
  }

  let filePath = null;
  let checkOnly = false;

  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--check') {
      checkOnly = true;
      if (i + 1 < args.length && !args[i + 1].startsWith('--')) {
        filePath = args[i + 1];
        i++;
      }
    } else if (!args[i].startsWith('--')) {
      filePath = args[i];
    }
  }

  if (!filePath) {
    printUsage();
    process.exit(1);
  }

  const resolved = path.resolve(filePath);
  if (!fs.existsSync(resolved)) {
    console.error(`File not found: ${resolved}`);
    process.exit(1);
  }

  try {
    const content = JSON.parse(fs.readFileSync(resolved, 'utf8'));
    const isValid = validateOperatorMetricsShape(content);
    if (!isValid) {
      console.error(`❌ Validation failed: ${resolved} does not conform to schemas/operator-metrics.schema.json`);
      process.exit(1);
    }

    if (checkOnly) {
      console.log(`✔ Valid operator metrics: ${resolved}`);
      process.exit(0);
    }

    console.log(formatOperatorMetricsSummary(content));
    process.exit(0);
  } catch (err) {
    console.error(`Error processing ${resolved}: ${err.message}`);
    process.exit(1);
  }
}
