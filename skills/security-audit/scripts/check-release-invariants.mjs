#!/usr/bin/env node
/**
 * check-release-invariants.mjs
 * Section 24 Release Invariants Gate for AGY Security Audit.
 * Formally validates that 100% of required specifications, contracts,
 * scripts, and test invariants are intact before milestone release.
 */

import fs from 'node:fs';
import path from 'node:path';
import { execFileSync } from 'node:child_process';

const REQUIRED_FILES = [
  'LICENSE',
  'README.md',
  'SECURITY.md',
  'plugin.json',
  'rules/AGENTS.md',
  'skills/security-audit/SKILL.md',
  'skills/security-audit/scripts/safe-git.mjs',
  'skills/security-audit/scripts/finalize-scan.mjs',
  'skills/security-audit/scripts/render-sarif.mjs',
  'skills/security-audit/scripts/build-inventory.mjs',
  'skills/security-audit/scripts/build-threat-model.mjs',
  'skills/security-audit/scripts/validate-attack-path.mjs',
  'skills/security-audit/scripts/validate-patch.mjs',
  'skills/security-audit/scripts/check-release-invariants.mjs',
  'skills/security-audit/jobs/scan.md',
  'skills/security-audit/jobs/review.md',
  'skills/security-audit/jobs/validate.md',
  'skills/security-audit/jobs/deep.md',
  'skills/security-audit/jobs/remediate.md',
  'skills/security-audit/jobs/verify-fix.md',
  'skills/security-audit/references/discovery.md',
  'skills/security-audit/references/patching-jail.md',
  'skills/security-audit/references/swarm-consensus.md',
  'skills/security-audit/references/threat-modeling.md',
  'skills/security-audit/references/verifier-protocol.md',
  'agents/threat-modeler.md',
  'agents/discovery-agent.md',
  'agents/verifier-reachability.md',
  'agents/verifier-defenses.md',
  'agents/verifier-impact.md'
];

/**
 * Validates repository release invariants.
 */
export function checkReleaseInvariants(repoRoot = process.cwd()) {
  const errors = [];
  const warnings = [];

  // 1. Check file completeness
  for (const relPath of REQUIRED_FILES) {
    const fullPath = path.resolve(repoRoot, relPath);
    if (!fs.existsSync(fullPath)) {
      errors.push(`Missing required release artifact: ${relPath}`);
    } else {
      const content = fs.readFileSync(fullPath, 'utf8');
      if (content.trim().length === 0) {
        errors.push(`Required release artifact is empty: ${relPath}`);
      }
      const isSelf = relPath.endsWith('check-release-invariants.mjs');
      if (!isSelf && /\bplaceholder\b/i.test(content)) {
        errors.push(`File contains unresolved placeholder: ${relPath}`);
      }
    }
  }

  // 2. Check package.json zero-dependency invariant across all dependency fields
  const pkgPath = path.resolve(repoRoot, 'package.json');
  if (!fs.existsSync(pkgPath)) {
    errors.push('Missing package.json');
  } else {
    try {
      const pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf8'));
      const depFields = ['dependencies', 'devDependencies', 'peerDependencies', 'optionalDependencies'];
      for (const field of depFields) {
        if (pkg[field] && Object.keys(pkg[field]).length > 0) {
          errors.push(`Release invariant violation: external ${field} found in package.json: ${Object.keys(pkg[field]).join(', ')}`);
        }
      }
    } catch (e) {
      errors.push(`Failed to parse package.json: ${e.message}`);
    }
  }

  // 3. Check automated test suite
  const testScriptPath = path.resolve(repoRoot, 'skills/security-audit/scripts/render-sarif.mjs');
  try {
    const stdout = execFileSync(process.execPath, [testScriptPath, '--test'], {
      cwd: repoRoot,
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'pipe']
    });
    if (!stdout.includes('All render-sarif.mjs automated verification tests passed successfully')) {
      errors.push('Test suite did not output successful completion signature');
    }
  } catch (err) {
    errors.push(`Automated test suite failed: ${err.message}\n${err.stderr || ''}`);
  }

  // 4. Validate Plugin Custom Agents Capability & Tool Invariants (P0-04)
  const agentFiles = [
    'agents/threat-modeler.md',
    'agents/discovery-agent.md',
    'agents/verifier-reachability.md',
    'agents/verifier-defenses.md',
    'agents/verifier-impact.md'
  ];
  for (const af of agentFiles) {
    const p = path.resolve(repoRoot, af);
    if (fs.existsSync(p)) {
      const content = fs.readFileSync(p, 'utf8');
      if (!content.includes('mainAgent: false')) {
        errors.push(`Agent invariant violation: ${af} must declare mainAgent: false`);
      }
      if (!content.includes('subagent: true')) {
        errors.push(`Agent invariant violation: ${af} must declare subagent: true`);
      }
      if (!content.includes('commandExecutionPolicy: off')) {
        errors.push(`Agent invariant violation: ${af} must declare commandExecutionPolicy: off`);
      }
      if (content.includes('read_file')) {
        errors.push(`Agent invariant violation: ${af} contains deprecated/invalid tool name 'read_file'; must use 'view_file'`);
      }
      if (content.includes('run_command') || content.includes('write_to_file') || content.includes('replace_file_content')) {
        errors.push(`Agent invariant violation: ${af} contains prohibited modifying/execution tools`);
      }
    }
  }


  return {
    passed: errors.length === 0,
    errors,
    warnings,
    verifiedFilesCount: REQUIRED_FILES.length
  };
}

// -----------------------------------------------------------------------------
// CLI Dispatch
// -----------------------------------------------------------------------------
const isDirectExecution = process.argv[1] && process.argv[1].endsWith('check-release-invariants.mjs');

if (isDirectExecution) {
  console.log('Validating Section 24 Release Invariants Gate...');
  const result = checkReleaseInvariants(process.cwd());

  if (!result.passed) {
    console.error(`\n❌ Release Invariants Gate FAILED with ${result.errors.length} error(s):`);
    for (const err of result.errors) {
      console.error(`  - ${err}`);
    }
    process.exit(1);
  }

  console.log(`\n✔ Release Invariants Gate PASSED! (${result.verifiedFilesCount} required specifications and scripts verified, 0 external dependencies, all automated invariants green).`);
}

