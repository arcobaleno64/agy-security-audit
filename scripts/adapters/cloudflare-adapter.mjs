#!/usr/bin/env node
/**
 * scripts/adapters/cloudflare-adapter.mjs
 * Backward-compatibility shim delegating to the authoritative TCB-controlled adapter:
 * skills/security-audit/scripts/adapters/cloudflare-adapter.mjs
 */

import path from 'node:path';
import { fileURLToPath } from 'node:url';
export * from '../../skills/security-audit/scripts/adapters/cloudflare-adapter.mjs';
import { runCli } from '../../skills/security-audit/scripts/adapters/cloudflare-adapter.mjs';

const isDirectExecution = process.argv[1] && fileURLToPath(import.meta.url) === path.resolve(process.argv[1]);
if (isDirectExecution) {
  runCli().catch(err => {
    console.error(`Fatal: ${err.message}`);
    process.exit(1);
  });
}
