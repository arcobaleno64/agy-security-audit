#!/usr/bin/env node
// Regenerates skills/security-audit/tool-integrity-manifest.json's script
// hashes from the files actually on disk. Run this after editing any critical
// script (see REQUIRED_CRITICAL_SCRIPTS in finalize-scan.mjs) or after
// scripts/bump-version.mjs changes TOOL_VERSION -- verifyToolSelfIntegrity
// fails closed on any mismatch, by design (see SEC-INV-16 in the test suite),
// so a stale manifest blocks every clean declaration until this is run.
import fs from "node:fs";
import path from "node:path";
import { generateToolIntegrityManifest } from "../skills/security-audit/scripts/finalize-scan.mjs";

const toolRoot = path.resolve("skills/security-audit");
const manifest = generateToolIntegrityManifest(toolRoot);
const outPath = path.join(toolRoot, "tool-integrity-manifest.json");
fs.writeFileSync(outPath, `${JSON.stringify(manifest, null, 2)}\n`);
console.log(`Wrote ${outPath}`);
console.log(JSON.stringify(manifest, null, 2));
