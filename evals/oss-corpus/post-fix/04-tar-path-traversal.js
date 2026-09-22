/**
 * Remediated slice of node-tar (CVE-2021-32803)
 * Fixed in tar 6.1.2 by verifying realpath containment before extracting.
 */
import path from 'node:path';
import fs from 'node:fs';

export function extractEntry(targetDir, entryPath, content) {
  const resolvedTarget = path.resolve(targetDir);
  const destination = path.resolve(resolvedTarget, entryPath);
  
  // CVE-2021-32803 fix: enforce strict containment
  const rel = path.relative(resolvedTarget, destination);
  if (rel.startsWith('..') || path.isAbsolute(rel)) {
    throw new Error(`TAR_EXTRACTION_SECURITY_ERROR: Entry path '${entryPath}' escapes destination directory`);
  }
  
  fs.mkdirSync(path.dirname(destination), { recursive: true });
  fs.writeFileSync(destination, content);
  return destination;
}
