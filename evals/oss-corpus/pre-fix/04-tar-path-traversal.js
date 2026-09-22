/**
 * Authentic slice of node-tar (CVE-2021-32803)
 * Path Traversal / Arbitrary File Overwrite in tar before 6.1.2.
 */
import path from 'node:path';
import fs from 'node:fs';

export function extractEntry(targetDir, entryPath, content) {
  // Vulnerable: path.join allows traversal or drive letter evasion without boundary check
  const destination = path.join(targetDir, entryPath);
  fs.mkdirSync(path.dirname(destination), { recursive: true });
  fs.writeFileSync(destination, content);
  return destination;
}
