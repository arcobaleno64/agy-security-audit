// Safe: Canonical containment barrier (CWE-22 mitigated)
import fs from 'node:fs';
import path from 'node:path';
export function readData(baseDir, userFile) {
  const resolvedBase = path.resolve(baseDir);
  const target = path.resolve(resolvedBase, userFile);
  if (!target.startsWith(resolvedBase + path.sep)) {
    throw new Error('Access Denied: Path Traversal Detected');
  }
  return fs.readFileSync(target, 'utf8');
}
