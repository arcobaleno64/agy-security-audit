// CWE-22: Path Traversal via unvalidated path join
import fs from 'node:fs';
import path from 'node:path';
export function readData(baseDir, userFile) {
  const target = path.join(baseDir, userFile);
  return fs.readFileSync(target, 'utf8');
}
