// Safe: execFile with argument array without shell (CWE-78 mitigated)
import { execFile } from 'node:child_process';
export function runPing(host) {
  execFile('ping', ['-c', '1', host]);
}
