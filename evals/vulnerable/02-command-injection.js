// CWE-78: Command Injection via shell execution
import { exec } from 'node:child_process';
export function runPing(host) {
  exec("ping -c 1 " + host, { shell: true });
}
