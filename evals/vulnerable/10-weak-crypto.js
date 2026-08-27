// CWE-328: Use of Weak Hash Algorithm
import crypto from 'node:crypto';
export function hashPassword(password) {
  return crypto.createHash('md5').update(password).digest('hex');
}
