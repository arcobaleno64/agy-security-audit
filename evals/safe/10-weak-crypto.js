// Safe: Key derivation with scrypt (CWE-328 mitigated)
import crypto from 'node:crypto';
export function hashPassword(password, salt) {
  return crypto.scryptSync(password, salt, 64).toString('hex');
}
