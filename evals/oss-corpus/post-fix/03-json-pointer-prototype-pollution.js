/**
 * Remediated slice of json-pointer (CVE-2020-7751)
 * Fixed in json-pointer 0.6.1 by blocking dangerous prototype keys.
 */
const FORBIDDEN = new Set(['__proto__', 'constructor', 'prototype']);

export function set(obj, pointer, value) {
  const parts = pointer.split('/').slice(1);
  let current = obj;
  for (let i = 0; i < parts.length - 1; i++) {
    const part = parts[i];
    if (FORBIDDEN.has(part)) {
      return obj; // CVE-2020-7751 mitigation
    }
    if (current[part] === undefined) {
      current[part] = {};
    }
    current = current[part];
  }
  const last = parts[parts.length - 1];
  if (FORBIDDEN.has(last)) {
    return obj; // CVE-2020-7751 mitigation
  }
  current[last] = value;
  return obj;
}
