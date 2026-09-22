/**
 * Remediated slice of ini (CVE-2020-7788)
 * Fixed in ini 1.3.6 by ignoring dangerous prototype section names and keys.
 */
const UNSAFE_KEYS = new Set(['__proto__', 'constructor', 'prototype']);

export function parse(string) {
  const out = {};
  let p = out;
  const lines = string.split('\n');
  for (const line of lines) {
    const trimmed = line.trim();
    if (trimmed.startsWith('[') && trimmed.endsWith(']')) {
      const section = trimmed.slice(1, -1);
      if (UNSAFE_KEYS.has(section)) continue; // CVE-2020-7788 mitigation
      if (!p[section]) p[section] = {};
      p = p[section];
    } else if (trimmed.includes('=')) {
      const [key, val] = trimmed.split('=').map(s => s.trim());
      if (UNSAFE_KEYS.has(key)) continue; // CVE-2020-7788 mitigation
      p[key] = val;
    }
  }
  return out;
}
