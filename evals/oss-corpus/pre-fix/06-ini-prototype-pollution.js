/**
 * Authentic slice of ini (CVE-2020-7788)
 * Prototype Pollution in ini parser before 1.3.6.
 */
export function parse(string) {
  const out = {};
  let p = out;
  const lines = string.split('\n');
  for (const line of lines) {
    const trimmed = line.trim();
    if (trimmed.startsWith('[') && trimmed.endsWith(']')) {
      const section = trimmed.slice(1, -1);
      // Vulnerable: section name [__proto__] poisons Object.prototype
      if (!p[section]) p[section] = {};
      p = p[section];
    } else if (trimmed.includes('=')) {
      const [key, val] = trimmed.split('=').map(s => s.trim());
      p[key] = val;
    }
  }
  return out;
}
