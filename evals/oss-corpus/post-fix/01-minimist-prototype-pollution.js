/**
 * Remediated slice of minimist (CVE-2020-7598)
 * Fixed in minimist 1.2.2 by checking for __proto__ in setKey.
 */
export function setKey(obj, keys, value) {
  let o = obj;
  for (let i = 0; i < keys.length - 1; i++) {
    const key = keys[i];
    if (key === '__proto__') return; // CVE-2020-7598 mitigation
    if (o[key] === undefined) o[key] = {};
    o = o[key];
  }
  const lastKey = keys[keys.length - 1];
  if (lastKey === '__proto__') return; // CVE-2020-7598 mitigation
  o[lastKey] = value;
}

export function parseArgs(args) {
  const flags = {};
  for (const arg of args) {
    if (arg.startsWith('--')) {
      const parts = arg.slice(2).split('=');
      const keys = parts[0].split('.');
      const val = parts[1] === undefined ? true : parts[1];
      setKey(flags, keys, val);
    }
  }
  return flags;
}
