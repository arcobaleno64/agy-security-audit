/**
 * Authentic slice of minimist (CVE-2020-7598)
 * Prototype Pollution in minimist before 1.2.2.
 */
export function setKey(obj, keys, value) {
  let o = obj;
  for (let i = 0; i < keys.length - 1; i++) {
    const key = keys[i];
    if (o[key] === undefined) o[key] = {};
    o = o[key];
  }
  const lastKey = keys[keys.length - 1];
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
