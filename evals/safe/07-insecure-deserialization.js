// Safe: Strict JSON parser (CWE-502 mitigated)
export function parseConfig(configStr) {
  return JSON.parse(configStr);
}
