// CWE-502: Insecure Deserialization via eval
export function parseConfig(configStr) {
  return eval("(" + configStr + ")");
}
