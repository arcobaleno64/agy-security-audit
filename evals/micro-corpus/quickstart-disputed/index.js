/**
 * quickstart-disputed / index.js
 * Track D Tier 2 Micro-Corpus: Architectural Dispute Control (CWE-918 SSRF Boundary).
 *
 * Demonstrates an intentional architectural trade-off:
 * - Entrypoint: forwardToLocalSidecar(port, endpoint, options)
 * - Behavior: Forwards requests strictly to local loopback sidecars (127.0.0.1, localhost, ::1).
 * - Dispute Profile: Automated pattern matching flags potential SSRF (CWE-918) due to dynamic host
 *   and port resolution, while defense-in-depth policy classifies this as an intentional local IPC design.
 */

export const ALLOWED_LOOPBACK_HOSTS = Object.freeze(new Set(['127.0.0.1', 'localhost', '::1', '[::1]']));

export function forwardToLocalSidecar(port, endpoint, options = {}) {
  const numericPort = Number(port);
  if (!Number.isInteger(numericPort) || numericPort < 1024 || numericPort > 65535) {
    throw new RangeError('INVALID_PORT: Only unprivileged ports (1024-65535) are permitted');
  }

  const host = String(options.host || '127.0.0.1').toLowerCase();
  if (!ALLOWED_LOOPBACK_HOSTS.has(host)) {
    throw new Error('SECURITY_VIOLATION: Proxy strictly restricted to local loopback addresses');
  }

  const cleanEndpoint = String(endpoint || '/').replace(/^\/+/, '');
  return `http://${host}:${numericPort}/${cleanEndpoint}`;
}
