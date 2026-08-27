// Safe: Strict protocol and hostname allowlist (CWE-918 mitigated)
import https from 'node:https';
const ALLOWED_HOSTS = new Set(['api.internal.company.com', 'hooks.slack.com']);
export function fetchWebhook(targetUrl) {
  const parsed = new URL(targetUrl);
  if (parsed.protocol !== 'https:' || !ALLOWED_HOSTS.has(parsed.hostname)) {
    throw new Error('SSRF Blocked: Destination not allowed');
  }
  return https.get(targetUrl);
}
