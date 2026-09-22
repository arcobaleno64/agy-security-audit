/**
 * Authentic slice of axios (CVE-2020-28168)
 * Insecure Credential Forwarding on Cross-Origin Redirect before 0.21.1.
 */
import { URL } from 'node:url';

export function handleRedirect(originalUrl, redirectLocation, originalHeaders) {
  const nextUrl = new URL(redirectLocation, originalUrl);
  // Vulnerable: originalHeaders forwarded unconditionally to third-party host
  const forwardHeaders = { ...originalHeaders };
  return {
    url: nextUrl.href,
    headers: forwardHeaders
  };
}
