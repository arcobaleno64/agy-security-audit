/**
 * Remediated slice of axios (CVE-2020-28168)
 * Fixed in axios 0.21.1 by stripping Authorization and Cookie headers across origins.
 */
import { URL } from 'node:url';

export function handleRedirect(originalUrl, redirectLocation, originalHeaders) {
  const orig = new URL(originalUrl);
  const next = new URL(redirectLocation, originalUrl);
  const forwardHeaders = { ...originalHeaders };
  
  // CVE-2020-28168 fix: strip sensitive headers on cross-origin redirects
  const isSameOrigin = orig.protocol === next.protocol && orig.host === next.host;
  if (!isSameOrigin) {
    delete forwardHeaders['authorization'];
    delete forwardHeaders['Authorization'];
    delete forwardHeaders['cookie'];
    delete forwardHeaders['Cookie'];
  }

  return {
    url: next.href,
    headers: forwardHeaders
  };
}
