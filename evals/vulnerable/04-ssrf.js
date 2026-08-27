// CWE-918: Server-Side Request Forgery
import http from 'node:http';
export function fetchWebhook(targetUrl) {
  return http.get(targetUrl);
}
