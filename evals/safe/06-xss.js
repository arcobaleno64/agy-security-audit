// Safe: Context-aware HTML entity encoding (CWE-79 mitigated)
function escapeHtml(str) {
  return String(str).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}
export function renderProfile(userName) {
  return "<div>Welcome " + escapeHtml(userName) + "</div>";
}
