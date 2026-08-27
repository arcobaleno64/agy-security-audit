// CWE-79: Cross-Site Scripting via unescaped output
export function renderProfile(userName) {
  return "<div>Welcome " + userName + "</div>";
}
