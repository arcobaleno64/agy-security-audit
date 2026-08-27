// Safe: Relative path validation (CWE-601 mitigated)
export function handleLoginRedirect(req, res) {
  const returnTo = req.query.returnTo;
  if (typeof returnTo !== 'string' || !returnTo.startsWith('/') || returnTo.startsWith('//')) {
    return res.redirect('/dashboard');
  }
  res.redirect(returnTo);
}
