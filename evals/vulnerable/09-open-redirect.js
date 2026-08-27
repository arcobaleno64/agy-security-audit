// CWE-601: Open Redirect via unvalidated parameter
export function handleLoginRedirect(req, res) {
  const returnTo = req.query.returnTo;
  res.redirect(returnTo);
}
