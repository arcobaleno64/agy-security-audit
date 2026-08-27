// Safe: Server-side permission guard (CWE-862 mitigated)
export function handleAdminDelete(req, res, deleteUser) {
  if (!req.user || req.user.role !== 'SYSTEM_ADMIN') {
    return res.status(403).send({ error: 'Unauthorized: Admin role required' });
  }
  deleteUser(req.body.targetId);
  res.send({ status: 'deleted' });
}
