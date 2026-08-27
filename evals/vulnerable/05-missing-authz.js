// CWE-862: Missing Authorization on admin endpoint
export function handleAdminDelete(req, res, deleteUser) {
  // Missing role/permission verification
  deleteUser(req.body.targetId);
  res.send({ status: 'deleted' });
}
