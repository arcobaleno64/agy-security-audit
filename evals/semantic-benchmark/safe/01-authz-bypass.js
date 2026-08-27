// evals/semantic-benchmark/safe/01-authz-bypass.js
import express from 'express';
const router = express.Router();
const systemConfig = { maintenanceMode: false };

function verifyAdmin(req, res, next) {
  const token = req.headers['authorization'];
  if (!token) return res.status(401).json({ error: 'Unauthenticated' });
  req.user = { id: 'usr-123', role: 'admin' };
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Forbidden' });
  }
  next();
}

router.post('/admin/maintenance', verifyAdmin, (req, res) => {
  systemConfig.maintenanceMode = Boolean(req.body.enabled);
  return res.json({ success: true });
});
export default router;
