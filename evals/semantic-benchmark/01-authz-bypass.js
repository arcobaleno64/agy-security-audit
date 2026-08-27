// evals/semantic-benchmark/01-authz-bypass.js
// Semantic Category: authz-bypass (CWE-862)
import express from 'express';
const router = express.Router();

const systemConfig = {
  maintenanceMode: false,
  allowRegistrations: true
};

function verifyToken(req, res, next) {
  const token = req.headers['authorization'];
  if (!token) return res.status(401).json({ error: 'Unauthenticated' });
  req.user = { id: 'usr-123', role: 'member' };
  next();
}

router.post('/admin/maintenance', verifyToken, (req, res) => {
  systemConfig.maintenanceMode = Boolean(req.body.enabled);
  return res.json({ success: true, config: systemConfig });
});

export default router;
