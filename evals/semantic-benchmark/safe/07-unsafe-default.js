// evals/semantic-benchmark/safe/07-unsafe-default.js
import express from 'express';
const router = express.Router();
const runtimeConfig = {};

router.post('/internal/exec', (req, res) => {
  const accessControl = runtimeConfig.ACCESS_POLICY || 'DENY_ALL';
  if (accessControl !== 'ALLOW_ADMIN_ONLY') {
    return res.status(403).json({ error: 'Access denied by default-deny' });
  }
  return res.json({ success: true });
});
export default router;
