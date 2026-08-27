// evals/semantic-benchmark/07-unsafe-default.js
// Semantic Category: unsafe-default (CWE-1188)
import express from 'express';
const router = express.Router();

const runtimeConfig = {};

router.post('/internal/exec', (req, res) => {
  // Vulnerability: Defaulting security access control to ALLOW_ALL when undefined
  const accessControl = runtimeConfig.ACCESS_POLICY || 'ALLOW_ALL';
  if (accessControl === 'DENY_ALL') {
    return res.status(403).json({ error: 'Access denied' });
  }
  return res.json({ success: true, message: 'Admin action executed without authorization' });
});

export default router;
