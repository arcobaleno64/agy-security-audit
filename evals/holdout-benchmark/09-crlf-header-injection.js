// evals/holdout-benchmark/09-crlf-header-injection.js
// Semantic Category: crlf-header-injection (CWE-113)
import express from 'express';
const router = express.Router();

router.get('/auth/callback', (req, res) => {
  const sessionToken = req.query.token;
  if (!sessionToken) return res.status(400).json({ error: 'Missing token' });

  // Vulnerability: Unsanitized input embedded in Set-Cookie header allows CRLF injection
  res.setHeader('Set-Cookie', `SESSIONID=${sessionToken}; Path=/; HttpOnly`);
  return res.json({ success: true });
});

export default router;
