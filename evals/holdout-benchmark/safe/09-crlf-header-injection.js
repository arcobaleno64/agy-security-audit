// evals/holdout-benchmark/safe/09-crlf-header-injection.js
import express from 'express';
const router = express.Router();

router.get('/auth/callback', (req, res) => {
  const sessionToken = req.query.token;
  if (!sessionToken) return res.status(400).json({ error: 'Missing token' });

  // Guard: Rejects any input containing CR or LF characters
  if (/[\r\n]/.test(String(sessionToken))) {
    return res.status(400).json({ error: 'CRLF characters rejected in header value' });
  }

  res.setHeader('Set-Cookie', `SESSIONID=${encodeURIComponent(sessionToken)}; Path=/; HttpOnly`);
  return res.json({ success: true });
});

export default router;
