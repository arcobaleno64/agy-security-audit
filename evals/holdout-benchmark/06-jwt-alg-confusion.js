// evals/holdout-benchmark/06-jwt-alg-confusion.js
// Semantic Category: jwt-alg-confusion (CWE-347)
import express from 'express';
import jwt from 'jsonwebtoken';
const router = express.Router();

const PUBLIC_KEY = `-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE\n-----END PUBLIC KEY-----`;

router.post('/auth/verify', (req, res) => {
  const token = req.headers['authorization']?.replace(/^Bearer\s+/, '');
  if (!token) return res.status(401).json({ error: 'Missing token' });

  // Vulnerability: No algorithm restriction allows 'none' or HMAC key-confusion
  try {
    const claims = jwt.verify(token, PUBLIC_KEY);
    return res.json({ success: true, claims });
  } catch (err) {
    return res.status(401).json({ error: 'Invalid token' });
  }
});

export default router;
