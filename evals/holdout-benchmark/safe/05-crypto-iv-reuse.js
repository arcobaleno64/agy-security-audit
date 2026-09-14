// evals/holdout-benchmark/safe/05-crypto-iv-reuse.js
import express from 'express';
import crypto from 'node:crypto';
const router = express.Router();

const SECRET_KEY = crypto.scryptSync('server-secret', 'salt', 32);

router.post('/data/encrypt', (req, res) => {
  const { plaintext } = req.body;
  if (!plaintext) return res.status(400).json({ error: 'Missing plaintext' });

  // Guard: Fresh cryptographically random IV generated per operation
  const freshIv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv('aes-256-cbc', SECRET_KEY, freshIv);
  let encrypted = cipher.update(String(plaintext), 'utf8', 'hex');
  encrypted += cipher.final('hex');
  return res.json({ success: true, iv: freshIv.toString('hex'), ciphertext: encrypted });
});

export default router;
