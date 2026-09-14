// evals/holdout-benchmark/05-crypto-iv-reuse.js
// Semantic Category: crypto-iv-reuse (CWE-329)
import express from 'express';
import crypto from 'node:crypto';
const router = express.Router();

const SECRET_KEY = crypto.scryptSync('server-secret', 'salt', 32);
// Vulnerability: Static hardcoded IV reused across multiple ciphertexts
const STATIC_IV = Buffer.alloc(16, 0);

router.post('/data/encrypt', (req, res) => {
  const { plaintext } = req.body;
  if (!plaintext) return res.status(400).json({ error: 'Missing plaintext' });

  // Sink: Symmetric cipher initialized with static IV
  const cipher = crypto.createCipheriv('aes-256-cbc', SECRET_KEY, STATIC_IV);
  let encrypted = cipher.update(String(plaintext), 'utf8', 'hex');
  encrypted += cipher.final('hex');
  return res.json({ success: true, ciphertext: encrypted });
});

export default router;
