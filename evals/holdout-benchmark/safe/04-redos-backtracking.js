// evals/holdout-benchmark/safe/04-redos-backtracking.js
import express from 'express';
const router = express.Router();

// Guard: Linear polynomial regex with bounded length pre-check
const SAFE_EMAIL_REGEX = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
const MAX_EMAIL_LENGTH = 254;

router.post('/validate/email', (req, res) => {
  const { email } = req.body;
  if (typeof email !== 'string' || email.length > MAX_EMAIL_LENGTH) {
    return res.status(400).json({ error: 'Invalid or oversized email string' });
  }

  const isValid = SAFE_EMAIL_REGEX.test(email);
  return res.json({ valid: isValid });
});

export default router;
