// evals/holdout-benchmark/10-race-token-reuse.js
// Semantic Category: race-token-reuse (CWE-362)
import express from 'express';
const router = express.Router();

const resetTokens = new Map([
  ['one-time-token-abc', { token: 'one-time-token-abc', userId: 'usr-99', used: false }]
]);

router.post('/auth/reset-password', async (req, res) => {
  const { token, newPassword } = req.body;
  const tokenRecord = resetTokens.get(token);

  // Time-of-check: Check without locking
  if (!tokenRecord || tokenRecord.used) {
    return res.status(400).json({ error: 'Token invalid or already consumed' });
  }

  // Non-atomic async processing gap
  await new Promise(resolve => setTimeout(resolve, 50));

  // Time-of-use: Mutation occurs after async delay, permitting concurrent reuse
  tokenRecord.used = true;
  return res.json({ success: true, message: 'Password updated successfully' });
});

export default router;
