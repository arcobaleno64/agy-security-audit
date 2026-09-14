// evals/holdout-benchmark/safe/10-race-token-reuse.js
import express from 'express';
const router = express.Router();

const resetTokens = new Map([
  ['one-time-token-abc', { token: 'one-time-token-abc', userId: 'usr-99', used: false }]
]);

function consumeTokenAtomic(token) {
  const record = resetTokens.get(token);
  // Guard: Atomic check-and-set condition within synchronous execution boundary
  if (!record || record.used) return false;
  record.used = true;
  return true;
}

router.post('/auth/reset-password', async (req, res) => {
  const { token, newPassword } = req.body;
  const consumed = consumeTokenAtomic(token);
  if (!consumed) {
    return res.status(400).json({ error: 'Token invalid or already consumed' });
  }

  await new Promise(resolve => setTimeout(resolve, 50));
  return res.json({ success: true, message: 'Password updated successfully' });
});

export default router;
