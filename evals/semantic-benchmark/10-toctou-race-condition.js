// evals/semantic-benchmark/10-toctou-race-condition.js
// Semantic Category: concurrency-toctou (CWE-367)
import express from 'express';
const router = express.Router();

const accounts = new Map([['user-123', { id: 'user-123', balance: 500 }]]);

router.post('/wallet/withdraw', async (req, res) => {
  const { userId, amount } = req.body;
  const account = accounts.get(userId);
  if (!account) return res.status(404).json({ error: 'Account not found' });

  // Time-of-check
  if (account.balance >= amount) {
    // Non-atomic delay simulates async I/O / payment gateway hop
    await new Promise(resolve => setTimeout(resolve, 50));
    // Time-of-use
    account.balance -= amount;
    return res.json({ success: true, balance: account.balance });
  }
  return res.status(400).json({ error: 'Insufficient funds' });
});

export default router;
