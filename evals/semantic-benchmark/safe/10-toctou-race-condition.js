// evals/semantic-benchmark/safe/10-toctou-race-condition.js
// Semantic Category: concurrency-toctou (CWE-367 - SAFE GUARDED)
import express from 'express';
const router = express.Router();

const accounts = new Map([['user-123', { id: 'user-123', balance: 500 }]]);
const locks = new Set();

async function withAccountLock(userId, fn) {
  while (locks.has(userId)) {
    await new Promise(resolve => setTimeout(resolve, 10));
  }
  locks.add(userId);
  try {
    return await fn();
  } finally {
    locks.delete(userId);
  }
}

router.post('/wallet/withdraw', async (req, res) => {
  const { userId, amount } = req.body;
  const account = accounts.get(userId);
  if (!account) return res.status(404).json({ error: 'Account not found' });

  return await withAccountLock(userId, async () => {
    if (account.balance >= amount) {
      await new Promise(resolve => setTimeout(resolve, 50));
      account.balance -= amount;
      return res.json({ success: true, balance: account.balance });
    }
    return res.status(400).json({ error: 'Insufficient funds' });
  });
});

export default router;
