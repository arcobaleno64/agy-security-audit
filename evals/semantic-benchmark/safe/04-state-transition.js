// evals/semantic-benchmark/safe/04-state-transition.js
// Semantic Category: state-transition (CWE-840 - SAFE GUARDED)
import express from 'express';
const router = express.Router();

const orders = new Map([
  ['ord-1', { id: 'ord-1', status: 'PENDING', amount: 100 }]
]);

router.post('/orders/:id/fulfill', (req, res) => {
  const order = orders.get(req.params.id);
  if (!order) return res.status(404).json({ error: 'Not found' });
  if (order.status !== 'PAID') {
    return res.status(409).json({ error: 'Order must be PAID before fulfillment' });
  }
  order.status = 'FULFILLED';
  return res.json({ success: true, order });
});

export default router;
