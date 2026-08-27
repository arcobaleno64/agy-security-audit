// evals/semantic-benchmark/04-state-transition.js
// Semantic Category: state-transition (CWE-840)
import express from 'express';
const router = express.Router();

const orders = new Map([
  ['ord-101', { id: 'ord-101', amount: 500, status: 'CREATED' }]
]);

router.post('/orders/:id/refund', async (req, res) => {
  const order = orders.get(req.params.id);
  if (!order) return res.status(404).json({ error: 'Order not found' });
  
  // Vulnerability: State transition allows jumping directly from CREATED to REFUNDED
  order.status = 'REFUNDED';
  order.refundedAt = new Date().toISOString();
  orders.set(order.id, order);
  return res.json({ success: true, order });
});

export default router;
