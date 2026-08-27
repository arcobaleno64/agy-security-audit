// evals/semantic-benchmark/safe/02-cross-tenant-access.js
import express from 'express';
const router = express.Router();
const mockDatabase = [
  { id: 'doc-1', tenantId: 'tenant-alpha', content: 'Secret 1' }
];

router.get('/documents/:id', (req, res) => {
  const currentTenantId = req.headers['x-tenant-id'] || 'tenant-alpha';
  const doc = mockDatabase.find(d => d.id === req.params.id && d.tenantId === currentTenantId);
  if (!doc) return res.status(404).json({ error: 'Not found' });
  return res.json(doc);
});
export default router;
