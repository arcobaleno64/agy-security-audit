// evals/semantic-benchmark/02-cross-tenant-access.js
// Semantic Category: cross-tenant-access (CWE-639)
import express from 'express';
const router = express.Router();

const mockDatabase = [
  { id: 'doc-1', tenantId: 'tenant-alpha', title: 'Alpha Secret Roadmap', content: 'Secret 1' },
  { id: 'doc-2', tenantId: 'tenant-beta', title: 'Beta Financial Q3', content: 'Secret 2' }
];

function tenantMiddleware(req, res, next) {
  req.currentTenantId = req.headers['x-tenant-id'] || 'tenant-alpha';
  next();
}

router.get('/documents/:id', tenantMiddleware, (req, res) => {
  const docId = req.params.id;
  const doc = mockDatabase.find(d => d.id === docId);
  if (!doc) return res.status(404).json({ error: 'Not found' });
  return res.json(doc);
});

export default router;
