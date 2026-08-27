// evals/semantic-benchmark/05-validated-vs-consumed.js
// Semantic Category: validated-vs-consumed (CWE-20)
import express from 'express';
import fs from 'node:fs';
import path from 'node:path';

const router = express.Router();
const DATA_DIR = path.resolve('public/data');

router.post('/report/export', (req, res) => {
  const queryPath = String(req.query.targetFile || '');
  if (queryPath.includes('..') || path.isAbsolute(queryPath)) {
    return res.status(400).json({ error: 'Traversal blocked in query' });
  }

  // Vulnerability: Validates query parameter, but consumes body parameter!
  const filePath = path.resolve(DATA_DIR, req.body.targetFile || 'default.json');
  const data = fs.readFileSync(filePath, 'utf8');
  return res.type('text/plain').send(data);
});

export default router;
