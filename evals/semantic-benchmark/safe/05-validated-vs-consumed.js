// evals/semantic-benchmark/safe/05-validated-vs-consumed.js
import express from 'express';
import fs from 'node:fs';
import path from 'node:path';
const router = express.Router();
const DATA_DIR = path.resolve('public/data');

router.post('/report/export', (req, res) => {
  const safeBase = path.basename(String(req.body.targetFile || 'default.json'));
  const filePath = path.resolve(DATA_DIR, safeBase);
  if (!filePath.startsWith(DATA_DIR)) {
    return res.status(400).json({ error: 'Traversal blocked' });
  }
  const data = fs.readFileSync(filePath, 'utf8');
  return res.send(data);
});
export default router;
