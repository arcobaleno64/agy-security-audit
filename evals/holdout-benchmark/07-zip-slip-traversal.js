// evals/holdout-benchmark/07-zip-slip-traversal.js
// Semantic Category: zip-slip-traversal (CWE-22)
import express from 'express';
import path from 'node:path';
import fs from 'node:fs';
const router = express.Router();

const EXTRACT_DIR = '/var/app/extracted';

router.post('/archive/extract-entry', (req, res) => {
  const { entryName, content } = req.body;
  if (!entryName || !content) return res.status(400).json({ error: 'Missing entry' });

  // Vulnerability: Unchecked path join allows Zip Slip escaping destination root
  const destinationPath = path.join(EXTRACT_DIR, entryName);
  fs.writeFileSync(destinationPath, content, 'utf8');
  return res.json({ success: true, path: destinationPath });
});

export default router;
