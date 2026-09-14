// evals/holdout-benchmark/safe/07-zip-slip-traversal.js
import express from 'express';
import path from 'node:path';
import fs from 'node:fs';
const router = express.Router();

const EXTRACT_DIR = path.resolve('/var/app/extracted');

router.post('/archive/extract-entry', (req, res) => {
  const { entryName, content } = req.body;
  if (!entryName || !content) return res.status(400).json({ error: 'Missing entry' });

  // Guard: Canonical path resolve and prefix boundary containment check
  const destinationPath = path.resolve(EXTRACT_DIR, entryName);
  if (!destinationPath.startsWith(EXTRACT_DIR + path.sep)) {
    return res.status(403).json({ error: 'Extraction path traversal rejected' });
  }

  fs.writeFileSync(destinationPath, content, 'utf8');
  return res.json({ success: true, path: destinationPath });
});

export default router;
