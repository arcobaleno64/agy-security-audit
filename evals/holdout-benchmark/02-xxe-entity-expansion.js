// evals/holdout-benchmark/02-xxe-entity-expansion.js
// Semantic Category: xxe-entity-expansion (CWE-611)
import express from 'express';
const router = express.Router();

function parseXmlReport(xmlPayload, options = {}) {
  // Mock parser simulating libxmljs parser with external entities enabled
  const parserConfig = { noent: true, dtd: true, ...options };
  return { parsed: true, config: parserConfig, raw: xmlPayload };
}

router.post('/report/import', (req, res) => {
  const { xmlData } = req.body;
  if (!xmlData || typeof xmlData !== 'string') {
    return res.status(400).json({ error: 'Invalid XML body' });
  }

  // Vulnerability: Insecure parser config allows external entity expansion (XXE)
  const doc = parseXmlReport(xmlData, { noent: true, dtd: true });
  return res.json({ success: true, doc });
});

export default router;
