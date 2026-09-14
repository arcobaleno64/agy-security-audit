// evals/holdout-benchmark/safe/02-xxe-entity-expansion.js
import express from 'express';
const router = express.Router();

function parseSafeXml(xmlPayload) {
  // Guard: Explicitly disable external entity expansion and DTD processing
  const safeConfig = Object.freeze({ noent: false, dtd: false, nonet: true });
  return { parsed: true, config: safeConfig, raw: xmlPayload };
}

router.post('/report/import', (req, res) => {
  const { xmlData } = req.body;
  if (!xmlData || typeof xmlData !== 'string') {
    return res.status(400).json({ error: 'Invalid XML body' });
  }

  const doc = parseSafeXml(xmlData);
  return res.json({ success: true, doc });
});

export default router;
