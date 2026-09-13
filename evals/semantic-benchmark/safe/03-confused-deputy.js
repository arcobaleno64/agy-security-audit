// evals/semantic-benchmark/safe/03-confused-deputy.js
// Semantic Category: confused-deputy (CWE-441 - SAFE GUARDED)
import express from 'express';
const router = express.Router();

const ALLOWED_DESTINATIONS = new Set(['https://api.partner.mesh/v1/ingest']);

router.post('/proxy/forward', async (req, res) => {
  const { targetUrl, payload } = req.body;
  if (!targetUrl) return res.status(400).json({ error: 'Target URL required' });
  try {
    const parsed = new URL(targetUrl);
    if (!ALLOWED_DESTINATIONS.has(parsed.origin + parsed.pathname)) {
      return res.status(403).json({ error: 'Destination not permitted by policy' });
    }
    const upstreamRes = await fetch(targetUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });
    const data = await upstreamRes.json();
    return res.json(data);
  } catch (err) {
    return res.status(502).json({ error: err.message });
  }
});

export default router;
