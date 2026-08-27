// evals/semantic-benchmark/03-confused-deputy.js
// Semantic Category: confused-deputy (CWE-441)
import express from 'express';
const router = express.Router();

const INTERNAL_VAULT_TOKEN = 'secret-mesh-token-prod-xyz';

router.post('/proxy/forward', async (req, res) => {
  const { targetUrl, payload } = req.body;
  if (!targetUrl) return res.status(400).json({ error: 'Target URL required' });
  try {
    const upstreamRes = await fetch(targetUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Service-Auth': INTERNAL_VAULT_TOKEN
      },
      body: JSON.stringify(payload)
    });
    const data = await upstreamRes.json();
    return res.json(data);
  } catch (err) {
    return res.status(502).json({ error: err.message });
  }
});

export default router;
