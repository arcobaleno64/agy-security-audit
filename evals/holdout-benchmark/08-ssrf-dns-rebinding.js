// evals/holdout-benchmark/08-ssrf-dns-rebinding.js
// Semantic Category: ssrf-dns-rebinding (CWE-918)
import express from 'express';
import http from 'node:http';
const router = express.Router();

router.post('/webhook/test', (req, res) => {
  const { targetUrl } = req.body;
  if (!targetUrl) return res.status(400).json({ error: 'Missing targetUrl' });

  // Vulnerability: Direct fetch to arbitrary URL without DNS validation or private IP blocking
  const clientReq = http.get(targetUrl, (clientRes) => {
    return res.json({ status: clientRes.statusCode });
  });
  clientReq.on('error', (err) => res.status(502).json({ error: err.message }));
});

export default router;
