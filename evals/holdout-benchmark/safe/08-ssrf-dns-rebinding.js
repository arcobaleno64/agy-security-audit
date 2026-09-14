// evals/holdout-benchmark/safe/08-ssrf-dns-rebinding.js
import express from 'express';
import http from 'node:http';
import dns from 'node:dns/promises';
const router = express.Router();

function isPrivateIp(ip) {
  return /^(127\.|10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|192\.168\.|169\.254\.|::1|fe80:)/i.test(ip);
}

router.post('/webhook/test', async (req, res) => {
  const { targetUrl } = req.body;
  if (!targetUrl) return res.status(400).json({ error: 'Missing targetUrl' });

  try {
    const parsed = new URL(targetUrl);
    const lookup = await dns.lookup(parsed.hostname);
    // Guard: Rejects loopback, private RFC 1918, and link-local addresses
    if (isPrivateIp(lookup.address)) {
      return res.status(403).json({ error: 'Egress to private/internal network prohibited' });
    }

    const clientReq = http.get(targetUrl, (clientRes) => {
      return res.json({ status: clientRes.statusCode });
    });
    clientReq.on('error', (err) => res.status(502).json({ error: err.message }));
  } catch (err) {
    return res.status(400).json({ error: err.message });
  }
});

export default router;
