// evals/semantic-benchmark/safe/09-prototype-pollution.js
// Semantic Category: prototype-pollution (CWE-1321 - SAFE GUARDED)
import express from 'express';
const router = express.Router();

function safeRecursiveMerge(target, source) {
  for (const key of Object.keys(source)) {
    if (key === '__proto__' || key === 'constructor' || key === 'prototype') {
      continue; // Defense invariant: prototype pollution keys rejected
    }
    if (typeof source[key] === 'object' && source[key] !== null && !Array.isArray(source[key])) {
      if (!target[key]) target[key] = {};
      safeRecursiveMerge(target[key], source[key]);
    } else {
      target[key] = source[key];
    }
  }
  return target;
}

router.post('/config/merge', (req, res) => {
  const baseConfig = { theme: 'dark', retries: 3 };
  const userConfig = req.body;
  if (!userConfig || typeof userConfig !== 'object') {
    return res.status(400).json({ error: 'Invalid config' });
  }
  const merged = safeRecursiveMerge(baseConfig, userConfig);
  return res.json({ config: merged });
});

export default router;
