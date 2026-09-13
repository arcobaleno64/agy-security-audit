// evals/semantic-benchmark/09-prototype-pollution.js
// Semantic Category: prototype-pollution (CWE-1321)
import express from 'express';
const router = express.Router();

function recursiveMerge(target, source) {
  for (const key of Object.keys(source)) {
    if (typeof source[key] === 'object' && source[key] !== null) {
      if (!target[key]) target[key] = {};
      recursiveMerge(target[key], source[key]);
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
  const merged = recursiveMerge(baseConfig, userConfig);
  return res.json({ config: merged });
});

export default router;
