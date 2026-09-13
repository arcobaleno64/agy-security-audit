// evals/semantic-benchmark/safe/08-multistep-attack-path.js
// Semantic Category: multistep-attack-path (CWE-94 - SAFE GUARDED)
import express from 'express';
const router = express.Router();

const TASK_HANDLERS = {
  syncProfile: (payload) => ({ action: 'syncProfile', user: String(payload.user) }),
  purgeCache: (payload) => ({ action: 'purgeCache', key: String(payload.key) })
};

router.post('/queue/dispatch', async (req, res) => {
  const { taskName, payload } = req.body;
  const handler = TASK_HANDLERS[taskName];
  if (!handler) {
    return res.status(400).json({ error: 'Disallowed task operation' });
  }
  const result = handler(payload || {});
  return res.json({ dispatched: true, result });
});

export default router;
