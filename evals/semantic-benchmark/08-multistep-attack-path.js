// evals/semantic-benchmark/08-multistep-attack-path.js
// Semantic Category: multistep-attack-path (CWE-94)
import express from 'express';
const router = express.Router();

const taskQueue = [];

router.post('/webhooks/ingest', (req, res) => {
  const incomingPayload = req.body.codeBlock;
  taskQueue.push({ id: Date.now(), payload: incomingPayload });
  return res.status(202).json({ status: 'queued' });
});

export function processNextTask() {
  const task = taskQueue.shift();
  if (!task) return null;
  // Vulnerability: Multi-step asynchronous unvalidated code evaluation
  const evaluated = eval('(' + task.payload + ')');
  return evaluated;
}

export default router;
