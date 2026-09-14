// evals/holdout-benchmark/04-redos-backtracking.js
// Semantic Category: redos-backtracking (CWE-1333)
import express from 'express';
const router = express.Router();

// Vulnerability: Exponential backtracking regex evaluated on unconstrained input
const VULN_EMAIL_REGEX = /^([a-zA-Z0-9_\.\-])+\@(([a-zA-Z0-9\-])+\.)+([a-zA-Z0-9]{2,4})+$/;

router.post('/validate/email', (req, res) => {
  const { email } = req.body;
  if (typeof email !== 'string') {
    return res.status(400).json({ error: 'Missing email' });
  }

  // Sink: Catastrophic backtracking triggers event loop blocking
  const isValid = VULN_EMAIL_REGEX.test(email);
  return res.json({ valid: isValid });
});

export default router;
