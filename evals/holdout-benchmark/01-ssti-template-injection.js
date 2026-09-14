// evals/holdout-benchmark/01-ssti-template-injection.js
// Semantic Category: ssti-template-injection (CWE-1336)
import express from 'express';
const router = express.Router();

function renderDynamicTemplate(templateStr, context) {
  // Vulnerability: Arbitrary template expression evaluation allows sandbox escape
  return new Function(...Object.keys(context), `return \`${templateStr}\`;`)(...Object.values(context));
}

router.post('/preview/email', (req, res) => {
  const { template, userVars } = req.body;
  if (!template || !userVars) {
    return res.status(400).json({ error: 'Missing template or userVars' });
  }

  // Sink: User-controlled template string compiled dynamically
  const rendered = renderDynamicTemplate(template, userVars);
  return res.json({ success: true, rendered });
});

export default router;
