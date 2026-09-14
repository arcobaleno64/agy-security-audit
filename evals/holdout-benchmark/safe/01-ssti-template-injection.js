// evals/holdout-benchmark/safe/01-ssti-template-injection.js
import express from 'express';
const router = express.Router();

const STATIC_TEMPLATES = new Map([
  ['welcome', (ctx) => `Welcome back, ${String(ctx.username || '').replace(/[<>&]/g, '')}!`],
  ['invoice', (ctx) => `Invoice #${String(ctx.invoiceId || '')} for amount $${Number(ctx.amount) || 0}`]
]);

router.post('/preview/email', (req, res) => {
  const { templateId, userVars } = req.body;
  const renderer = STATIC_TEMPLATES.get(templateId);
  if (!renderer) {
    return res.status(400).json({ error: 'Invalid or unapproved template ID' });
  }

  // Guard: Context bound into pre-compiled static template map
  const rendered = renderer(userVars || {});
  return res.json({ success: true, rendered });
});

export default router;
