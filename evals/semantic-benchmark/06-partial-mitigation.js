// evals/semantic-benchmark/06-partial-mitigation.js
// Semantic Category: partial-mitigation (CWE-79)
import express from 'express';
const router = express.Router();

function sanitizeHtmlAttribute(input) {
  if (!input) return '';
  return String(input).replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

router.get('/render-profile', (req, res) => {
  const rawHandle = req.query.handle || '';
  const sanitized = sanitizeHtmlAttribute(rawHandle);
  // Vulnerability: Escapes HTML quotes, but embeds directly into script context!
  const page = '<script>var handle = ' + sanitized + ';</script>';
  return res.send(page);
});

export default router;
