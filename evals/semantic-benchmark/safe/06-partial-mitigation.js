// evals/semantic-benchmark/safe/06-partial-mitigation.js
// Semantic Category: partial-mitigation (CWE-79 - SAFE GUARDED)
import express from 'express';
const router = express.Router();

function encodeHtmlAttribute(str) {
  if (typeof str !== 'string') return '';
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#x27;');
}

router.get('/profile', (req, res) => {
  const userNick = req.query.nick || 'Guest';
  const safeNick = encodeHtmlAttribute(userNick);
  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  res.send(`<input type="text" name="nick" value="${safeNick}">`);
});

export default router;
