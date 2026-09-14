// evals/holdout-benchmark/03-mass-assignment.js
// Semantic Category: mass-assignment (CWE-915)
import express from 'express';
const router = express.Router();

const users = new Map([
  ['usr-1', { id: 'usr-1', displayName: 'Alice', role: 'member', isSuperuser: false }]
]);

router.put('/users/:id/profile', (req, res) => {
  const user = users.get(req.params.id);
  if (!user) return res.status(404).json({ error: 'User not found' });

  // Vulnerability: Unrestricted mass assignment allows overwriting role / isSuperuser
  Object.assign(user, req.body);
  users.set(user.id, user);
  return res.json({ success: true, user });
});

export default router;
