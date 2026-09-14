// evals/holdout-benchmark/safe/03-mass-assignment.js
import express from 'express';
const router = express.Router();

const users = new Map([
  ['usr-1', { id: 'usr-1', displayName: 'Alice', role: 'member', isSuperuser: false }]
]);

const ALLOWED_PROFILE_FIELDS = ['displayName', 'bio', 'locale'];

router.put('/users/:id/profile', (req, res) => {
  const user = users.get(req.params.id);
  if (!user) return res.status(404).json({ error: 'User not found' });

  // Guard: Whitelist-based property extraction prevents mass assignment
  for (const field of ALLOWED_PROFILE_FIELDS) {
    if (req.body[field] !== undefined) {
      user[field] = String(req.body[field]);
    }
  }
  users.set(user.id, user);
  return res.json({ success: true, user });
});

export default router;
