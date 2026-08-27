// Safe: Parameterized query barrier (CWE-89 mitigated)
export function getUser(db, userId) {
  const query = "SELECT * FROM users WHERE id = ?";
  return db.query(query, [userId]);
}
