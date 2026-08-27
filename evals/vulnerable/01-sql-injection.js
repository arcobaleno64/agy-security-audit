// CWE-89: SQL Injection via string concatenation
export function getUser(db, userId) {
  const query = "SELECT * FROM users WHERE id = '" + userId + "'";
  return db.query(query);
}
