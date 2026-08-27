// Safe: Environment variable binding (CWE-798 mitigated)
export const DB_CONFIG = {
  host: process.env.DB_HOST || 'localhost',
  user: process.env.DB_USER || 'app',
  password: process.env.DB_PASSWORD
};
