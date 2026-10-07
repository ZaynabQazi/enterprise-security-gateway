const mysql = require('mysql2/promise');
const env = require('./env');

let pool;

const USERS_TABLE = `
CREATE TABLE IF NOT EXISTS users (
  id INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
  name VARCHAR(80) NOT NULL,
  email VARCHAR(190) NOT NULL UNIQUE,
  password_hash VARCHAR(100) NULL,
  role ENUM('SuperAdmin','Manager','Employee') NOT NULL DEFAULT 'Employee',
  tenant_id VARCHAR(64) NOT NULL DEFAULT 'default',
  is_local TINYINT(1) NOT NULL DEFAULT 0,
  google_id VARCHAR(64) NULL,
  github_id VARCHAR(64) NULL,
  avatar VARCHAR(500) NULL,
  failed_login_attempts INT NOT NULL DEFAULT 0,
  lock_until DATETIME NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  INDEX idx_users_tenant (tenant_id),
  INDEX idx_users_google (google_id),
  INDEX idx_users_github (github_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci`;

// One row per issued refresh token. `family` ties together every token descended from a
// single login, so a reused (stolen) token can revoke the whole chain.
const REFRESH_TABLE = `
CREATE TABLE IF NOT EXISTS refresh_tokens (
  id INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
  jti CHAR(36) NOT NULL UNIQUE,
  user_id INT UNSIGNED NOT NULL,
  family CHAR(36) NOT NULL,
  revoked TINYINT(1) NOT NULL DEFAULT 0,
  expires_at DATETIME NOT NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  INDEX idx_rt_family (family),
  INDEX idx_rt_user (user_id),
  INDEX idx_rt_expires (expires_at),
  CONSTRAINT fk_rt_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci`;

const base = () => ({
  host: env.db.host,
  port: env.db.port,
  user: env.db.user,
  password: env.db.password,
  ssl: env.db.ssl ? { rejectUnauthorized: true } : undefined,
  timezone: 'Z', // store and read all dates as UTC
});

// Creates the database (if allowed) and tables, then opens the connection pool.
async function init() {
  try {
    const conn = await mysql.createConnection(base());
    await conn.query(`CREATE DATABASE IF NOT EXISTS \`${env.db.name}\` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci`);
    await conn.end();
  } catch (err) {
    // Hosted databases often forbid CREATE DATABASE; the database may already exist, so carry on.
    if (err.code === 'ECONNREFUSED' || err.code === 'ER_ACCESS_DENIED_ERROR' || err.code === 'ENOTFOUND') throw err;
  }

  pool = mysql.createPool({
    ...base(),
    database: env.db.name,
    waitForConnections: true,
    connectionLimit: 10,
  });

  await pool.query(USERS_TABLE);
  await pool.query(REFRESH_TABLE);
}

// Parameterized query helper: values are always sent separately from the SQL text (SQL injection safe).
async function run(sql, params = []) {
  const safe = params.map((p) => (p === undefined ? null : p));
  const [result] = await pool.execute(sql, safe);
  return result;
}

async function close() {
  if (pool) await pool.end();
}

module.exports = { init, run, close };
