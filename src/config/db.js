const fs = require('fs');
const path = require('path');
const env = require('./env');

const useSqlite = env.db.client === 'sqlite';

let pool; // mysql2 pool
let sqlite; // better-sqlite3 handle

// ---------------- MySQL / MariaDB (XAMPP) ----------------

const MYSQL_USERS = `
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
const MYSQL_REFRESH = `
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

const mysqlBase = () => ({
  host: env.db.host,
  port: env.db.port,
  user: env.db.user,
  password: env.db.password,
  ssl: env.db.ssl ? { rejectUnauthorized: true } : undefined,
  timezone: 'Z', // store and read all dates as UTC
});

async function initMysql() {
  const mysql = require('mysql2/promise');
  try {
    const conn = await mysql.createConnection(mysqlBase());
    await conn.query(`CREATE DATABASE IF NOT EXISTS \`${env.db.name}\` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci`);
    await conn.end();
  } catch (err) {
    // Hosted databases often forbid CREATE DATABASE; the database may already exist, so carry on.
    if (err.code === 'ECONNREFUSED' || err.code === 'ER_ACCESS_DENIED_ERROR' || err.code === 'ENOTFOUND') throw err;
  }

  pool = mysql.createPool({
    ...mysqlBase(),
    database: env.db.name,
    waitForConnections: true,
    connectionLimit: 10,
  });

  await pool.query(MYSQL_USERS);
  await pool.query(MYSQL_REFRESH);
}

// ---------------- SQLite (no separate database server needed) ----------------

const SQLITE_SCHEMA = `
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  email TEXT NOT NULL UNIQUE,
  password_hash TEXT,
  role TEXT NOT NULL DEFAULT 'Employee' CHECK (role IN ('SuperAdmin','Manager','Employee')),
  tenant_id TEXT NOT NULL DEFAULT 'default',
  is_local INTEGER NOT NULL DEFAULT 0,
  google_id TEXT,
  github_id TEXT,
  avatar TEXT,
  failed_login_attempts INTEGER NOT NULL DEFAULT 0,
  lock_until TEXT,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
  updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);
CREATE INDEX IF NOT EXISTS idx_users_tenant ON users (tenant_id);
CREATE INDEX IF NOT EXISTS idx_users_google ON users (google_id);
CREATE INDEX IF NOT EXISTS idx_users_github ON users (github_id);

CREATE TABLE IF NOT EXISTS refresh_tokens (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  jti TEXT NOT NULL UNIQUE,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  family TEXT NOT NULL,
  revoked INTEGER NOT NULL DEFAULT 0,
  expires_at TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);
CREATE INDEX IF NOT EXISTS idx_rt_family ON refresh_tokens (family);
CREATE INDEX IF NOT EXISTS idx_rt_user ON refresh_tokens (user_id);
CREATE INDEX IF NOT EXISTS idx_rt_expires ON refresh_tokens (expires_at);
`;

function initSqlite() {
  let Database;
  try {
    Database = require('better-sqlite3');
  } catch {
    throw new Error('DB_CLIENT=sqlite needs the better-sqlite3 package. Run: npm install better-sqlite3');
  }
  fs.mkdirSync(path.dirname(env.db.sqlitePath), { recursive: true });
  sqlite = new Database(env.db.sqlitePath);
  sqlite.pragma('journal_mode = WAL');
  sqlite.pragma('foreign_keys = ON'); // needed for ON DELETE CASCADE
  sqlite.exec(SQLITE_SCHEMA);
}

// ---------------- Shared API ----------------

async function init() {
  if (useSqlite) initSqlite();
  else await initMysql();
}

// Parameterized query helper: values are always sent separately from the SQL text (SQL injection safe).
// SELECT returns an array of rows; INSERT/UPDATE/DELETE return { insertId, affectedRows }.
async function run(sql, params = []) {
  if (useSqlite) {
    const safe = params.map((p) => (p === undefined ? null : p instanceof Date ? p.toISOString() : p));
    const stmt = sqlite.prepare(sql);
    if (stmt.reader) return stmt.all(...safe);
    const info = stmt.run(...safe);
    return { insertId: Number(info.lastInsertRowid), affectedRows: info.changes };
  }
  const safe = params.map((p) => (p === undefined ? null : p));
  const [result] = await pool.execute(sql, safe);
  return result;
}

async function close() {
  if (pool) await pool.end();
  if (sqlite) sqlite.close();
}

module.exports = { init, run, close };
