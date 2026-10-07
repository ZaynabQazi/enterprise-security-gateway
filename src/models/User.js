const db = require('../config/db');

const ROLES = ['SuperAdmin', 'Manager', 'Employee'];

// Whitelist of updatable fields (camelCase -> column). Column names never come from user input.
const UPDATABLE = {
  name: 'name',
  avatar: 'avatar',
  googleId: 'google_id',
  githubId: 'github_id',
  isLocal: 'is_local',
  failedLoginAttempts: 'failed_login_attempts',
  lockUntil: 'lock_until',
};

function map(row, withPassword = false) {
  if (!row) return null;
  const user = {
    id: row.id,
    name: row.name,
    email: row.email,
    role: row.role,
    tenantId: row.tenant_id,
    avatar: row.avatar,
    providers: { local: !!row.is_local, googleId: row.google_id, githubId: row.github_id },
    failedLoginAttempts: row.failed_login_attempts,
    lockUntil: row.lock_until ? new Date(row.lock_until) : null,
    createdAt: row.created_at,
  };
  if (withPassword) user.passwordHash = row.password_hash;
  return user;
}

async function findById(id) {
  const rows = await db.run('SELECT * FROM users WHERE id = ? LIMIT 1', [id]);
  return map(rows[0]);
}

async function findByEmail(email, { withPassword = false } = {}) {
  const rows = await db.run('SELECT * FROM users WHERE email = ? LIMIT 1', [email]);
  return map(rows[0], withPassword);
}

async function findByProviderId(provider, providerId) {
  const column = provider === 'google' ? 'google_id' : 'github_id';
  const rows = await db.run(`SELECT * FROM users WHERE ${column} = ? LIMIT 1`, [providerId]);
  return map(rows[0]);
}

async function create({
  name,
  email,
  passwordHash = null,
  role = 'Employee',
  tenantId = 'default',
  isLocal = false,
  googleId = null,
  githubId = null,
  avatar = null,
}) {
  const result = await db.run(
    `INSERT INTO users (name, email, password_hash, role, tenant_id, is_local, google_id, github_id, avatar)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    [name, email, passwordHash, role, tenantId, isLocal ? 1 : 0, googleId, githubId, avatar]
  );
  return findById(result.insertId);
}

async function update(id, fields) {
  const sets = [];
  const values = [];
  for (const [key, value] of Object.entries(fields)) {
    if (!UPDATABLE[key]) throw new Error(`Field not updatable: ${key}`);
    sets.push(`${UPDATABLE[key]} = ?`);
    values.push(typeof value === 'boolean' ? (value ? 1 : 0) : value);
  }
  if (!sets.length) return;
  await db.run(`UPDATE users SET ${sets.join(', ')} WHERE id = ?`, [...values, id]);
}

async function listByTenant(tenantId) {
  const rows = await db.run('SELECT * FROM users WHERE tenant_id = ? ORDER BY id ASC', [tenantId]);
  return rows.map((r) => map(r));
}

async function findInTenant(id, tenantId) {
  const rows = await db.run('SELECT * FROM users WHERE id = ? AND tenant_id = ? LIMIT 1', [id, tenantId]);
  return map(rows[0]);
}

async function deleteInTenant(id, tenantId) {
  const result = await db.run('DELETE FROM users WHERE id = ? AND tenant_id = ?', [id, tenantId]);
  return result.affectedRows > 0; // refresh_tokens rows go too (ON DELETE CASCADE)
}

function isLocked(user) {
  return !!user.lockUntil && user.lockUntil > new Date();
}

function toSafeJSON(user) {
  return {
    id: user.id,
    name: user.name,
    email: user.email,
    role: user.role,
    tenantId: user.tenantId,
    avatar: user.avatar,
    providers: {
      local: user.providers.local,
      google: !!user.providers.googleId,
      github: !!user.providers.githubId,
    },
    createdAt: user.createdAt,
  };
}

module.exports = {
  ROLES,
  findById,
  findByEmail,
  findByProviderId,
  create,
  update,
  listByTenant,
  findInTenant,
  deleteInTenant,
  isLocked,
  toSafeJSON,
};
