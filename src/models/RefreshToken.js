const db = require('../config/db');

async function create({ jti, userId, family, expiresAt }) {
  await db.run('INSERT INTO refresh_tokens (jti, user_id, family, expires_at) VALUES (?, ?, ?, ?)', [
    jti,
    userId,
    family,
    expiresAt,
  ]);
}

// Atomic single-use check: only one request can flip revoked from 0 to 1.
// Returns true if THIS call consumed the token, false if it was unknown or already used.
async function consume(jti) {
  const result = await db.run('UPDATE refresh_tokens SET revoked = 1 WHERE jti = ? AND revoked = 0', [jti]);
  return result.affectedRows === 1;
}

async function revokeFamily(family) {
  await db.run('UPDATE refresh_tokens SET revoked = 1 WHERE family = ?', [family]);
}

async function purgeExpired() {
  await db.run('DELETE FROM refresh_tokens WHERE expires_at < ?', [new Date()]);
}

module.exports = { create, consume, revokeFamily, purgeExpired };
