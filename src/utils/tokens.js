const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const env = require('../config/env');
const RefreshToken = require('../models/RefreshToken');

const COOKIE_NAME = 'refresh_token';

function signAccessToken(user) {
  return jwt.sign(
    { sub: String(user.id), role: user.role, tenantId: user.tenantId },
    env.accessSecret,
    { expiresIn: env.accessTtl, algorithm: 'HS256' }
  );
}

// Creates a refresh token, records its jti in the DB so it can be rotated/revoked.
async function issueRefreshToken(user, family = crypto.randomUUID()) {
  const jti = crypto.randomUUID();
  const token = jwt.sign({ sub: String(user.id), jti, fam: family }, env.refreshSecret, {
    expiresIn: env.refreshTtl,
    algorithm: 'HS256',
  });
  await RefreshToken.create({
    jti,
    userId: user.id,
    family,
    expiresAt: new Date(Date.now() + env.refreshTtlMs),
  });
  return token;
}

function cookieOptions() {
  return {
    httpOnly: true,
    secure: env.cookieSecure,
    sameSite: 'strict',
    maxAge: env.refreshTtlMs,
    path: '/api/v1/auth',
  };
}

function setRefreshCookie(res, token) {
  res.cookie(COOKIE_NAME, token, cookieOptions());
}

function clearRefreshCookie(res) {
  const { maxAge, ...opts } = cookieOptions();
  res.clearCookie(COOKIE_NAME, opts);
}

function verifyRefreshToken(token, { ignoreExpiration = false } = {}) {
  return jwt.verify(token, env.refreshSecret, { algorithms: ['HS256'], ignoreExpiration });
}

function verifyAccessToken(token) {
  return jwt.verify(token, env.accessSecret, { algorithms: ['HS256'] });
}

module.exports = {
  COOKIE_NAME,
  signAccessToken,
  issueRefreshToken,
  setRefreshCookie,
  clearRefreshCookie,
  verifyRefreshToken,
  verifyAccessToken,
};
