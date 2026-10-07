const crypto = require('crypto');
const express = require('express');
const bcrypt = require('bcryptjs');
const RefreshToken = require('../models/RefreshToken');
const User = require('../models/User');
const env = require('../config/env');
const { passport, enabled } = require('../config/passport');
const { authenticate } = require('../middleware/auth');
const { loginLimiter, registerLimiter } = require('../middleware/rateLimit');
const {
  COOKIE_NAME,
  signAccessToken,
  issueRefreshToken,
  setRefreshCookie,
  clearRefreshCookie,
  verifyRefreshToken,
} = require('../utils/tokens');

const router = express.Router();

const BCRYPT_ROUNDS = 12; // bcrypt generates a unique salt per hash automatically
const MAX_FAILED_ATTEMPTS = 5;
const LOCK_MS = 15 * 60 * 1000;
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;
const STRONG_PW_RE = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d).{8,72}$/;
// Compared against when the email does not exist, so response time does not reveal valid emails
const DUMMY_HASH = bcrypt.hashSync('dummy-password-for-timing', BCRYPT_ROUNDS);

// ---------- Local auth ----------

router.post('/register', registerLimiter, async (req, res, next) => {
  try {
    const { name, email, password } = req.body || {};
    if (typeof name !== 'string' || typeof email !== 'string' || typeof password !== 'string') {
      return res.status(400).json({ error: 'name, email and password must be strings' });
    }
    if (name.trim().length < 2 || name.length > 80) {
      return res.status(400).json({ error: 'Name must be 2 to 80 characters' });
    }
    if (!EMAIL_RE.test(email) || email.length > 190) {
      return res.status(400).json({ error: 'Invalid email address' });
    }
    if (!STRONG_PW_RE.test(password)) {
      return res.status(400).json({
        error: 'Password must be 8 to 72 characters with at least one uppercase letter, one lowercase letter and one number',
      });
    }

    const normalized = email.toLowerCase().trim();
    if (await User.findByEmail(normalized)) {
      return res.status(409).json({ error: 'An account with this email already exists' });
    }

    const passwordHash = await bcrypt.hash(password, BCRYPT_ROUNDS);
    let user;
    try {
      // Role is NEVER taken from the request body: self-registration is always Employee.
      user = await User.create({ name: name.trim(), email: normalized, passwordHash, role: 'Employee', isLocal: true });
    } catch (err) {
      if (err.code === 'ER_DUP_ENTRY') return res.status(409).json({ error: 'An account with this email already exists' });
      throw err;
    }

    res.status(201).json({ message: 'Registered successfully', user: User.toSafeJSON(user) });
  } catch (err) {
    next(err);
  }
});

router.post('/login', loginLimiter, async (req, res, next) => {
  try {
    const { email, password } = req.body || {};
    if (typeof email !== 'string' || typeof password !== 'string') {
      return res.status(400).json({ error: 'email and password must be strings' });
    }

    const user = await User.findByEmail(email.toLowerCase().trim(), { withPassword: true });

    if (user && User.isLocked(user)) {
      const minutes = Math.ceil((user.lockUntil - Date.now()) / 60000);
      return res.status(423).json({ error: `Account locked due to too many failed attempts. Try again in ${minutes} minute(s).` });
    }

    const hash = user?.passwordHash || DUMMY_HASH;
    const ok = await bcrypt.compare(password, hash);

    if (!user || !user.passwordHash || !ok) {
      if (user) {
        // A previous lock may have expired: start counting from zero again
        const previous = user.lockUntil && user.lockUntil <= new Date() ? 0 : user.failedLoginAttempts;
        const attempts = previous + 1;
        if (attempts >= MAX_FAILED_ATTEMPTS) {
          await User.update(user.id, { failedLoginAttempts: 0, lockUntil: new Date(Date.now() + LOCK_MS) });
        } else {
          await User.update(user.id, { failedLoginAttempts: attempts, lockUntil: null });
        }
      }
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    await User.update(user.id, { failedLoginAttempts: 0, lockUntil: null });

    const refreshToken = await issueRefreshToken(user);
    setRefreshCookie(res, refreshToken);
    res.json({ accessToken: signAccessToken(user), expiresIn: 900, user: User.toSafeJSON(user) });
  } catch (err) {
    next(err);
  }
});

// ---------- Refresh token rotation ----------

router.post('/refresh', async (req, res, next) => {
  try {
    const token = req.cookies?.[COOKIE_NAME];
    if (!token) return res.status(401).json({ error: 'No refresh token' });

    let payload;
    try {
      payload = verifyRefreshToken(token);
    } catch {
      clearRefreshCookie(res);
      return res.status(401).json({ error: 'Invalid or expired refresh token' });
    }

    // Atomically revoke the presented token. Only one request can win this race.
    const consumed = await RefreshToken.consume(payload.jti);

    if (!consumed) {
      // Token is unknown or was already used: treat as theft and burn the whole family.
      await RefreshToken.revokeFamily(payload.fam);
      clearRefreshCookie(res);
      return res.status(401).json({ error: 'Refresh token reuse detected. All sessions in this chain were revoked. Please log in again.' });
    }

    const userId = Number(payload.sub);
    const user = Number.isSafeInteger(userId) ? await User.findById(userId) : null;
    if (!user) {
      clearRefreshCookie(res);
      return res.status(401).json({ error: 'User no longer exists' });
    }

    const newRefresh = await issueRefreshToken(user, payload.fam); // same family, new jti
    setRefreshCookie(res, newRefresh);
    res.json({ accessToken: signAccessToken(user), expiresIn: 900, user: User.toSafeJSON(user) });
  } catch (err) {
    next(err);
  }
});

// ---------- Logout / revocation ----------

router.post('/logout', async (req, res, next) => {
  try {
    const token = req.cookies?.[COOKIE_NAME];
    if (token) {
      try {
        const payload = verifyRefreshToken(token, { ignoreExpiration: true });
        await RefreshToken.revokeFamily(payload.fam);
      } catch {
        /* bad token: nothing to revoke */
      }
    }
    clearRefreshCookie(res);
    res.json({ message: 'Logged out. Refresh token revoked.' });
  } catch (err) {
    next(err);
  }
});

router.get('/me', authenticate, (req, res) => res.json({ user: User.toSafeJSON(req.user) }));

router.get('/providers', (req, res) => res.json(enabled));

// ---------- Social login (Google / GitHub) ----------

const STATE_COOKIE = 'oauth_state';

function startOAuth(provider, scope) {
  return (req, res, next) => {
    if (!enabled[provider]) return res.status(503).json({ error: `${provider} login is not configured on this server` });
    const state = crypto.randomBytes(24).toString('hex');
    // SameSite=Lax (not Strict) because the callback is a cross-site redirect coming back from the provider
    res.cookie(STATE_COOKIE, state, {
      httpOnly: true,
      secure: env.cookieSecure,
      sameSite: 'lax',
      maxAge: 10 * 60 * 1000,
      path: '/api/v1/auth',
    });
    passport.authenticate(provider, { scope, session: false, state })(req, res, next);
  };
}

function finishOAuth(provider) {
  return [
    (req, res, next) => {
      if (!enabled[provider]) return res.status(503).json({ error: `${provider} login is not configured` });
      const expected = req.cookies?.[STATE_COOKIE];
      const received = req.query.state;
      res.clearCookie(STATE_COOKIE, { httpOnly: true, secure: env.cookieSecure, sameSite: 'lax', path: '/api/v1/auth' });
      const a = Buffer.from(String(expected || ''));
      const b = Buffer.from(String(received || ''));
      if (!expected || a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
        return res.redirect('/?oauth=failed&reason=state');
      }
      next();
    },
    passport.authenticate(provider, { session: false, failureRedirect: '/?oauth=failed' }),
    async (req, res, next) => {
      try {
        // Issue our own credentials: refresh cookie now, access token via /refresh from the SPA
        const refreshToken = await issueRefreshToken(req.user);
        setRefreshCookie(res, refreshToken);
        res.redirect('/?oauth=success');
      } catch (err) {
        next(err);
      }
    },
  ];
}

router.get('/google', startOAuth('google', ['profile', 'email']));
router.get('/google/callback', ...finishOAuth('google'));
router.get('/github', startOAuth('github', ['user:email']));
router.get('/github/callback', ...finishOAuth('github'));

module.exports = router;
