const User = require('../models/User');
const { verifyAccessToken } = require('../utils/tokens');

// Verifies the Bearer access token and loads the current user from the DB,
// so a deleted user or changed role takes effect immediately.
async function authenticate(req, res, next) {
  try {
    const header = req.headers.authorization || '';
    const [scheme, token] = header.split(' ');
    if (scheme !== 'Bearer' || !token) {
      return res.status(401).json({ error: 'Missing or malformed Authorization header' });
    }

    let payload;
    try {
      payload = verifyAccessToken(token);
    } catch (err) {
      const expired = err.name === 'TokenExpiredError';
      return res
        .status(401)
        .json({ error: expired ? 'Access token expired' : 'Invalid access token', code: expired ? 'TOKEN_EXPIRED' : 'TOKEN_INVALID' });
    }

    const userId = Number(payload.sub);
    if (!Number.isSafeInteger(userId)) return res.status(401).json({ error: 'Invalid access token' });

    const user = await User.findById(userId);
    if (!user) return res.status(401).json({ error: 'User no longer exists' });

    req.user = user;
    next();
  } catch (err) {
    next(err);
  }
}

// Usage: router.delete('/:id', authenticate, checkRole(['SuperAdmin']), handler)
function checkRole(allowedRoles) {
  return (req, res, next) => {
    if (!req.user) return res.status(401).json({ error: 'Not authenticated' });
    if (!allowedRoles.includes(req.user.role)) {
      return res.status(403).json({
        error: 'Forbidden: insufficient role',
        yourRole: req.user.role,
        requiredRoles: allowedRoles,
      });
    }
    next();
  };
}

module.exports = { authenticate, checkRole };
