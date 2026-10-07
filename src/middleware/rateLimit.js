const rateLimit = require('express-rate-limit');

const tooMany = (message) => (req, res) =>
  res.status(429).json({ error: message, retryAfterSeconds: Math.ceil((req.rateLimit?.resetTime - Date.now()) / 1000) || undefined });

// Max 5 FAILED logins per 15 minutes per IP (successful logins are not counted).
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 5,
  skipSuccessfulRequests: true,
  standardHeaders: 'draft-7',
  legacyHeaders: false,
  handler: tooMany('Too many failed login attempts. Try again in 15 minutes.'),
});

// Stops mass account creation from one IP.
const registerLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  limit: 20,
  standardHeaders: 'draft-7',
  legacyHeaders: false,
  handler: tooMany('Too many registrations from this IP. Try again later.'),
});

// General safety net for the whole API.
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 300,
  standardHeaders: 'draft-7',
  legacyHeaders: false,
  handler: tooMany('Too many requests. Slow down.'),
});

module.exports = { loginLimiter, registerLimiter, apiLimiter };
