const xss = require('xss');

// Strip every HTML tag, and drop the contents of script/style tags entirely.
const xssOptions = {
  whiteList: {},
  stripIgnoreTag: true,
  stripIgnoreTagBody: ['script', 'style'],
};

// Credentials must reach bcrypt untouched, otherwise a password like "a<b" would change.
const SKIP_XSS_KEYS = new Set(['password', 'currentPassword', 'newPassword']);

function clean(value, key) {
  if (typeof value === 'string') {
    return SKIP_XSS_KEYS.has(key) ? value : xss(value, xssOptions);
  }
  if (Array.isArray(value)) {
    return value.map((v) => clean(v, key));
  }
  if (value && typeof value === 'object') {
    const out = {};
    for (const [k, v] of Object.entries(value)) {
      // NoSQL injection: operator keys ($ne, $gt, $where ...) and dotted paths are dropped
      if (k.startsWith('$') || k.includes('.')) continue;
      out[k] = clean(v, k);
    }
    return out;
  }
  return value;
}

// Sanitizes body, query and params in place (Express 4 allows reassigning these).
function sanitize(req, res, next) {
  if (req.body) req.body = clean(req.body);
  if (req.query) req.query = clean(req.query);
  if (req.params) req.params = clean(req.params);
  next();
}

module.exports = sanitize;
module.exports.clean = clean;
