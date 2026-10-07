require('dotenv').config();

const required = ['ACCESS_TOKEN_SECRET', 'REFRESH_TOKEN_SECRET'];
const missing = required.filter((k) => !process.env[k]);
if (missing.length) {
  console.error(`Missing required environment variables: ${missing.join(', ')}`);
  process.exit(1);
}

const isProd = process.env.NODE_ENV === 'production';
const port = Number(process.env.PORT) || 5000;
const appUrl = (process.env.APP_URL || `http://localhost:${port}`).replace(/\/$/, '');

// DB_* names are used locally (XAMPP). MYSQL* names are what Railway's MySQL plugin provides.
const dbName = process.env.DB_NAME || process.env.MYSQLDATABASE || 'security_gateway';
if (!/^[A-Za-z0-9_]+$/.test(dbName)) {
  console.error('DB_NAME may only contain letters, numbers and underscores');
  process.exit(1);
}

module.exports = {
  isProd,
  port,
  appUrl,
  db: {
    host: process.env.DB_HOST || process.env.MYSQLHOST || '127.0.0.1',
    port: Number(process.env.DB_PORT || process.env.MYSQLPORT) || 3306,
    user: process.env.DB_USER || process.env.MYSQLUSER || 'root',
    password: process.env.DB_PASSWORD ?? process.env.MYSQLPASSWORD ?? '',
    name: dbName,
    ssl: process.env.DB_SSL === 'true',
  },
  accessSecret: process.env.ACCESS_TOKEN_SECRET,
  refreshSecret: process.env.REFRESH_TOKEN_SECRET,
  accessTtl: '15m',
  refreshTtlMs: 7 * 24 * 60 * 60 * 1000,
  refreshTtl: '7d',
  corsOrigins: (process.env.CORS_ORIGINS || appUrl)
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean),
  // Secure flag is always on unless explicitly disabled for local http testing
  cookieSecure: process.env.COOKIE_SECURE !== 'false',
  google: {
    clientId: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
  },
  github: {
    clientId: process.env.GITHUB_CLIENT_ID,
    clientSecret: process.env.GITHUB_CLIENT_SECRET,
  },
  seedOnStart: process.env.SEED_ON_START === 'true',
};
