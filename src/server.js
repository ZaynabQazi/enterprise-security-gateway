const path = require('path');
const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const env = require('./config/env');
const db = require('./config/db');
const RefreshToken = require('./models/RefreshToken');
const { passport } = require('./config/passport');
const sanitize = require('./middleware/sanitize');
const { apiLimiter } = require('./middleware/rateLimit');
const authRoutes = require('./routes/auth');
const resourceRoutes = require('./routes/resources');
const { seedDemoUsers } = require('./utils/seedUsers');

const app = express();

// Render/Railway/Vercel sit behind a proxy: needed for correct client IPs (rate limiting) and Secure cookies
app.set('trust proxy', 1);
app.disable('x-powered-by');

// OWASP: secure HTTP headers (CSP, HSTS, X-Frame-Options, noSniff, ...)
app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'"],
        styleSrc: ["'self'"],
        imgSrc: ["'self'", 'data:', 'https:'],
        objectSrc: ["'none'"],
        frameAncestors: ["'none'"],
      },
    },
  })
);

// OWASP: strict CORS allowlist. Requests with no Origin header (Postman, curl, same-origin) are allowed.
app.use(
  cors({
    origin(origin, cb) {
      if (!origin || env.corsOrigins.includes(origin)) return cb(null, true);
      cb(Object.assign(new Error('Origin not allowed by CORS'), { status: 403 }));
    },
    credentials: true,
    methods: ['GET', 'POST', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization'],
    maxAge: 600,
  })
);

app.use(express.json({ limit: '10kb' }));
app.use(cookieParser());
app.use(sanitize); // NoSQL-injection + XSS scrubbing for body, query and params
app.use(passport.initialize());

app.get('/health', (req, res) => res.json({ status: 'ok', uptime: process.uptime() }));

app.use('/api/v1', apiLimiter);
app.use('/api/v1/auth', authRoutes);
app.use('/api/v1', resourceRoutes);

app.use(express.static(path.join(__dirname, '..', 'public')));

app.use('/api', (req, res) => res.status(404).json({ error: 'Route not found' }));

// Central error handler: never leak stack traces
// eslint-disable-next-line no-unused-vars
app.use((err, req, res, next) => {
  if (err.type === 'entity.parse.failed') return res.status(400).json({ error: 'Malformed JSON body' });
  if (err.type === 'entity.too.large') return res.status(413).json({ error: 'Payload too large' });
  const status = err.status || 500;
  if (status >= 500) console.error(err);
  res.status(status).json({ error: status >= 500 ? 'Internal server error' : err.message });
});

async function start() {
  await db.init();
  console.log(`MySQL connected (database: ${env.db.name})`);
  if (env.seedOnStart) await seedDemoUsers();
  // Clean up expired refresh tokens now and then hourly
  await RefreshToken.purgeExpired();
  setInterval(() => RefreshToken.purgeExpired().catch(() => {}), 60 * 60 * 1000).unref();
  app.listen(env.port, () => console.log(`Gateway listening on port ${env.port} (${env.appUrl})`));
}

if (require.main === module) {
  start().catch((err) => {
    console.error('Failed to start:', err);
    process.exit(1);
  });
}

module.exports = app;
