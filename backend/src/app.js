const express = require('express');
const path = require('path');
const helmet = require('helmet');
const cors = require('cors');
const session = require('express-session');
const pgSession = require('connect-pg-simple')(session);

const env = require('./config/env');
const { pool } = require('./config/db');
const { attachUser } = require('./middleware/auth');
const { apiLimiter } = require('./middleware/rateLimiters');
const { errorHandler, notFoundHandler } = require('./middleware/errorHandler');

const authRoutes = require('./routes/auth.routes');
const meRoutes = require('./routes/me.routes');
const modulesRoutes = require('./routes/modules.routes');
const testsRoutes = require('./routes/tests.routes');
const labsRoutes = require('./routes/labs.routes');
const contestsRoutes = require('./routes/contests.routes');
const rankingRoutes = require('./routes/ranking.routes');
const adminRoutes = require('./routes/admin.routes');

const app = express();

// Trust the first proxy hop (needed for correct req.ip / secure cookies behind a reverse proxy like nginx).
app.set('trust proxy', 1);
app.set('sessionCookieName', env.sessionCookieName);

// ---------- Security headers ----------
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'"],
      styleSrc: ["'self'", "'unsafe-inline'"], // single-file frontend uses an inline <style> block
      imgSrc: ["'self'", 'data:'],
      connectSrc: ["'self'"],
      objectSrc: ["'none'"],
      frameAncestors: ["'none'"],
      baseUri: ["'none'"],
      formAction: ["'self'"],
    },
  },
  crossOriginResourcePolicy: { policy: 'same-site' },
}));

// ---------- CORS ----------
// Locked to a single known origin; credentials required for session cookies.
app.use(cors({
  origin: env.frontendOrigin,
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type'],
}));

app.use(express.json({ limit: '256kb' }));

// ---------- Sessions ----------
app.use(session({
  store: new pgSession({ pool, tableName: 'session', createTableIfMissing: false }),
  name: env.sessionCookieName,
  secret: env.sessionSecret,
  resave: false,
  saveUninitialized: false,
  rolling: true,
  cookie: {
    httpOnly: true,
    secure: env.nodeEnv === 'production',
    sameSite: 'strict', // primary CSRF defense: cross-site requests never carry this cookie
    maxAge: env.sessionMaxAgeMs,
  },
}));

app.use(attachUser);
app.use('/api', apiLimiter);

// ---------- Frontend (single Render service) ----------
// Render runs from /backend, while the static frontend lives one level above it.
const frontendDir = path.resolve(__dirname, '../../frontend');
app.use(express.static(frontendDir));

app.get('/', (req, res) => {
  res.sendFile(path.join(frontendDir, 'index.html'));
});

// ---------- Routes ----------
app.get('/api/health', (req, res) => res.json({ ok: true }));
app.use('/api/auth', authRoutes);
app.use('/api/me', meRoutes);
app.use('/api/modules', modulesRoutes);
app.use('/api/tests', testsRoutes);
app.use('/api/labs', labsRoutes);
app.use('/api/contests', contestsRoutes);
app.use('/api/ranking', rankingRoutes);
app.use('/api/admin', adminRoutes);

app.use(notFoundHandler);
app.use(errorHandler);

module.exports = app;
