const express = require('express');
const argon2 = require('argon2');
const { z } = require('zod');
const { query } = require('../config/db');
const { validateBody } = require('../utils/validate');
const { requireAuth } = require('../middleware/auth');
const { loginLimiter, registerLimiter } = require('../middleware/rateLimiters');
const { logSecurityEvent } = require('../utils/audit');

const router = express.Router();
const ARGON2_OPTS = { type: argon2.argon2id, memoryCost: 19456, timeCost: 2, parallelism: 1 };

const MAX_FAILED_ATTEMPTS = 5;
const LOCK_DURATION_MS = 15 * 60 * 1000;

const usernameSchema = z.string().trim().min(3).max(32).regex(/^[a-zA-Z0-9_.-]+$/, 'Login może zawierać tylko litery, cyfry, "_", "." i "-".');
const passwordSchema = z.string().min(10, 'Hasło musi mieć co najmniej 10 znaków.').max(256);

const registerSchema = z.object({
  username: usernameSchema,
  email: z.string().trim().email().max(255),
  password: passwordSchema,
  passwordConfirm: z.string(),
}).refine((data) => data.password === data.passwordConfirm, {
  message: 'Hasła nie są identyczne.',
  path: ['passwordConfirm'],
});

const loginSchema = z.object({
  identifier: z.string().trim().min(1).max(255),
  password: z.string().min(1).max(256),
});

const changePasswordSchema = z.object({
  currentPassword: z.string().min(1).max(256),
  newPassword: passwordSchema,
  newPasswordConfirm: z.string(),
}).refine((data) => data.newPassword === data.newPasswordConfirm, {
  message: 'Nowe hasła nie są identyczne.',
  path: ['newPasswordConfirm'],
});

function publicUser(u) {
  return {
    id: u.id,
    username: u.username,
    email: u.email,
    role: u.role,
    xp: u.xp,
    level: u.level,
    mustChangePassword: u.must_change_password,
  };
}

// POST /api/auth/register
router.post('/register', registerLimiter, validateBody(registerSchema), async (req, res, next) => {
  try {
    const { username, email, password } = req.validated;

    const { rows: clashes } = await query(
      'SELECT username, email FROM users WHERE username = $1 OR email = $2',
      [username, email],
    );
    if (clashes.length > 0) {
      return res.status(409).json({ error: 'Użytkownik z tym loginem lub e-mailem już istnieje.' });
    }

    const hash = await argon2.hash(password, ARGON2_OPTS);
    const { rows } = await query(
      `INSERT INTO users (username, email, password_hash, role)
       VALUES ($1, $2, $3, 'user')
       RETURNING id, username, email, role, xp, level, must_change_password`,
      [username, email, hash],
    );
    const user = rows[0];

    // Regenerate session on privilege change (login) to prevent session fixation.
    req.session.regenerate((err) => {
      if (err) return next(err);
      req.session.userId = user.id;
      logSecurityEvent({ eventType: 'register', req, actorId: user.id, actorUsername: user.username });
      res.status(201).json({ user: publicUser(user) });
    });
  } catch (err) {
    next(err);
  }
});

// POST /api/auth/login
router.post('/login', loginLimiter, validateBody(loginSchema), async (req, res, next) => {
  try {
    const { identifier, password } = req.validated;

    const { rows } = await query(
      `SELECT id, username, email, password_hash, role, must_change_password, is_blocked,
              xp, level, failed_login_count, locked_until
       FROM users WHERE username = $1 OR email = $1`,
      [identifier],
    );

    // Constant-shape response whether or not the user exists, to avoid
    // user enumeration. We still run a dummy hash verify to keep timing
    // roughly consistent.
    if (rows.length === 0) {
      await argon2.hash('dummy-password-to-equalize-timing', ARGON2_OPTS);
      logSecurityEvent({ eventType: 'login_failed', req, details: { reason: 'unknown_identifier', identifier } });
      return res.status(401).json({ error: 'Nieprawidłowy login/e-mail lub hasło.' });
    }

    const user = rows[0];

    if (user.is_blocked) {
      logSecurityEvent({ eventType: 'login_failed', req, actorId: user.id, actorUsername: user.username, details: { reason: 'blocked' } });
      return res.status(403).json({ error: 'Konto zostało zablokowane. Skontaktuj się z administratorem.' });
    }

    if (user.locked_until && new Date(user.locked_until) > new Date()) {
      logSecurityEvent({ eventType: 'login_failed', req, actorId: user.id, actorUsername: user.username, details: { reason: 'locked' } });
      return res.status(423).json({ error: 'Konto tymczasowo zablokowane z powodu zbyt wielu nieudanych prób logowania.' });
    }

    const valid = await argon2.verify(user.password_hash, password);

    if (!valid) {
      const failedCount = user.failed_login_count + 1;
      const shouldLock = failedCount >= MAX_FAILED_ATTEMPTS;
      await query(
        `UPDATE users SET failed_login_count = $1, locked_until = $2 WHERE id = $3`,
        [shouldLock ? 0 : failedCount, shouldLock ? new Date(Date.now() + LOCK_DURATION_MS) : null, user.id],
      );
      logSecurityEvent({
        eventType: shouldLock ? 'account_locked' : 'login_failed',
        req,
        actorId: user.id,
        actorUsername: user.username,
        details: { failedCount },
      });
      return res.status(401).json({ error: 'Nieprawidłowy login/e-mail lub hasło.' });
    }

    // Success: reset failed-attempt counter.
    await query('UPDATE users SET failed_login_count = 0, locked_until = NULL WHERE id = $1', [user.id]);

    req.session.regenerate((err) => {
      if (err) return next(err);
      req.session.userId = user.id;
      logSecurityEvent({ eventType: 'login_success', req, actorId: user.id, actorUsername: user.username });
      res.json({ user: publicUser(user) });
    });
  } catch (err) {
    next(err);
  }
});

// POST /api/auth/logout — kills current session only.
router.post('/logout', requireAuth, (req, res, next) => {
  const { id, username } = req.user;
  req.session.destroy((err) => {
    if (err) return next(err);
    res.clearCookie(req.app.get('sessionCookieName'));
    logSecurityEvent({ eventType: 'logout', req, actorId: id, actorUsername: username });
    res.json({ ok: true });
  });
});

// POST /api/auth/logout-all — invalidate every session belonging to the user
// by clearing session store rows referencing this userId. Requires storing
// sessions in Postgres (connect-pg-simple), which we do.
router.post('/logout-all', requireAuth, async (req, res, next) => {
  try {
    await query(
      `DELETE FROM session WHERE (sess->>'userId') = $1`,
      [req.user.id],
    );
    logSecurityEvent({ eventType: 'logout_all', req, actorId: req.user.id, actorUsername: req.user.username });
    res.clearCookie(req.app.get('sessionCookieName'));
    res.json({ ok: true });
  } catch (err) {
    next(err);
  }
});

// POST /api/auth/change-password
router.post('/change-password', requireAuth, validateBody(changePasswordSchema), async (req, res, next) => {
  try {
    const { currentPassword, newPassword } = req.validated;
    const { rows } = await query('SELECT password_hash FROM users WHERE id = $1', [req.user.id]);
    const valid = await argon2.verify(rows[0].password_hash, currentPassword);
    if (!valid) {
      logSecurityEvent({ eventType: 'password_change_failed', req, actorId: req.user.id, actorUsername: req.user.username });
      return res.status(401).json({ error: 'Aktualne hasło jest nieprawidłowe.' });
    }
    const hash = await argon2.hash(newPassword, ARGON2_OPTS);
    await query(
      'UPDATE users SET password_hash = $1, must_change_password = FALSE, updated_at = now() WHERE id = $2',
      [hash, req.user.id],
    );
    logSecurityEvent({ eventType: 'password_changed', req, actorId: req.user.id, actorUsername: req.user.username });
    res.json({ ok: true });
  } catch (err) {
    next(err);
  }
});

module.exports = router;
