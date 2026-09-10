const express = require('express');
const argon2 = require('argon2');
const { z } = require('zod');
const { query } = require('../config/db');
const { requireAuth, requireRole } = require('../middleware/auth');
const { requirePermission, ALL_PERMISSIONS } = require('../middleware/permissions');
const { validateBody } = require('../utils/validate');
const { logSecurityEvent } = require('../utils/audit');

const router = express.Router();
const ARGON2_OPTS = { type: argon2.argon2id, memoryCost: 19456, timeCost: 2, parallelism: 1 };

// ---------- DASHBOARD ----------

// GET /api/admin/dashboard — requires at least employee role; counts only, no PII.
router.get('/dashboard', requireAuth, requireRole('admin', 'employee'), async (req, res, next) => {
  try {
    const [users, employees, modules, tests, labs, contests, activeUsers] = await Promise.all([
      query("SELECT COUNT(*) FROM users WHERE role = 'user'"),
      query("SELECT COUNT(*) FROM users WHERE role = 'employee'"),
      query('SELECT COUNT(*) FROM modules'),
      query('SELECT COUNT(*) FROM tests'),
      query('SELECT COUNT(*) FROM labs'),
      query('SELECT COUNT(*) FROM contests'),
      query("SELECT COUNT(*) FROM users WHERE role = 'user' AND updated_at > now() - interval '7 days'"),
    ]);
    res.json({
      users: parseInt(users.rows[0].count, 10),
      employees: parseInt(employees.rows[0].count, 10),
      modules: parseInt(modules.rows[0].count, 10),
      tests: parseInt(tests.rows[0].count, 10),
      labs: parseInt(labs.rows[0].count, 10),
      contests: parseInt(contests.rows[0].count, 10),
      activeUsersLast7Days: parseInt(activeUsers.rows[0].count, 10),
    });
  } catch (err) {
    next(err);
  }
});

// ---------- USERS ----------

// GET /api/admin/users (requires user.view)
router.get('/users', requireAuth, requirePermission('user.view'), async (req, res, next) => {
  try {
    const { rows } = await query(
      `SELECT id, username, email, role, is_blocked, xp, level, created_at
       FROM users WHERE role = 'user' ORDER BY created_at DESC`,
    );
    res.json({ users: rows });
  } catch (err) {
    next(err);
  }
});

const blockSchema = z.object({ blocked: z.boolean() });

// PUT /api/admin/users/:id/block (requires user.block)
router.put('/users/:id/block', requireAuth, requirePermission('user.block'), validateBody(blockSchema), async (req, res, next) => {
  try {
    if (req.params.id === req.user.id) {
      return res.status(400).json({ error: 'Nie możesz zablokować własnego konta.' });
    }
    const { rows } = await query(
      "UPDATE users SET is_blocked = $1 WHERE id = $2 AND role = 'user' RETURNING id, username, is_blocked",
      [req.validated.blocked, req.params.id],
    );
    if (rows.length === 0) return res.status(404).json({ error: 'Użytkownik nie istnieje.' });
    // Blocking should also kill any live sessions immediately.
    if (req.validated.blocked) {
      await query(`DELETE FROM session WHERE (sess->>'userId') = $1`, [req.params.id]);
    }
    logSecurityEvent({
      eventType: req.validated.blocked ? 'user_blocked' : 'user_unblocked',
      req, actorId: req.user.id, actorUsername: req.user.username, targetId: req.params.id,
    });
    res.json({ user: rows[0] });
  } catch (err) {
    next(err);
  }
});

const resetPasswordSchema = z.object({ temporaryPassword: z.string().min(10).max(256) });

// POST /api/admin/users/:id/reset-password (requires user.edit) — admin only sets a temp password; forces change on next login.
router.post('/users/:id/reset-password', requireAuth, requirePermission('user.edit'), validateBody(resetPasswordSchema), async (req, res, next) => {
  try {
    const hash = await argon2.hash(req.validated.temporaryPassword, ARGON2_OPTS);
    const { rows } = await query(
      `UPDATE users SET password_hash = $1, must_change_password = TRUE, updated_at = now()
       WHERE id = $2 RETURNING id, username`,
      [hash, req.params.id],
    );
    if (rows.length === 0) return res.status(404).json({ error: 'Użytkownik nie istnieje.' });
    await query(`DELETE FROM session WHERE (sess->>'userId') = $1`, [req.params.id]);
    logSecurityEvent({ eventType: 'password_reset_by_admin', req, actorId: req.user.id, actorUsername: req.user.username, targetId: req.params.id });
    res.json({ ok: true });
  } catch (err) {
    next(err);
  }
});

// ---------- EMPLOYEES (admin only — role/permission changes are never delegated) ----------

const createEmployeeSchema = z.object({
  username: z.string().trim().min(3).max(32).regex(/^[a-zA-Z0-9_.-]+$/),
  email: z.string().trim().email().max(255),
  temporaryPassword: z.string().min(10).max(256),
  permissions: z.array(z.enum(ALL_PERMISSIONS)).default([]),
});

// GET /api/admin/employees (admin only)
router.get('/employees', requireAuth, requireRole('admin'), async (req, res, next) => {
  try {
    const { rows } = await query(
      `SELECT u.id, u.username, u.email, u.is_blocked, u.created_at,
              COALESCE(array_agg(up.permission) FILTER (WHERE up.permission IS NOT NULL), '{}') AS permissions
       FROM users u LEFT JOIN user_permissions up ON up.user_id = u.id
       WHERE u.role = 'employee' GROUP BY u.id ORDER BY u.created_at DESC`,
    );
    res.json({ employees: rows });
  } catch (err) {
    next(err);
  }
});

// POST /api/admin/employees (admin only) — creates employee + grants permissions atomically.
router.post('/employees', requireAuth, requireRole('admin'), validateBody(createEmployeeSchema), async (req, res, next) => {
  try {
    const d = req.validated;
    const { rows: clashes } = await query('SELECT 1 FROM users WHERE username = $1 OR email = $2', [d.username, d.email]);
    if (clashes.length > 0) return res.status(409).json({ error: 'Login lub e-mail już zajęty.' });

    const hash = await argon2.hash(d.temporaryPassword, ARGON2_OPTS);
    const { rows } = await query(
      `INSERT INTO users (username, email, password_hash, role, must_change_password)
       VALUES ($1, $2, $3, 'employee', TRUE) RETURNING id, username, email`,
      [d.username, d.email, hash],
    );
    const employee = rows[0];
    for (const perm of d.permissions) {
      await query(
        'INSERT INTO user_permissions (user_id, permission, granted_by) VALUES ($1, $2, $3)',
        [employee.id, perm, req.user.id],
      );
    }
    logSecurityEvent({ eventType: 'employee_created', req, actorId: req.user.id, actorUsername: req.user.username, targetId: employee.id, details: { permissions: d.permissions } });
    res.status(201).json({ employee });
  } catch (err) {
    next(err);
  }
});

const updatePermissionsSchema = z.object({ permissions: z.array(z.enum(ALL_PERMISSIONS)) });

// PUT /api/admin/employees/:id/permissions (admin only)
router.put('/employees/:id/permissions', requireAuth, requireRole('admin'), validateBody(updatePermissionsSchema), async (req, res, next) => {
  try {
    const { rows: empRows } = await query("SELECT id FROM users WHERE id = $1 AND role = 'employee'", [req.params.id]);
    if (empRows.length === 0) return res.status(404).json({ error: 'Pracownik nie istnieje.' });

    await query('DELETE FROM user_permissions WHERE user_id = $1', [req.params.id]);
    for (const perm of req.validated.permissions) {
      await query(
        'INSERT INTO user_permissions (user_id, permission, granted_by) VALUES ($1, $2, $3)',
        [req.params.id, perm, req.user.id],
      );
    }
    logSecurityEvent({
      eventType: 'permission_changed', req, actorId: req.user.id, actorUsername: req.user.username,
      targetId: req.params.id, details: { permissions: req.validated.permissions },
    });
    res.json({ ok: true, permissions: req.validated.permissions });
  } catch (err) {
    next(err);
  }
});

const blockEmployeeSchema = z.object({ blocked: z.boolean() });

// PUT /api/admin/employees/:id/block (admin only)
router.put('/employees/:id/block', requireAuth, requireRole('admin'), validateBody(blockEmployeeSchema), async (req, res, next) => {
  try {
    if (req.params.id === req.user.id) {
      return res.status(400).json({ error: 'Nie możesz zablokować własnego konta.' });
    }
    const { rows } = await query(
      "UPDATE users SET is_blocked = $1 WHERE id = $2 AND role = 'employee' RETURNING id, username, is_blocked",
      [req.validated.blocked, req.params.id],
    );
    if (rows.length === 0) return res.status(404).json({ error: 'Pracownik nie istnieje.' });
    if (req.validated.blocked) {
      await query(`DELETE FROM session WHERE (sess->>'userId') = $1`, [req.params.id]);
    }
    logSecurityEvent({
      eventType: req.validated.blocked ? 'user_blocked' : 'user_unblocked',
      req, actorId: req.user.id, actorUsername: req.user.username, targetId: req.params.id,
    });
    res.json({ user: rows[0] });
  } catch (err) {
    next(err);
  }
});

// DELETE /api/admin/employees/:id (admin only) — cannot delete self, cannot delete other admins.
router.delete('/employees/:id', requireAuth, requireRole('admin'), async (req, res, next) => {
  try {
    if (req.params.id === req.user.id) {
      return res.status(400).json({ error: 'Nie możesz usunąć własnego konta.' });
    }
    const { rowCount } = await query("DELETE FROM users WHERE id = $1 AND role = 'employee'", [req.params.id]);
    if (rowCount === 0) return res.status(404).json({ error: 'Pracownik nie istnieje.' });
    logSecurityEvent({ eventType: 'employee_deleted', req, actorId: req.user.id, actorUsername: req.user.username, targetId: req.params.id });
    res.json({ ok: true });
  } catch (err) {
    next(err);
  }
});

// ---------- SECURITY LOGS (admin only) ----------

router.get('/security-logs', requireAuth, requireRole('admin'), async (req, res, next) => {
  try {
    const limit = Math.min(parseInt(req.query.limit, 10) || 100, 500);
    const { rows } = await query(
      `SELECT id, event_type, actor_username, target_id, ip_address, details, created_at
       FROM security_logs ORDER BY created_at DESC LIMIT $1`,
      [limit],
    );
    res.json({ logs: rows });
  } catch (err) {
    next(err);
  }
});

// ---------- SETTINGS ----------

router.get('/settings', requireAuth, requirePermission('settings.manage'), async (req, res, next) => {
  try {
    const { rows } = await query('SELECT key, value, updated_at FROM settings ORDER BY key');
    res.json({ settings: rows });
  } catch (err) {
    next(err);
  }
});

const updateSettingSchema = z.object({ value: z.any() });

router.put('/settings/:key', requireAuth, requirePermission('settings.manage'), validateBody(updateSettingSchema), async (req, res, next) => {
  try {
    const { rows } = await query(
      `UPDATE settings SET value = $1, updated_at = now() WHERE key = $2 RETURNING key, value, updated_at`,
      [JSON.stringify(req.validated.value), req.params.key],
    );
    if (rows.length === 0) return res.status(404).json({ error: 'Ustawienie nie istnieje.' });
    logSecurityEvent({ eventType: 'settings_changed', req, actorId: req.user.id, actorUsername: req.user.username, details: { key: req.params.key } });
    res.json({ setting: rows[0] });
  } catch (err) {
    next(err);
  }
});

module.exports = router;
