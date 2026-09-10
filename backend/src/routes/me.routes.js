const express = require('express');
const { query } = require('../config/db');
const { requireAuth } = require('../middleware/auth');
const { requirePermission } = require('../middleware/permissions');

const router = express.Router();

// GET /api/me
router.get('/', requireAuth, async (req, res, next) => {
  try {
    const { rows: permRows } = req.user.role === 'employee'
      ? await query('SELECT permission FROM user_permissions WHERE user_id = $1', [req.user.id])
      : { rows: [] };

    res.json({
      user: {
        id: req.user.id,
        username: req.user.username,
        email: req.user.email,
        role: req.user.role,
        xp: req.user.xp,
        level: req.user.level,
        mustChangePassword: req.user.must_change_password,
        permissions: req.user.role === 'admin' ? 'all' : permRows.map((r) => r.permission),
      },
    });
  } catch (err) {
    next(err);
  }
});

// GET /api/me/dashboard — poziom, XP, postęp, ostatnie aktywności, moduły w toku
router.get('/dashboard', requireAuth, async (req, res, next) => {
  try {
    const userId = req.user.id;

    const [inProgress, recentTests, recentLabs, activeContests, badges, rank] = await Promise.all([
      query(
        `SELECT m.id, m.title, m.difficulty, ump.status, ump.started_at
         FROM user_module_progress ump JOIN modules m ON m.id = ump.module_id
         WHERE ump.user_id = $1 ORDER BY ump.started_at DESC LIMIT 5`,
        [userId],
      ),
      query(
        `SELECT ta.id, t.title, ta.score_points, ta.max_points, ta.xp_awarded, ta.submitted_at
         FROM test_attempts ta JOIN tests t ON t.id = ta.test_id
         WHERE ta.user_id = $1 ORDER BY ta.submitted_at DESC LIMIT 5`,
        [userId],
      ),
      query(
        `SELECT ls.id, l.title, ls.is_correct, ls.xp_awarded, ls.submitted_at
         FROM lab_submissions ls JOIN labs l ON l.id = ls.lab_id
         WHERE ls.user_id = $1 ORDER BY ls.submitted_at DESC LIMIT 5`,
        [userId],
      ),
      query(
        `SELECT id, title, description, starts_at, ends_at FROM contests
         WHERE is_published = TRUE AND now() BETWEEN starts_at AND ends_at
         ORDER BY ends_at ASC LIMIT 5`,
      ),
      query(
        `SELECT b.code, b.title, b.icon, ub.awarded_at
         FROM user_badges ub JOIN badges b ON b.id = ub.badge_id
         WHERE ub.user_id = $1 ORDER BY ub.awarded_at DESC`,
        [userId],
      ),
      query(
        `SELECT rank FROM (
           SELECT id, RANK() OVER (ORDER BY xp DESC) AS rank FROM users WHERE role = 'user'
         ) ranked WHERE id = $1`,
        [userId],
      ),
    ]);

    res.json({
      xp: req.user.xp,
      level: req.user.level,
      rank: rank.rows[0] ? rank.rows[0].rank : null,
      modulesInProgress: inProgress.rows,
      recentTests: recentTests.rows,
      recentLabs: recentLabs.rows,
      activeContests: activeContests.rows,
      badges: badges.rows,
    });
  } catch (err) {
    next(err);
  }
});

module.exports = router;
