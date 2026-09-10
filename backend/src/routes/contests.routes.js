const express = require('express');
const argon2 = require('argon2');
const { z } = require('zod');
const { query, withTransaction } = require('../config/db');
const { requireAuth } = require('../middleware/auth');
const { requirePermission } = require('../middleware/permissions');
const { validateBody } = require('../utils/validate');
const { logSecurityEvent } = require('../utils/audit');

const router = express.Router();

const contestSchema = z.object({
  title: z.string().trim().min(3).max(160),
  description: z.string().max(5000).default(''),
  startsAt: z.string().datetime(),
  endsAt: z.string().datetime(),
  isPublished: z.boolean().default(false),
  tasks: z.array(z.object({
    title: z.string().trim().min(1).max(160),
    description: z.string().max(5000).default(''),
    flag: z.string().trim().min(3).max(200),
    points: z.number().int().min(1).max(10000).default(100),
  })).min(1).max(100),
}).refine((d) => new Date(d.endsAt) > new Date(d.startsAt), {
  message: 'Data zakończenia musi być późniejsza niż data rozpoczęcia.',
  path: ['endsAt'],
});

const flagSubmitSchema = z.object({ flag: z.string().trim().min(1).max(500) });

// GET /api/contests
router.get('/', requireAuth, async (req, res, next) => {
  try {
    const canManage = req.user.role === 'admin' || req.user.role === 'employee';
    const { rows } = await query(
      `SELECT id, title, description, starts_at, ends_at, is_published FROM contests
       ${canManage ? '' : 'WHERE is_published = TRUE'} ORDER BY starts_at DESC`,
    );
    res.json({ contests: rows });
  } catch (err) {
    next(err);
  }
});

// GET /api/contests/:id — tasks without flag_hash, plus user's own score + live ranking.
router.get('/:id', requireAuth, async (req, res, next) => {
  try {
    const { rows: contestRows } = await query('SELECT * FROM contests WHERE id = $1', [req.params.id]);
    if (contestRows.length === 0) return res.status(404).json({ error: 'Konkurs nie istnieje.' });
    const contest = contestRows[0];
    const canManage = req.user.role === 'admin' || req.user.role === 'employee';
    if (!contest.is_published && !canManage) return res.status(404).json({ error: 'Konkurs nie istnieje.' });

    const { rows: tasks } = await query(
      'SELECT id, title, description, points, position FROM contest_tasks WHERE contest_id = $1 ORDER BY position',
      [req.params.id],
    );
    const { rows: solvedRows } = await query(
      `SELECT contest_task_id FROM contest_submissions
       WHERE user_id = $1 AND is_correct = TRUE AND contest_task_id = ANY($2::uuid[])`,
      [req.user.id, tasks.map((t) => t.id)],
    );
    const solvedSet = new Set(solvedRows.map((r) => r.contest_task_id));

    const { rows: ranking } = await query(
      `SELECT u.username, COALESCE(SUM(cs.points_awarded), 0) AS points
       FROM users u
       JOIN contest_tasks ct ON ct.contest_id = $1
       LEFT JOIN contest_submissions cs ON cs.contest_task_id = ct.id AND cs.user_id = u.id AND cs.is_correct = TRUE
       WHERE u.role = 'user'
       GROUP BY u.id, u.username
       HAVING COALESCE(SUM(cs.points_awarded), 0) > 0
       ORDER BY points DESC LIMIT 20`,
      [req.params.id],
    );

    res.json({
      contest,
      tasks: tasks.map((t) => ({ ...t, solved: solvedSet.has(t.id) })),
      ranking,
    });
  } catch (err) {
    next(err);
  }
});

// POST /api/contests — create with tasks (requires contest.create)
router.post('/', requireAuth, requirePermission('contest.create'), validateBody(contestSchema), async (req, res, next) => {
  try {
    const d = req.validated;
    const result = await withTransaction(async (client) => {
      const { rows } = await client.query(
        `INSERT INTO contests (title, description, starts_at, ends_at, is_published, created_by)
         VALUES ($1, $2, $3, $4, $5, $6) RETURNING *`,
        [d.title, d.description, d.startsAt, d.endsAt, d.isPublished, req.user.id],
      );
      const contest = rows[0];
      for (let i = 0; i < d.tasks.length; i += 1) {
        const t = d.tasks[i];
        const flagHash = await argon2.hash(t.flag, { type: argon2.argon2id });
        await client.query(
          `INSERT INTO contest_tasks (contest_id, title, description, flag_hash, points, position)
           VALUES ($1, $2, $3, $4, $5, $6)`,
          [contest.id, t.title, t.description, flagHash, t.points, i],
        );
      }
      return contest;
    });
    logSecurityEvent({ eventType: 'contest_created', req, actorId: req.user.id, actorUsername: req.user.username, targetId: result.id });
    res.status(201).json({ contest: result });
  } catch (err) {
    next(err);
  }
});

// DELETE /api/contests/:id (requires contest.delete)
router.delete('/:id', requireAuth, requirePermission('contest.delete'), async (req, res, next) => {
  try {
    const { rowCount } = await query('DELETE FROM contests WHERE id = $1', [req.params.id]);
    if (rowCount === 0) return res.status(404).json({ error: 'Konkurs nie istnieje.' });
    logSecurityEvent({ eventType: 'content_deleted', req, actorId: req.user.id, actorUsername: req.user.username, targetId: req.params.id, details: { type: 'contest' } });
    res.json({ ok: true });
  } catch (err) {
    next(err);
  }
});

// POST /api/contests/tasks/:taskId/submit — flag check, points only within the contest window.
router.post('/tasks/:taskId/submit', requireAuth, validateBody(flagSubmitSchema), async (req, res, next) => {
  try {
    const { flag } = req.validated;

    const result = await withTransaction(async (client) => {
      const { rows: taskRows } = await client.query(
        `SELECT ct.id, ct.flag_hash, ct.points, c.starts_at, c.ends_at, c.is_published
         FROM contest_tasks ct JOIN contests c ON c.id = ct.contest_id
         WHERE ct.id = $1`,
        [req.params.taskId],
      );
      if (taskRows.length === 0) return { notFound: true };
      const task = taskRows[0];
      const now = new Date();
      if (!task.is_published || now < new Date(task.starts_at) || now > new Date(task.ends_at)) {
        return { outOfWindow: true };
      }

      const { rows: already } = await client.query(
        'SELECT 1 FROM contest_submissions WHERE contest_task_id = $1 AND user_id = $2 AND is_correct = TRUE LIMIT 1',
        [req.params.taskId, req.user.id],
      );

      const isCorrect = await argon2.verify(task.flag_hash, flag);
      const pointsAwarded = isCorrect && already.length === 0 ? task.points : 0;

      await client.query(
        `INSERT INTO contest_submissions (contest_task_id, user_id, is_correct, points_awarded)
         VALUES ($1, $2, $3, $4)`,
        [req.params.taskId, req.user.id, isCorrect, pointsAwarded],
      );

      return { correct: isCorrect, alreadySolved: already.length > 0, pointsAwarded };
    });

    if (result.notFound) return res.status(404).json({ error: 'Zadanie nie istnieje.' });
    if (result.outOfWindow) return res.status(403).json({ error: 'Konkurs nie jest aktualnie aktywny.' });
    res.json(result);
  } catch (err) {
    next(err);
  }
});

module.exports = router;
