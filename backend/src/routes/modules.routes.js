const express = require('express');
const { z } = require('zod');
const { query, withTransaction } = require('../config/db');
const { requireAuth } = require('../middleware/auth');
const { requirePermission } = require('../middleware/permissions');
const { validateBody } = require('../utils/validate');
const { logSecurityEvent } = require('../utils/audit');
const { awardXp } = require('../utils/xp');

const router = express.Router();

const moduleSchema = z.object({
  title: z.string().trim().min(3).max(160),
  description: z.string().max(5000).default(''),
  difficulty: z.enum(['beginner', 'intermediate', 'advanced']).default('beginner'),
  imageUrl: z.string().url().max(1000).optional().nullable(),
  xpReward: z.number().int().min(0).max(10000).default(50),
  isPublished: z.boolean().default(false),
  lessons: z.array(z.object({
    title: z.string().trim().min(1).max(160),
    contentMd: z.string().max(20000).default(''),
  })).max(100).default([]),
});

// GET /api/modules — list. Regular users see only published modules.
router.get('/', requireAuth, async (req, res, next) => {
  try {
    const canSeeUnpublished = req.user.role === 'admin' || req.user.role === 'employee';
    const { rows } = await query(
      `SELECT id, title, description, difficulty, image_url, xp_reward, is_published, created_at
       FROM modules ${canSeeUnpublished ? '' : 'WHERE is_published = TRUE'}
       ORDER BY created_at DESC`,
    );
    res.json({ modules: rows });
  } catch (err) {
    next(err);
  }
});

// GET /api/modules/:id — detail including lessons + user's progress status.
router.get('/:id', requireAuth, async (req, res, next) => {
  try {
    const { rows: modRows } = await query('SELECT * FROM modules WHERE id = $1', [req.params.id]);
    if (modRows.length === 0) return res.status(404).json({ error: 'Moduł nie istnieje.' });
    const mod = modRows[0];

    const canSeeUnpublished = req.user.role === 'admin' || req.user.role === 'employee';
    if (!mod.is_published && !canSeeUnpublished) {
      return res.status(404).json({ error: 'Moduł nie istnieje.' });
    }

    const [{ rows: lessons }, { rows: progress }] = await Promise.all([
      query('SELECT id, title, content_md, position FROM lessons WHERE module_id = $1 ORDER BY position', [req.params.id]),
      query('SELECT status, started_at, completed_at FROM user_module_progress WHERE user_id = $1 AND module_id = $2', [req.user.id, req.params.id]),
    ]);

    res.json({ module: mod, lessons, progress: progress[0] || null });
  } catch (err) {
    next(err);
  }
});

// POST /api/modules — create (requires module.create)
router.post('/', requireAuth, requirePermission('module.create'), validateBody(moduleSchema), async (req, res, next) => {
  try {
    const d = req.validated;
    const result = await withTransaction(async (client) => {
      const { rows } = await client.query(
        `INSERT INTO modules (title, description, difficulty, image_url, xp_reward, is_published, created_by)
         VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING *`,
        [d.title, d.description, d.difficulty, d.imageUrl || null, d.xpReward, d.isPublished, req.user.id],
      );
      const mod = rows[0];
      for (let i = 0; i < d.lessons.length; i += 1) {
        await client.query(
          'INSERT INTO lessons (module_id, title, content_md, position) VALUES ($1, $2, $3, $4)',
          [mod.id, d.lessons[i].title, d.lessons[i].contentMd, i],
        );
      }
      return mod;
    });
    logSecurityEvent({ eventType: 'module_created', req, actorId: req.user.id, actorUsername: req.user.username, targetId: result.id });
    res.status(201).json({ module: result });
  } catch (err) {
    next(err);
  }
});

// PUT /api/modules/:id — edit (requires module.edit)
router.put('/:id', requireAuth, requirePermission('module.edit'), validateBody(moduleSchema), async (req, res, next) => {
  try {
    const d = req.validated;
    const { rows } = await query(
      `UPDATE modules SET title = $1, description = $2, difficulty = $3, image_url = $4,
              xp_reward = $5, is_published = $6, updated_at = now()
       WHERE id = $7 RETURNING *`,
      [d.title, d.description, d.difficulty, d.imageUrl || null, d.xpReward, d.isPublished, req.params.id],
    );
    if (rows.length === 0) return res.status(404).json({ error: 'Moduł nie istnieje.' });

    await withTransaction(async (client) => {
      await client.query('DELETE FROM lessons WHERE module_id = $1', [req.params.id]);
      for (let i = 0; i < d.lessons.length; i += 1) {
        await client.query(
          'INSERT INTO lessons (module_id, title, content_md, position) VALUES ($1, $2, $3, $4)',
          [req.params.id, d.lessons[i].title, d.lessons[i].contentMd, i],
        );
      }
    });

    logSecurityEvent({ eventType: 'module_edited', req, actorId: req.user.id, actorUsername: req.user.username, targetId: req.params.id });
    res.json({ module: rows[0] });
  } catch (err) {
    next(err);
  }
});

// DELETE /api/modules/:id (requires module.delete)
router.delete('/:id', requireAuth, requirePermission('module.delete'), async (req, res, next) => {
  try {
    const { rowCount } = await query('DELETE FROM modules WHERE id = $1', [req.params.id]);
    if (rowCount === 0) return res.status(404).json({ error: 'Moduł nie istnieje.' });
    logSecurityEvent({ eventType: 'content_deleted', req, actorId: req.user.id, actorUsername: req.user.username, targetId: req.params.id, details: { type: 'module' } });
    res.json({ ok: true });
  } catch (err) {
    next(err);
  }
});

// POST /api/modules/:id/complete — mark as completed, award XP once.
router.post('/:id/complete', requireAuth, async (req, res, next) => {
  try {
    const result = await withTransaction(async (client) => {
      const { rows: modRows } = await client.query('SELECT id, xp_reward, is_published FROM modules WHERE id = $1', [req.params.id]);
      if (modRows.length === 0 || !modRows[0].is_published) return null;

      const { rows: existing } = await client.query(
        'SELECT status FROM user_module_progress WHERE user_id = $1 AND module_id = $2',
        [req.user.id, req.params.id],
      );

      if (existing.length > 0 && existing[0].status === 'completed') {
        return { alreadyCompleted: true };
      }

      await client.query(
        `INSERT INTO user_module_progress (user_id, module_id, status, completed_at)
         VALUES ($1, $2, 'completed', now())
         ON CONFLICT (user_id, module_id) DO UPDATE SET status = 'completed', completed_at = now()`,
        [req.user.id, req.params.id],
      );
      const xpResult = await awardXp(req.user.id, modRows[0].xp_reward, client);
      return { alreadyCompleted: false, ...xpResult };
    });

    if (!result) return res.status(404).json({ error: 'Moduł nie istnieje lub nie jest opublikowany.' });
    res.json(result);
  } catch (err) {
    next(err);
  }
});

module.exports = router;
