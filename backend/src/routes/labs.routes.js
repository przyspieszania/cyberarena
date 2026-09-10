const express = require('express');
const argon2 = require('argon2');
const { z } = require('zod');
const { query, withTransaction } = require('../config/db');
const { requireAuth } = require('../middleware/auth');
const { requirePermission } = require('../middleware/permissions');
const { validateBody } = require('../utils/validate');
const { logSecurityEvent } = require('../utils/audit');
const { awardXp } = require('../utils/xp');

const router = express.Router();

const labSchema = z.object({
  title: z.string().trim().min(3).max(160),
  description: z.string().max(5000).default(''),
  instructionsMd: z.string().max(20000).default(''),
  difficulty: z.enum(['beginner', 'intermediate', 'advanced']).default('beginner'),
  flag: z.string().trim().min(3).max(200),
  xpReward: z.number().int().min(0).max(10000).default(150),
  isPublished: z.boolean().default(false),
});

const flagSubmitSchema = z.object({ flag: z.string().trim().min(1).max(500) });

// GET /api/labs
router.get('/', requireAuth, async (req, res, next) => {
  try {
    const canManage = req.user.role === 'admin' || req.user.role === 'employee';
    const { rows } = await query(
      `SELECT id, title, description, difficulty, xp_reward, is_published, created_at
       FROM labs ${canManage ? '' : 'WHERE is_published = TRUE'} ORDER BY created_at DESC`,
    );
    res.json({ labs: rows });
  } catch (err) {
    next(err);
  }
});

// GET /api/labs/:id — never expose flag_hash to the client.
router.get('/:id', requireAuth, async (req, res, next) => {
  try {
    const { rows } = await query(
      'SELECT id, title, description, instructions_md, difficulty, xp_reward, is_published, created_at FROM labs WHERE id = $1',
      [req.params.id],
    );
    if (rows.length === 0) return res.status(404).json({ error: 'Lab nie istnieje.' });
    const lab = rows[0];
    const canManage = req.user.role === 'admin' || req.user.role === 'employee';
    if (!lab.is_published && !canManage) return res.status(404).json({ error: 'Lab nie istnieje.' });

    const { rows: solved } = await query(
      'SELECT 1 FROM lab_submissions WHERE lab_id = $1 AND user_id = $2 AND is_correct = TRUE LIMIT 1',
      [req.params.id, req.user.id],
    );
    res.json({ lab, solved: solved.length > 0 });
  } catch (err) {
    next(err);
  }
});

// POST /api/labs — create (requires lab.create). Flag is hashed, never stored plaintext.
router.post('/', requireAuth, requirePermission('lab.create'), validateBody(labSchema), async (req, res, next) => {
  try {
    const d = req.validated;
    const flagHash = await argon2.hash(d.flag, { type: argon2.argon2id });
    const { rows } = await query(
      `INSERT INTO labs (title, description, instructions_md, difficulty, flag_hash, xp_reward, is_published, created_by)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
       RETURNING id, title, description, instructions_md, difficulty, xp_reward, is_published, created_at`,
      [d.title, d.description, d.instructionsMd, d.difficulty, flagHash, d.xpReward, d.isPublished, req.user.id],
    );
    logSecurityEvent({ eventType: 'lab_created', req, actorId: req.user.id, actorUsername: req.user.username, targetId: rows[0].id });
    res.status(201).json({ lab: rows[0] });
  } catch (err) {
    next(err);
  }
});

// DELETE /api/labs/:id (requires lab.delete)
router.delete('/:id', requireAuth, requirePermission('lab.delete'), async (req, res, next) => {
  try {
    const { rowCount } = await query('DELETE FROM labs WHERE id = $1', [req.params.id]);
    if (rowCount === 0) return res.status(404).json({ error: 'Lab nie istnieje.' });
    logSecurityEvent({ eventType: 'content_deleted', req, actorId: req.user.id, actorUsername: req.user.username, targetId: req.params.id, details: { type: 'lab' } });
    res.json({ ok: true });
  } catch (err) {
    next(err);
  }
});

// POST /api/labs/:id/submit — verify flag hash, award XP once per user.
router.post('/:id/submit', requireAuth, validateBody(flagSubmitSchema), async (req, res, next) => {
  try {
    const { flag } = req.validated;

    const result = await withTransaction(async (client) => {
      const { rows: labRows } = await client.query('SELECT id, flag_hash, xp_reward FROM labs WHERE id = $1 AND is_published = TRUE', [req.params.id]);
      if (labRows.length === 0) return null;
      const lab = labRows[0];

      const { rows: already } = await client.query(
        'SELECT 1 FROM lab_submissions WHERE lab_id = $1 AND user_id = $2 AND is_correct = TRUE LIMIT 1',
        [req.params.id, req.user.id],
      );

      const isCorrect = await argon2.verify(lab.flag_hash, flag);
      const xpAwarded = isCorrect && already.length === 0 ? lab.xp_reward : 0;

      await client.query(
        `INSERT INTO lab_submissions (lab_id, user_id, is_correct, xp_awarded) VALUES ($1, $2, $3, $4)`,
        [req.params.id, req.user.id, isCorrect, xpAwarded],
      );

      let xpResult = null;
      if (xpAwarded > 0) {
        xpResult = await awardXp(req.user.id, xpAwarded, client);
      }

      return { correct: isCorrect, alreadySolved: already.length > 0, xpResult };
    });

    if (!result) return res.status(404).json({ error: 'Lab nie istnieje lub nie jest opublikowany.' });
    res.json(result);
  } catch (err) {
    next(err);
  }
});

module.exports = router;
