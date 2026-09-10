const express = require('express');
const { z } = require('zod');
const { query, withTransaction } = require('../config/db');
const { requireAuth } = require('../middleware/auth');
const { requirePermission } = require('../middleware/permissions');
const { validateBody } = require('../utils/validate');
const { logSecurityEvent } = require('../utils/audit');
const { awardXp } = require('../utils/xp');

const router = express.Router();

const questionSchema = z.object({
  type: z.enum(['single_choice', 'multiple_choice', 'true_false', 'text']),
  prompt: z.string().trim().min(1).max(2000),
  options: z.array(z.object({ id: z.string().max(8), label: z.string().max(500) })).max(10).optional(),
  correctAnswer: z.any(),
  points: z.number().int().min(1).max(1000).default(10),
});

const testSchema = z.object({
  moduleId: z.string().uuid().optional().nullable(),
  title: z.string().trim().min(3).max(160),
  description: z.string().max(3000).default(''),
  xpReward: z.number().int().min(0).max(10000).default(100),
  isPublished: z.boolean().default(false),
  questions: z.array(questionSchema).min(1).max(200),
});

const attemptSchema = z.object({
  // { "<questionId>": answer }
  answers: z.record(z.string().uuid(), z.any()),
});

// GET /api/tests — list (published only for plain users)
router.get('/', requireAuth, async (req, res, next) => {
  try {
    const canSeeUnpublished = req.user.role === 'admin' || req.user.role === 'employee';
    const { rows } = await query(
      `SELECT id, module_id, title, description, xp_reward, is_published, created_at
       FROM tests ${canSeeUnpublished ? '' : 'WHERE is_published = TRUE'}
       ORDER BY created_at DESC`,
    );
    res.json({ tests: rows });
  } catch (err) {
    next(err);
  }
});

// GET /api/tests/:id — questions WITHOUT correct_answer for plain users.
router.get('/:id', requireAuth, async (req, res, next) => {
  try {
    const { rows: testRows } = await query('SELECT * FROM tests WHERE id = $1', [req.params.id]);
    if (testRows.length === 0) return res.status(404).json({ error: 'Test nie istnieje.' });
    const test = testRows[0];

    const canManage = req.user.role === 'admin' || req.user.role === 'employee';
    if (!test.is_published && !canManage) return res.status(404).json({ error: 'Test nie istnieje.' });

    const { rows: questions } = await query(
      'SELECT id, type, prompt, options, points, position FROM questions WHERE test_id = $1 ORDER BY position',
      [req.params.id],
    );
    res.json({ test, questions });
  } catch (err) {
    next(err);
  }
});

// POST /api/tests — create with questions (requires test.create)
router.post('/', requireAuth, requirePermission('test.create'), validateBody(testSchema), async (req, res, next) => {
  try {
    const d = req.validated;
    const result = await withTransaction(async (client) => {
      const { rows } = await client.query(
        `INSERT INTO tests (module_id, title, description, xp_reward, is_published, created_by)
         VALUES ($1, $2, $3, $4, $5, $6) RETURNING *`,
        [d.moduleId || null, d.title, d.description, d.xpReward, d.isPublished, req.user.id],
      );
      const test = rows[0];
      for (let i = 0; i < d.questions.length; i += 1) {
        const q = d.questions[i];
        await client.query(
          `INSERT INTO questions (test_id, type, prompt, options, correct_answer, points, position)
           VALUES ($1, $2, $3, $4, $5, $6, $7)`,
          [test.id, q.type, q.prompt, JSON.stringify(q.options || null), JSON.stringify(q.correctAnswer), q.points, i],
        );
      }
      return test;
    });
    logSecurityEvent({ eventType: 'test_created', req, actorId: req.user.id, actorUsername: req.user.username, targetId: result.id });
    res.status(201).json({ test: result });
  } catch (err) {
    next(err);
  }
});

// DELETE /api/tests/:id (requires test.delete)
router.delete('/:id', requireAuth, requirePermission('test.delete'), async (req, res, next) => {
  try {
    const { rowCount } = await query('DELETE FROM tests WHERE id = $1', [req.params.id]);
    if (rowCount === 0) return res.status(404).json({ error: 'Test nie istnieje.' });
    logSecurityEvent({ eventType: 'content_deleted', req, actorId: req.user.id, actorUsername: req.user.username, targetId: req.params.id, details: { type: 'test' } });
    res.json({ ok: true });
  } catch (err) {
    next(err);
  }
});

function isAnswerCorrect(question, submitted) {
  const correct = question.correct_answer;
  if (question.type === 'multiple_choice') {
    if (!Array.isArray(submitted)) return false;
    const a = [...submitted].sort();
    const b = [...correct].sort();
    return a.length === b.length && a.every((v, i) => v === b[i]);
  }
  if (question.type === 'text') {
    return typeof submitted === 'string'
      && submitted.trim().toLowerCase() === String(correct).trim().toLowerCase();
  }
  // single_choice, true_false
  return submitted === correct;
}

// POST /api/tests/:id/submit — SERVER-SIDE scoring only. Client never sends a score.
router.post('/:id/submit', requireAuth, validateBody(attemptSchema), async (req, res, next) => {
  try {
    const { answers } = req.validated;

    const result = await withTransaction(async (client) => {
      const { rows: testRows } = await client.query('SELECT * FROM tests WHERE id = $1 AND is_published = TRUE', [req.params.id]);
      if (testRows.length === 0) return null;
      const test = testRows[0];

      const { rows: questions } = await client.query('SELECT * FROM questions WHERE test_id = $1', [req.params.id]);

      let scorePoints = 0;
      let maxPoints = 0;
      let correctCount = 0;
      for (const q of questions) {
        maxPoints += q.points;
        const submitted = answers[q.id];
        if (submitted !== undefined && isAnswerCorrect(q, submitted)) {
          scorePoints += q.points;
          correctCount += 1;
        }
      }

      const passed = maxPoints > 0 && scorePoints / maxPoints >= 0.5;
      const xpAwarded = passed ? test.xp_reward : 0;

      const { rows: attemptRows } = await client.query(
        `INSERT INTO test_attempts (test_id, user_id, answers, score_points, max_points, correct_count, total_count, xp_awarded)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING *`,
        [req.params.id, req.user.id, JSON.stringify(answers), scorePoints, maxPoints, correctCount, questions.length, xpAwarded],
      );

      let xpResult = null;
      if (xpAwarded > 0) {
        xpResult = await awardXp(req.user.id, xpAwarded, client);
      }

      return { attempt: attemptRows[0], xpResult };
    });

    if (!result) return res.status(404).json({ error: 'Test nie istnieje lub nie jest opublikowany.' });
    res.json(result);
  } catch (err) {
    next(err);
  }
});

module.exports = router;
