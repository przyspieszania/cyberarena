const express = require('express');
const { query } = require('../config/db');
const { requireAuth } = require('../middleware/auth');

const router = express.Router();

// GET /api/ranking — top users by XP
router.get('/', requireAuth, async (req, res, next) => {
  try {
    const { rows } = await query(
      `SELECT username, xp, level, RANK() OVER (ORDER BY xp DESC) AS rank
       FROM users WHERE role = 'user' ORDER BY xp DESC LIMIT 100`,
    );
    res.json({ ranking: rows });
  } catch (err) {
    next(err);
  }
});

module.exports = router;
