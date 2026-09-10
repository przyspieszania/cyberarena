const { query } = require('../config/db');

// Prosty próg poziomowy: poziom n wymaga n * 250 skumulowanego XP.
function levelForXp(xp) {
  let level = 1;
  while (xp >= level * 250) {
    level += 1;
  }
  return level;
}

async function awardXp(userId, amount, client = { query }) {
  if (amount <= 0) return null;
  const { rows } = await client.query(
    'UPDATE users SET xp = xp + $1, updated_at = now() WHERE id = $2 RETURNING xp',
    [amount, userId],
  );
  if (rows.length === 0) return null;
  const newXp = rows[0].xp;
  const newLevel = levelForXp(newXp);
  await client.query('UPDATE users SET level = $1 WHERE id = $2', [newLevel, userId]);
  return { xp: newXp, level: newLevel };
}

module.exports = { levelForXp, awardXp };
