/* eslint-disable no-console */
const argon2 = require('argon2');
const { pool, query } = require('../src/config/db');
const env = require('../src/config/env');

const ARGON2_OPTS = { type: argon2.argon2id, memoryCost: 19456, timeCost: 2, parallelism: 1 };

async function main() {
  const { rows: existing } = await query('SELECT id FROM users WHERE username = $1', [env.adminUsername]);

  if (existing.length > 0) {
    console.log(`[seed] Konto administratora "${env.adminUsername}" już istnieje — pomijam.`);
  } else {
    if (env.nodeEnv === 'production' && env.adminInitialPassword === 'admin') {
      console.warn('[seed] UWAGA: seedujesz produkcję z domyślnym hasłem "admin". '
        + 'Zostanie ono wymuszone do zmiany przy pierwszym logowaniu, ale rozważ ustawienie '
        + 'ADMIN_INITIAL_PASSWORD na coś losowego przed pierwszym uruchomieniem.');
    }
    const hash = await argon2.hash(env.adminInitialPassword, ARGON2_OPTS);
    await query(
      `INSERT INTO users (username, email, password_hash, role, must_change_password)
       VALUES ($1, $2, $3, 'admin', TRUE)`,
      [env.adminUsername, env.adminEmail, hash],
    );
    console.log(`[seed] Utworzono konto administratora "${env.adminUsername}". `
      + 'Hasło musi zostać zmienione przy pierwszym logowaniu.');
  }

  const badges = [
    ['first_steps', 'Pierwsze kroki', 'Ukończ swój pierwszy moduł.', 'footprints'],
    ['test_ace', 'As testów', 'Zdobądź 100% w dowolnym teście.', 'award'],
    ['lab_hunter', 'Łowca flag', 'Rozwiąż swój pierwszy lab.', 'flag'],
    ['contest_veteran', 'Weteran konkursów', 'Weź udział w 5 konkursach.', 'trophy'],
    ['top_three', 'Podium', 'Zajmij miejsce w TOP 3 rankingu.', 'medal'],
  ];
  for (const [code, title, description, icon] of badges) {
    await query(
      `INSERT INTO badges (code, title, description, icon) VALUES ($1, $2, $3, $4)
       ON CONFLICT (code) DO NOTHING`,
      [code, title, description, icon],
    );
  }
  console.log('[seed] Odznaki startowe gotowe.');

  await pool.end();
}

main().catch((err) => {
  console.error('[seed] failed:', err);
  process.exit(1);
});
