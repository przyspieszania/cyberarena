/**
 * Wszystkie decyzje o tożsamości i roli opierają się WYŁĄCZNIE na danych
 * sesji po stronie serwera (req.session.userId), nigdy na nagłówkach czy
 * polach przesłanych przez klienta. Frontend nie może się "podszyć" pod
 * inną rolę — rola jest doczytywana z bazy przy każdym żądaniu.
 */
const { query } = require('../config/db');

async function attachUser(req, res, next) {
  if (!req.session || !req.session.userId) {
    req.user = null;
    return next();
  }
  try {
    const { rows } = await query(
      `SELECT id, username, email, role, must_change_password, is_blocked, xp, level
       FROM users WHERE id = $1`,
      [req.session.userId],
    );
    if (rows.length === 0 || rows[0].is_blocked) {
      req.session.destroy(() => {});
      req.user = null;
      return next();
    }
    req.user = rows[0];
    next();
  } catch (err) {
    next(err);
  }
}

function requireAuth(req, res, next) {
  if (!req.user) {
    return res.status(401).json({ error: 'Wymagane logowanie.' });
  }
  if (req.user.must_change_password && req.path !== '/api/auth/change-password') {
    return res.status(403).json({ error: 'Musisz zmienić hasło przed dalszym korzystaniem z platformy.', code: 'MUST_CHANGE_PASSWORD' });
  }
  next();
}

function requireRole(...roles) {
  return (req, res, next) => {
    if (!req.user || !roles.includes(req.user.role)) {
      return res.status(403).json({ error: 'Brak uprawnień do tej operacji.' });
    }
    next();
  };
}

module.exports = { attachUser, requireAuth, requireRole };
