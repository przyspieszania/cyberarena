const { query } = require('../config/db');

const ALL_PERMISSIONS = [
  'module.create', 'module.edit', 'module.delete',
  'test.create', 'test.edit', 'test.delete',
  'lab.create', 'lab.edit', 'lab.delete',
  'contest.create', 'contest.edit', 'contest.delete',
  'user.view', 'user.edit', 'user.block',
  'employee.create', 'employee.edit',
  'settings.manage',
];

/**
 * requirePermission — admin zawsze przechodzi. Pracownik (employee) musi mieć
 * jawnie nadane uprawnienie w tabeli user_permissions. Zwykły user nigdy nie
 * przechodzi. Sprawdzenie odbywa się przy KAŻDYM żądaniu — nic nie jest
 * cache'owane po stronie klienta.
 */
function requirePermission(permission) {
  if (!ALL_PERMISSIONS.includes(permission)) {
    throw new Error(`Nieznane uprawnienie w kodzie: ${permission}`);
  }
  return async (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({ error: 'Wymagane logowanie.' });
    }
    if (req.user.role === 'admin') {
      return next();
    }
    if (req.user.role !== 'employee') {
      return res.status(403).json({ error: 'Brak uprawnień do tej operacji.' });
    }
    try {
      const { rows } = await query(
        'SELECT 1 FROM user_permissions WHERE user_id = $1 AND permission = $2',
        [req.user.id, permission],
      );
      if (rows.length === 0) {
        return res.status(403).json({ error: `Brak uprawnienia: ${permission}.` });
      }
      next();
    } catch (err) {
      next(err);
    }
  };
}

module.exports = { requirePermission, ALL_PERMISSIONS };
