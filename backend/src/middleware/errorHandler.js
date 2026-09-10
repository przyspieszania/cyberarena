const env = require('../config/env');

// eslint-disable-next-line no-unused-vars
function errorHandler(err, req, res, next) {
  console.error('[error]', err);

  if (err.type === 'validation') {
    return res.status(400).json({ error: err.message, details: err.details });
  }

  // Never leak stack traces or internal details to the client in production.
  const message = env.nodeEnv === 'production' ? 'Wystąpił błąd serwera.' : err.message;
  res.status(err.status || 500).json({ error: message });
}

function notFoundHandler(req, res) {
  res.status(404).json({ error: 'Nie znaleziono zasobu.' });
}

module.exports = { errorHandler, notFoundHandler };
