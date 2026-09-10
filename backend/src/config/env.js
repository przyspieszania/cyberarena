const path = require('path');
require('dotenv').config({ path: path.join(__dirname, '..', '..', '.env') });

function required(name) {
  const value = process.env[name];
  if (!value || value.trim() === '') {
    throw new Error(`Brakująca zmienna środowiskowa: ${name}. Sprawdź plik .env (patrz .env.example).`);
  }
  return value;
}

// Fail fast in production if secrets look like placeholders/defaults.
function assertNotDefault(name, badValue) {
  const value = process.env[name];
  if (process.env.NODE_ENV === 'production' && value === badValue) {
    throw new Error(`Zmienna ${name} ma wartość domyślną/placeholder w środowisku produkcyjnym. Ustaw prawdziwy sekret.`);
  }
}

assertNotDefault('SESSION_SECRET', 'CHANGE_ME_TO_A_LONG_RANDOM_VALUE');

module.exports = {
  nodeEnv: process.env.NODE_ENV || 'development',
  port: parseInt(process.env.PORT || '4000', 10),
  databaseUrl: required('DATABASE_URL'),
  pgSsl: process.env.PGSSL === 'true',
  sessionSecret: required('SESSION_SECRET'),
  sessionCookieName: process.env.SESSION_COOKIE_NAME || 'cyberarena_sid',
  sessionMaxAgeMs: parseInt(process.env.SESSION_MAX_AGE_MS || '28800000', 10),
  frontendOrigin: process.env.FRONTEND_ORIGIN || 'http://localhost:5173',
  adminUsername: process.env.ADMIN_USERNAME || 'admin',
  adminInitialPassword: process.env.ADMIN_INITIAL_PASSWORD || 'admin',
  adminEmail: process.env.ADMIN_EMAIL || 'admin@cyberarena.local',
  loginRateLimitMax: parseInt(process.env.LOGIN_RATE_LIMIT_MAX || '5', 10),
  loginRateLimitWindowMs: parseInt(process.env.LOGIN_RATE_LIMIT_WINDOW_MS || '900000', 10),
  apiRateLimitMax: parseInt(process.env.API_RATE_LIMIT_MAX || '300', 10),
  apiRateLimitWindowMs: parseInt(process.env.API_RATE_LIMIT_WINDOW_MS || '60000', 10),
};
