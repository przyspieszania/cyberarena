const rateLimit = require('express-rate-limit');
const env = require('../config/env');
const { logSecurityEvent } = require('../utils/audit');

/**
 * Rate limiting po adresie IP + (dla logowania) po nazwie użytkownika, żeby
 * ograniczyć zarówno brute-force z jednego IP jak i rozproszony brute-force
 * na jedno konto (credential stuffing).
 */
const loginLimiter = rateLimit({
  windowMs: env.loginRateLimitWindowMs,
  max: env.loginRateLimitMax,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => `${req.ip}:${(req.body && req.body.identifier) || ''}`,
  handler: (req, res) => {
    logSecurityEvent({
      eventType: 'rate_limit_exceeded',
      req,
      details: { scope: 'login', identifier: req.body && req.body.identifier },
    });
    res.status(429).json({ error: 'Zbyt wiele prób logowania. Spróbuj ponownie później.' });
  },
});

const apiLimiter = rateLimit({
  windowMs: env.apiRateLimitWindowMs,
  max: env.apiRateLimitMax,
  standardHeaders: true,
  legacyHeaders: false,
  handler: (req, res) => {
    res.status(429).json({ error: 'Zbyt wiele żądań. Zwolnij tempo.' });
  },
});

const registerLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  handler: (req, res) => {
    res.status(429).json({ error: 'Zbyt wiele rejestracji z tego adresu. Spróbuj później.' });
  },
});

module.exports = { loginLimiter, apiLimiter, registerLimiter };
