const { query } = require('../config/db');

/**
 * Centralny zapis logów bezpieczeństwa. NIGDY nie przekazuj tu haseł,
 * tokenów sesji ani innych sekretów w polu `details`.
 */
async function logSecurityEvent({ eventType, req, actorId = null, actorUsername = null, targetId = null, details = {} }) {
  try {
    const ip = req ? (req.headers['x-forwarded-for'] || req.socket.remoteAddress) : null;
    const userAgent = req ? req.headers['user-agent'] : null;
    await query(
      `INSERT INTO security_logs (event_type, actor_id, actor_username, target_id, ip_address, user_agent, details)
       VALUES ($1, $2, $3, $4, $5, $6, $7)`,
      [eventType, actorId, actorUsername, targetId, ip, userAgent, JSON.stringify(details)],
    );
  } catch (err) {
    // Logging must never break the request path.
    console.error('[audit] failed to write security log:', err.message);
  }
}

module.exports = { logSecurityEvent };
