const { Pool } = require('pg');
const env = require('./env');

const pool = new Pool({
  connectionString: env.databaseUrl,
  ssl: env.pgSsl ? { rejectUnauthorized: true } : false,
  max: 20,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 5000,
});

pool.on('error', (err) => {
  // Never crash the process on an idle client error — log and keep serving.
  console.error('[db] Unexpected error on idle PostgreSQL client', err);
});

/**
 * Always use parameterized queries ($1, $2, ...) — never string-concatenate
 * user input into SQL. This is the primary SQL-injection defense.
 */
async function query(text, params) {
  return pool.query(text, params);
}

/**
 * Run a set of queries inside a transaction with a single client.
 * fn receives a client with the same query(text, params) signature.
 */
async function withTransaction(fn) {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const result = await fn(client);
    await client.query('COMMIT');
    return result;
  } catch (err) {
    await client.query('ROLLBACK');
    throw err;
  } finally {
    client.release();
  }
}

module.exports = { pool, query, withTransaction };
