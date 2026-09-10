const app = require('./app');
const env = require('./config/env');

const server = app.listen(env.port, () => {
  console.log(`[server] CyberArena backend nasłuchuje na porcie ${env.port} (${env.nodeEnv})`);
});

function shutdown(signal) {
  console.log(`[server] Otrzymano ${signal}, zamykanie...`);
  server.close(() => process.exit(0));
  setTimeout(() => process.exit(1), 10000).unref();
}

process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));
