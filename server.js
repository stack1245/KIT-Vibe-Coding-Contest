const { app, port } = require('./src/server/app');
const { closeDatabase } = require('./src/server/database');

const server = app.listen(port, () => {
  console.log(`server listening on http://localhost:${port}`);
});

let isShuttingDown = false;

function shutdown(signal) {
  if (isShuttingDown) {
    return;
  }

  isShuttingDown = true;

  server.close(() => {
    closeDatabase();

    if (signal) {
      console.log(`server stopped by ${signal}`);
    }
  });
}

process.once('SIGINT', () => shutdown('SIGINT'));
process.once('SIGTERM', () => shutdown('SIGTERM'));