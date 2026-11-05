require('dotenv').config();
const express = require('express');
const cors = require('cors');
const http = require('http');
const { WebSocketServer } = require('ws');

const apiRoutes = require('./routes/api');
const cicdRoutes = require('./routes/cicd');
const notificationRoutes = require('./routes/notifications');
const aiRoutes = require('./routes/ai');
const adminRoutes = require('./routes/admin');
const { init: initDb } = require('./db/store');
const { startThreatFeed } = require('./modules/threatFeed');

async function main() {
  await initDb();

  const app = express();
  app.set('trust proxy', 1);

  const allowedOrigins = process.env.FRONTEND_URL
    ? process.env.FRONTEND_URL.split(',').map((url) => url.trim())
    : '*';

  app.use(cors({ origin: '*', credentials: true }));

  // Mounted BEFORE global JSON parser for raw GitHub webhook signature verification
  app.use('/api/cicd', cicdRoutes);

  app.use(express.json({ limit: '5mb' }));

  app.get('/health', (req, res) =>
    res.status(200).json({ status: 'ok', service: 'securechain-backend', time: new Date().toISOString() })
  );

  app.use('/api', apiRoutes);
  app.use('/api', notificationRoutes);
  app.use('/api', aiRoutes);
  app.use('/api', adminRoutes);

  const server = http.createServer(app);
  const wss = new WebSocketServer({ server, path: '/ws/threat-feed' });

  wss.on('connection', (ws) => {
    ws.isAlive = true;
    ws.on('pong', () => { ws.isAlive = true; });
    ws.send(JSON.stringify({ type: 'CONNECTED', message: 'Live threat feed connected' }));
  });

  // 30s ping/pong heartbeat so Azure Load Balancer doesn't drop the socket after 240s
  const wsHeartbeat = setInterval(() => {
    wss.clients.forEach((ws) => {
      if (ws.isAlive === false) return ws.terminate();
      ws.isAlive = false;
      ws.ping();
    });
  }, 30000);

  wss.on('close', () => clearInterval(wsHeartbeat));

  startThreatFeed(wss);

  const port = Number(process.env.PORT) || 4000;
  server.listen(port, '0.0.0.0', () => {
    console.log(`SecureChain backend listening on http://0.0.0.0:${port}`);
    console.log(`WebSocket threat feed at /ws/threat-feed`);
  });

  process.on('SIGTERM', () => {
    clearInterval(wsHeartbeat);
    server.close(() => process.exit(0));
  });
}

main().catch((err) => {
  console.error('Fatal startup error', err);
  process.exit(1);
});