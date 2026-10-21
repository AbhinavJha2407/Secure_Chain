require('dotenv').config({ override: true });
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
  app.use(cors({ origin: process.env.FRONTEND_URL || '*' }));

  // Mounted BEFORE the global JSON parser: the GitHub webhook route needs
  // the raw, unparsed request body to verify the HMAC-SHA256 signature.
  app.use('/api/cicd', cicdRoutes);

  app.use(express.json({ limit: '5mb' }));

  app.get('/health', (req, res) => res.json({ status: 'ok', service: 'securechain-backend', time: new Date().toISOString() }));
  app.use('/api', apiRoutes);
  app.use('/api', notificationRoutes);
  app.use('/api', aiRoutes);
  app.use('/api', adminRoutes);

  const server = http.createServer(app);
  const wss = new WebSocketServer({ server, path: '/ws/threat-feed' });

  wss.on('connection', (ws) => {
    ws.send(JSON.stringify({ type: 'CONNECTED', message: 'Live threat feed connected' }));
  });

  startThreatFeed(wss);

  const port = process.env.PORT || 4000;
  server.listen(port, () => {
    console.log(`SecureChain backend listening on :${port}`);
    console.log(`WebSocket threat feed at ws://localhost:${port}/ws/threat-feed`);
    if (process.env.GEMINI_API_KEY) {
      console.log(`[AI Threat Engine] 🤖 Active LLM: Google Gemini (${process.env.GEMINI_MODEL || 'gemini-1.5-flash'})`);
    } else if (process.env.ANTHROPIC_API_KEY) {
      console.log(`[AI Threat Engine] 🤖 Active LLM: Anthropic Claude`);
    } else {
      console.log(`[AI Threat Engine] ℹ️ GEMINI_API_KEY not configured yet (AI features dormant)`);
    }
  });
}

main().catch((err) => {
  console.error('Fatal startup error', err);
  process.exit(1);
});
