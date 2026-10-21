/**
 * Threat Feed Aggregator + WebSocket broadcast (report section 3.2.1 'Intelligence' layer).
 * Polls OSV.dev's recently-published vulnerabilities (via a curated watch-list
 * of popular packages, since OSV has no global "latest CVEs" endpoint) every
 * POLL_INTERVAL_MS and pushes new findings to all connected dashboard clients.
 */

const axios = require('axios');
const { TOP_NPM_PACKAGES } = require('./maliciousPackageAnalyzer');

const POLL_INTERVAL_MS = 5 * 60 * 1000; // 5 minutes, matches report's MTTD target
const seenVulnIds = new Set();

function startThreatFeed(wss) {
  async function pollOnce() {
    const watchlist = TOP_NPM_PACKAGES.slice(0, 15); // bounded for demo; production would watch all monitored repos' components
    for (const pkg of watchlist) {
      try {
        const { data } = await axios.post(
          'https://api.osv.dev/v1/query',
          { package: { name: pkg, ecosystem: 'npm' } },
          { timeout: 10000 }
        );
        for (const v of data.vulns || []) {
          if (seenVulnIds.has(v.id)) continue;
          seenVulnIds.add(v.id);
          broadcast(wss, {
            type: 'NEW_VULNERABILITY',
            id: v.id,
            package: pkg,
            summary: v.summary,
            published: v.published,
            timestamp: new Date().toISOString(),
          });
        }
      } catch (err) {
        // Network-restricted environments (e.g. this dev sandbox) can't reach
        // api.osv.dev; in production/deployed environments this succeeds.
        broadcast(wss, { type: 'FEED_ERROR', source: 'OSV', message: err.message, timestamp: new Date().toISOString() });
      }
    }
  }

  broadcast(wss, { type: 'FEED_STARTED', intervalMs: POLL_INTERVAL_MS, timestamp: new Date().toISOString() });
  pollOnce();
  return setInterval(pollOnce, POLL_INTERVAL_MS);
}

function broadcast(wss, payload) {
  const msg = JSON.stringify(payload);
  wss.clients.forEach((client) => {
    if (client.readyState === 1) client.send(msg);
  });
}

module.exports = { startThreatFeed, broadcast };
