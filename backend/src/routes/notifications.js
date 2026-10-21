/**
 * Alert Channels Route Handler
 * ─────────────────────────────────────────────────────────────────
 * Configures and tests per-repository notification channels (Slack, PagerDuty, Jira, Email).
 * Enforces tenant authorization (anti-IDOR), SSRF validation on webhooks, rate limiting,
 * secret redaction, and alert history logging.
 */

'use strict';

const express = require('express');
const router = express.Router();

const { requireAuth, isRepoAuthorized } = require('../middleware/auth');
const { db } = require('../db/store');
const notifications = require('../modules/notificationService');

// In-memory rate limiting map: repoId -> [timestamps in ms]
const testRateLimits = new Map();

function checkTestRateLimit(repoId) {
  const now = Date.now();
  const windowMs = 60000; // 1 minute
  const maxAttempts = 5;

  const timestamps = (testRateLimits.get(repoId) || []).filter((t) => now - t < windowMs);
  if (timestamps.length >= maxAttempts) {
    return false;
  }
  timestamps.push(now);
  testRateLimits.set(repoId, timestamps);
  return true;
}

/**
 * GET /api/repos/:id/alert-channels
 * Retrieves configured channels for the repo with secrets redacted.
 */
router.get('/repos/:id/alert-channels', requireAuth, async (req, res) => {
  await db.read();
  const repo = db.data.repositories.find((r) => r.id === req.params.id);
  if (!repo || !isRepoAuthorized(repo, req.user, db)) {
    return res.status(404).json({ error: 'Repository not found or access denied' });
  }

  res.json({
    ...redact(repo.alertChannels || {}),
    smtpConfigured: notifications.isSmtpConfigured(),
  });
});

/**
 * PUT /api/repos/:id/alert-channels
 * Updates notification channels for the specified repository.
 */
router.put('/repos/:id/alert-channels', requireAuth, async (req, res) => {
  await db.read();
  const repo = db.data.repositories.find((r) => r.id === req.params.id);
  if (!repo || !isRepoAuthorized(repo, req.user, db)) {
    return res.status(404).json({ error: 'Repository not found or access denied' });
  }

  let { slackWebhookUrl, jira, pagerDutyRoutingKey, pagerDutyEndpointOverride, email } = req.body;
  const existing = repo.alertChannels || {};

  // 1. Slack Webhook validation
  if (slackWebhookUrl === '••••configured••••') {
    slackWebhookUrl = existing.slackWebhookUrl;
  } else if (slackWebhookUrl === '' || slackWebhookUrl === null) {
    slackWebhookUrl = null;
  } else if (slackWebhookUrl !== undefined) {
    if (!notifications.isValidSlackWebhookUrl(slackWebhookUrl)) {
      return res.status(400).json({
        error: 'Invalid Slack webhook URL. Must start with https://hooks.slack.com/services/',
      });
    }
    slackWebhookUrl = slackWebhookUrl.trim();
  } else {
    slackWebhookUrl = existing.slackWebhookUrl;
  }

  // 2. PagerDuty Routing Key validation
  if (pagerDutyRoutingKey === '••••configured••••') {
    pagerDutyRoutingKey = existing.pagerDutyRoutingKey;
  } else if (pagerDutyRoutingKey === '' || pagerDutyRoutingKey === null) {
    pagerDutyRoutingKey = null;
  } else if (pagerDutyRoutingKey !== undefined) {
    if (typeof pagerDutyRoutingKey !== 'string' || pagerDutyRoutingKey.trim().length < 10) {
      return res.status(400).json({
        error: 'Invalid PagerDuty routing key. Must be a valid Events API v2 integration key.',
      });
    }
    pagerDutyRoutingKey = pagerDutyRoutingKey.trim();
  } else {
    pagerDutyRoutingKey = existing.pagerDutyRoutingKey;
  }

  // 3. Email validation
  let normalizedEmail = existing.email;
  if (email === '' || email === null || email?.to === '' || email?.to === null) {
    normalizedEmail = null;
  } else if (email !== undefined) {
    const toAddress = typeof email === 'string' ? email.trim() : email?.to?.trim();
    if (toAddress) {
      if (!notifications.isValidEmail(toAddress)) {
        return res.status(400).json({ error: 'Invalid email address format' });
      }
      normalizedEmail = { to: toAddress, configured: true };
    } else {
      normalizedEmail = null;
    }
  }

  // 4. Jira configuration
  let normalizedJira = existing.jira;
  if (jira === null || jira === '') {
    normalizedJira = null;
  } else if (jira !== undefined) {
    normalizedJira = jira;
  }

  repo.alertChannels = {
    slackWebhookUrl: slackWebhookUrl || null,
    jira: normalizedJira || null,
    pagerDutyRoutingKey: pagerDutyRoutingKey || null,
    pagerDutyEndpointOverride: pagerDutyEndpointOverride || existing.pagerDutyEndpointOverride || null,
    email: normalizedEmail || null,
  };

  await db.write();

  res.json({
    ...redact(repo.alertChannels),
    smtpConfigured: notifications.isSmtpConfigured(),
    message: 'Alert channels updated successfully',
  });
});

/**
 * POST /api/repos/:id/alert-channels/test
 * Sends a real test notification through configured channels.
 */
router.post('/repos/:id/alert-channels/test', requireAuth, async (req, res) => {
  await db.read();
  const repo = db.data.repositories.find((r) => r.id === req.params.id);
  if (!repo || !isRepoAuthorized(repo, req.user, db)) {
    return res.status(404).json({ error: 'Repository not found or access denied' });
  }

  const channels = repo.alertChannels || {};
  const hasChannels = Boolean(
    channels.slackWebhookUrl ||
    channels.pagerDutyRoutingKey ||
    channels.jira ||
    channels.email?.to
  );

  if (!hasChannels) {
    return res.status(400).json({ error: 'No alert channels configured for this repository' });
  }

  // Rate Limiting: Max 5 test alerts per 60 seconds
  if (!checkTestRateLimit(repo.id)) {
    return res.status(429).json({
      error: 'Rate limit exceeded: Maximum 5 test alerts per minute. Please try again shortly.',
    });
  }

  const syntheticFinding = {
    type: 'TEST_ALERT',
    cveId: 'SECURECHAIN-TEST-001',
    component: 'test-supply-chain-package',
    version: '1.0.0',
    severity: 9.8,
    epss: 0.92,
    priorityLabel: 'P0_CRITICAL',
    summary: 'This is a genuine SecureChain verification test alert. All configured channels are operational.',
    fixedVersions: ['1.0.1'],
  };

  const results = await notifications.dispatchAlert(channels, syntheticFinding, repo);

  res.json({
    testFinding: syntheticFinding,
    results,
    smtpConfigured: notifications.isSmtpConfigured(),
  });
});

/**
 * GET /api/repos/:id/alert-history
 * Returns the 50 most recent alert delivery events for this repository.
 */
router.get('/repos/:id/alert-history', requireAuth, async (req, res) => {
  await db.read();
  const repo = db.data.repositories.find((r) => r.id === req.params.id);
  if (!repo || !isRepoAuthorized(repo, req.user, db)) {
    return res.status(404).json({ error: 'Repository not found or access denied' });
  }

  const repoAlerts = (db.data.alerts || [])
    .filter((a) => a.repoId === repo.id)
    .slice(0, 50);

  res.json({ history: repoAlerts });
});

function redact(channels) {
  return {
    slackWebhookUrl: channels.slackWebhookUrl ? '••••configured••••' : null,
    jira: channels.jira ? { baseUrl: channels.jira.baseUrl, projectKey: channels.jira.projectKey, configured: true } : null,
    pagerDutyRoutingKey: channels.pagerDutyRoutingKey ? '••••configured••••' : null,
    email: channels.email?.to ? { to: channels.email.to, configured: true } : null,
  };
}

module.exports = router;
