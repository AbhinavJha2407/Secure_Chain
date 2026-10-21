'use strict';

const { test, describe, beforeEach, afterEach } = require('node:test');
const assert = require('node:assert/strict');
const axios = require('axios');
const nodemailer = require('nodemailer');

const {
  isValidSlackWebhookUrl,
  isValidEmail,
  isSmtpConfigured,
  sendSlackAlert,
  createJiraTicket,
  triggerPagerDutyAlert,
  sendEmailAlert,
  dispatchAlert,
  dispatchScanAlerts,
} = require('../src/modules/notificationService');

const { isRepoAuthorized } = require('../src/middleware/auth');
const policyGate = require('../src/modules/policyGate');
const { db, uuid } = require('../src/db/store');

describe('Alert Channels & Notification Security Suite', () => {
  let originalEnv;
  let originalAxiosPost;
  let originalCreateTransport;

  beforeEach(() => {
    originalEnv = { ...process.env };
    originalAxiosPost = axios.post;
    originalCreateTransport = nodemailer.createTransport;
  });

  afterEach(() => {
    process.env = originalEnv;
    axios.post = originalAxiosPost;
    nodemailer.createTransport = originalCreateTransport;
  });

  // 1 & 2: Authorization & IDOR protection
  test('authorized user can access repo alerts, unauthorized tenant is rejected (anti-IDOR)', () => {
    const mockDb = {
      data: {
        users: [
          { id: 'user-tenant-a', githubId: '1001', orgId: 'org-1' },
          { id: 'user-tenant-b', githubId: '1002', orgId: 'org-2' },
        ],
        repositories: [
          { id: 'repo-1', ownerId: 'user-tenant-a', fullName: 'tenant-a/repo' },
        ],
      },
    };

    const userA = { sub: 'user-tenant-a', role: 'Developer' };
    const userB = { sub: 'user-tenant-b', role: 'Developer' };
    const repo = mockDb.data.repositories[0];

    assert.equal(isRepoAuthorized(repo, userA, mockDb), true);
    assert.equal(isRepoAuthorized(repo, userB, mockDb), false);
  });

  // 3 & 4: SMTP Email notifications
  test('missing SMTP configuration returns skipped with explanatory reason', async () => {
    delete process.env.SMTP_HOST;
    delete process.env.SMTP_USER;
    delete process.env.SMTP_PASS;

    const res = await sendEmailAlert('alerts@company.com', {
      priorityLabel: 'P0_CRITICAL',
      cveId: 'CVE-2025-0001',
      summary: 'Critical vulnerability',
    });

    assert.equal(res.skipped, true);
    assert.match(res.reason, /SMTP not configured/i);
    assert.equal(res.sent, undefined);
  });

  test('invalid email address format is rejected with error', async () => {
    process.env.SMTP_HOST = 'smtp.example.com';
    process.env.SMTP_USER = 'user';
    process.env.SMTP_PASS = 'pass';

    const res = await sendEmailAlert('invalid-email-address', {
      priorityLabel: 'P0_CRITICAL',
    });

    assert.equal(res.failed, true);
    assert.match(res.error, /invalid.*email/i);
  });

  test('configured SMTP sends email and handles failure gracefully', async () => {
    process.env.SMTP_HOST = 'smtp.example.com';
    process.env.SMTP_USER = 'user';
    process.env.SMTP_PASS = 'pass';

    // Mock successful nodemailer transport
    let sentPayload = null;
    nodemailer.createTransport = () => ({
      sendMail: async (options) => {
        sentPayload = options;
        return { messageId: '<msg-12345@securechain>' };
      },
    });

    const resSuccess = await sendEmailAlert('security@example.com', {
      priorityLabel: 'P0_CRITICAL',
      cveId: 'CVE-2025-1111',
      summary: 'SQL Injection in dependency',
      severity: 9.8,
    }, { fullName: 'acme/webapp' });

    assert.equal(resSuccess.sent, true);
    assert.equal(resSuccess.messageId, '<msg-12345@securechain>');
    assert.match(sentPayload.subject, /acme\/webapp/);

    // Mock SMTP error
    nodemailer.createTransport = () => ({
      sendMail: async () => {
        throw new Error('Connection timeout to mail server');
      },
    });

    const resFail = await sendEmailAlert('security@example.com', {
      priorityLabel: 'P0_CRITICAL',
    });

    assert.equal(resFail.failed, true);
    assert.match(resFail.error, /Connection timeout/);
  });

  // 5 & 6: Slack webhook anti-SSRF & error handling
  test('Slack webhook rejects non-Slack or internal URLs to prevent SSRF', async () => {
    assert.equal(isValidSlackWebhookUrl('http://169.254.169.254/latest/meta-data'), false);
    assert.equal(isValidSlackWebhookUrl('http://localhost:4000/internal-api'), false);
    assert.equal(isValidSlackWebhookUrl('https://evil-attacker.com/webhook'), false);
    assert.equal(isValidSlackWebhookUrl('https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX'), true);

    const ssrfAttempt = await sendSlackAlert('http://169.254.169.254/secret', { cveId: 'CVE-TEST' });
    assert.equal(ssrfAttempt.failed, true);
    assert.match(ssrfAttempt.error, /Invalid Slack webhook URL/);
  });

  test('Slack handles HTTP errors and network timeouts safely', async () => {
    const validUrl = 'https://hooks.slack.com/services/T111/B222/abc123456';
    axios.post = async () => {
      const err = new Error('getaddrinfo ENOTFOUND hooks.slack.com');
      err.response = { status: 502, data: 'Bad Gateway' };
      throw err;
    };

    const res = await sendSlackAlert(validUrl, { cveId: 'CVE-2025-9999' });
    assert.equal(res.failed, true);
    assert.ok(res.error);
  });

  // 7: PagerDuty integration
  test('PagerDuty payload formatting, deduplication key, and mock delivery', async () => {
    let capturedCall = null;
    axios.post = async (url, payload) => {
      capturedCall = { url, payload };
      return { status: 202, data: { status: 'success' } };
    };

    const res = await triggerPagerDutyAlert('test-routing-key-12345678', {
      priorityLabel: 'P0_CRITICAL',
      cveId: 'CVE-2025-1000',
      packageName: 'malicious-lib',
      severity: 9.8,
    }, { id: 'repo-abc', fullName: 'acme/core' });

    assert.equal(res.sent, true);
    assert.equal(capturedCall.url, 'https://events.pagerduty.com/v2/enqueue');
    assert.equal(capturedCall.payload.routing_key, 'test-routing-key-12345678');
    assert.equal(capturedCall.payload.event_action, 'trigger');
    assert.equal(capturedCall.payload.dedup_key, 'securechain-repo-abc-CVE-2025-1000');
    assert.equal(capturedCall.payload.payload.severity, 'critical');
  });

  // 8: Jira integration
  test('Jira skips when unconfigured and creates ticket when credentials provided', async () => {
    delete process.env.JIRA_BASE_URL;
    delete process.env.JIRA_API_TOKEN;

    const unconf = await createJiraTicket(null, { cveId: 'CVE-1' });
    assert.equal(unconf.skipped, true);
    assert.match(unconf.reason, /No Jira credentials/);

    // With credentials configured
    axios.post = async (url, payload) => {
      return { status: 201, data: { key: 'SEC-999' } };
    };

    const configured = await createJiraTicket({
      baseUrl: 'https://acme.atlassian.net',
      email: 'bot@acme.com',
      apiToken: 'secret-token',
      projectKey: 'SEC',
    }, { priorityLabel: 'P0_CRITICAL', cveId: 'CVE-2025-5000' });

    assert.equal(configured.sent, true);
    assert.equal(configured.ticketKey, 'SEC-999');
  });

  // 9 & 10: Alert threshold routing (P0 triggers Jira/PD; lower findings do not)
  test('P0 findings trigger PagerDuty and Jira; findings below threshold do not', async () => {
    const channels = {
      slackWebhookUrl: 'https://hooks.slack.com/services/T1/B2/C3',
      pagerDutyRoutingKey: 'pd-routing-key-12345',
      jira: { baseUrl: 'https://test.atlassian.net', email: 'a@b.com', apiToken: 'token', projectKey: 'PROJ' },
    };

    axios.post = async () => ({ status: 200, data: { ok: true, key: 'SEC-1' } });

    // P0 finding
    const p0Results = await dispatchAlert(channels, { priorityLabel: 'P0_CRITICAL', cveId: 'CVE-CRIT' });
    assert.ok(p0Results.slack);
    assert.ok(p0Results.pagerduty);
    assert.ok(p0Results.jira);

    // P2 Medium finding
    const p2Results = await dispatchAlert(channels, { priorityLabel: 'P2_MEDIUM', cveId: 'CVE-MED' });
    assert.ok(p2Results.slack);
    assert.equal(p2Results.pagerduty, undefined); // Suppressed
    assert.equal(p2Results.jira, undefined);      // Suppressed
  });

  // 11: Duplicate findings deduplication
  test('duplicate findings within 24h are not alerted repeatedly', async () => {
    await db.read();
    const testRepo = {
      id: 'repo-dedup-test-' + Date.now(),
      fullName: 'test/dedup',
      alertChannels: { slackWebhookUrl: 'https://hooks.slack.com/services/T1/B1/K1' },
    };
    db.data.repositories.push(testRepo);

    let dispatchCount = 0;
    axios.post = async () => {
      dispatchCount++;
      return { status: 200, data: 'ok' };
    };

    const vuln = { id: 'v1', cveId: 'CVE-DUPLICATE-TEST', priorityLabel: 'P0_CRITICAL' };

    // First scan run
    await dispatchScanAlerts(testRepo, [vuln], []);
    assert.equal(dispatchCount, 1);

    // Second scan run immediately after
    await dispatchScanAlerts(testRepo, [vuln], []);
    // Dispatch count should remain 1 due to 24h deduplication window!
    assert.equal(dispatchCount, 1);
  });

  // 12: Notification failure does NOT alter security decision
  test('external notification failure never turns blocked policy gate into PASS', async () => {
    // Failing external API
    axios.post = async () => {
      throw new Error('500 Internal Server Error on downstream webhook');
    };

    const channels = { slackWebhookUrl: 'https://hooks.slack.com/services/T1/B1/K1' };
    const alertResult = await dispatchAlert(channels, { priorityLabel: 'P0_CRITICAL', cveId: 'CVE-CRITICAL' });
    assert.equal(alertResult.slack.failed, true);

    // Policy gate evaluation with critical finding must still evaluate to FAILED (vulnerability limit exceeded)
    const vulnGate = policyGate.evaluateGate({
      vulnerabilities: [{ priorityLabel: 'P0_CRITICAL', severity: 9.8 }],
      maliciousPackages: [],
    });
    assert.equal(vulnGate.verdict, 'FAILED');
    assert.notEqual(vulnGate.verdict, 'PASS');

    // Policy gate evaluation with malicious package must evaluate to BLOCKED
    const malwareGate = policyGate.evaluateGate({
      vulnerabilities: [],
      maliciousPackages: [{ type: 'TYPOSQUAT', packageName: 'lodahs' }],
    });
    assert.equal(malwareGate.verdict, 'BLOCKED');
    assert.notEqual(malwareGate.verdict, 'PASS');
  });
});
