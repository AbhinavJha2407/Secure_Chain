/**
 * SecureChain Notification Service
 * ─────────────────────────────────────────────────────────────────
 * Handles alerts across Slack, PagerDuty, Jira, and Email (SMTP).
 * 
 * Features:
 * - Anti-SSRF Slack Webhook URL validation (strictly https://hooks.slack.com/)
 * - PagerDuty Events API v2 with stable deduplication keys
 * - Server-side SMTP credentials via environment variables
 * - Jira Cloud integration with automated P0 bug ticketing
 * - Alert history recording and scan deduplication
 * - Non-blocking asynchronous event dispatching
 */

'use strict';

const axios = require('axios');
const nodemailer = require('nodemailer');
const { db, uuid } = require('../db/store');

// ---------- Validation Helpers ----------

function isValidSlackWebhookUrl(url) {
  if (typeof url !== 'string' || !url.trim()) return false;
  try {
    const parsed = new URL(url.trim());
    if (parsed.protocol !== 'https:') return false;
    return (
      parsed.hostname === 'hooks.slack.com' &&
      (parsed.pathname.startsWith('/services/') || parsed.pathname.startsWith('/workflows/'))
    );
  } catch {
    return false;
  }
}

function isValidEmail(email) {
  if (typeof email !== 'string') return false;
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email.trim());
}

function isSmtpConfigured() {
  return Boolean(
    process.env.SMTP_HOST &&
    (process.env.SMTP_USER || process.env.SMTP_AUTH_NONE === 'true') &&
    (process.env.SMTP_PASS || process.env.SMTP_AUTH_NONE === 'true')
  );
}

function getSmtpConfig() {
  if (!isSmtpConfigured()) return null;
  return {
    host: process.env.SMTP_HOST,
    port: parseInt(process.env.SMTP_PORT || '587', 10),
    secure: process.env.SMTP_SECURE === 'true' || process.env.SMTP_PORT === '465',
    auth: process.env.SMTP_AUTH_NONE === 'true' ? undefined : {
      user: process.env.SMTP_USER,
      pass: process.env.SMTP_PASS,
    },
    tls: {
      rejectUnauthorized: process.env.SMTP_REJECT_UNAUTHORIZED !== 'false',
    },
    connectionTimeout: 8000,
    greetingTimeout: 5000,
    socketTimeout: 8000,
  };
}

function severityColor(label) {
  if (label === 'P0_CRITICAL') return '#e01e5a';
  if (label === 'P1_HIGH') return '#ECB22E';
  if (label === 'P2_MEDIUM') return '#2EB67D';
  return '#36C5F0';
}

function pagerDutySeverity(label) {
  if (label === 'P0_CRITICAL') return 'critical';
  if (label === 'P1_HIGH') return 'error';
  if (label === 'P2_MEDIUM') return 'warning';
  return 'info';
}

function sanitizeError(err) {
  if (!err) return 'Unknown error';
  const msg = err.response?.data?.message || err.response?.data || err.message || String(err);
  // Strip out any accidental tokens or passwords from error text
  return String(msg).replace(/Bearer\s+[A-Za-z0-9\-._~+/]+=*/gi, 'Bearer [REDACTED]')
    .replace(/(password|secret|key|token)=([^&\s]+)/gi, '$1=[REDACTED]');
}

// ---------- Slack ----------
async function sendSlackAlert(webhookUrl, finding, repo = {}) {
  if (!webhookUrl) return { skipped: true, reason: 'No Slack webhook configured' };
  if (!isValidSlackWebhookUrl(webhookUrl)) {
    return { failed: true, error: 'Invalid Slack webhook URL. Must start with https://hooks.slack.com/services/' };
  }

  const repoName = repo.fullName || 'Repository';
  const color = severityColor(finding.priorityLabel || finding.severityLabel);
  const frontendBase = process.env.FRONTEND_URL || 'http://localhost:5173';
  const vulnLink = repo.id ? `${frontendBase}/dashboard/vulns?repoId=${repo.id}` : `${frontendBase}/dashboard/vulns`;

  const payload = {
    attachments: [
      {
        color,
        title: `[${finding.priorityLabel || finding.type || 'ALERT'}] ${finding.cveId || finding.packageName} — ${repoName}`,
        title_link: vulnLink,
        text: finding.summary || finding.detail || 'Security finding detected by SecureChain',
        fields: [
          { title: 'Repository', value: repoName, short: true },
          { title: 'Component', value: `${finding.component || finding.packageName || 'N/A'}${finding.version ? '@' + finding.version : ''}`, short: true },
          { title: 'Priority', value: finding.priorityLabel || 'N/A', short: true },
          { title: 'CVSS Base', value: String(finding.severity ?? 'N/A'), short: true },
          { title: 'EPSS Score', value: finding.epss != null ? `${(finding.epss * 100).toFixed(1)}%` : 'N/A', short: true },
          { title: 'Fix Version', value: (finding.fixedVersions || []).join(', ') || 'N/A', short: true },
        ],
        footer: 'SecureChain Supply Chain Security',
        ts: Math.floor(Date.now() / 1000),
      },
    ],
  };

  try {
    const { data, status } = await axios.post(webhookUrl, payload, { timeout: 8000 });
    return { sent: true, status, data };
  } catch (err) {
    return { failed: true, error: sanitizeError(err) };
  }
}

// ---------- PagerDuty ----------
async function triggerPagerDutyAlert(routingKey, finding, repo = {}, endpointOverride) {
  if (!routingKey) return { skipped: true, reason: 'No PagerDuty routing key configured' };
  if (typeof routingKey !== 'string' || routingKey.trim().length < 10) {
    return { failed: true, error: 'Invalid PagerDuty routing key' };
  }

  const isTest = finding.type === 'TEST_ALERT';
  const dedupKey = isTest
    ? `securechain-test-${repo.id || 'repo'}-${Date.now()}`
    : `securechain-${repo.id || 'repo'}-${finding.cveId || finding.id || finding.packageName}`;

  const payload = {
    routing_key: routingKey.trim(),
    event_action: 'trigger',
    dedup_key: dedupKey,
    payload: {
      summary: isTest
        ? `[SecureChain Test] Verification Alert for ${repo.fullName || 'Repository'}`
        : `[SecureChain] ${finding.priorityLabel || 'CRITICAL'}: ${finding.cveId || finding.packageName} in ${repo.fullName || 'Repository'}`,
      severity: isTest ? 'info' : pagerDutySeverity(finding.priorityLabel),
      source: repo.fullName || 'SecureChain',
      component: finding.component || finding.packageName || 'supply-chain',
      timestamp: new Date().toISOString(),
      custom_details: {
        repository: repo.fullName || 'N/A',
        findingType: finding.type || 'VULNERABILITY',
        cveId: finding.cveId || 'N/A',
        component: finding.component || finding.packageName || 'N/A',
        version: finding.version || 'N/A',
        severity: finding.severity,
        epss: finding.epss,
        fixedVersions: finding.fixedVersions || [],
        summary: finding.summary || finding.detail,
        isTest,
      },
    },
  };

  const endpoint = endpointOverride || 'https://events.pagerduty.com/v2/enqueue';
  try {
    const { data, status } = await axios.post(endpoint, payload, { timeout: 8000 });
    return { sent: true, status, data, dedupKey };
  } catch (err) {
    return { failed: true, error: sanitizeError(err) };
  }
}

// ---------- Jira ----------
async function createJiraTicket(jiraSettings, finding, repo = {}) {
  const baseUrl = jiraSettings?.baseUrl || process.env.JIRA_BASE_URL;
  const email = jiraSettings?.email || process.env.JIRA_EMAIL;
  const apiToken = jiraSettings?.apiToken || process.env.JIRA_API_TOKEN;
  const projectKey = jiraSettings?.projectKey || process.env.JIRA_PROJECT_KEY;

  if (!baseUrl || !apiToken || !email || !projectKey) {
    return {
      skipped: true,
      reason: 'No Jira credentials configured (requires JIRA_BASE_URL, JIRA_EMAIL, JIRA_API_TOKEN, JIRA_PROJECT_KEY)',
    };
  }

  const auth = Buffer.from(`${email}:${apiToken}`).toString('base64');
  const repoName = repo.fullName || 'Repository';
  const payload = {
    fields: {
      project: { key: projectKey },
      summary: `[SecureChain] ${finding.priorityLabel || 'P0'}: ${finding.cveId || finding.id} in ${finding.component || finding.packageName}@${finding.version || 'latest'} (${repoName})`,
      description: {
        type: 'doc',
        version: 1,
        content: [
          {
            type: 'paragraph',
            content: [
              {
                type: 'text',
                text: `Repository: ${repoName}\nFinding: ${finding.summary || finding.detail || 'Critical vulnerability detected'}\nCVSS: ${finding.severity ?? 'N/A'} | EPSS: ${finding.epss != null ? (finding.epss * 100).toFixed(1) + '%' : 'N/A'}\nFix Version(s): ${(finding.fixedVersions || []).join(', ') || 'None available'}\n\nAutomated issue created by SecureChain policy gate.`,
              },
            ],
          },
        ],
      },
      issuetype: { name: 'Bug' },
      labels: ['securechain', (finding.priorityLabel || 'p0').toLowerCase(), 'security-gate'],
    },
  };

  try {
    const { data, status } = await axios.post(`${baseUrl.replace(/\/$/, '')}/rest/api/3/issue`, payload, {
      headers: { Authorization: `Basic ${auth}`, 'Content-Type': 'application/json' },
      timeout: 10000,
    });
    return { sent: true, status, ticketKey: data.key, ticketUrl: `${baseUrl}/browse/${data.key}` };
  } catch (err) {
    return { failed: true, error: sanitizeError(err) };
  }
}

// ---------- Email (SMTP) ----------
async function sendEmailAlert(recipient, finding, repo = {}) {
  const to = typeof recipient === 'string' ? recipient : recipient?.to;
  if (!to) {
    return { skipped: true, reason: 'No alert email address configured' };
  }
  if (!isValidEmail(to)) {
    return { failed: true, error: 'Invalid recipient email address format' };
  }

  if (!isSmtpConfigured()) {
    return {
      skipped: true,
      reason: 'SMTP not configured on server (set SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS in backend environment)',
    };
  }

  const repoName = repo.fullName || 'Repository';
  const smtpConfig = getSmtpConfig();
  const from = process.env.SMTP_FROM || 'SecureChain Alerts <alerts@securechain.local>';
  const subject = `[SecureChain] ${finding.priorityLabel || finding.type || 'ALERT'}: ${finding.cveId || finding.packageName} in ${repoName}`;
  const text = `SecureChain Security Alert
=============================
Repository:   ${repoName}
Finding:      ${finding.cveId || finding.id || finding.packageName}
Priority:     ${finding.priorityLabel || 'N/A'}
CVSS Score:   ${finding.severity ?? 'N/A'}
EPSS Score:   ${finding.epss != null ? (finding.epss * 100).toFixed(1) + '%' : 'N/A'}
Component:    ${finding.component || finding.packageName || 'N/A'}@${finding.version || 'N/A'}
Fix Versions: ${(finding.fixedVersions || []).join(', ') || 'N/A'}

Summary:
${finding.summary || finding.detail || 'Security finding identified by SecureChain.'}

View details at: ${process.env.FRONTEND_URL || 'http://localhost:5173'}
`;

  const html = `
<div style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 24px; border: 1px solid #e2e8f0; border-radius: 8px;">
  <div style="display: flex; align-items: center; margin-bottom: 20px;">
    <h2 style="color: #0f172a; margin: 0; font-size: 20px;">SecureChain Security Alert</h2>
  </div>
  <div style="background-color: #f8fafc; border-left: 4px solid ${severityColor(finding.priorityLabel)}; padding: 12px 16px; margin-bottom: 20px; border-radius: 4px;">
    <div style="font-weight: bold; font-size: 16px; color: #0f172a;">${finding.cveId || finding.packageName}</div>
    <div style="color: #64748b; font-size: 14px; margin-top: 4px;">${finding.summary || finding.detail || 'Security finding detected.'}</div>
  </div>
  <table style="width: 100%; border-collapse: collapse; font-size: 13px; margin-bottom: 20px;">
    <tr><td style="padding: 6px 0; color: #64748b;">Repository:</td><td style="padding: 6px 0; font-weight: bold; color: #0f172a;">${repoName}</td></tr>
    <tr><td style="padding: 6px 0; color: #64748b;">Component:</td><td style="padding: 6px 0; font-family: monospace; color: #0f172a;">${finding.component || finding.packageName || 'N/A'}@${finding.version || 'N/A'}</td></tr>
    <tr><td style="padding: 6px 0; color: #64748b;">Priority:</td><td style="padding: 6px 0; font-weight: bold; color: ${severityColor(finding.priorityLabel)};">${finding.priorityLabel || 'N/A'}</td></tr>
    <tr><td style="padding: 6px 0; color: #64748b;">CVSS Base:</td><td style="padding: 6px 0; color: #0f172a;">${finding.severity ?? 'N/A'}</td></tr>
    <tr><td style="padding: 6px 0; color: #64748b;">EPSS Probability:</td><td style="padding: 6px 0; color: #0f172a;">${finding.epss != null ? (finding.epss * 100).toFixed(1) + '%' : 'N/A'}</td></tr>
    <tr><td style="padding: 6px 0; color: #64748b;">Fix Versions:</td><td style="padding: 6px 0; color: #166534; font-weight: bold;">${(finding.fixedVersions || []).join(', ') || 'None available'}</td></tr>
  </table>
  <div style="border-top: 1px solid #e2e8f0; padding-top: 16px; font-size: 12px; color: #94a3b8;">
    SecureChain Platform Automated Notification
  </div>
</div>
`;

  try {
    const transporter = nodemailer.createTransport(smtpConfig);
    const info = await transporter.sendMail({ from, to, subject, text, html });
    return { sent: true, messageId: info.messageId, to };
  } catch (err) {
    return { failed: true, error: sanitizeError(err) };
  }
}

// ---------- Alert History & Persistence ----------

async function recordAlertHistory(repoId, channel, finding, result) {
  if (!db?.data?.alerts) return;
  try {
    const record = {
      id: uuid(),
      repoId,
      channel,
      eventType: finding.type || (finding.priorityLabel === 'P0_CRITICAL' ? 'P0_CRITICAL_VULNERABILITY' : 'VULNERABILITY'),
      findingId: finding.cveId || finding.id || finding.packageName || 'test',
      status: result.sent ? 'sent' : result.skipped ? 'skipped' : 'failed',
      summary: finding.summary || finding.detail || 'Test notification',
      error: result.error || (result.skipped ? result.reason : null),
      ticketKey: result.ticketKey || null,
      timestamp: new Date().toISOString(),
    };
    db.data.alerts.unshift(record);
    if (db.data.alerts.length > 500) {
      db.data.alerts = db.data.alerts.slice(0, 500);
    }
    await db.write();
  } catch (err) {
    console.warn('[alerts] Could not persist alert history event:', err.message);
  }
}

// ---------- Dispatch Engine ----------

/**
 * Dispatches a single finding across configured channels.
 */
async function dispatchAlert(channels = {}, finding = {}, repo = {}) {
  const results = {};
  const isP0 = finding.priorityLabel === 'P0_CRITICAL';
  const isTest = finding.type === 'TEST_ALERT';

  const tasks = [];

  // Slack: Sends for P0, P1, or test alerts
  if (channels.slackWebhookUrl) {
    tasks.push(
      sendSlackAlert(channels.slackWebhookUrl, finding, repo)
        .then((r) => {
          results.slack = r;
          return recordAlertHistory(repo.id, 'slack', finding, r);
        })
        .catch((e) => {
          results.slack = { failed: true, error: sanitizeError(e) };
          return recordAlertHistory(repo.id, 'slack', finding, results.slack);
        })
    );
  }

  // PagerDuty: P0 only, or test alerts
  if (channels.pagerDutyRoutingKey && (isP0 || isTest)) {
    tasks.push(
      triggerPagerDutyAlert(channels.pagerDutyRoutingKey, finding, repo, channels.pagerDutyEndpointOverride)
        .then((r) => {
          results.pagerduty = r;
          return recordAlertHistory(repo.id, 'pagerduty', finding, r);
        })
        .catch((e) => {
          results.pagerduty = { failed: true, error: sanitizeError(e) };
          return recordAlertHistory(repo.id, 'pagerduty', finding, results.pagerduty);
        })
    );
  }

  // Jira: P0 only, or test alerts
  if ((channels.jira || process.env.JIRA_BASE_URL) && (isP0 || isTest)) {
    tasks.push(
      createJiraTicket(channels.jira, finding, repo)
        .then((r) => {
          results.jira = r;
          return recordAlertHistory(repo.id, 'jira', finding, r);
        })
        .catch((e) => {
          results.jira = { failed: true, error: sanitizeError(e) };
          return recordAlertHistory(repo.id, 'jira', finding, results.jira);
        })
    );
  }

  // Email: All qualified alerts, or test alerts
  const emailTarget = channels.email?.to || (typeof channels.email === 'string' ? channels.email : null);
  if (emailTarget) {
    tasks.push(
      sendEmailAlert(emailTarget, finding, repo)
        .then((r) => {
          results.email = r;
          return recordAlertHistory(repo.id, 'email', finding, r);
        })
        .catch((e) => {
          results.email = { failed: true, error: sanitizeError(e) };
          return recordAlertHistory(repo.id, 'email', finding, results.email);
        })
    );
  }

  await Promise.all(tasks);
  return results;
}

/**
 * Scan Event Connector:
 * Filters findings based on severity, deduplicates against recently alerted findings,
 * and triggers alerts asynchronously without blocking scanning pipeline or altering gate verdict.
 */
async function dispatchScanAlerts(repo, vulnerabilities = [], maliciousPackages = [], scanJob = {}) {
  if (!repo || !repo.alertChannels) return [];

  // Filter qualifying findings: all P0s, and malicious packages / P1s above threshold
  const qualifying = [
    ...vulnerabilities.filter((v) => v.priorityLabel === 'P0_CRITICAL' || v.priorityLabel === 'P1_HIGH'),
    ...maliciousPackages.map((m) => ({
      ...m,
      priorityLabel: 'P0_CRITICAL',
      cveId: `MALWARE-${m.packageName}`,
      component: m.packageName,
      summary: m.detail || 'Malicious package detected',
    })),
  ];

  if (qualifying.length === 0) return [];

  // Deduplication check: check if an alert for this finding was already sent for this repo in last 24h
  const now = Date.now();
  const ONE_DAY_MS = 24 * 60 * 60 * 1000;
  const recentAlerts = (db?.data?.alerts || []).filter(
    (a) => a.repoId === repo.id && a.status === 'sent' && now - new Date(a.timestamp).getTime() < ONE_DAY_MS
  );
  const recentFindingIds = new Set(recentAlerts.map((a) => a.findingId));

  const toAlert = qualifying.filter((f) => {
    const id = f.cveId || f.id || f.packageName;
    return !recentFindingIds.has(id);
  });

  if (toAlert.length === 0) return [];

  // Non-blocking execution
  const promises = toAlert.map((finding) => dispatchAlert(repo.alertChannels, finding, repo));
  return Promise.all(promises).catch((err) => {
    console.error('[alerts] Scan alerts dispatch error:', err.message);
    return [];
  });
}

module.exports = {
  isValidSlackWebhookUrl,
  isValidEmail,
  isSmtpConfigured,
  sendSlackAlert,
  createJiraTicket,
  triggerPagerDutyAlert,
  sendEmailAlert,
  dispatchAlert,
  dispatchScanAlerts,
};
