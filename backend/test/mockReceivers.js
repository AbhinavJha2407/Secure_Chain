/**
 * Mock third-party receivers — used ONLY for local integration testing of
 * notificationService.js. Mimics the exact response shapes Slack/Jira/
 * PagerDuty return, so we can verify SecureChain's real HTTP request code
 * round-trips correctly without needing live accounts on each service.
 * Not part of the SecureChain product itself.
 */
const express = require('express');
const app = express();
app.use(express.json());

const received = { slack: [], jira: [], pagerduty: [] };

app.post('/mock/slack-webhook', (req, res) => {
  console.log('[MOCK SLACK] received payload:', JSON.stringify(req.body, null, 2));
  received.slack.push(req.body);
  res.status(200).send('ok'); // Slack's real incoming webhook returns plain text "ok"
});

app.post('/mock/jira/rest/api/3/issue', (req, res) => {
  console.log('[MOCK JIRA] received payload:', JSON.stringify(req.body, null, 2));
  console.log('[MOCK JIRA] Authorization header:', req.headers.authorization);
  received.jira.push(req.body);
  res.status(201).json({ id: '10001', key: 'SEC-101', self: 'http://mock-jira/issue/10001' });
});

app.post('/v2/enqueue', (req, res) => {
  console.log('[MOCK PAGERDUTY] received payload:', JSON.stringify(req.body, null, 2));
  received.pagerduty.push(req.body);
  res.status(202).json({ status: 'success', message: 'Event processed', dedup_key: req.body.dedup_key });
});

app.get('/mock/received', (req, res) => res.json(received));

const port = process.env.MOCK_PORT || 4500;
app.listen(port, () => console.log(`Mock receivers listening on :${port}`));
