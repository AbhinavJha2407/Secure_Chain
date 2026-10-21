const express = require('express');
const router = express.Router();
const { requireAuth, requireOperationalRole } = require('../middleware/auth');
const ai = require('../modules/aiThreatEngine');
const { getModelInfo } = require('../modules/mlClassifier');
const { db } = require('../db/store');

/**
 * All routes require auth. GEMINI_API_KEY (or ANTHROPIC_API_KEY) must be set in .env.
 * If it isn't, every handler returns 503 with a clear message rather
 * than crashing — the rest of the platform keeps working without it.
 */
function requireAiKey(req, res, next) {
  if (!process.env.GEMINI_API_KEY && !process.env.ANTHROPIC_API_KEY) {
    return res.status(503).json({
      error: 'AI features disabled',
      detail: 'Set GEMINI_API_KEY in backend .env to enable the AI Threat Engine',
    });
  }
  next();
}

// ── 1. Explain a vulnerability in plain English ───────────────────────────────
router.post('/ai/explain', requireAuth, requireOperationalRole, requireAiKey, async (req, res) => {
  const { finding } = req.body;
  if (!finding) return res.status(400).json({ error: '`finding` object required' });
  try {
    const explanation = await ai.explainVulnerability(finding);
    res.json({ explanation });
  } catch (err) {
    res.status(500).json({ error: 'AI explain failed', detail: err.message });
  }
});

// ── 2. Explain (streaming SSE) — for the dashboard typing animation ──────────
router.post('/ai/explain/stream', requireAuth, requireOperationalRole, requireAiKey, async (req, res) => {
  const { finding } = req.body;
  if (!finding) return res.status(400).json({ error: '`finding` object required' });
  try {
    await ai.streamExplainVulnerability(finding, res);
  } catch (err) {
    if (!res.headersSent) res.status(500).json({ error: 'AI stream failed', detail: err.message });
  }
});

// ── 3. Classify threat + MITRE ATT&CK mapping ────────────────────────────────
router.post('/ai/classify', requireAuth, requireOperationalRole, requireAiKey, async (req, res) => {
  const { finding } = req.body;
  if (!finding) return res.status(400).json({ error: '`finding` object required' });
  try {
    const classification = await ai.classifyThreat(finding);
    res.json({ classification });
  } catch (err) {
    res.status(500).json({ error: 'AI classify failed', detail: err.message });
  }
});

// ── 4. Remediation recommendation ────────────────────────────────────────────
router.post('/ai/remediate', requireAuth, requireOperationalRole, requireAiKey, async (req, res) => {
  const { finding, sbomContext } = req.body;
  if (!finding) return res.status(400).json({ error: '`finding` object required' });
  try {
    const remediation = await ai.recommendRemediation(finding, sbomContext);
    res.json({ remediation });
  } catch (err) {
    res.status(500).json({ error: 'AI remediate failed', detail: err.message });
  }
});

// ── 5. Root cause analysis ────────────────────────────────────────────────────
router.post('/ai/root-cause', requireAuth, requireOperationalRole, requireAiKey, async (req, res) => {
  const { finding, dependencyChain } = req.body;
  if (!finding) return res.status(400).json({ error: '`finding` object required' });
  try {
    const rootCause = await ai.analyseRootCause(finding, dependencyChain);
    res.json({ rootCause });
  } catch (err) {
    res.status(500).json({ error: 'AI root-cause failed', detail: err.message });
  }
});

// ── 6. Repository risk prediction ─────────────────────────────────────────────
router.get('/ai/predict-risk/:repoId', requireAuth, requireAiKey, async (req, res) => {
  await db.read();
  const repo = db.data.repositories.find(r => r.id === req.params.repoId);
  if (!repo) return res.status(404).json({ error: 'Repository not found' });

  const vulns = db.data.vulnerabilities.filter(v => v.repoId === repo.id);
  const malicious = db.data.malicious_packages.filter(m => m.repoId === repo.id);
  const scans = db.data.scan_jobs.filter(s => s.repoId === repo.id);
  const lastScan = scans.sort((a, b) => new Date(b.startedAt) - new Date(a.startedAt))[0];

  const repoContext = {
    fullName: repo.fullName,
    currentRiskScore: repo.riskScore ?? 100,
    totalVulnerabilities: vulns.length,
    p0Count: vulns.filter(v => v.priorityLabel === 'P0_CRITICAL').length,
    p1Count: vulns.filter(v => v.priorityLabel === 'P1_HIGH').length,
    openCount: vulns.filter(v => v.status === 'Open').length,
    maliciousPackageCount: malicious.length,
    totalScans: scans.length,
    lastScanDaysAgo: lastScan
      ? Math.floor((Date.now() - new Date(lastScan.startedAt)) / 86400000)
      : null,
  };

  try {
    const prediction = await ai.predictRisk(repoContext);
    res.json({ repoId: repo.id, repoContext, prediction });
  } catch (err) {
    res.status(500).json({ error: 'AI risk prediction failed', detail: err.message });
  }
});

// ── 7. AI Security Chatbot (conversational, multi-turn) ───────────────────────
router.post('/ai/chat', requireAuth, requireOperationalRole, requireAiKey, async (req, res) => {
  const { messages, repoId } = req.body;
  if (!Array.isArray(messages) || messages.length === 0) {
    return res.status(400).json({ error: '`messages` array required' });
  }

  const activeModel = process.env.GEMINI_API_KEY
    ? (process.env.GEMINI_MODEL || 'gemini-1.5-flash')
    : (process.env.ANTHROPIC_API_KEY ? 'claude-sonnet-4-6' : 'None');

  // Optionally inject repo context so the assistant knows what it's talking about
  let systemContext = `You are SecureChain's AI security assistant powered by ${process.env.GEMINI_API_KEY ? 'Google Gemini (' + activeModel + ')' : 'Claude'} — an expert in software supply chain security, CVE analysis, SBOM management, and DevSecOps practices. Be concise and technical. Format code in markdown code blocks. If the user asks which model you are running, tell them clearly that you are running ${process.env.GEMINI_API_KEY ? 'Google Gemini (' + activeModel + ')' : 'Claude'}.`;

  if (repoId) {
    await db.read();
    const repo = db.data.repositories.find(r => r.id === repoId);
    if (repo) {
      const vulns = db.data.vulnerabilities.filter(v => v.repoId === repoId);
      systemContext += `\n\nCurrent repository context:\n- Name: ${repo.fullName}\n- Risk score: ${repo.riskScore ?? 'not yet scanned'}\n- Open vulnerabilities: ${vulns.filter(v => v.status === 'Open').length}\n- Critical (P0): ${vulns.filter(v => v.priorityLabel === 'P0_CRITICAL').length}`;
    }
  }

  try {
    const reply = await ai.chat(messages, systemContext);
    res.json({ reply, model: activeModel });
  } catch (err) {
    res.status(500).json({ error: 'AI chat failed', detail: err.message });
  }
});

// ── 8. Model info (ML classifiers + active LLM engine) ───────────────────────
router.get('/ai/model-info', requireAuth, (req, res) => {
  const activeModel = process.env.GEMINI_API_KEY
    ? (process.env.GEMINI_MODEL || 'gemini-1.5-flash')
    : (process.env.ANTHROPIC_API_KEY ? 'claude-sonnet-4-6' : null);

  res.json({
    ...getModelInfo(),
    llm: {
      provider: process.env.GEMINI_API_KEY ? 'Google Gemini' : (process.env.ANTHROPIC_API_KEY ? 'Anthropic Claude' : 'None'),
      model: activeModel,
      configured: Boolean(process.env.GEMINI_API_KEY || process.env.ANTHROPIC_API_KEY),
    },
  });
});

module.exports = router;
