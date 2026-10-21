const express = require('express');
const router = express.Router();
const { requireAuth, authenticateToken, requireAdmin, isRepoAuthorized } = require('../middleware/auth');
const admin = require('../modules/adminLayer');
const compliance = require('../modules/complianceEngine');
const { db } = require('../db/store');

// ── Compliance reports ────────────────────────────────────────────────────────

router.get('/repos/:id/compliance', requireAuth, async (req, res) => {
  try {
    await db.read();
    const repo = db.data.repositories.find(r => r.id === req.params.id);
    if (!repo || (req.user.role?.toLowerCase() !== 'admin' && repo.ownerId !== req.user.sub)) {
      return res.status(404).json({ error: 'Repository not found or access denied' });
    }

    const scans     = db.data.scan_jobs.filter(s => s.repoId === repo.id);
    const sboms     = db.data.sboms.filter(s => s.repoId === repo.id);
    const vulns     = db.data.vulnerabilities.filter(v => v.repoId === repo.id);
    const malicious = db.data.malicious_packages.filter(m => m.repoId === repo.id);

    const report = compliance.generateReport(repo, { scans, sboms, vulns, malicious });

    // Persist the report record
    db.data.compliance_reports = db.data.compliance_reports || [];
    const existing = db.data.compliance_reports.findIndex(r => r.repoId === repo.id);
    if (existing >= 0) db.data.compliance_reports[existing] = report;
    else db.data.compliance_reports.push(report);
    await db.write();

    res.json(report);
  } catch (err) {
    res.status(500).json({ error: 'Compliance report generation failed', detail: err.message });
  }
});

// Download compliance report as JSON
router.get(['/repos/:id/compliance/download', '/compliance/:id/download'], authenticateToken, async (req, res) => {
  await db.read();
  const repo = db.data.repositories?.find(r => r.id === req.params.id);
  if (!repo || !isRepoAuthorized(repo, req.user, db)) {
    return res.status(404).json({ error: 'Repository not found or access denied' });
  }
  let report = db.data.compliance_reports?.find(r => r.repoId === req.params.id);
  if (!report) {
    try {
      const scans     = db.data.scan_jobs?.filter(s => s.repoId === repo.id) || [];
      const sboms     = db.data.sboms?.filter(s => s.repoId === repo.id) || [];
      const vulns     = db.data.vulnerabilities?.filter(v => v.repoId === repo.id) || [];
      const malicious = db.data.malicious_packages?.filter(m => m.repoId === repo.id) || [];
      report = compliance.generateReport(repo, { scans, sboms, vulns, malicious });
      db.data.compliance_reports = db.data.compliance_reports || [];
      db.data.compliance_reports.push(report);
      await db.write();
    } catch (e) {
      return res.status(404).json({ error: 'No compliance report found — generate one first via GET /compliance' });
    }
  }
  res.setHeader('Content-Type', 'application/json');
  res.setHeader('Content-Disposition', `attachment; filename=securechain-compliance-${req.params.id}.json`);
  res.json(report);
});

// ── Organisations (Admin only) ────────────────────────────────────────────────

router.get('/admin/orgs', requireAuth, requireAdmin, async (req, res) => {
  res.json(await admin.listOrganisations());
});

router.post('/admin/orgs', requireAuth, requireAdmin, async (req, res) => {
  const { name } = req.body;
  if (!name) return res.status(400).json({ error: 'name required' });
  try {
    res.status(201).json(await admin.createOrganisation(name, req.user.sub));
  } catch (err) { res.status(409).json({ error: err.message }); }
});

router.patch('/admin/orgs/:id/plan', requireAuth, requireAdmin, async (req, res) => {
  const { plan } = req.body;
  try { res.json(await admin.updateOrganisationPlan(req.params.id, plan)); }
  catch (err) { res.status(400).json({ error: err.message }); }
});

// ── Users (Admin only) ────────────────────────────────────────────────────────

router.get('/admin/users', requireAuth, requireAdmin, async (req, res) => {
  res.json(await admin.listUsers());
});

router.patch('/admin/users/:id/role', requireAuth, requireAdmin, async (req, res) => {
  const { role } = req.body;
  try { res.json(await admin.setUserRole(req.params.id, role, req.user)); }
  catch (err) { res.status(400).json({ error: err.message }); }
});

router.post('/admin/users/invite', requireAuth, requireAdmin, async (req, res) => {
  const { email, role, orgId } = req.body;
  if (!email || !role) return res.status(400).json({ error: 'email and role required' });
  try { res.status(201).json(await admin.inviteUser(email, role, orgId, req.user)); }
  catch (err) { res.status(400).json({ error: err.message }); }
});

// ── Platform API keys (Admin only) ────────────────────────────────────────────

router.get('/admin/api-keys', requireAuth, requireAdmin, async (req, res) => {
  res.json(await admin.listApiKeys(req.user.sub));
});

router.post('/admin/api-keys', requireAuth, requireAdmin, async (req, res) => {
  const { name, scopes } = req.body;
  if (!name || !Array.isArray(scopes) || scopes.length === 0) {
    return res.status(400).json({ error: 'name and scopes[] required' });
  }
  try {
    const key = await admin.createApiKey(name, scopes, req.user.sub, req.user);
    // raw is returned ONCE here and never again
    res.status(201).json(key);
  } catch (err) { res.status(400).json({ error: err.message }); }
});

router.delete('/admin/api-keys/:id', requireAuth, requireAdmin, async (req, res) => {
  try { res.json(await admin.revokeApiKey(req.params.id, req.user)); }
  catch (err) { res.status(404).json({ error: err.message }); }
});

// ── Audit log (Admin only) ────────────────────────────────────────────────────

router.get('/admin/audit-log', requireAuth, requireAdmin, async (req, res) => {
  const { limit = 50, action, targetId, actorId } = req.query;
  res.json(await admin.getAuditLog({ limit: Number(limit), action, targetId, actorId }));
});

module.exports = router;

