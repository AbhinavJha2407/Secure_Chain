const express = require('express');
const router = express.Router();

const github = require('../modules/githubAuth');
const google = require('../modules/googleAuth');
const sbomEngine = require('../modules/sbomEngine');
const ecosystemResolvers = require('../modules/ecosystemResolvers');
const vulnEngine = require('../modules/vulnerabilityEngine');
const malwareAnalyzer = require('../modules/maliciousPackageAnalyzer');
const buildIntegrity = require('../modules/buildIntegrity');
const policyGate = require('../modules/policyGate');
const { requireAuth, authenticateToken, requireAdmin, requireRole, checkRole, requireOperationalRole, blockViewers, isRepoAuthorized, getAllowedRepoIds } = require('../middleware/auth');
const notifications = require('../modules/notificationService');
const { db, uuid, saveUser } = require('../db/store');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

// ---------- Auth ----------

router.get('/auth/github', (req, res) => {
  res.json({ authorizeUrl: github.buildAuthorizeUrl() });
});

// ── GitHub Account Linking (for Google users who want to connect GitHub) ──────
// Builds a GitHub OAuth URL that carries the current user's session token
// in the state param so the callback knows which account to link to.
router.get('/auth/github/link', requireAuth, (req, res) => {
  const jwt = require('jsonwebtoken');
  // Embed the current user's sub into state so callback can find them
  const state = jwt.sign(
    { sub: req.user.sub, mode: 'link' },
    process.env.JWT_SECRET,
    { expiresIn: '10m' }
  );
  const params = new URLSearchParams({
    client_id: process.env.GITHUB_CLIENT_ID,
    redirect_uri: process.env.GITHUB_CALLBACK_URL,
    scope: 'read:user user:email repo',
    state,
  });
  res.json({ authorizeUrl: `https://github.com/login/oauth/authorize?${params}` });
});

// The existing /auth/github/callback handles both login AND link —
// it checks the state to decide which mode it's in.
// ── Google OAuth ──────────────────────────────────────────────────────────────
router.get('/auth/google', (req, res) => {
  if (!process.env.GOOGLE_CLIENT_ID) {
    return res.status(503).json({ error: 'Google OAuth not configured — add GOOGLE_CLIENT_ID/SECRET to .env' });
  }
  res.json({ authorizeUrl: google.buildAuthorizeUrl() });
});

router.get('/auth/google/callback', async (req, res) => {
  try {
    const { code } = req.query;
    if (!code) return res.status(400).json({ error: 'Missing code' });
    const tokens = await google.exchangeCodeForTokens(code);
    const googleUser = await google.fetchGoogleUser(tokens.access_token);
    await db.read();
    const googleId = `google:${googleUser.id}`;
    let user = db.data.users.find(u => u.googleId === googleId);
    if (!user) {
      const isFirst = (db.data.users || []).length === 0;
      user = {
        id: uuid(),
        googleId,
        login: googleUser.email.split('@')[0],
        email: googleUser.email,
        avatar: googleUser.picture,
        name: googleUser.name,
        role: isFirst ? 'admin' : 'Developer',
        provider: 'google',
        createdAt: new Date().toISOString(),
      };
      db.data.users.push(user);
    }
    await db.write();

    const sessionToken = google.issueSessionToken(user);
    res.redirect(`${process.env.FRONTEND_URL}/auth/callback?token=${sessionToken}`);
  } catch (err) {
    res.status(500).json({ error: 'Google OAuth exchange failed', detail: err.message });
  }
});

router.get('/auth/github/callback', async (req, res) => {
  try {
    const { code, state } = req.query;
    if (!code) return res.status(400).json({ error: 'Missing code' });

    const accessToken = await github.exchangeCodeForToken(code);
    const ghUser = await github.fetchGitHubUser(accessToken);

    await db.read();

    // ── LINK MODE: state contains { sub, mode:'link' } ───────────────────────
    // A Google user clicked "Connect GitHub" — attach the GitHub token to their
    // existing account instead of creating a new session.
    let linkSub = null;
    if (state) {
      try {
        const jwt = require('jsonwebtoken');
        const decoded = jwt.verify(state, process.env.JWT_SECRET);
        if (decoded.mode === 'link') linkSub = decoded.sub;
      } catch { /* invalid state — fall through to normal login */ }
    }

    if (linkSub) {
      // Find the existing user (Google user) and attach their GitHub credentials
      const existingUser = db.data.users.find(u =>
        String(u.githubId) === linkSub || u.googleId === linkSub || u.id === linkSub
      );
      if (existingUser) {
        existingUser.githubId = ghUser.id;
        existingUser.githubLogin = ghUser.login;
        existingUser.githubAccessToken = accessToken;
        existingUser.githubLinkedAt = new Date().toISOString();
        await db.write();
        // Redirect back to frontend with a success flag — no new session token needed
        return res.redirect(`${process.env.FRONTEND_URL}/dashboard/repos?github_linked=1`);
      }
    }

    // ── NORMAL LOGIN MODE ─────────────────────────────────────────────────────
    let user = db.data.users.find((u) => u.githubId === ghUser.id);
    if (!user) {
      user = {
        id: uuid(),
        githubId: ghUser.id,
        login: ghUser.login,
        name: ghUser.name || ghUser.login,   // GitHub display name
        email: ghUser.email || null,
        avatar: ghUser.avatar_url,
        provider: 'github',
        role: 'admin',
        githubAccessToken: accessToken,
        createdAt: new Date().toISOString(),
      };
      db.data.users.push(user);
    } else {
      // Refresh avatar, name, and token on every login
      user.githubAccessToken = accessToken;
      user.avatar = ghUser.avatar_url;          // keep in sync with GitHub
      user.name   = ghUser.name || ghUser.login;
      user.provider = 'github';
      if (user.role && user.role.toLowerCase() === 'admin') user.role = 'admin';
    }
    await db.write();

    const sessionToken = github.issueSessionToken(user);
    res.redirect(`${process.env.FRONTEND_URL}/auth/callback?token=${sessionToken}`);
  } catch (err) {
    res.status(500).json({ error: 'GitHub OAuth exchange failed', detail: err.message });
  }
});

// ── Email/Password Registration (stores in Supabase & local DB) ───────────────
router.post('/auth/register', async (req, res) => {
  try {
    const { email, password, name } = req.body;
    if (!email || typeof email !== 'string' || !email.includes('@')) {
      return res.status(400).json({ error: 'Valid email address is required' });
    }
    if (!password || typeof password !== 'string' || password.length < 6) {
      return res.status(400).json({ error: 'Password must be at least 6 characters' });
    }

    const cleanEmail = email.trim().toLowerCase();
    await db.read();

    const existing = db.data.users.find(
      (u) => u.email && u.email.toLowerCase() === cleanEmail
    );
    if (existing) {
      return res.status(400).json({ error: 'An account with this email already exists. Please sign in.' });
    }

    const salt = await bcrypt.genSalt(10);
    const passwordHash = await bcrypt.hash(password, salt);
    const displayName = (name && name.trim()) || cleanEmail.split('@')[0];

    const newUser = {
      id: uuid(),
      email: cleanEmail,
      name: displayName,
      login: cleanEmail.split('@')[0],
      passwordHash,
      avatar: `https://api.dicebear.com/7.x/initials/svg?seed=${encodeURIComponent(displayName)}`,
      role: 'Developer',
      provider: 'email',
      createdAt: new Date().toISOString(),
    };

    await saveUser(newUser);

    const sessionToken = jwt.sign(
      { sub: newUser.id, email: newUser.email, name: newUser.name, role: newUser.role, provider: 'email' },
      process.env.JWT_SECRET,
      { expiresIn: '7d' }
    );

    const { passwordHash: _, ...safeUser } = newUser;
    safeUser.hasGitHubLinked = false;

    res.json({ token: sessionToken, user: safeUser });
  } catch (err) {
    console.error('Registration failed:', err);
    res.status(500).json({ error: 'Registration failed', detail: err.message });
  }
});

// ── Email/Password Login (verifies credentials against Supabase & local DB) ────
router.post('/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required' });
    }

    const cleanEmail = email.trim().toLowerCase();
    await db.read();

    let user = db.data.users.find(
      (u) => u.email && u.email.toLowerCase() === cleanEmail
    );

    // If not in local cache, check Supabase directly
    if (!user && db.supabase) {
      const { data } = await db.supabase.from('users').select('*').eq('email', cleanEmail).single();
      if (data) {
        user = {
          id: data.id,
          githubId: data.github_id,
          googleId: data.google_id,
          login: data.login,
          email: data.email,
          passwordHash: data.password_hash,
          avatar: data.avatar,
          name: data.name,
          role: data.role || 'Developer',
          provider: data.provider || 'email',
          createdAt: data.created_at,
        };
        db.data.users.push(user);
        await db.write();
      }
    }

    if (!user) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    if (!user.passwordHash) {
      return res.status(400).json({
        error: `This account was registered using ${user.provider || 'OAuth'}. Please sign in using the OAuth button below.`
      });
    }

    const isValid = await bcrypt.compare(password, user.passwordHash);
    if (!isValid) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    const userRole = (user.role || 'developer').toLowerCase();
    const sessionToken = jwt.sign(
      { sub: user.id, email: user.email, name: user.name, role: userRole, provider: user.provider || 'email' },
      process.env.JWT_SECRET,
      { expiresIn: '7d' }
    );

    const { passwordHash: _, githubAccessToken, ...safeUser } = user;
    safeUser.hasGitHubLinked = !!githubAccessToken;
    safeUser.role = userRole;

    res.json({ token: sessionToken, user: safeUser });
  } catch (err) {
    console.error('Login failed:', err);
    res.status(500).json({ error: 'Login failed', detail: err.message });
  }
});

// ── Auth & Supabase Status ───────────────────────────────────────────────────
router.get('/auth/status', (req, res) => {
  res.json({
    supabaseConnected: db.isSupabaseConnected(),
    hasSupabaseConfig: !!(process.env.SUPABASE_URL && (process.env.SUPABASE_SERVICE_ROLE_KEY || process.env.SUPABASE_ANON_KEY)),
    hasGithubOAuth: !!process.env.GITHUB_CLIENT_ID,
    hasGoogleOAuth: !!process.env.GOOGLE_CLIENT_ID,
  });
});

router.get('/auth/me', requireAuth, async (req, res) => {
  await db.read();
  const user = db.data.users.find(
    (u) =>
      String(u.githubId) === req.user.sub ||
      u.googleId === req.user.sub ||
      u.id === req.user.sub ||
      (req.user.email && u.email && u.email.toLowerCase() === req.user.email.toLowerCase())
  );
  if (!user) return res.status(404).json({ error: 'User not found' });
  const { githubAccessToken, passwordHash, ...safeUser } = user;
  safeUser.hasGitHubLinked = !!githubAccessToken;
  safeUser.role = (user.role || 'developer').toLowerCase();
  res.json(safeUser);
});

// ---------- Repositories ----------

// Connected repos (stored in SecureChain DB — survives across sessions)
router.get('/repos/connected', requireAuth, async (req, res) => {
  await db.read();
  const allowedRepoIds = getAllowedRepoIds(req.user, db);
  const repos = (db.data.repositories || []).filter((r) => allowedRepoIds.has(r.id));
  // Enrich with latest scan summary
  const enriched = repos.map((repo) => {
    const latestScan = db.data.scan_jobs
      .filter((s) => s.repoId === repo.id)
      .sort((a, b) => new Date(b.startedAt || 0) - new Date(a.startedAt || 0))[0];
    const vulns = db.data.vulnerabilities.filter((v) => v.repoId === repo.id);
    const malicious = db.data.malicious_packages.filter((m) => m.repoId === repo.id);
    return {
      ...repo,
      ciApiKey: undefined, // never expose the key
      lastScan: latestScan
        ? { id: latestScan.id, startedAt: latestScan.startedAt, gateVerdict: latestScan.gateVerdict }
        : null,
      openVulnCount: vulns.filter((v) => v.status === 'Open').length,
      criticalCount: vulns.filter((v) => v.priorityLabel === 'P0_CRITICAL').length,
      maliciousCount: malicious.length,
    };
  });
  res.json(enriched);
});

router.get('/repos', requireAuth, async (req, res) => {
  try {
    await db.read();
    const user = db.data.users.find((u) => String(u.githubId) === req.user.sub || u.googleId === req.user.sub || u.id === req.user.sub);
    if (!user?.githubAccessToken) {
      // Google user — return empty list with a flag instead of crashing
      return res.json({ repos: [], hasGitHubToken: false, message: 'Connect GitHub to browse repos, or add a repo manually below.' });
    }
    const repos = await github.listUserRepos(user.githubAccessToken);
    res.json({
      repos: repos.map((r) => ({
        id: r.id,
        name: r.name,
        fullName: r.full_name,
        private: r.private,
        defaultBranch: r.default_branch,
        language: r.language,
        updatedAt: r.updated_at,
      })),
      hasGitHubToken: true,
    });
  } catch (err) {
    res.status(500).json({ error: 'Failed to list repositories', detail: err.message });
  }
});

router.post('/repos/connect', requireAuth, requireOperationalRole, async (req, res) => {
  const { fullName, defaultBranch } = req.body;
  if (!fullName) return res.status(400).json({ error: 'fullName required' });
  await db.read();
  const repo = {
    id: uuid(),
    fullName,
    defaultBranch: defaultBranch || 'main',
    ownerId: req.user.sub,
    riskScore: null,
    lastScanId: null,
    createdAt: new Date().toISOString(),
  };
  db.data.repositories.push(repo);
  await db.write();
  res.status(201).json(repo);
});

// Scan by pasting manifest directly — works for ALL users (GitHub + Google)
router.post('/repos/scan-manifest', requireAuth, requireOperationalRole, async (req, res) => {
  const startedAt = Date.now();
  try {
    const { manifestContent, projectName = 'my-project', maxDepth = 2 } = req.body;
    if (!manifestContent) return res.status(400).json({ error: 'manifestContent is required' });

    let parsedManifest = null;
    let manifestCorrupted = false;
    let parseError = null;

    try {
      parsedManifest = typeof manifestContent === 'string' ? JSON.parse(manifestContent) : manifestContent;
    } catch (err) {
      manifestCorrupted = true;
      parseError = err.message;
    }

    let rootDeps = {};
    if (!manifestCorrupted && parsedManifest && typeof parsedManifest === 'object') {
      const deps = typeof parsedManifest.dependencies === 'object' && parsedManifest.dependencies !== null ? parsedManifest.dependencies : {};
      const devDeps = typeof parsedManifest.devDependencies === 'object' && parsedManifest.devDependencies !== null ? parsedManifest.devDependencies : {};
      const peerDeps = typeof parsedManifest.peerDependencies === 'object' && parsedManifest.peerDependencies !== null ? parsedManifest.peerDependencies : {};
      const optDeps = typeof parsedManifest.optionalDependencies === 'object' && parsedManifest.optionalDependencies !== null ? parsedManifest.optionalDependencies : {};
      rootDeps = { ...deps, ...devDeps, ...peerDeps, ...optDeps };
    }

    // Fallback regex extractor if JSON parse failed or no dependencies were parsed
    if (manifestCorrupted || Object.keys(rootDeps).length === 0) {
      const rawText = typeof manifestContent === 'string' ? manifestContent : JSON.stringify(manifestContent);
      const fallbackDeps = sbomEngine.extractDependenciesFromCorruptJson(rawText);
      if (Object.keys(fallbackDeps).length > 0) {
        rootDeps = { ...rootDeps, ...fallbackDeps };
        manifestCorrupted = true;
        if (!parseError) parseError = 'Manifest dependency structure invalid or unparseable';
      }
    }

    const tree = await sbomEngine.resolveDependencyTree(rootDeps, { maxDepth });
    const cycloneDX = sbomEngine.toCycloneDX(parsedManifest?.name || projectName, parsedManifest?.version, tree);
    const spdx = sbomEngine.toSPDX(parsedManifest?.name || projectName, parsedManifest?.version, tree);
    const [vulnerabilities, maliciousPackages] = await Promise.all([
      vulnEngine.correlateComponents(tree.components, 'npm'),
      malwareAnalyzer.analyzeComponents(tree.components, 'npm'),
    ]);

    const scanResult = {
      vulnerabilities,
      maliciousPackages,
      components: tree.components,
      manifestCorrupted,
      parseError,
    };
    const gate = policyGate.evaluateGate(scanResult);

    await db.read();
    let repo = db.data.repositories.find(r => r.fullName === projectName && r.ownerId === req.user.sub);
    if (!repo) {
      repo = { id: uuid(), fullName: projectName, defaultBranch: 'main', ownerId: req.user.sub, riskScore: null, lastScanId: null, createdAt: new Date().toISOString() };
      db.data.repositories.push(repo);
    }
    const scanJob = { id: uuid(), repoId: repo.id, status: 'completed', source: 'MANUAL_UPLOAD', startedAt: new Date(startedAt).toISOString(), durationMs: Date.now() - startedAt, gateVerdict: gate.verdict, componentCount: tree.components.length };
    db.data.scan_jobs.push(scanJob);
    const sbomRecord = { id: uuid(), repoId: repo.id, scanJobId: scanJob.id, components: tree.components, cycloneDX, spdx, createdAt: new Date().toISOString() };
    db.data.sboms.push(sbomRecord);
    for (const v of vulnerabilities) db.data.vulnerabilities.push({ id: uuid(), repoId: repo.id, scanJobId: scanJob.id, ...v, status: 'Open' });
    for (const m of maliciousPackages) db.data.malicious_packages.push({ id: uuid(), repoId: repo.id, scanJobId: scanJob.id, ...m });
    repo.lastScanId = scanJob.id;
    computeHarmnessAndRank(vulnerabilities, maliciousPackages, tree.components);
    repo.riskScore = (gate.verdict === 'BLOCKED' && gate.riskScore === 0)
      ? 0
      : computeRiskScore(vulnerabilities, maliciousPackages, tree.components, scanResult);
    await db.write();

    res.json({
      scanJob,
      riskScore: repo.riskScore,
      manifestCorrupted,
      parseError,
      repoId: repo.id,
      sbomSummary: { totalComponents: tree.components.length, resolved: tree.components.filter(c => c.resolved).length },
      vulnerabilities,
      maliciousPackages,
      sbomId: sbomRecord.id,
      components: tree.components,
      cycloneDX,
      spdx,
      gate: { verdict: gate.verdict, reasons: gate.reasons, riskScore: gate.riskScore },
      gateVerdict: gate.verdict
    });
  } catch (err) {
    res.status(500).json({ error: 'Scan failed', detail: err.message });
  }
});


router.get('/repos/:id', requireAuth, async (req, res) => {
  await db.read();
  const repo = db.data.repositories.find((r) => r.id === req.params.id);
  if (!repo || !isRepoAuthorized(repo, req.user, db)) {
    return res.status(404).json({ error: 'Repository not found or access denied' });
  }
  res.json(repo);
});

router.delete('/repos/:id', requireAuth, requireOperationalRole, async (req, res) => {
  await db.read();
  const idx = db.data.repositories.findIndex(
    (r) => r.id === req.params.id && (req.user.role?.toLowerCase() === 'admin' || r.ownerId === req.user.sub)
  );
  if (idx === -1) return res.status(404).json({ error: 'Repository not found or not owned by you' });
  const [removed] = db.data.repositories.splice(idx, 1);
  // Also clean up related scan data
  db.data.scan_jobs        = db.data.scan_jobs.filter(s => s.repoId !== req.params.id);
  db.data.sboms            = db.data.sboms.filter(s => s.repoId !== req.params.id);
  db.data.vulnerabilities  = db.data.vulnerabilities.filter(v => v.repoId !== req.params.id);
  db.data.malicious_packages = db.data.malicious_packages.filter(m => m.repoId !== req.params.id);
  await db.write();
  res.json({ deleted: true, id: req.params.id, fullName: removed.fullName });
});

// ---------- Scans (the core pipeline: SBOM -> Vuln Correlation -> Malicious Package Check) ----------

/**
 * Triggers a full scan of a connected repository's package.json:
 *  1. Fetch manifest from GitHub
 *  2. SBOM Engine resolves the transitive dependency graph (real npm registry)
 *  3. Vulnerability Correlation Engine queries OSV.dev + EPSS for each component
 *  4. Malicious Package Analyzer runs typosquat + heuristic checks
 *  5. Persist scan_job, sbom, vulnerabilities, malicious_packages records
 */
router.post('/repos/:id/scan', requireAuth, requireOperationalRole, async (req, res) => {
  const startedAt = Date.now();
  try {
    await db.read();
    const repo = db.data.repositories.find((r) => r.id === req.params.id);
    if (!repo || !isRepoAuthorized(repo, req.user, db)) {
      return res.status(404).json({ error: 'Repository not found or access denied' });
    }

    const user = db.data.users.find((u) => String(u.githubId) === req.user.sub || u.googleId === req.user.sub || u.id === req.user.sub);

    if (!user?.githubAccessToken) {
      return res.status(400).json({
        error: 'GitHub access required to scan this repository',
        detail: 'Connect your GitHub account first, or use the Paste Manifest tab to scan directly without GitHub.',
        hint: 'MISSING_GITHUB_TOKEN',
      });
    }

    const [owner, repoName] = repo.fullName.split('/');
    const manifestPath = req.body.manifestPath || 'package.json';

    let manifest;
    try {
      manifest = await github.fetchManifest(user.githubAccessToken, owner, repoName, manifestPath);
    } catch (fetchErr) {
      return res.status(400).json({
        error: 'Could not fetch manifest from GitHub',
        detail: fetchErr.message,
        hint: 'Make sure the repository exists, is accessible, and has a package.json on its default branch.',
      });
    }

    let tree, ecosystem;
    let manifestCorrupted = false;
    let parseError = null;

    if (manifestPath === 'package.json') {
      let parsedManifest = manifest;
      if (typeof manifest === 'string') {
        try {
          parsedManifest = JSON.parse(manifest);
        } catch (e) {
          manifestCorrupted = true;
          parseError = e.message;
        }
      }

      let rootDeps = {};
      if (!manifestCorrupted && parsedManifest && typeof parsedManifest === 'object') {
        const deps = typeof parsedManifest.dependencies === 'object' && parsedManifest.dependencies !== null ? parsedManifest.dependencies : {};
        const devDeps = typeof parsedManifest.devDependencies === 'object' && parsedManifest.devDependencies !== null ? parsedManifest.devDependencies : {};
        const peerDeps = typeof parsedManifest.peerDependencies === 'object' && parsedManifest.peerDependencies !== null ? parsedManifest.peerDependencies : {};
        const optDeps = typeof parsedManifest.optionalDependencies === 'object' && parsedManifest.optionalDependencies !== null ? parsedManifest.optionalDependencies : {};
        rootDeps = { ...deps, ...devDeps, ...peerDeps, ...optDeps };
      }

      if (manifestCorrupted || Object.keys(rootDeps).length === 0) {
        const rawText = typeof manifest === 'string' ? manifest : JSON.stringify(manifest);
        const fallback = sbomEngine.extractDependenciesFromCorruptJson(rawText);
        if (Object.keys(fallback).length > 0) {
          rootDeps = { ...rootDeps, ...fallback };
          manifestCorrupted = true;
          if (!parseError) parseError = 'Corrupt dependency section in manifest';
        }
      }

      tree = await sbomEngine.resolveDependencyTree(rootDeps, { maxDepth: req.body.maxDepth ?? 2 });
      ecosystem = 'npm';
    } else {
      const rawContent = typeof manifest === 'string' ? manifest : JSON.stringify(manifest);
      const result = await ecosystemResolvers.resolveFromManifest(manifestPath.split('/').pop(), rawContent, { maxDepth: req.body.maxDepth ?? 2 });
      tree = result;
      ecosystem = result.ecosystem || 'npm';
      if (result.manifestCorrupted) {
        manifestCorrupted = true;
        parseError = result.parseError;
      }
    }

    const osvEcosystem = ecosystemResolvers.ecosystemToOSV(ecosystem);

    const cycloneDX = sbomEngine.toCycloneDX(manifest?.name || repoName, manifest?.version, tree);
    const spdx = sbomEngine.toSPDX(manifest?.name || repoName, manifest?.version, tree);

    // Diff against the previous SBOM for this repo, if one exists
    const previousSbom = db.data.sboms
      .filter((s) => s.repoId === repo.id)
      .sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt))[0];
    const diff = previousSbom ? sbomEngine.diffSBOMs(previousSbom.components, tree.components) : null;

    const [vulnFindings, malwareFindings] = await Promise.all([
      vulnEngine.correlateComponents(tree.components, osvEcosystem),
      malwareAnalyzer.analyzeComponents(tree.components, ecosystem),
    ]);

    const scanResult = {
      vulnerabilities: vulnFindings,
      maliciousPackages: malwareFindings,
      components: tree.components,
      manifestCorrupted,
      parseError,
    };
    const gate = policyGate.evaluateGate(scanResult);

    const scanJob = {
      id: uuid(),
      repoId: repo.id,
      status: 'completed',
      gateVerdict: gate.verdict,
      startedAt: new Date(startedAt).toISOString(),
      durationMs: Date.now() - startedAt,
      componentCount: tree.components.length,
      vulnerabilityCount: vulnFindings.length,
      maliciousFindingCount: malwareFindings.length,
    };
    db.data.scan_jobs.push(scanJob);

    const sbomRecord = {
      id: uuid(),
      repoId: repo.id,
      scanJobId: scanJob.id,
      components: tree.components,
      cycloneDX,
      spdx,
      createdAt: new Date().toISOString(),
    };
    db.data.sboms.push(sbomRecord);

    for (const v of vulnFindings) {
      db.data.vulnerabilities.push({ id: uuid(), repoId: repo.id, scanJobId: scanJob.id, ...v, status: 'Open' });
    }
    for (const m of malwareFindings) {
      db.data.malicious_packages.push({ id: uuid(), repoId: repo.id, scanJobId: scanJob.id, ...m });
    }

    repo.lastScanId = scanJob.id;
    computeHarmnessAndRank(vulnFindings, malwareFindings, tree.components);
    repo.riskScore = (gate.verdict === 'BLOCKED' && gate.riskScore === 0)
      ? 0
      : computeRiskScore(vulnFindings, malwareFindings, tree.components, scanResult);
    await db.write();

    // Trigger non-blocking scan alerts for qualifying findings
    notifications.dispatchScanAlerts(repo, vulnFindings, malwareFindings, scanJob).catch((e) => {
      console.warn('[scan] Failed to dispatch scan alerts:', e.message);
    });

    res.json({
      scanJob,
      riskScore: repo.riskScore,
      manifestCorrupted,
      parseError,
      gate: { verdict: gate.verdict, reasons: gate.reasons, riskScore: gate.riskScore },
      sbomSummary: { totalComponents: tree.components.length, resolved: tree.components.filter((c) => c.resolved).length },
      diff,
      vulnerabilities: vulnFindings,
      maliciousPackages: malwareFindings,
      sbomId: sbomRecord.id,
    });
  } catch (err) {
    res.status(500).json({ error: 'Scan failed', detail: err.message });
  }
});

/**
 * Composite Harmness & Damage Potential Ranking Engine
 * Formula:
 * Harmness Score = min(100, round((CVSS Base Score * 6.0) + (Malicious Probability * 40.0) + Depth Penalty))
 */
function computeHarmnessAndRank(vulnFindings = [], malwareFindings = [], components = []) {
  const componentDepthMap = new Map();
  for (const c of components) {
    componentDepthMap.set(c.name || c.packageName, c.depth ?? 0);
  }

  // Process Vulnerability Findings
  for (const v of vulnFindings) {
    const rawCvss = typeof v.severity === 'number' && !isNaN(v.severity) ? v.severity : parseFloat(v.severity);
    const cvss = (!isNaN(rawCvss) && rawCvss >= 0)
      ? rawCvss
      : (v.priorityLabel === 'P0_CRITICAL' ? 9.5 : v.priorityLabel === 'P1_HIGH' ? 7.5 : v.priorityLabel === 'P2_MEDIUM' ? 5.0 : 2.5);

    const depth = componentDepthMap.get(v.component) ?? 1;
    const depthPenalty = depth === 0 ? 10 : 5; // +10 for root direct deps, +5 for transitive
    const harmness = Math.min(100, Math.max(10, Math.round(cvss * 7.0 + depthPenalty)));

    v.harmnessScore = harmness;
    v.riskLevel = harmness >= 75 ? 'CRITICAL' : harmness >= 50 ? 'HIGH' : harmness >= 25 ? 'MEDIUM' : 'LOW';
    v.damagePotential = harmness >= 75 ? 'Severe (Project Takeover / RCE Risk)' : harmness >= 50 ? 'High (Data Breach / Denial of Service)' : 'Moderate (Localized Feature Disruption)';
  }

  // Process Malware Findings
  for (const m of malwareFindings) {
    const rawProb = typeof m.maliciousProbability === 'number' && !isNaN(m.maliciousProbability) ? m.maliciousProbability : parseFloat(m.maliciousProbability);
    const prob = (!isNaN(rawProb) && rawProb >= 0) ? rawProb : (m.confidence === 'high' ? 0.90 : 0.60);
    const depth = componentDepthMap.get(m.packageName) ?? 0;
    const depthPenalty = depth === 0 ? 10 : 5;
    const baseOffset = m.severity === 'critical' ? 50 : m.severity === 'high' ? 40 : 25;
    const harmness = Math.min(100, Math.max(20, Math.round(prob * 35.0 + depthPenalty + baseOffset)));

    m.harmnessScore = harmness;
    m.riskLevel = harmness >= 75 ? 'CRITICAL' : harmness >= 50 ? 'HIGH' : 'MEDIUM';
    m.damagePotential = m.type === 'TYPOSQUAT'
      ? `Severe (Typosquatting Attack against '${m.suspectedTarget || 'legitimate library'}')`
      : m.type === 'HEURISTIC_INSTALL_SCRIPT'
      ? 'High (Suspicious Script Execution in Dependency Lifecycle)'
      : m.severity === 'critical'
      ? 'Critical (Confirmed Malicious Package / Exfiltration Risk)'
      : 'Moderate (Unverified Publisher / Metadata Anomaly)';
  }

  // Sort Vulnerabilities in descending order of harmness score & assign Damage Rank
  vulnFindings.sort((a, b) => (b.harmnessScore || 0) - (a.harmnessScore || 0));
  vulnFindings.forEach((v, idx) => { v.damageRank = idx + 1; });

  // Sort Malware Findings in descending order of harmness score & assign Damage Rank
  malwareFindings.sort((a, b) => (b.harmnessScore || 0) - (a.harmnessScore || 0));
  malwareFindings.forEach((m, idx) => { m.damageRank = idx + 1; });
}

function computeRiskScore(vulnFindings = [], malwareFindings = [], components = [], scanResult = {}) {
  // If manifest was corrupted, had parse errors, corrupt component entries, or zero components, risk score is immediately 0
  if (
    scanResult.manifestCorrupted === true ||
    Boolean(scanResult.parseError) ||
    (components || []).some((c) => c.corruptEntry === true) ||
    (components || []).length === 0
  ) {
    return 0;
  }

  computeHarmnessAndRank(vulnFindings, malwareFindings, components);

  let deduction = 0;
  for (const v of vulnFindings) {
    const h = (typeof v.harmnessScore === 'number' && !isNaN(v.harmnessScore)) ? v.harmnessScore : 50;
    deduction += Math.round(h * 0.12);
  }
  for (const m of malwareFindings) {
    const h = (typeof m.harmnessScore === 'number' && !isNaN(m.harmnessScore)) ? m.harmnessScore : 80;
    deduction += Math.round(h * 0.25);
  }
  if (isNaN(deduction)) deduction = 0;
  return Math.max(0, Math.min(100, 100 - deduction));
}

// ---------- SBOM endpoints ----------

router.get('/sboms', requireAuth, async (req, res) => {
  await db.read();
  const allowedRepoIds = getAllowedRepoIds(req.user, db);
  const repoIdFilter = req.query.repoId;
  let sboms = (db.data.sboms || []).filter((s) => allowedRepoIds.has(s.repoId));
  if (repoIdFilter) {
    if (!allowedRepoIds.has(repoIdFilter)) {
      return res.status(404).json({ error: 'Repository not found or access denied' });
    }
    sboms = sboms.filter(s => s.repoId === repoIdFilter);
  }
  // Sort latest first
  sboms = [...sboms].sort((a, b) => new Date(b.createdAt || 0) - new Date(a.createdAt || 0));

  const enriched = sboms.map(s => {
    const repo = db.data.repositories.find(r => r.id === s.repoId);
    const scanJob = db.data.scan_jobs.find(j => j.id === s.scanJobId);
    const vulns = db.data.vulnerabilities.filter(v => v.scanJobId === s.scanJobId);
    const malicious = db.data.malicious_packages.filter(m => m.scanJobId === s.scanJobId);
    return {
      id: s.id,
      repoId: s.repoId,
      repoName: repo ? repo.fullName : 'Unknown Project',
      scanJobId: s.scanJobId,
      createdAt: s.createdAt,
      componentCount: s.components ? s.components.length : 0,
      resolvedCount: s.components ? s.components.filter(c => c.resolved !== false).length : 0,
      vulnerabilityCount: vulns.length,
      maliciousCount: malicious.length,
      gateVerdict: scanJob ? scanJob.gateVerdict : null,
    };
  });
  res.json(enriched);
});

router.get('/sboms/:id', requireAuth, async (req, res) => {
  await db.read();
  const sbom = db.data.sboms.find((s) => s.id === req.params.id);
  if (!sbom) return res.status(404).json({ error: 'SBOM not found' });
  const repo = db.data.repositories.find((r) => r.id === sbom.repoId);
  if (!repo || !isRepoAuthorized(repo, req.user, db)) {
    return res.status(404).json({ error: 'SBOM not found or access denied' });
  }
  const scanJob = db.data.scan_jobs.find((j) => j.id === sbom.scanJobId);
  const vulns = db.data.vulnerabilities.filter((v) => v.scanJobId === sbom.scanJobId);
  const malicious = db.data.malicious_packages.filter((m) => m.scanJobId === sbom.scanJobId);

  // Compute diff against previous SBOM for same repo if available
  const previousSbom = db.data.sboms
    .filter((s) => s.repoId === sbom.repoId && s.id !== sbom.id && new Date(s.createdAt) < new Date(sbom.createdAt))
    .sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt))[0];
  const diff = previousSbom ? sbomEngine.diffSBOMs(previousSbom.components, sbom.components) : null;

  res.json({
    ...sbom,
    repoName: repo ? repo.fullName : 'Unknown Project',
    riskScore: repo ? repo.riskScore : null,
    gateVerdict: scanJob ? scanJob.gateVerdict : null,
    vulnerabilities: vulns,
    maliciousPackages: malicious,
    diff,
    sbomSummary: {
      totalComponents: sbom.components ? sbom.components.length : 0,
      resolved: sbom.components ? sbom.components.filter((c) => c.resolved !== false).length : 0,
    },
  });
});

router.get('/repos/:id/sbom', requireAuth, async (req, res) => {
  await db.read();
  const repo = db.data.repositories.find((r) => r.id === req.params.id);
  if (!repo || !isRepoAuthorized(repo, req.user, db)) {
    return res.status(404).json({ error: 'Repository not found or access denied' });
  }

  const sbom = db.data.sboms
    .filter((s) => s.repoId === req.params.id)
    .sort((a, b) => new Date(b.createdAt || 0) - new Date(a.createdAt || 0))[0];

  if (!sbom) return res.status(404).json({ error: 'No SBOM generated for this repository yet' });

  const scanJob = db.data.scan_jobs.find((j) => j.id === sbom.scanJobId);
  const vulns = db.data.vulnerabilities.filter((v) => v.scanJobId === sbom.scanJobId);
  const malicious = db.data.malicious_packages.filter((m) => m.scanJobId === sbom.scanJobId);

  // Compute diff against previous SBOM for same repo if available
  const previousSbom = db.data.sboms
    .filter((s) => s.repoId === sbom.repoId && s.id !== sbom.id && new Date(s.createdAt) < new Date(sbom.createdAt))
    .sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt))[0];
  const diff = previousSbom ? sbomEngine.diffSBOMs(previousSbom.components, sbom.components) : null;

  res.json({
    ...sbom,
    repoName: repo.fullName,
    riskScore: repo.riskScore,
    gateVerdict: scanJob ? scanJob.gateVerdict : null,
    vulnerabilities: vulns,
    maliciousPackages: malicious,
    diff,
    sbomSummary: {
      totalComponents: sbom.components ? sbom.components.length : 0,
      resolved: sbom.components ? sbom.components.filter((c) => c.resolved !== false).length : 0,
    },
  });
});

router.get('/sboms/:id/export', authenticateToken, async (req, res) => {
  await db.read();
  const sbom = db.data.sboms.find((s) => s.id === req.params.id);
  if (!sbom) return res.status(404).json({ error: 'Not found' });
  const repo = db.data.repositories.find((r) => r.id === sbom.repoId);
  if (!repo || !isRepoAuthorized(repo, req.user, db)) {
    return res.status(404).json({ error: 'SBOM not found or access denied' });
  }
  const format = req.query.format === 'spdx' ? 'spdx' : 'cyclonedx';
  res.setHeader('Content-Type', 'application/json');
  res.setHeader('Content-Disposition', `attachment; filename=sbom-${sbom.id}-${format}.json`);
  res.json(format === 'spdx' ? sbom.spdx : sbom.cycloneDX);
});

router.get(['/vulnerabilities/:repoId/export', '/vulnerabilities/export'], authenticateToken, async (req, res) => {
  await db.read();
  const allowedRepoIds = getAllowedRepoIds(req.user, db);
  const repoId = req.params.repoId;
  const vulns = db.data.vulnerabilities || [];
  let list = [];
  if (repoId && repoId !== 'all') {
    if (!allowedRepoIds.has(repoId)) {
      return res.status(404).json({ error: 'Repository not found or access denied' });
    }
    list = vulns.filter((v) => v.repoId === repoId);
  } else {
    list = vulns.filter((v) => allowedRepoIds.has(v.repoId));
  }
  res.setHeader('Content-Type', 'application/json');
  res.setHeader('Content-Disposition', `attachment; filename=vulnerabilities-report-${repoId || 'all'}.json`);
  res.json({
    generatedAt: new Date().toISOString(),
    repoId: repoId || 'all',
    count: list.length,
    vulnerabilities: list,
  });
});

// ---------- Vulnerability detail lookups (NVD / GitHub Advisory supplementary) ----------

router.get('/vulnerabilities/:cveId/nvd', requireAuth, async (req, res) => {
  const result = await vulnEngine.queryNVD(req.params.cveId, process.env.NVD_API_KEY);
  if (!result) return res.status(404).json({ error: 'Not found in NVD or lookup failed' });
  res.json(result);
});

router.get('/vulnerabilities/:repoId/list', requireAuth, async (req, res) => {
  await db.read();
  const allowedRepoIds = getAllowedRepoIds(req.user, db);
  const repoId = req.params.repoId;
  const vulns = db.data.vulnerabilities || [];
  if (repoId && repoId !== 'all') {
    if (!allowedRepoIds.has(repoId)) {
      return res.status(404).json({ error: 'Repository not found or access denied' });
    }
    return res.json(vulns.filter((v) => v.repoId === repoId));
  }
  res.json(vulns.filter((v) => allowedRepoIds.has(v.repoId)));
});

router.get('/malicious-packages/:repoId', requireAuth, async (req, res) => {
  await db.read();
  const allowedRepoIds = getAllowedRepoIds(req.user, db);
  const repoId = req.params.repoId;
  const malicious = db.data.malicious_packages || [];
  if (repoId && repoId !== 'all') {
    if (!allowedRepoIds.has(repoId)) {
      return res.status(404).json({ error: 'Repository not found or access denied' });
    }
    return res.json(malicious.filter((m) => m.repoId === repoId));
  }
  res.json(malicious.filter((m) => allowedRepoIds.has(m.repoId)));
});

router.patch('/vulnerabilities/:id/status', requireAuth, requireOperationalRole, async (req, res) => {
  const { status, vexJustification } = req.body;
  const valid = ['Open', 'In Progress', 'Resolved', 'Accepted Risk'];
  if (!valid.includes(status)) return res.status(400).json({ error: `status must be one of ${valid.join(', ')}` });
  await db.read();
  const finding = db.data.vulnerabilities.find((v) => v.id === req.params.id);
  if (!finding) return res.status(404).json({ error: 'Not found' });
  const repo = db.data.repositories.find((r) => r.id === finding.repoId);
  if (!repo || !isRepoAuthorized(repo, req.user, db)) {
    return res.status(404).json({ error: 'Finding not found or access denied' });
  }
  finding.status = status;
  if (status === 'Accepted Risk') finding.vex = { justification: vexJustification || 'No justification provided', acceptedAt: new Date().toISOString() };
  await db.write();
  res.json(finding);
});

// ---------- Build integrity ----------

router.post('/repos/:id/verify-build', requireAuth, requireOperationalRole, async (req, res) => {
  await db.read();
  const repo = db.data.repositories.find((r) => r.id === req.params.id);
  if (!repo || !isRepoAuthorized(repo, req.user, db)) {
    return res.status(404).json({ error: 'Repository not found or access denied' });
  }
  const { currentContent, baselineHash } = req.body;
  if (!currentContent) return res.status(400).json({ error: 'currentContent required' });
  const verdict = buildIntegrity.verifyBuildIntegrity(currentContent, baselineHash);
  res.json(verdict);
});

router.post('/repos/:id/set-baseline', requireAuth, requireOperationalRole, async (req, res) => {
  await db.read();
  const repo = db.data.repositories.find((r) => r.id === req.params.id);
  if (!repo || !isRepoAuthorized(repo, req.user, db)) {
    return res.status(404).json({ error: 'Repository not found or access denied' });
  }
  const { content } = req.body;
  if (!content) return res.status(400).json({ error: 'content required' });
  res.json({ baselineHash: buildIntegrity.setBaseline(content) });
});

// ---------- Onboarding ----------

/**
 * Called once after first login. Saves the user's mode (solo/team) with
 * project details, team creation metadata, or join request creation.
 */
router.post('/auth/complete-onboarding', requireAuth, async (req, res) => {
  try {
    await db.read();
    const user = db.data.users.find(
      (u) => String(u.githubId) === req.user.sub || u.googleId === req.user.sub || u.id === req.user.sub
    );
    if (!user) return res.status(404).json({ error: 'User not found' });

    const {
      mode,
      // Solo fields
      projectTitle,
      projectIntro,
      primaryStack,
      scanFrequency,
      // Team create fields
      teamName,
      projectName,
      projectDescription,
      category,
      securityPolicy,
      // Team join fields
      targetTeamId,
      requestNote,
      inviteToken,
    } = req.body;

    if (mode === 'solo') {
      user.mode = 'solo';
      user.onboardingComplete = true;
      user.soloProject = {
        projectTitle: projectTitle || 'My Core Application',
        projectIntro: projectIntro || 'Primary codebase security scanning',
        primaryStack: primaryStack || 'Node.js (npm)',
        scanFrequency: scanFrequency || 'realtime',
        updatedAt: new Date().toISOString(),
      };

      // Create an initial default repo for the solo user if projectTitle provided
      if (projectTitle) {
        const repoName = (projectTitle || 'my-project').toLowerCase().replace(/\s+/g, '-');
        let existingRepo = db.data.repositories.find((r) => r.ownerId === req.user.sub && r.fullName === repoName);
        if (!existingRepo) {
          db.data.repositories.push({
            id: uuid(),
            fullName: repoName,
            description: projectIntro || 'Solo Developer Security Workspace',
            defaultBranch: 'main',
            ownerId: req.user.sub,
            riskScore: 100,
            lastScanId: null,
            createdAt: new Date().toISOString(),
          });
        }
      }

      await db.write();
      return res.json({ ok: true, mode: 'solo', soloProject: user.soloProject });
    }

    if (mode === 'team_create' || mode === 'team') {
      if (inviteToken) {
        return res.json({ ok: true, mode: 'team', requiresInvite: true });
      }
      const finalTeamName = teamName || req.body.name;
      if (!finalTeamName) return res.status(400).json({ error: 'Team name is required' });

      const admin = require('../modules/adminLayer');
      const org = await admin.createOrganisation(finalTeamName.trim(), user.id);

      org.category = category || 'Cybersecurity / General';
      org.securityPolicy = securityPolicy || 'Strict Zero-Trust (Block P0/P1)';
      org.description = projectDescription || `${finalTeamName} Security Operations`;

      user.mode = 'team';
      user.orgId = org.id;
      user.role = 'Admin';
      user.onboardingComplete = true;

      // Create initial project repo under this organization
      const initProjectName = (projectName || `${finalTeamName}-core`).toLowerCase().replace(/\s+/g, '-');
      db.data.repositories.push({
        id: uuid(),
        fullName: initProjectName,
        description: projectDescription || 'Primary Team Core Security Project',
        defaultBranch: 'main',
        ownerId: req.user.sub,
        orgId: org.id,
        riskScore: 100,
        lastScanId: null,
        createdAt: new Date().toISOString(),
      });

      await db.write();
      return res.json({ ok: true, mode: 'team', org });
    }

    if (mode === 'team_join_request') {
      if (!targetTeamId) return res.status(400).json({ error: 'Target Team ID is required to send join request' });

      const org = db.data.organisations.find((o) => o.id === targetTeamId);
      if (!org) return res.status(404).json({ error: 'Target team not found' });

      db.data.team_requests = db.data.team_requests || [];
      const existingReq = db.data.team_requests.find(
        (r) => r.orgId === targetTeamId && r.userId === user.id && r.status === 'pending'
      );
      if (existingReq) {
        return res.json({ ok: true, pendingRequest: true, request: existingReq, message: 'Join request is already pending admin review.' });
      }

      const newRequest = {
        id: uuid(),
        orgId: targetTeamId,
        orgName: org.name,
        userId: user.id,
        userName: user.name || user.login || 'Developer',
        userEmail: user.email || `${user.login}@users.noreply.github.com`,
        userAvatar: user.avatar || null,
        note: requestNote || 'Requesting to join team workspace',
        status: 'pending',
        requestedAt: new Date().toISOString(),
      };

      db.data.team_requests.push(newRequest);
      user.pendingJoinOrgId = targetTeamId;
      // Leave onboarding incomplete until admin approves
      await db.write();

      return res.json({
        ok: true,
        pendingRequest: true,
        request: newRequest,
        message: `Join request sent to ${org.name} Admin for approval.`,
      });
    }

    return res.status(400).json({ error: 'Invalid onboarding mode provided' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ---------- Public / Team Directory & Join Requests ----------

/** GET /teams/search — search discoverable teams */
router.get('/teams/search', requireAuth, async (req, res) => {
  try {
    await db.read();
    const query = (req.query.query || '').trim().toLowerCase();

    let orgs = db.data.organisations || [];
    if (query) {
      orgs = orgs.filter((o) => o.name.toLowerCase().includes(query) || (o.slug && o.slug.includes(query)));
    }

    const members = db.data.users || [];
    const formatted = orgs.map((org) => {
      const memberCount = members.filter((u) => u.orgId === org.id).length;
      return {
        id: org.id,
        name: org.name,
        slug: org.slug,
        category: org.category || 'Engineering',
        securityPolicy: org.securityPolicy || 'Standard OWASP',
        description: org.description || 'SecureChain Managed Team Workspace',
        memberCount: Math.max(memberCount, 1),
        plan: org.plan || 'free',
        createdAt: org.createdAt,
      };
    });

    res.json(formatted);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/** POST /teams/:teamId/request-join — request to join a team directly */
router.post('/teams/:teamId/request-join', requireAuth, async (req, res) => {
  try {
    await db.read();
    const user = db.data.users.find(
      (u) => String(u.githubId) === req.user.sub || u.googleId === req.user.sub || u.id === req.user.sub
    );
    if (!user) return res.status(404).json({ error: 'User not found' });

    const org = (db.data.organisations || []).find((o) => o.id === req.params.teamId);
    if (!org) return res.status(404).json({ error: 'Team not found' });

    db.data.team_requests = db.data.team_requests || [];
    const existing = db.data.team_requests.find(
      (r) => r.orgId === org.id && r.userId === user.id && r.status === 'pending'
    );
    if (existing) {
      return res.json({ ok: true, request: existing, message: 'Request already pending' });
    }

    const requestRecord = {
      id: uuid(),
      orgId: org.id,
      orgName: org.name,
      userId: user.id,
      userName: user.name || user.login || 'Developer',
      userEmail: user.email || `${user.login}@securechain.dev`,
      userAvatar: user.avatar || null,
      note: req.body.note || 'Requesting team membership',
      status: 'pending',
      requestedAt: new Date().toISOString(),
    };

    db.data.team_requests.push(requestRecord);
    user.pendingJoinOrgId = org.id;
    await db.write();

    res.json({ ok: true, request: requestRecord });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/** GET /team/requests — Admin list of pending join requests for their team */
router.get('/team/requests', requireAuth, requireAdmin, async (req, res) => {
  try {
    await db.read();
    const user = db.data.users.find(
      (u) => String(u.githubId) === req.user.sub || u.googleId === req.user.sub || u.id === req.user.sub
    );
    if (!user) return res.status(404).json({ error: 'User not found' });
    if (!user.orgId) return res.json([]);

    const requests = (db.data.team_requests || []).filter(
      (r) => r.orgId === user.orgId && r.status === 'pending'
    );
    res.json(requests);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/** POST /team/requests/:requestId/respond — Approve or Reject a join request (Admin only) */
router.post('/team/requests/:requestId/respond', requireAuth, requireAdmin, async (req, res) => {
  try {
    await db.read();
    const actor = db.data.users.find(
      (u) => String(u.githubId) === req.user.sub || u.googleId === req.user.sub || u.id === req.user.sub
    );
    if (!actor || actor.role?.toLowerCase() !== 'admin') {
      return res.status(403).json({ error: 'Only team Admins can approve or reject join requests' });
    }

    db.data.team_requests = db.data.team_requests || [];
    const requestItem = db.data.team_requests.find((r) => r.id === req.params.requestId);
    if (!requestItem) return res.status(404).json({ error: 'Join request not found' });

    const { action, role = 'Developer' } = req.body; // action: 'approve' | 'reject'
    const targetUser = db.data.users.find((u) => u.id === requestItem.userId);

    if (action === 'approve') {
      requestItem.status = 'approved';
      requestItem.respondedAt = new Date().toISOString();
      requestItem.respondedBy = actor.id;

      if (targetUser) {
        targetUser.orgId = actor.orgId;
        targetUser.role = role;
        targetUser.mode = 'team';
        targetUser.onboardingComplete = true;
        targetUser.pendingJoinOrgId = null;
      }
    } else if (action === 'reject') {
      requestItem.status = 'rejected';
      requestItem.respondedAt = new Date().toISOString();
      requestItem.respondedBy = actor.id;

      if (targetUser) {
        targetUser.pendingJoinOrgId = null;
      }
    } else {
      return res.status(400).json({ error: 'Action must be "approve" or "reject"' });
    }

    await db.write();
    res.json({ ok: true, action, requestId: requestItem.id });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ---------- Invite acceptance ----------

/**
 * GET /invite/:token — validate token and return invite details (email, role, org)
 */
router.get('/invite/:token', async (req, res) => {
  try {
    await db.read();
    const invite = (db.data.invites || []).find(
      (i) => i.token === req.params.token && i.status === 'pending'
    );
    if (!invite) return res.status(404).json({ error: 'Invite not found or already used' });
    if (new Date(invite.expiresAt) < new Date()) {
      return res.status(410).json({ error: 'Invite has expired' });
    }
    const org = db.data.organisations.find((o) => o.id === invite.orgId);
    res.json({ email: invite.email, role: invite.role, orgName: org?.name, orgId: invite.orgId });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/**
 * POST /invite/:token/accept — accept invite, link user to org
 */
router.post('/invite/:token/accept', requireAuth, async (req, res) => {
  try {
    await db.read();
    const invite = (db.data.invites || []).find(
      (i) => i.token === req.params.token && i.status === 'pending'
    );
    if (!invite) return res.status(404).json({ error: 'Invite not found or already used' });
    if (new Date(invite.expiresAt) < new Date()) {
      return res.status(410).json({ error: 'Invite has expired' });
    }

    const user = db.data.users.find(
      (u) => String(u.githubId) === req.user.sub || u.googleId === req.user.sub || u.id === req.user.sub
    );
    if (!user) return res.status(404).json({ error: 'User not found' });

    // Link user to organisation
    user.orgId = invite.orgId;
    user.role = invite.role;
    user.mode = 'team';
    user.onboardingComplete = true;

    // Mark invite as used
    invite.status = 'accepted';
    invite.acceptedBy = user.id;
    invite.acceptedAt = new Date().toISOString();

    await db.write();

    const org = db.data.organisations.find((o) => o.id === invite.orgId);
    res.json({ ok: true, org, role: invite.role });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ---------- Team / Org ----------

/** GET /team/info — returns the current user's organisation details */
router.get('/team/info', requireAuth, async (req, res) => {
  try {
    await db.read();
    const user = db.data.users.find(
      (u) => String(u.githubId) === req.user.sub || u.googleId === req.user.sub || u.id === req.user.sub
    );
    if (!user) return res.status(404).json({ error: 'User not found' });
    if (!user.orgId) return res.json({ org: null, mode: user.mode || 'solo' });

    const org = db.data.organisations.find((o) => o.id === user.orgId);
    const pendingInvites = (db.data.invites || []).filter(
      (i) => i.orgId === user.orgId && i.status === 'pending'
    );
    const pendingRequests = (db.data.team_requests || []).filter(
      (r) => r.orgId === user.orgId && r.status === 'pending'
    );
    res.json({ org, mode: 'team', pendingInvites, pendingRequests });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/** GET /team/members — returns all members of the current user's team */
router.get('/team/members', requireAuth, async (req, res) => {
  try {
    await db.read();
    const user = db.data.users.find(
      (u) => String(u.githubId) === req.user.sub || u.googleId === req.user.sub || u.id === req.user.sub
    );
    if (!user) return res.status(404).json({ error: 'User not found' });

    let members = [];
    if (user.orgId) {
      members = db.data.users
        .filter((u) => u.orgId === user.orgId)
        .map(({ githubAccessToken, ...safe }) => safe);
    } else {
      // Solo user — return just themselves
      const { githubAccessToken, ...safe } = user;
      members = [safe];
    }
    res.json(members);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/** DELETE /team/members/:id — remove a member from the team (Admin only) */
router.delete('/team/members/:id', requireAuth, requireAdmin, async (req, res) => {
  try {
    await db.read();
    const actor = db.data.users.find(
      (u) => String(u.githubId) === req.user.sub || u.googleId === req.user.sub || u.id === req.user.sub
    );
    if (!actor || actor.role?.toLowerCase() !== 'admin') {
      return res.status(403).json({ error: 'Only Admins can remove members' });
    }
    const target = db.data.users.find((u) => u.id === req.params.id);
    if (!target) return res.status(404).json({ error: 'User not found' });
    if (target.orgId !== actor.orgId) return res.status(403).json({ error: 'User not in your team' });

    target.orgId = null;
    target.mode = 'solo';
    await db.write();
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ---------- Dashboard summary ----------

router.get('/dashboard/summary', requireAuth, async (req, res) => {
  await db.read();

  // Find the current user to scope data
  const user = db.data.users.find(
    (u) => String(u.githubId) === req.user.sub || u.googleId === req.user.sub || u.id === req.user.sub
  );

  // Collect repo IDs the user can see (own + team members')
  let allowedOwnerIds = [req.user.sub];
  if (user?.orgId) {
    const teamMemberSubs = db.data.users
      .filter((u) => u.orgId === user.orgId)
      .map((u) => String(u.githubId) || u.googleId || u.id);
    allowedOwnerIds = [...new Set([...allowedOwnerIds, ...teamMemberSubs])];
  }

  const repos     = db.data.repositories.filter((r) => allowedOwnerIds.includes(r.ownerId));
  const repoIds   = repos.map((r) => r.id);
  const vulns     = db.data.vulnerabilities.filter((v) => repoIds.includes(v.repoId));
  const malicious = db.data.malicious_packages.filter((m) => repoIds.includes(m.repoId));

  res.json({
    monitoredRepositories: repos.length,
    activeThreats: vulns.filter((v) => v.status === 'Open').length + malicious.length,
    criticalVulnerabilities: vulns.filter((v) => v.priorityLabel === 'P0_CRITICAL').length,
    averageRiskScore: repos.length
      ? Math.round(repos.reduce((s, r) => s + (r.riskScore ?? 100), 0) / repos.length)
      : 100,
    totalScans: db.data.scan_jobs.filter((s) => repoIds.includes(s.repoId)).length,
    onboardingComplete: user?.onboardingComplete ?? false,
    userMode: user?.mode || null,
    teamName: user?.orgId
      ? db.data.organisations.find((o) => o.id === user.orgId)?.name
      : null,
  });
});

// ---------- Public Stats ----------

router.get('/stats/cve-count', async (req, res) => {
  try {
    await db.read();
    const count = db.data.vulnerabilities ? db.data.vulnerabilities.length : 0;
    const scansCount = db.data.scan_jobs ? db.data.scan_jobs.length : 0;
    res.json({ count, scansCount });
  } catch (err) {
    res.json({ count: 0, scansCount: 0 }); // fallback
  }
});

module.exports = router;