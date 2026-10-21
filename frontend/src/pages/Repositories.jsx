import { useEffect, useState } from 'react';
import { useSearchParams, Link } from 'react-router-dom';
import { api } from '../lib/api';
import { useAuth } from '../hooks/useAuth';
import { Button, Badge, Card, Spinner, RiskGauge, SectionLabel, EmptyState, ErrorBanner } from '../components/ui';

// ── Scan result summary strip ─────────────────────────────────────────────────
function ScanResultBadges({ sr }) {
  if (!sr) return null;
  return (
    <div className="flex flex-wrap gap-2 mt-2">
      <Badge variant={sr.gate?.verdict === 'PASS' || sr.scanJob?.gateVerdict === 'PASS' ? 'safe' : 'critical'}>
        {sr.gate?.verdict || sr.scanJob?.gateVerdict || 'N/A'}
      </Badge>
      <Badge variant="default">{sr.sbomSummary?.totalComponents ?? 0} components</Badge>
      <Badge variant={sr.vulnerabilities?.length > 0 ? 'high' : 'safe'}>
        {sr.vulnerabilities?.length ?? 0} CVEs
      </Badge>
      <Badge variant={sr.maliciousPackages?.length > 0 ? 'critical' : 'safe'}>
        {sr.maliciousPackages?.length ?? 0} malicious
      </Badge>
    </div>
  );
}

// ── Connected repo card ───────────────────────────────────────────────────────
function RepoCard({ repo, onScan, onDelete, scanning, scanResult }) {
  const [confirmDelete, setConfirmDelete] = useState(false);

  return (
    <Card className="p-5 hover:border-slate-300 hover:-translate-y-0.5 hover:shadow-md transition-all duration-200">
      <div className="flex items-center gap-5">
        <RiskGauge score={repo.riskScore ?? 100} />
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 mb-1">
            <span className="font-mono text-sm font-semibold text-slate-900">{repo.fullName}</span>
            <Badge variant="default">{repo.defaultBranch}</Badge>
            {repo.lastScan?.source === 'MANUAL_UPLOAD' && <Badge variant="violet">manual</Badge>}
          </div>
          <div className="flex flex-wrap gap-2 mb-1">
            {repo.openVulnCount > 0 && <Badge variant="high">{repo.openVulnCount} open vulns</Badge>}
            {repo.criticalCount > 0 && <Badge variant="critical">{repo.criticalCount} critical</Badge>}
            {repo.maliciousCount > 0 && <Badge variant="blocked">{repo.maliciousCount} malicious</Badge>}
            {repo.openVulnCount === 0 && repo.maliciousCount === 0 && repo.lastScan && <Badge variant="safe">clean</Badge>}
          </div>
          <ScanResultBadges sr={scanResult} />
          <div className="text-[11px] font-mono text-slate-500 mt-1">
            {repo.lastScan
              ? `Last scan: ${new Date(repo.lastScan.startedAt).toLocaleString()}`
              : 'Never scanned'}
          </div>
        </div>
        <div className="flex items-center gap-2 shrink-0">
          <Link to={`/dashboard/sbom?repoId=${repo.id}`}>
            <Button size="sm" variant="ghost">View SBOM →</Button>
          </Link>
          <Button onClick={() => onScan(repo)} loading={scanning === repo.id} size="sm"
            variant={scanning === repo.id ? 'ghost' : 'primary'}>
            {scanning === repo.id ? 'Scanning…' : 'Scan now'}
          </Button>
          {confirmDelete ? (
            <div className="flex items-center gap-1">
              <button onClick={() => onDelete(repo.id)}
                className="text-xs px-2.5 py-1 rounded bg-rose-50 border border-rose-200 text-rose-700 hover:bg-rose-100 transition-colors font-semibold cursor-pointer">
                Confirm
              </button>
              <button onClick={() => setConfirmDelete(false)}
                className="text-xs px-2.5 py-1 rounded border border-slate-200 text-slate-600 hover:text-slate-900 transition-colors font-medium cursor-pointer">
                Cancel
              </button>
            </div>
          ) : (
            <button onClick={() => setConfirmDelete(true)}
              className="text-slate-400 hover:text-rose-600 transition-colors text-base p-1 rounded hover:bg-slate-100 leading-none cursor-pointer"
              title="Remove repository">
              ✕
            </button>
          )}
        </div>
      </div>
    </Card>
  );
}

// ── Main page ─────────────────────────────────────────────────────────────────
export default function Repositories() {
  const { user, refresh } = useAuth();
  const [searchParams, setSearchParams] = useSearchParams();
  const [connected, setConnected] = useState([]);
  const [ghRepos, setGhRepos] = useState([]);
  const [hasGitHubToken, setHasGitHubToken] = useState(false);
  const [loading, setLoading] = useState(true);
  const [scanning, setScanning] = useState(null);
  const [scanResults, setScanResults] = useState({});
  const [err, setErr] = useState('');
  const [tab, setTab] = useState('connected');

  // Manual repo connect (for GitHub users who want to type a name)
  const [manualName, setManualName] = useState('');
  const [manualBranch, setManualBranch] = useState('main');
  const [connecting, setConnecting] = useState(false);

  // Paste manifest (for Google users or anyone without GitHub access)
  const [manifestText, setManifestText] = useState('');
  const [manifestProject, setManifestProject] = useState('');
  const [manifestScanning, setManifestScanning] = useState(false);
  const [manifestResult, setManifestResult] = useState(null);

  async function loadConnected() {
    try {
      const list = await api.connectedRepos();
      setConnected(list);
    } catch { /* not fatal */ }
  }

  async function loadGitHub() {
    try {
      const res = await api.listGitHubRepos();
      if (Array.isArray(res)) {
        setGhRepos(res);
        setHasGitHubToken(true);
      } else {
        setGhRepos(res.repos || []);
        setHasGitHubToken(res.hasGitHubToken || false);
      }
    } catch { /* non-fatal */ }
  }

  async function load() {
    setLoading(true);
    setErr('');
    await Promise.all([loadConnected(), loadGitHub()]);
    setLoading(false);
  }

  useEffect(() => {
    // Coming back from GitHub link OAuth flow
    if (searchParams.get('github_linked') === '1') {
      setSearchParams({});           // clean the URL
      refresh();                     // re-fetch user (now has hasGitHubLinked: true)
      setTab('github');              // jump straight to GitHub tab
    }
    load();
  }, []);

  // ── Connect GitHub account (for Google users) ─────────────────────────────
  async function connectGitHub() {
    setErr('');
    try {
      const { authorizeUrl } = await api.githubLinkUrl();
      window.location.href = authorizeUrl;
    } catch (e) { setErr(e.message); }
  }

  // ── Connect from GitHub browser list ─────────────────────────────────────
  async function connectFromList(repo) {
    setErr('');
    try {
      const r = await api.connectRepo(repo.fullName || repo.full_name, repo.defaultBranch || repo.default_branch);
      setConnected(prev => [...prev, r]);
      setTab('connected');
    } catch (e) { setErr(e.message); }
  }

  // ── Connect by manually typing owner/repo ─────────────────────────────────
  async function connectManual() {
    if (!manualName.trim()) return;
    setConnecting(true);
    setErr('');
    try {
      const r = await api.connectRepo(manualName.trim(), manualBranch.trim() || 'main');
      setConnected(prev => [...prev, r]);
      setManualName('');
      setTab('connected');
    } catch (e) { setErr(e.message); }
    finally { setConnecting(false); }
  }

  // ── Delete a connected repo ───────────────────────────────────────────────
  async function deleteRepo(repoId) {
    setErr('');
    try {
      await api.deleteRepo(repoId);
      setConnected(prev => prev.filter(r => r.id !== repoId));
      setScanResults(prev => { const n = { ...prev }; delete n[repoId]; return n; });
    } catch (e) { setErr(e.message); }
  }

  // ── Scan a connected repo (needs GitHub token) ────────────────────────────
  async function scanRepo(repo) {
    setScanning(repo.id);
    setErr('');
    try {
      const result = await api.scanRepo(repo.id, { maxDepth: 2 });
      setScanResults(prev => ({ ...prev, [repo.id]: result }));
      await loadConnected();
    } catch (e) {
      if (e.body?.hint === 'MISSING_GITHUB_TOKEN') {
        setErr(`Cannot scan "${repo.fullName}" — GitHub account not connected. Use the Paste Manifest tab to scan without GitHub, or click "Connect GitHub Account" above.`);
      } else if (e.body?.hint === 'MISSING_GITHUB_TOKEN' || e.message?.includes('GitHub')) {
        setErr(e.body?.detail || e.message);
      } else {
        setErr(e.body?.detail || e.message);
      }
    } finally {
      setScanning(null);
    }
  }

  // ── Scan by pasting manifest (works for ALL users, no GitHub needed) ──────
  async function scanPastedManifest() {
    if (!manifestText.trim()) return;
    setManifestScanning(true);
    setManifestResult(null);
    setErr('');
    try {
      const result = await api.scanManifest(
        manifestText.trim(),
        manifestProject.trim() || 'my-project',
        2
      );
      setManifestResult(result);
      await loadConnected(); // refresh connected list — a repo entry is auto-created
    } catch (e) { setErr(e.message); }
    finally { setManifestScanning(false); }
  }

  // ── Load manifest from file upload ────────────────────────────────────────
  function handleFileUpload(e) {
    const file = e.target.files?.[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = ev => {
      setManifestText(ev.target.result);
      setManifestProject(file.name.replace('.json', ''));
    };
    reader.readAsText(file);
  }

  const isAlreadyConnected = (repo) =>
    connected.some(c => c.fullName === (repo.fullName || repo.full_name));

  const TABS = [
    { id: 'connected', label: `Connected (${connected.length})` },
    ...(hasGitHubToken ? [{ id: 'github', label: `GitHub (${ghRepos.length})` }] : []),
    { id: 'manual',  label: 'Add manually' },
    { id: 'paste',   label: 'Paste manifest' },
  ];

  if (loading) return (
    <div className="flex items-center justify-center h-64">
      <Spinner size={28} color="#0f172a" />
    </div>
  );

  return (
    <div className="space-y-6 w-full">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-black font-['Space_Grotesk'] text-slate-900">Repositories</h1>
          <p className="text-slate-500 text-sm mt-1">
            {connected.length} connected
            {hasGitHubToken
              ? ` · ${ghRepos.length} on GitHub`
              : user?.hasGitHubLinked
              ? ' · GitHub linked — loading repos…'
              : ' · Connect GitHub to browse repos'}
          </p>
        </div>
        <Button size="sm" variant="ghost" onClick={load}>↺ Refresh</Button>
      </div>

      <ErrorBanner message={err} onRetry={() => setErr('')} retryLabel="Dismiss" />

      {/* Info banner for Google users without GitHub linked */}
      {!hasGitHubToken && (
        <div className="flex items-start gap-4 px-5 py-4 rounded-xl bg-slate-50 border border-slate-200 shadow-2xs">
          <span className="text-2xl shrink-0">🔗</span>
          <div className="flex-1">
            <p className="font-semibold text-slate-900 font-['Space_Grotesk']">Connect your GitHub account</p>
            <p className="text-xs mt-1 text-slate-600">
              You're signed in with Google. Connect GitHub to browse and scan your repositories directly —
              or use <strong className="text-slate-900">Add manually</strong> / <strong className="text-slate-900">Paste manifest</strong> to scan any project right now without linking GitHub.
            </p>
            <Button onClick={connectGitHub} size="sm" className="mt-3">
              <svg width="14" height="14" viewBox="0 0 24 24" fill="currentColor">
                <path d="M12 0C5.37 0 0 5.37 0 12c0 5.31 3.435 9.795 8.205 11.385.6.105.825-.255.825-.57 0-.285-.015-1.23-.015-2.235-3.015.555-3.795-.735-4.035-1.41-.135-.345-.72-1.41-1.23-1.695-.42-.225-1.02-.78-.015-.795.945-.015 1.62.87 1.845 1.23 1.08 1.815 2.805 1.305 3.495.99.105-.78.42-1.305.765-1.605-2.67-.3-5.46-1.335-5.46-5.925 0-1.305.465-2.385 1.23-3.225-.12-.3-.54-1.53.12-3.18 0 0 1.005-.315 3.3 1.23.96-.27 1.98-.405 3-.405s2.04.135 3 .405c2.295-1.56 3.3-1.23 3.3-1.23.66 1.65.24 2.88.12 3.18.765.84 1.23 1.905 1.23 3.225 0 4.605-2.805 5.625-5.475 5.925.435.375.81 1.095.81 2.22 0 1.605-.015 2.895-.015 3.3 0 .315.225.69.825.57A12.02 12.02 0 0024 12c0-6.63-5.37-12-12-12z"/>
              </svg>
              Connect GitHub Account
            </Button>
          </div>
        </div>
      )}

      {/* Tabs */}
      <div className="flex flex-wrap gap-0 border-b border-slate-200">
        {TABS.map(t => (
          <button key={t.id} onClick={() => setTab(t.id)}
            className={`px-4 py-2.5 text-xs font-semibold transition-colors border-b-2 -mb-px cursor-pointer ${
              tab === t.id
                ? 'border-slate-900 text-slate-900'
                : 'border-transparent text-slate-500 hover:text-slate-800'
            }`}>
            {t.label}
          </button>
        ))}
      </div>

      {/* ── Tab: Connected ── */}
      {tab === 'connected' && (
        connected.length === 0 ? (
          <EmptyState icon="⊞" title="No repositories connected yet"
            body="Use one of the other tabs to connect a repo or scan a project directly."
            action={<Button size="sm" variant="ghost" onClick={() => setTab('paste')}>Paste manifest to scan now →</Button>}
          />
        ) : (
          <div className="space-y-3">
            {connected.map(repo => (
              <RepoCard key={repo.id} repo={repo}
                onScan={scanRepo}
                onDelete={deleteRepo}
                scanning={scanning}
                scanResult={scanResults[repo.id]}
              />
            ))}
          </div>
        )
      )}

      {/* ── Tab: GitHub browser ── */}
      {tab === 'github' && (
        ghRepos.length === 0 ? (
          <EmptyState icon="⊞" title="No GitHub repos found"
            body="Make sure you signed in with GitHub OAuth." />
        ) : (
          <div className="space-y-2">
            {ghRepos.map(repo => (
              <Card key={repo.id} className="px-5 py-3.5 flex items-center gap-4 hover:border-slate-300">
                <div className="flex-1 min-w-0">
                  <span className="font-mono text-xs font-semibold text-slate-900">{repo.fullName || repo.full_name}</span>
                  <div className="flex items-center gap-2 mt-1">
                    {repo.language && <Badge variant="default">{repo.language}</Badge>}
                    {repo.private && <Badge variant="default">private</Badge>}
                  </div>
                </div>
                <Button size="sm"
                  variant={isAlreadyConnected(repo) ? 'ghost' : 'primary'}
                  disabled={isAlreadyConnected(repo)}
                  onClick={() => connectFromList(repo)}>
                  {isAlreadyConnected(repo) ? '✓ Connected' : 'Connect'}
                </Button>
              </Card>
            ))}
          </div>
        )
      )}

      {/* ── Tab: Add manually ── */}
      {tab === 'manual' && (
        <Card className="p-6 space-y-4">
          <SectionLabel>Connect any GitHub repository by name</SectionLabel>
          <p className="text-xs text-slate-600 leading-relaxed">
            Type the GitHub repository name in <code className="font-mono text-slate-800 bg-slate-100 px-1 py-0.5 rounded">owner/repo</code> format.
            This works even if you're signed in with Google — SecureChain will fetch the manifest using its verified GitHub connection.
          </p>
          <div className="flex gap-3 flex-wrap">
            <input
              value={manualName}
              onChange={e => setManualName(e.target.value)}
              onKeyDown={e => e.key === 'Enter' && connectManual()}
              placeholder="e.g. facebook/react or your-username/your-repo"
              className="flex-1 min-w-0 bg-white border border-slate-300 rounded-lg px-4 py-2 text-xs text-slate-900 placeholder-slate-400 focus:outline-none focus:border-slate-900 font-mono shadow-2xs"
            />
            <input
              value={manualBranch}
              onChange={e => setManualBranch(e.target.value)}
              placeholder="main"
              className="w-28 bg-white border border-slate-300 rounded-lg px-3 py-2 text-xs text-slate-900 placeholder-slate-400 focus:outline-none focus:border-slate-900 font-mono shadow-2xs"
            />
            <Button onClick={connectManual} loading={connecting}>Connect</Button>
          </div>
          <p className="text-[11px] text-slate-400">
            After connecting, click <strong>Scan now</strong> from the Connected tab.
          </p>
        </Card>
      )}

      {/* ── Tab: Paste manifest ── */}
      {tab === 'paste' && (
        <div className="space-y-4">
          <Card className="p-6 space-y-4">
            <SectionLabel>Scan any project — no GitHub login needed</SectionLabel>
            <p className="text-xs text-slate-600 leading-relaxed">
              Paste your <code className="font-mono text-slate-800 bg-slate-100 px-1 py-0.5 rounded">package.json</code> content below,
              or upload the file. SecureChain will resolve all dependencies from the registry
              and run the full security scan — works for any project regardless of where it's hosted.
            </p>

            {/* File upload */}
            <div className="flex items-center gap-3">
              <label className="cursor-pointer px-4 py-2 text-xs font-medium border border-slate-300 rounded-lg text-slate-700 hover:bg-slate-50 transition-colors shadow-2xs">
                📁 Upload package.json
                <input type="file" accept=".json" className="hidden" onChange={handleFileUpload} />
              </label>
              <span className="text-xs text-slate-400">or paste below</span>
            </div>

            {/* Project name */}
            <div>
              <label className="text-xs font-mono text-slate-600 font-medium">Project name (optional)</label>
              <input
                value={manifestProject}
                onChange={e => setManifestProject(e.target.value)}
                placeholder="my-project"
                className="w-full mt-1 bg-white border border-slate-300 rounded-lg px-3 py-2 text-xs text-slate-900 placeholder-slate-400 focus:outline-none focus:border-slate-900 font-mono shadow-2xs"
              />
            </div>

            {/* Manifest textarea */}
            <div>
              <label className="text-xs font-mono text-slate-600 font-medium">package.json content</label>
              <textarea
                value={manifestText}
                onChange={e => setManifestText(e.target.value)}
                rows={10}
                placeholder={`{\n  "name": "my-app",\n  "dependencies": {\n    "express": "^4.18.0",\n    "lodash": "^4.17.21"\n  }\n}`}
                className="w-full mt-1 bg-white border border-slate-300 rounded-lg px-3 py-2 text-xs text-slate-900 placeholder-slate-400 focus:outline-none focus:border-slate-900 font-mono resize-y shadow-2xs"
              />
            </div>

            <Button
              onClick={scanPastedManifest}
              loading={manifestScanning}
              disabled={!manifestText.trim()}
              className="w-full justify-center"
              size="lg"
            >
              {manifestScanning ? 'Scanning dependencies…' : '▶ Run security scan'}
            </Button>
          </Card>

          {/* Manifest scan result */}
          {manifestResult && (
            <div className="space-y-3">
              <Card className={`p-5 border ${
                manifestResult.gate?.verdict === 'PASS'
                  ? 'border-emerald-200 bg-emerald-50/20'
                  : 'border-rose-200 bg-rose-50/20'
              }`}>
                <div className="flex items-center gap-3 mb-3">
                  <span className="text-2xl">
                    {manifestResult.gate?.verdict === 'PASS' ? '✅' : '🚫'}
                  </span>
                  <div>
                    <div className="font-bold text-slate-900 font-['Space_Grotesk']">
                      Gate verdict: {(manifestResult.gateVerdict || manifestResult.gate?.verdict) ?? 'N/A'}
                    </div>
                    <div className="text-xs text-slate-500">Risk score: {manifestResult.riskScore}</div>
                  </div>
                </div>
                <ScanResultBadges sr={manifestResult} />
              </Card>

              {/* Corrupt manifest warning */}
              {manifestResult.manifestCorrupted && (
                <Card className="p-4 border-rose-300 bg-rose-50/60 shadow-xs">
                  <SectionLabel className="text-rose-800">⚠️ Corrupt Manifest Detected</SectionLabel>
                  <p className="text-xs font-mono text-rose-700 mt-1">
                    {manifestResult.parseError || 'Syntax error in manifest JSON'}. Extracted dependencies using regex fallback parser. Policy gate enforced fail-closed (BLOCKED, Risk Score 0).
                  </p>
                </Card>
              )}

              {/* Show blocking reasons if any */}
              {manifestResult.gate?.reasons?.length > 0 && (
                <Card className="p-4 border-rose-200 bg-rose-50/30">
                  <SectionLabel className="text-rose-700">Gate reasons</SectionLabel>
                  {manifestResult.gate.reasons.map((r, i) => (
                    <p key={i} className="text-xs font-mono text-rose-700 mt-2">{r.detail}</p>
                  ))}
                </Card>
              )}

              {/* Top vulnerabilities */}
              {manifestResult.vulnerabilities?.length > 0 && (
                <Card className="p-4">
                  <SectionLabel>Top findings</SectionLabel>
                  <div className="mt-3 space-y-2">
                    {manifestResult.vulnerabilities.slice(0, 10).map((v, i) => (
                      <div key={i} className="flex items-center gap-3 text-xs">
                        <Badge variant={v.priorityLabel === 'P0_CRITICAL' ? 'critical' : v.priorityLabel === 'P1_HIGH' ? 'high' : 'medium'}>
                          {v.priorityLabel}
                        </Badge>
                        <span className="font-mono text-slate-900 font-semibold">{v.cveId || v.id}</span>
                        <span className="text-slate-600">{v.component || v.packageName}@{v.version}</span>
                        <span className="text-slate-400 ml-auto">CVSS {v.severity ?? v.cvssScore ?? 'N/A'}</span>
                      </div>
                    ))}
                    {manifestResult.vulnerabilities.length > 10 && (
                      <p className="text-xs text-slate-400 mt-1">
                        + {manifestResult.vulnerabilities.length - 10} more — go to Vulnerabilities page for the full list
                      </p>
                    )}
                  </div>
                </Card>
              )}

              {/* Malicious packages */}
              {manifestResult.maliciousPackages?.length > 0 && (
                <Card className="p-4 border border-rose-200 bg-rose-50/20">
                  <SectionLabel className="text-rose-700">Malicious packages detected</SectionLabel>
                  <div className="mt-3 space-y-2">
                    {manifestResult.maliciousPackages.map((m, i) => (
                      <div key={i} className="flex items-start gap-3 text-xs">
                        <Badge variant="critical">{m.type}</Badge>
                        <div>
                          <span className="font-mono text-rose-600 font-semibold">{m.packageName}</span>
                          <p className="text-slate-600 mt-0.5">{m.detail}</p>
                        </div>
                      </div>
                    ))}
                  </div>
                </Card>
              )}

              <div className="flex flex-wrap items-center justify-between gap-3 p-3.5 rounded-xl bg-slate-50 border border-slate-200">
                <span className="text-xs text-slate-500">
                  Scan saved — find it under <strong>Connected</strong> tab as "{manifestProject || 'my-project'}"
                </span>
                <Link to={`/dashboard/sbom?repoId=${manifestResult.repoId}&sbomId=${manifestResult.sbomId}`}>
                  <Button size="sm" variant="ghost">View SBOM in SBOM tab →</Button>
                </Link>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}