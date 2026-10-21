// ── Malicious Packages ─────────────────────────────────────────────────────
import { useState, useEffect } from 'react';
import { useSearchParams } from 'react-router-dom';
import { api } from '../lib/api';
import { Button, Badge, Card, Spinner, SectionLabel, EmptyState, ErrorBanner } from '../components/ui';

const TYPE_META = {
  TYPOSQUAT: { label: 'Typosquat', color: '#e11d48', icon: '◬' },
  HEURISTIC_INSTALL_SCRIPT: { label: 'Install Script', color: '#d97706', icon: '⊙' },
  HEURISTIC_NEW_PACKAGE: { label: 'New Package', color: '#d97706', icon: '◎' },
  HEURISTIC_LOW_PROVENANCE: { label: 'Low Provenance', color: '#475569', icon: '◻' },
  HEURISTIC_RELEASE_BURST: { label: 'Release Burst', color: '#475569', icon: '◈' },
};

export function MaliciousPackages() {
  const [searchParams, setSearchParams] = useSearchParams();
  const repoIdParam = searchParams.get('repoId');

  const [repos, setRepos] = useState([]);
  const [selectedRepoId, setSelectedRepoId] = useState(repoIdParam || 'all');
  const [findings, setFindings] = useState([]);
  const [loading, setLoading] = useState(true);
  const [scanLoading, setScanLoading] = useState(false);
  const [err, setErr] = useState('');

  async function loadData() {
    setLoading(true);
    setErr('');
    try {
      const [reposList, maliciousList] = await Promise.all([
        api.connectedRepos().catch(() => []),
        api.listMaliciousPackages(selectedRepoId),
      ]);
      setRepos(reposList);
      setFindings(maliciousList);
    } catch (e) {
      setErr(e.message);
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    loadData();
  }, [selectedRepoId]);

  function handleRepoChange(id) {
    setSelectedRepoId(id);
    setSearchParams(id && id !== 'all' ? { repoId: id } : {});
  }

  async function runScan() {
    if (!selectedRepoId || selectedRepoId === 'all') {
      setErr('Please select a specific repository to run an analysis on.');
      return;
    }
    setScanLoading(true);
    setErr('');
    try {
      const r = await api.scanRepo(selectedRepoId, { maxDepth: 2 });
      setFindings(r.maliciousPackages || []);
    } catch (e) {
      setErr(e.message);
    } finally {
      setScanLoading(false);
    }
  }

  return (
    <div className="space-y-6 w-full">
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-black font-['Space_Grotesk'] text-slate-900 tracking-tight">Malicious Packages</h1>
          <p className="text-slate-500 text-sm mt-1">Typosquat detection (Levenshtein distance) + behavioral heuristics.</p>
        </div>
        <Badge variant={findings.length > 0 ? 'critical' : 'safe'}>
          {findings.length} findings
        </Badge>
      </div>

      <ErrorBanner message={err} onRetry={loadData} />

      {/* Repo Dropdown Selector */}
      <Card className="p-4 flex flex-wrap items-center justify-between gap-4 bg-white border border-slate-200 shadow-xs">
        <SectionLabel>Select Repository / Package</SectionLabel>
        <div className="flex items-center gap-3 flex-1 min-w-[280px]">
          <select
            value={selectedRepoId}
            onChange={e => handleRepoChange(e.target.value)}
            className="flex-1 bg-white border border-slate-200 rounded-lg px-4 py-2.5 text-sm text-slate-800 focus:outline-none focus:ring-2 focus:ring-slate-900/10 focus:border-slate-800 font-mono cursor-pointer shadow-xs"
          >
            <option value="all">All Scanned Repositories & Packages</option>
            {repos.map(r => (
              <option key={r.id} value={r.id}>
                {r.fullName} ({r.maliciousCount} malicious pkgs)
              </option>
            ))}
          </select>
          <Button onClick={runScan} loading={scanLoading} disabled={selectedRepoId === 'all'}>
            {scanLoading ? 'Analyzing…' : 'Run analysis'}
          </Button>
        </div>
      </Card>

      {loading && <div className="flex justify-center py-12"><Spinner size={28} color="#e11d48" /></div>}

      {!loading && findings.length === 0 && (
        <EmptyState icon="◬" title="No malicious packages found" body="All packages passed typosquat and heuristic checks." />
      )}

      {!loading && findings.length > 0 && (
        <div className="space-y-3">
          {findings.map((f, i) => {
            const meta = TYPE_META[f.type] || { label: f.type, color: '#64748b', icon: '◈' };
            return (
              <Card key={i} className="p-5 bg-white border border-slate-200 shadow-xs hover:border-slate-300 transition-all">
                <div className="flex items-start gap-4">
                  <span className="text-2xl mt-0.5" style={{ color: meta.color }}>{meta.icon}</span>
                  <div className="flex-1">
                    <div className="flex items-center gap-2 mb-1.5 flex-wrap">
                      <span className="font-mono text-sm font-bold text-slate-900">{f.packageName}</span>
                      <Badge variant={f.type === 'TYPOSQUAT' ? 'critical' : 'high'}>{meta.label}</Badge>
                      {f.confidence && <Badge variant={f.confidence === 'high' ? 'critical' : 'high'}>{f.confidence} confidence</Badge>}
                    </div>
                    <p className="text-sm text-slate-600 leading-relaxed">{f.detail}</p>
                    {f.suspectedTarget && (
                      <p className="text-xs font-mono text-slate-500 mt-2 bg-slate-50 border border-slate-200 rounded-md px-2.5 py-1 inline-block">
                        Suspected target: <span className="font-bold text-emerald-700">{f.suspectedTarget}</span>
                        {' '}· edit distance: <span className="font-bold text-rose-600">{f.editDistance}</span>
                      </p>
                    )}
                  </div>
                </div>
              </Card>
            );
          })}
        </div>
      )}
    </div>
  );
}

// ── CI/CD ──────────────────────────────────────────────────────────────────
export function CicdPage() {
  const [repos, setRepos] = useState([]);
  const [repoId, setRepoId] = useState('');
  const [apiKey, setApiKey] = useState('');
  const [buildContent, setBuildContent] = useState('');
  const [baselineHash, setBaselineHash] = useState('');
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [err, setErr] = useState('');

  useEffect(() => {
    api.connectedRepos()
      .then(list => {
        setRepos(list);
        if (list.length > 0) setRepoId(list[0].id);
      })
      .catch(() => []);
  }, []);

  async function genKey() {
    if (!repoId) return;
    try {
      const r = await api.generateCiApiKey(repoId);
      setApiKey(r.apiKey);
    } catch (e) { setErr(e.message); }
  }

  async function setBaseline() {
    if (!repoId || !buildContent) return;
    try {
      const r = await api.setBaseline(repoId, buildContent);
      setBaselineHash(r.baselineHash);
    } catch (e) { setErr(e.message); }
  }

  async function verify() {
    if (!repoId || !buildContent) return;
    setLoading(true); setErr('');
    try {
      const r = await api.verifyBuild(repoId, buildContent, baselineHash);
      setResult(r);
    } catch (e) { setErr(e.message); }
    finally { setLoading(false); }
  }

  return (
    <div className="space-y-6 w-full">
      <div>
        <h1 className="text-2xl font-black font-['Space_Grotesk'] text-slate-900 tracking-tight">CI/CD Security</h1>
        <p className="text-slate-500 text-sm mt-1">Pipeline plugins, policy gates, SHA-256 build integrity.</p>
      </div>
      <ErrorBanner message={err} />

      <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
        {/* CI API key */}
        <Card className="p-5 bg-white border border-slate-200 shadow-xs flex flex-col justify-between">
          <div>
            <SectionLabel>CI API key</SectionLabel>
            <p className="text-xs text-slate-500 mt-2 mb-3">Store this as <code className="font-mono bg-slate-100 text-slate-800 px-1.5 py-0.5 rounded border border-slate-200">SECURECHAIN_API_KEY</code> in your CI provider's secrets. The pipeline CLI uses it to submit SBOMs.</p>
            <div className="flex gap-2 mb-3">
              <select
                value={repoId}
                onChange={e => setRepoId(e.target.value)}
                className="flex-1 bg-white border border-slate-200 rounded-lg px-3 py-2 text-xs text-slate-800 focus:outline-none focus:ring-2 focus:ring-slate-900/10 focus:border-slate-800 font-mono cursor-pointer shadow-xs"
              >
                <option value="">Select repository…</option>
                {repos.map(r => (
                  <option key={r.id} value={r.id}>{r.fullName}</option>
                ))}
              </select>
              <Button size="sm" onClick={genKey} disabled={!repoId}>Generate</Button>
            </div>
          </div>
          {apiKey && (
            <div className="bg-slate-50 border border-slate-200 rounded-lg px-4 py-3 mt-2">
              <p className="font-mono text-xs text-slate-800 break-all select-all font-semibold">{apiKey}</p>
            </div>
          )}
        </Card>

        {/* Build integrity */}
        <Card className="p-5 bg-white border border-slate-200 shadow-xs">
          <SectionLabel>Build script integrity (SHA-256)</SectionLabel>
          <p className="text-xs text-slate-500 mt-2 mb-3">Paste your CI config content. Set a baseline once, then verify on every run.</p>
          <textarea
            value={buildContent}
            onChange={e => setBuildContent(e.target.value)}
            rows={4}
            placeholder="Paste .github/workflows/ci.yml content here…"
            className="w-full bg-slate-50 border border-slate-200 rounded-lg px-3 py-2 text-xs text-slate-800 placeholder-slate-400 focus:outline-none focus:bg-white focus:ring-2 focus:ring-slate-900/10 focus:border-slate-800 font-mono resize-none mb-3 shadow-inner"
          />
          <div className="flex gap-2 mb-3">
            <Button size="sm" variant="ghost" onClick={setBaseline} disabled={!repoId}>Set baseline</Button>
            <Button size="sm" onClick={verify} loading={loading} disabled={!repoId}>Verify</Button>
          </div>
          {baselineHash && (
            <p className="text-[11px] font-mono text-slate-500 break-all bg-slate-50 p-2 rounded border border-slate-200">
              Baseline: <span className="font-bold text-slate-800">{baselineHash}</span>
            </p>
          )}
          {result && (
            <div className={`mt-3 p-3 rounded-lg border text-xs font-mono font-medium ${result.match ? 'bg-emerald-50 border-emerald-200 text-emerald-800' : 'bg-rose-50 border-rose-200 text-rose-800'}`}>
              {result.verdict}: {result.detail}
            </div>
          )}
        </Card>
      </div>

      {/* Integration guide */}
      <Card className="p-6 bg-white border border-slate-200 shadow-xs">
        <SectionLabel>Pipeline integration</SectionLabel>
        <div className="mt-4 space-y-4">
          {[
            { title: 'GitHub Actions', code: `- name: SecureChain security gate\n  uses: ./.github/actions/securechain-scan\n  with:\n    api-url: \${{ secrets.SECURECHAIN_API_URL }}\n    api-key: \${{ secrets.SECURECHAIN_API_KEY }}` },
            { title: 'GitLab CI', code: `securechain_gate:\n  stage: security\n  script:\n    - node securechain-cli.js\n        --api-url "$SECURECHAIN_API_URL"\n        --api-key "$SECURECHAIN_API_KEY"` },
            { title: 'Jenkins', code: `stage('SecureChain Gate') {\n  steps {\n    sh 'node bin/securechain-cli.js --api-url $SECURECHAIN_API_URL --api-key $SECURECHAIN_API_KEY'\n  }\n}` },
          ].map(({ title, code }) => (
            <div key={title}>
              <p className="text-xs text-slate-600 font-mono font-semibold mb-2">{title}</p>
              <pre className="bg-slate-900 border border-slate-800 rounded-lg p-4 text-xs font-mono text-slate-200 overflow-x-auto shadow-sm">{code}</pre>
            </div>
          ))}
        </div>
      </Card>
    </div>
  );
}

// ── Alerts ────────────────────────────────────────────────────────────────
export function AlertsPage() {
  const [repos, setRepos] = useState([]);
  const [repoId, setRepoId] = useState('');
  const [channels, setChannels] = useState({ slackWebhookUrl: '', pagerDutyRoutingKey: '', email: { to: '' } });
  const [channelStatus, setChannelStatus] = useState({ slack: false, pagerduty: false, email: false });
  const [smtpConfigured, setSmtpConfigured] = useState(false);
  const [saving, setSaving] = useState(false);
  const [testing, setTesting] = useState(false);
  const [testResult, setTestResult] = useState(null);
  const [history, setHistory] = useState([]);
  const [err, setErr] = useState('');
  const [saved, setSaved] = useState(false);

  useEffect(() => {
    api.connectedRepos()
      .then(list => {
        setRepos(list);
        if (list.length > 0) {
          setRepoId(list[0].id);
        }
      })
      .catch(() => []);
  }, []);

  async function loadRepoAlerts(id) {
    if (!id) return;
    try {
      const [res, histRes] = await Promise.all([
        api.getAlertChannels(id).catch(() => null),
        api.getAlertHistory(id).catch(() => ({ history: [] })),
      ]);

      if (res) {
        setChannelStatus({
          slack: Boolean(res.slackWebhookUrl),
          pagerduty: Boolean(res.pagerDutyRoutingKey),
          email: Boolean(res.email?.to),
        });
        setSmtpConfigured(Boolean(res.smtpConfigured));
        setChannels({
          slackWebhookUrl: res.slackWebhookUrl ? '••••configured••••' : '',
          pagerDutyRoutingKey: res.pagerDutyRoutingKey ? '••••configured••••' : '',
          email: { to: res.email?.to || '' },
        });
      }
      setHistory(histRes?.history || []);
    } catch (e) {
      setErr(e.message);
    }
  }

  useEffect(() => {
    if (repoId) {
      loadRepoAlerts(repoId);
    }
  }, [repoId]);

  async function save() {
    if (!repoId) return;
    setSaving(true);
    setErr('');
    try {
      const payload = {
        slackWebhookUrl: channels.slackWebhookUrl,
        pagerDutyRoutingKey: channels.pagerDutyRoutingKey,
        email: channels.email?.to ? channels.email.to : null,
      };
      await api.setAlertChannels(repoId, payload);
      setSaved(true);
      setTimeout(() => setSaved(false), 2500);
      await loadRepoAlerts(repoId);
    } catch (e) {
      setErr(e.message);
    } finally {
      setSaving(false);
    }
  }

  async function clearChannel(channelKey) {
    if (!repoId) return;
    setSaving(true);
    setErr('');
    try {
      const payload = {
        [channelKey]: null,
      };
      await api.setAlertChannels(repoId, payload);
      await loadRepoAlerts(repoId);
    } catch (e) {
      setErr(e.message);
    } finally {
      setSaving(false);
    }
  }

  async function test() {
    if (!repoId) return;
    setTesting(true);
    setErr('');
    setTestResult(null);
    try {
      const r = await api.testAlertChannels(repoId);
      setTestResult(r.results);
      if (r.smtpConfigured !== undefined) setSmtpConfigured(r.smtpConfigured);
      // Reload history to show the test event
      const histRes = await api.getAlertHistory(repoId).catch(() => ({ history: [] }));
      setHistory(histRes?.history || []);
    } catch (e) {
      setErr(e.message);
    } finally {
      setTesting(false);
    }
  }

  return (
    <div className="space-y-6 w-full">
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-black font-['Space_Grotesk'] text-slate-900 tracking-tight">Alert Channels</h1>
          <p className="text-slate-500 text-sm mt-1">
            P0 critical vulnerabilities automatically trigger Jira & PagerDuty. High findings and policy violations notify Slack & Email.
          </p>
        </div>
        <div className="flex items-center gap-2">
          {smtpConfigured ? (
            <span className="text-xs font-mono px-2.5 py-1 rounded-full border border-emerald-300 bg-emerald-50 text-emerald-800 font-semibold shadow-xs">
              ✓ Server SMTP Active
            </span>
          ) : (
            <span className="text-xs font-mono px-2.5 py-1 rounded-full border border-amber-300 bg-amber-50 text-amber-800 font-semibold shadow-xs">
              ⚠ Server SMTP Not Configured
            </span>
          )}
        </div>
      </div>

      <ErrorBanner message={err} />

      {/* Configuration Card */}
      <Card className="p-5 space-y-5 bg-white border border-slate-200 shadow-xs">
        <div>
          <label className="text-xs font-mono font-medium text-slate-600">Select Target Repository</label>
          <select
            value={repoId}
            onChange={e => setRepoId(e.target.value)}
            className="w-full mt-1.5 bg-white border border-slate-200 rounded-lg px-4 py-2.5 text-sm text-slate-800 focus:outline-none focus:ring-2 focus:ring-slate-900/10 focus:border-slate-800 font-mono cursor-pointer shadow-xs"
          >
            <option value="">Select repository…</option>
            {repos.map(r => (
              <option key={r.id} value={r.id}>{r.fullName}</option>
            ))}
          </select>
        </div>

        {/* Slack Webhook */}
        <div className="pt-2 border-t border-slate-100">
          <div className="flex items-center justify-between mb-1.5">
            <div className="flex items-center gap-2">
              <label className="text-xs font-mono font-medium text-slate-700">Slack Incoming Webhook URL</label>
              {channelStatus.slack ? (
                <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-emerald-50 text-emerald-700 border border-emerald-200 font-bold">
                  Configured
                </span>
              ) : (
                <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-slate-100 text-slate-500 border border-slate-200">
                  Not set
                </span>
              )}
            </div>
            {channelStatus.slack && (
              <button
                type="button"
                onClick={() => clearChannel('slackWebhookUrl')}
                className="text-xs text-rose-600 hover:text-rose-800 underline font-mono"
              >
                Clear
              </button>
            )}
          </div>
          <input
            type="password"
            value={channels.slackWebhookUrl || ''}
            onChange={e => setChannels(c => ({ ...c, slackWebhookUrl: e.target.value }))}
            placeholder={channelStatus.slack ? '••••configured•••• (enter new URL to update)' : 'https://hooks.slack.com/services/T.../B.../...'}
            className="w-full bg-white border border-slate-200 rounded-lg px-3 py-2 text-sm text-slate-800 placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-slate-900/10 focus:border-slate-800 shadow-xs font-mono"
          />
          <p className="text-[11px] text-slate-400 mt-1">Must strictly begin with <code className="font-mono bg-slate-50 px-1 border rounded">https://hooks.slack.com/services/</code></p>
        </div>

        {/* PagerDuty Routing Key */}
        <div className="pt-2 border-t border-slate-100">
          <div className="flex items-center justify-between mb-1.5">
            <div className="flex items-center gap-2">
              <label className="text-xs font-mono font-medium text-slate-700">PagerDuty Events API v2 Routing Key</label>
              {channelStatus.pagerduty ? (
                <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-emerald-50 text-emerald-700 border border-emerald-200 font-bold">
                  Configured
                </span>
              ) : (
                <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-slate-100 text-slate-500 border border-slate-200">
                  Not set
                </span>
              )}
            </div>
            {channelStatus.pagerduty && (
              <button
                type="button"
                onClick={() => clearChannel('pagerDutyRoutingKey')}
                className="text-xs text-rose-600 hover:text-rose-800 underline font-mono"
              >
                Clear
              </button>
            )}
          </div>
          <input
            type="password"
            value={channels.pagerDutyRoutingKey || ''}
            onChange={e => setChannels(c => ({ ...c, pagerDutyRoutingKey: e.target.value }))}
            placeholder={channelStatus.pagerduty ? '••••configured•••• (enter new key to update)' : '32-character integration routing key'}
            className="w-full bg-white border border-slate-200 rounded-lg px-3 py-2 text-sm text-slate-800 placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-slate-900/10 focus:border-slate-800 shadow-xs font-mono"
          />
          <p className="text-[11px] text-slate-400 mt-1">Used exclusively for triggering P0 critical supply-chain incidents.</p>
        </div>

        {/* Email */}
        <div className="pt-2 border-t border-slate-100">
          <div className="flex items-center justify-between mb-1.5">
            <div className="flex items-center gap-2">
              <label className="text-xs font-mono font-medium text-slate-700">Alert Email Address</label>
              {channelStatus.email ? (
                <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-emerald-50 text-emerald-700 border border-emerald-200 font-bold">
                  Configured
                </span>
              ) : (
                <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-slate-100 text-slate-500 border border-slate-200">
                  Not set
                </span>
              )}
            </div>
            {channelStatus.email && (
              <button
                type="button"
                onClick={() => clearChannel('email')}
                className="text-xs text-rose-600 hover:text-rose-800 underline font-mono"
              >
                Clear
              </button>
            )}
          </div>
          <input
            type="email"
            value={channels.email?.to || ''}
            onChange={e => setChannels(c => ({ ...c, email: { to: e.target.value } }))}
            placeholder="security-team@yourcompany.com"
            className="w-full bg-white border border-slate-200 rounded-lg px-3 py-2 text-sm text-slate-800 placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-slate-900/10 focus:border-slate-800 shadow-xs"
          />
          {!smtpConfigured && (
            <p className="text-[11px] text-amber-700 mt-1 font-mono">
              Note: Email delivery requires backend SMTP configuration (<code className="bg-amber-100 px-1 rounded">SMTP_HOST</code>, <code className="bg-amber-100 px-1 rounded">SMTP_USER</code>, <code className="bg-amber-100 px-1 rounded">SMTP_PASS</code> in .env).
            </p>
          )}
        </div>

        <div className="flex items-center gap-3 pt-3">
          <Button onClick={save} loading={saving} disabled={!repoId}>
            {saved ? '✓ Channels Saved' : 'Save channels'}
          </Button>
          <Button variant="ghost" onClick={test} loading={testing} disabled={!repoId}>
            {testing ? 'Sending test…' : 'Send test alert'}
          </Button>
        </div>
      </Card>

      {/* Test Results Display */}
      {testResult && (
        <Card className="p-5 bg-white border border-slate-200 shadow-xs">
          <SectionLabel>Live Test Dispatch Results</SectionLabel>
          <p className="text-xs text-slate-500 mt-1 mb-3">
            Real external verification results. Credentials and secrets are kept server-side.
          </p>
          <div className="space-y-2.5 divide-y divide-slate-100">
            {Object.entries(testResult).map(([ch, r]) => (
              <div key={ch} className="pt-2 flex flex-wrap items-center justify-between gap-3 text-sm">
                <span className="font-mono text-slate-800 font-bold w-24 capitalize">{ch}</span>
                <div className="flex-1">
                  {r.sent ? (
                    <span className="inline-flex items-center gap-1.5 text-xs font-mono font-bold text-emerald-800 bg-emerald-50 border border-emerald-200 px-2.5 py-1 rounded-md">
                      ✓ Successfully Delivered {r.ticketKey ? `(Ticket: ${r.ticketKey})` : ''} {r.to ? `to ${r.to}` : ''}
                    </span>
                  ) : r.skipped ? (
                    <span className="inline-flex items-center gap-1.5 text-xs font-mono text-slate-600 bg-slate-50 border border-slate-200 px-2.5 py-1 rounded-md">
                      ⊙ Skipped: {r.reason}
                    </span>
                  ) : (
                    <span className="inline-flex items-center gap-1.5 text-xs font-mono font-bold text-rose-800 bg-rose-50 border border-rose-200 px-2.5 py-1 rounded-md">
                      ✗ Delivery Failed: {r.error}
                    </span>
                  )}
                </div>
              </div>
            ))}
          </div>
        </Card>
      )}

      {/* Alert History Section */}
      <Card className="p-5 bg-white border border-slate-200 shadow-xs">
        <SectionLabel>Recent Alert Delivery History</SectionLabel>
        <p className="text-xs text-slate-500 mt-1 mb-4">
          Audit log of alerts dispatched for this repository across CI/CD scans and manual analyses.
        </p>

        {history.length === 0 ? (
          <EmptyState
            icon="◎"
            title="No alert events recorded yet"
            body="Alerts dispatched during security scans or test notifications will be recorded here."
          />
        ) : (
          <div className="divide-y divide-slate-100 max-h-96 overflow-y-auto">
            {history.map((item) => (
              <div key={item.id} className="py-2.5 flex flex-wrap items-center justify-between gap-3 text-xs">
                <div className="flex items-center gap-3 min-w-[200px]">
                  <span className="font-mono text-slate-400">
                    {new Date(item.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })}
                  </span>
                  <span className="font-mono font-bold text-slate-800 uppercase px-1.5 py-0.5 rounded bg-slate-100 border border-slate-200 text-[10px]">
                    {item.channel}
                  </span>
                  <span className="font-mono text-slate-700 font-semibold">{item.findingId}</span>
                </div>
                <div className="flex-1 min-w-[200px] text-slate-600 truncate">
                  {item.summary}
                </div>
                <div>
                  {item.status === 'sent' ? (
                    <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-emerald-50 text-emerald-800 border border-emerald-200 font-bold">
                      ✓ Sent
                    </span>
                  ) : item.status === 'skipped' ? (
                    <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-slate-50 text-slate-600 border border-slate-200">
                      ⊙ Skipped
                    </span>
                  ) : (
                    <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-rose-50 text-rose-800 border border-rose-200 font-bold">
                      ✗ Failed
                    </span>
                  )}
                </div>
              </div>
            ))}
          </div>
        )}
      </Card>
    </div>
  );
}


// ── Compliance ─────────────────────────────────────────────────────────────
export function CompliancePage() {
  const [searchParams, setSearchParams] = useSearchParams();
  const repoIdParam = searchParams.get('repoId');

  const [repos, setRepos] = useState([]);
  const [selectedRepoId, setSelectedRepoId] = useState(repoIdParam || '');
  const [report, setReport] = useState(null);
  const [loading, setLoading] = useState(false);
  const [downloading, setDownloading] = useState(false);
  const [err, setErr] = useState('');

  async function handleDownloadCompliance() {
    if (!selectedRepoId) return;
    try {
      setDownloading(true);
      await api.downloadCompliance(selectedRepoId);
    } catch (e) {
      setErr(e.message || 'Download failed');
    } finally {
      setDownloading(false);
    }
  }

  useEffect(() => {
    api.connectedRepos()
      .then(list => {
        setRepos(list);
        if (!selectedRepoId && list.length > 0) {
          setSelectedRepoId(list[0].id);
        }
      })
      .catch(() => []);
  }, []);

  async function generate(targetId) {
    const id = targetId || selectedRepoId;
    if (!id) return;
    setLoading(true); setErr(''); setReport(null);
    try {
      const r = await api.getCompliance(id);
      setReport(r);
    } catch (e) { setErr(e.message); }
    finally { setLoading(false); }
  }

  useEffect(() => {
    if (selectedRepoId) {
      generate(selectedRepoId);
    }
  }, [selectedRepoId]);

  function handleRepoChange(id) {
    setSelectedRepoId(id);
    setSearchParams(id ? { repoId: id } : {});
  }

  const frameworks = report
    ? [
      { key: 'slsa', name: `SLSA v1.0 (Level ${report.slsa.achievedLevel}/${report.slsa.maxLevel})`, data: report.slsa },
      { key: 'ssdf', name: 'NIST SSDF SP 800-218', data: report.ssdf },
      { key: 'owasp', name: 'OWASP CI/CD Top 10', data: report.owasp },
    ]
    : [];

  return (
    <div className="space-y-6 w-full">
      <div className="flex items-start justify-between flex-wrap gap-3">
        <div>
          <h1 className="text-2xl font-black font-['Space_Grotesk'] text-slate-900 tracking-tight">Compliance</h1>
          <p className="text-slate-500 text-sm mt-1">SLSA · NIST SSDF · OWASP — generated live from your scan data.</p>
        </div>
        {report && selectedRepoId && (
          <Button
            size="sm"
            variant="ghost"
            loading={downloading}
            onClick={handleDownloadCompliance}
          >
            ↓ Download JSON
          </Button>
        )}
      </div>

      <ErrorBanner message={err} />

      <Card className="p-5 flex flex-wrap items-center justify-between gap-4 bg-white border border-slate-200 shadow-xs">
        <SectionLabel>Select Repository / Package</SectionLabel>
        <div className="flex items-center gap-3 flex-1 min-w-[280px]">
          <select
            value={selectedRepoId}
            onChange={e => handleRepoChange(e.target.value)}
            className="flex-1 bg-white border border-slate-200 rounded-lg px-4 py-2.5 text-sm text-slate-800 focus:outline-none focus:ring-2 focus:ring-slate-900/10 focus:border-slate-800 font-mono cursor-pointer shadow-xs"
          >
            <option value="">Choose repository…</option>
            {repos.map(r => (
              <option key={r.id} value={r.id}>{r.fullName}</option>
            ))}
          </select>
          <Button onClick={() => generate(selectedRepoId)} loading={loading} disabled={!selectedRepoId}>Generate Report</Button>
        </div>
      </Card>

      {loading && <div className="flex justify-center py-12"><Spinner size={28} color="#059669" /></div>}

      {report && (
        <>
          {/* Overall score */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <Card className="p-5 text-center col-span-2 md:col-span-1 bg-white border border-slate-200 shadow-xs">
              <SectionLabel>Overall</SectionLabel>
              <div className="text-4xl font-black font-['Space_Grotesk'] mt-2"
                style={{ color: report.overallScore >= 80 ? '#059669' : report.overallScore >= 60 ? '#d97706' : '#e11d48' }}>
                {report.overallScore}%
              </div>
            </Card>
            {frameworks.map(fw => (
              <Card key={fw.key} className="p-5 text-center bg-white border border-slate-200 shadow-xs">
                <SectionLabel>{fw.key.toUpperCase()}</SectionLabel>
                <div className="text-2xl font-black font-['Space_Grotesk'] mt-2"
                  style={{ color: fw.data.score >= 80 ? '#059669' : fw.data.score >= 60 ? '#d97706' : '#e11d48' }}>
                  {fw.data.score}%
                </div>
                <div className="text-[11px] text-slate-500 mt-1 font-mono">{fw.data.passed}/{fw.data.total} controls</div>
              </Card>
            ))}
          </div>

          {/* Critical gaps */}
          {report.summary?.criticalGaps?.length > 0 && (
            <Card className="p-5 bg-rose-50/50 border border-rose-200 shadow-xs">
              <SectionLabel>Critical gaps</SectionLabel>
              <div className="mt-3 space-y-1.5">
                {report.summary.criticalGaps.map((g, i) => (
                  <div key={i} className="flex items-center gap-2 text-xs text-rose-700 font-mono font-semibold">
                    <span>✗</span> {g}
                  </div>
                ))}
              </div>
            </Card>
          )}

          {/* Framework breakdown */}
          {frameworks.map(fw => (
            <Card key={fw.key} className="p-5 bg-white border border-slate-200 shadow-xs">
              <div className="flex items-center justify-between mb-4">
                <SectionLabel>{fw.name}</SectionLabel>
                <div className="w-32 h-2 bg-slate-100 rounded-full overflow-hidden border border-slate-200">
                  <div className="h-full rounded-full transition-all duration-700"
                    style={{ width: `${fw.data.score}%`, background: fw.data.score >= 80 ? '#059669' : fw.data.score >= 60 ? '#d97706' : '#e11d48' }} />
                </div>
              </div>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                {fw.data.controls.map(ctrl => (
                  <div key={ctrl.id} className={`flex items-start gap-2.5 text-xs p-2.5 rounded-lg border ${ctrl.passing ? 'bg-emerald-50/60 border-emerald-100' : 'bg-rose-50/60 border-rose-100'}`}>
                    <span className={`font-bold mt-0.5 ${ctrl.passing ? 'text-emerald-700' : 'text-rose-600'}`}>
                      {ctrl.passing ? '✓' : '✗'}
                    </span>
                    <div>
                      <span className="font-mono text-[10px] text-slate-500 font-medium">{ctrl.id} </span>
                      <span className={`font-medium ${ctrl.passing ? 'text-slate-800' : 'text-rose-800'}`}>{ctrl.name}</span>
                    </div>
                  </div>
                ))}
              </div>
            </Card>
          ))}
        </>
      )}

      {!report && !loading && (
        <EmptyState icon="◻" title="No compliance report yet" body="Select a connected repository above and click Generate Report." />
      )}
    </div>
  );
}

// ── Admin ─────────────────────────────────────────────────────────────────
import { useAuth } from '../hooks/useAuth';

const ROLE_COLORS = {
  Admin: '#e11d48',
  Developer: '#059669',
  SecurityAnalyst: '#d97706',
  DevOpsEngineer: '#7c3aed',
  Viewer: '#64748b',
};

export function AdminPage() {
  const { user } = useAuth();
  const [members, setMembers] = useState([]);
  const [teamInfo, setTeamInfo] = useState(null);
  const [requests, setRequests] = useState([]);
  const [apiKeys, setApiKeys] = useState([]);
  const [auditLog, setAuditLog] = useState([]);
  const [newKeyName, setNewKeyName] = useState('');
  const [newKeyScopes, setNewKeyScopes] = useState(['read:repos', 'write:scans']);
  const [newKeyResult, setNewKeyResult] = useState(null);
  const [inviteEmail, setInviteEmail] = useState('');
  const [inviteRole, setInviteRole] = useState('Developer');
  const [inviteLink, setInviteLink] = useState('');
  const [copiedLink, setCopiedLink] = useState(false);
  const [loading, setLoading] = useState(true);
  const [err, setErr] = useState('');
  const [activeTab, setActiveTab] = useState('team');

  const isAdmin = user?.role === 'Admin' || user?.role === 'admin';

  async function load() {
    setLoading(true);
    try {
      const [mem, info, reqs, k, l] = await Promise.allSettled([
        api.teamMembers(),
        api.teamInfo(),
        api.getTeamRequests(),
        api.adminApiKeys(),
        api.adminAuditLog({ limit: 20 }),
      ]);
      if (mem.status === 'fulfilled') setMembers(mem.value);
      if (info.status === 'fulfilled') setTeamInfo(info.value);
      if (reqs.status === 'fulfilled') setRequests(reqs.value || []);
      if (k.status === 'fulfilled') setApiKeys(k.value);
      if (l.status === 'fulfilled') setAuditLog(l.value);
    } catch (e) { setErr(e.message); }
    finally { setLoading(false); }
  }

  useEffect(() => { load(); }, []);

  async function createKey() {
    if (!newKeyName) return;
    try {
      const result = await api.adminCreateApiKey(newKeyName, newKeyScopes);
      setNewKeyResult(result);
      setNewKeyName('');
      await load();
    } catch (e) { setErr(e.message); }
  }

  async function revokeKey(id) {
    try { await api.adminRevokeApiKey(id); await load(); }
    catch (e) { setErr(e.message); }
  }

  async function changeRole(userId, role) {
    try { await api.adminSetRole(userId, role); await load(); }
    catch (e) { setErr(e.message); }
  }

  async function removeMember(id) {
    if (!window.confirm('Remove this member from the team?')) return;
    try { await api.removeMember(id); await load(); }
    catch (e) { setErr(e.message); }
  }

  async function respondRequest(requestId, action, role = 'Developer') {
    try {
      await api.respondTeamRequest(requestId, action, role);
      await load();
    } catch (e) { setErr(e.message); }
  }

  async function invite() {
    if (!inviteEmail) return;
    setErr('');
    try {
      const token = localStorage.getItem('securechain_token');
      const r = await api.adminInvite(
        inviteEmail,
        inviteRole,
        teamInfo?.org?.id,
        token ? { Authorization: `Bearer ${token}` } : {}
      );
      const link = `${window.location.origin}${r.inviteLink}`;
      setInviteLink(link);
      setInviteEmail('');
    } catch (e) { setErr(e.message); }
  }

  function copyLink() {
    navigator.clipboard.writeText(inviteLink);
    setCopiedLink(true);
    setTimeout(() => setCopiedLink(false), 2000);
  }

  const ALL_SCOPES = ['read:repos', 'write:scans', 'read:vulns', 'write:alerts', 'admin'];
  const ROLES = ['Admin', 'Developer', 'SecurityAnalyst', 'DevOpsEngineer', 'Viewer'];
  const tabs = [
    { id: 'team', label: `Team Members (${members.length})`, icon: '👥' },
    { id: 'keys', label: 'API Keys', icon: '🔑' },
    { id: 'audit', label: 'Audit Log', icon: '📋' },
  ];

  return (
    <div className="space-y-6 w-full max-w-4xl">
      {/* Header */}
      <div className="flex items-start justify-between flex-wrap gap-4">
        <div>
          <h1 className="text-2xl font-black font-['Space_Grotesk'] text-slate-900 tracking-tight">
            {teamInfo?.org ? teamInfo.org.name : 'Admin Panel'}
          </h1>
          <p className="text-slate-500 text-sm mt-1">
            {teamInfo?.mode === 'team'
              ? `Team workspace · ${members.length} member${members.length !== 1 ? 's' : ''}`
              : 'Solo workspace'}
          </p>
        </div>
        {/* Current user badge */}
        {user && (
          <div className="flex items-center gap-3 bg-white border border-slate-200 shadow-xs rounded-xl px-4 py-2.5">
            {user.avatar ? (
              <img
                src={user.avatar}
                alt=""
                referrerPolicy="no-referrer"
                onError={e => { e.target.style.display = 'none'; e.target.nextSibling?.style.setProperty('display', 'flex'); }}
                className="w-7 h-7 rounded-full object-cover border border-slate-200"
              />
            ) : null}
            <div className="w-7 h-7 rounded-full items-center justify-center font-bold text-xs text-white hidden bg-slate-900"
              style={{ display: user.avatar ? 'none' : 'flex' }}>
              {(user.name || user.login || '?')[0].toUpperCase()}
            </div>
            <div>
              <p className="text-sm text-slate-900 font-semibold leading-none">{user.name || user.login}</p>
              <p className="text-[10px] font-mono mt-0.5 font-bold" style={{ color: ROLE_COLORS[user.role] || '#64748b' }}>
                {user.role || 'Developer'}
              </p>
            </div>
          </div>
        )}
      </div>

      <ErrorBanner message={err} />

      {/* Tabs */}
      <div className="flex gap-1 bg-slate-100 border border-slate-200 rounded-xl p-1 shadow-inner">
        {tabs.map(t => (
          <button key={t.id} onClick={() => setActiveTab(t.id)}
            className={`flex-1 flex items-center justify-center gap-2 py-2 rounded-lg text-sm font-semibold transition-all ${activeTab === t.id
                ? 'bg-white text-slate-900 shadow-xs'
                : 'text-slate-500 hover:text-slate-900 hover:bg-slate-200/50'
              }`}>
            <span>{t.icon}</span> {t.label}
          </button>
        ))}
      </div>

      {loading ? (
        <div className="flex justify-center py-16"><Spinner size={28} color="#0f172a" /></div>
      ) : (
        <>
          {/* ── Team Members Tab ── */}
          {activeTab === 'team' && (
            <div className="space-y-4">
              {/* Pending Join Requests (If any) */}
              {isAdmin && requests.length > 0 && (
                <Card className="p-5 border-amber-200 bg-amber-50/50 shadow-xs">
                  <div className="flex items-center justify-between mb-3">
                    <SectionLabel>Pending Join Requests ({requests.length})</SectionLabel>
                    <span className="text-[11px] bg-amber-100 text-amber-900 px-2.5 py-0.5 rounded-full border border-amber-300 font-semibold">
                      Action Required
                    </span>
                  </div>
                  <div className="divide-y divide-amber-200/60">
                    {requests.map((rq) => (
                      <div key={rq.id} className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 py-3">
                        <div className="flex items-center gap-3">
                          {rq.userAvatar ? (
                            <img src={rq.userAvatar} alt="" referrerPolicy="no-referrer" className="w-8 h-8 rounded-full object-cover border border-slate-200" />
                          ) : (
                            <div className="w-8 h-8 rounded-full bg-slate-900 text-white font-bold flex items-center justify-center text-xs">
                              {(rq.userName || '?')[0].toUpperCase()}
                            </div>
                          )}
                          <div>
                            <p className="text-sm font-bold text-slate-900">{rq.userName}</p>
                            <p className="text-xs text-slate-500 font-mono">{rq.userEmail}</p>
                            {rq.note && <p className="text-[11px] text-slate-700 italic mt-0.5">"{rq.note}"</p>}
                          </div>
                        </div>

                        <div className="flex items-center gap-2">
                          <select
                            id={`role-${rq.id}`}
                            defaultValue="Developer"
                            className="text-xs bg-white border border-slate-200 text-slate-800 rounded-lg px-2.5 py-1.5 focus:outline-none focus:ring-2 focus:ring-slate-900/10 font-medium"
                          >
                            {ROLES.map((r) => <option key={r} value={r}>{r}</option>)}
                          </select>
                          <button
                            onClick={() => {
                              const selRole = document.getElementById(`role-${rq.id}`)?.value || 'Developer';
                              respondRequest(rq.id, 'approve', selRole);
                            }}
                            className="text-xs font-bold px-3 py-1.5 rounded-lg bg-emerald-600 text-white hover:bg-emerald-700 transition-colors shadow-xs"
                          >
                            Approve
                          </button>
                          <button
                            onClick={() => respondRequest(rq.id, 'reject')}
                            className="text-xs font-bold px-3 py-1.5 rounded-lg border border-rose-200 bg-white text-rose-700 hover:bg-rose-50 transition-colors shadow-xs"
                          >
                            Reject
                          </button>
                        </div>
                      </div>
                    ))}
                  </div>
                </Card>
              )}

              {/* Invite section */}
              {isAdmin && (
                <Card className="p-5 bg-white border border-slate-200 shadow-xs">
                  <SectionLabel>Invite Member</SectionLabel>
                  <div className="flex flex-wrap gap-2 mt-3">
                    <input
                      value={inviteEmail}
                      onChange={e => setInviteEmail(e.target.value)}
                      placeholder="colleague@company.com"
                      onKeyDown={e => e.key === 'Enter' && invite()}
                      className="flex-1 min-w-48 text-sm bg-white border border-slate-200 rounded-lg px-3 py-2 text-slate-800 placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-slate-900/10 focus:border-slate-800 transition-colors shadow-xs"
                    />
                    <select
                      value={inviteRole}
                      onChange={e => setInviteRole(e.target.value)}
                      className="text-sm bg-white border border-slate-200 text-slate-800 rounded-lg px-3 py-2 focus:outline-none cursor-pointer shadow-xs font-medium"
                    >
                      {ROLES.map(r => <option key={r}>{r}</option>)}
                    </select>
                    <Button size="sm" onClick={invite}>Send Invite</Button>
                  </div>

                  {/* Generated invite link */}
                  {inviteLink && (
                    <div className="mt-3 p-3 rounded-lg bg-emerald-50 border border-emerald-200 flex items-center gap-3">
                      <div className="flex-1 min-w-0">
                        <p className="text-[11px] text-emerald-800 font-bold mb-1">✓ Invite link generated — share this with your colleague</p>
                        <p className="text-xs font-mono text-emerald-900 truncate font-semibold">{inviteLink}</p>
                      </div>
                      <button
                        onClick={copyLink}
                        className="shrink-0 text-xs px-3 py-1.5 rounded-lg bg-white border border-emerald-300 hover:bg-emerald-100 text-emerald-800 font-mono font-bold transition-colors shadow-xs"
                      >
                        {copiedLink ? '✓ Copied!' : 'Copy'}
                      </button>
                    </div>
                  )}
                </Card>
              )}

              {/* Members list */}
              <Card className="p-5 bg-white border border-slate-200 shadow-xs">
                <SectionLabel>Members ({members.length})</SectionLabel>
                <div className="mt-3 divide-y divide-slate-100">
                  {members.map(m => (
                    <div key={m.id} className="flex items-center gap-4 py-3">
                      {m.avatar ? (
                        <img
                          src={m.avatar}
                          alt=""
                          referrerPolicy="no-referrer"
                          className="w-8 h-8 rounded-full border border-slate-200 shrink-0 object-cover"
                          onError={e => { e.target.style.display = 'none'; }}
                        />
                      ) : (
                        <div className="w-8 h-8 rounded-full border border-slate-200 shrink-0 flex items-center justify-center font-bold text-xs text-white bg-slate-900">
                          {(m.name || m.login || '?')[0].toUpperCase()}
                        </div>
                      )}
                      <div className="flex-1 min-w-0">
                        <p className="text-sm text-slate-900 font-bold">
                          {m.login || m.name || m.email}
                          {m.id === user?.id && (
                            <span className="ml-2 text-[10px] font-mono text-emerald-700 bg-emerald-50 border border-emerald-200 px-1.5 py-0.5 rounded font-bold">(you)</span>
                          )}
                        </p>
                        <p className="text-xs text-slate-500 font-mono truncate">{m.email || m.githubLogin || ''}</p>
                      </div>
                      <span className="text-xs font-mono px-2.5 py-0.5 rounded-full border font-semibold"
                        style={{ color: ROLE_COLORS[m.role] || '#64748b', borderColor: (ROLE_COLORS[m.role] || '#64748b') + '30', background: (ROLE_COLORS[m.role] || '#64748b') + '12' }}>
                        {m.role || 'Developer'}
                      </span>
                      {isAdmin && m.id !== user?.id && (
                        <div className="flex items-center gap-2">
                          <select
                            value={m.role || 'Developer'}
                            onChange={e => changeRole(m.id, e.target.value)}
                            className="text-xs bg-white border border-slate-200 text-slate-800 rounded-lg px-2 py-1 focus:outline-none cursor-pointer shadow-xs"
                          >
                            {ROLES.map(r => <option key={r}>{r}</option>)}
                          </select>
                          <button
                            onClick={() => removeMember(m.id)}
                            className="text-xs text-rose-700 hover:bg-rose-50 border border-rose-200 px-2.5 py-1 rounded-lg transition-colors font-medium shadow-xs"
                          >
                            Remove
                          </button>
                        </div>
                      )}
                    </div>
                  ))}
                  {members.length === 0 && (
                    <p className="text-xs text-slate-500 py-6 text-center">No members yet</p>
                  )}
                </div>
              </Card>
            </div>
          )}

          {/* ── API Keys Tab ── */}
          {activeTab === 'keys' && (
            <Card className="p-5 bg-white border border-slate-200 shadow-xs">
              <SectionLabel>Platform API Keys</SectionLabel>
              <div className="flex flex-wrap gap-2 mt-3 mb-4">
                <input
                  value={newKeyName}
                  onChange={e => setNewKeyName(e.target.value)}
                  placeholder="Key name…"
                  className="text-xs bg-white border border-slate-200 rounded-lg px-3 py-1.5 text-slate-800 placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-slate-900/10 focus:border-slate-800 shadow-xs"
                />
                <div className="flex gap-1.5 flex-wrap">
                  {ALL_SCOPES.map(s => (
                    <button key={s}
                      onClick={() => setNewKeyScopes(p => p.includes(s) ? p.filter(x => x !== s) : [...p, s])}
                      className={`text-[11px] px-2.5 py-1 rounded-md font-mono border transition-colors ${newKeyScopes.includes(s)
                          ? 'border-emerald-300 bg-emerald-50 text-emerald-800 font-bold shadow-xs'
                          : 'border-slate-200 bg-white text-slate-600 hover:border-slate-300 shadow-xs'
                        }`}>
                      {s}
                    </button>
                  ))}
                </div>
                <Button size="sm" onClick={createKey}>Create key</Button>
              </div>

              {newKeyResult?.raw && (
                <div className="mb-4 p-3 rounded-lg bg-emerald-50 border border-emerald-200">
                  <p className="text-[10px] text-emerald-800 font-mono font-bold mb-1">✓ Copy now — shown only once</p>
                  <p className="text-xs font-mono text-emerald-950 font-bold break-all select-all">{newKeyResult.raw}</p>
                </div>
              )}

              <div className="divide-y divide-slate-100">
                {apiKeys.map(k => (
                  <div key={k.id} className="flex items-center gap-3 py-3">
                    <div className="flex-1">
                      <span className="text-sm text-slate-900 font-semibold">{k.name}</span>
                      <span className="text-xs font-mono text-slate-500 ml-2">{k.prefix}</span>
                      <div className="flex gap-1 mt-1">
                        {k.scopes?.map(s => <Badge key={s} variant="default">{s}</Badge>)}
                      </div>
                    </div>
                    <span className="text-[11px] text-slate-500 font-mono">
                      {k.lastUsedAt ? 'Used ' + new Date(k.lastUsedAt).toLocaleDateString() : 'Never used'}
                    </span>
                    <Button size="sm" variant="danger" onClick={() => revokeKey(k.id)}>Revoke</Button>
                  </div>
                ))}
                {apiKeys.length === 0 && <p className="text-xs text-slate-500 py-4 text-center">No API keys yet</p>}
              </div>
            </Card>
          )}

          {/* ── Audit Log Tab ── */}
          {activeTab === 'audit' && (
            <Card className="p-5 bg-white border border-slate-200 shadow-xs">
              <SectionLabel>Audit Log (last 20 events)</SectionLabel>
              <div className="mt-3 divide-y divide-slate-100">
                {auditLog.map(e => (
                  <div key={e.id} className="flex items-center gap-3 py-2.5 text-xs">
                    <span className="font-mono text-slate-400 shrink-0 w-20">
                      {e.timestamp?.slice(11, 19)}
                    </span>
                    <span className="font-mono text-slate-900 font-bold shrink-0">{e.action}</span>
                    <span className="text-slate-600 truncate">by <strong className="text-slate-800 font-semibold">{e.actor?.login}</strong></span>
                    <span className="text-slate-400 shrink-0 hidden sm:block font-mono">
                      {new Date(e.timestamp).toLocaleDateString()}
                    </span>
                  </div>
                ))}
                {auditLog.length === 0 && (
                  <p className="text-xs text-slate-500 py-6 text-center">No audit events yet</p>
                )}
              </div>
            </Card>
          )}
        </>
      )}
    </div>
  );
}
