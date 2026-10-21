import { useEffect, useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import { api } from '../lib/api';
import { Button, Badge, Card, Spinner, SectionLabel, EmptyState, ErrorBanner } from '../components/ui';

const PRIORITY_BADGE = { P0_CRITICAL: 'critical', P1_HIGH: 'high', P2_MEDIUM: 'medium', P3_LOW: 'low', UNKNOWN: 'default' };
const STATUS_BADGE = { Open: 'critical', 'In Progress': 'high', Resolved: 'safe', 'Accepted Risk': 'violet' };
const STATUSES = ['Open', 'In Progress', 'Resolved', 'Accepted Risk'];

function VulnRow({ vuln, onStatusChange }) {
  const [changing, setChanging] = useState(false);
  const [showVex, setShowVex] = useState(false);
  const [vexNote, setVexNote] = useState('');
  const [aiText, setAiText] = useState('');
  const [aiLoading, setAiLoading] = useState(false);
  const [showAi, setShowAi] = useState(false);

  async function explainWithAi() {
    setShowAi(true);
    setAiText('');
    setAiLoading(true);
    try {
      const res = await api.aiExplainStream(vuln);
      if (!res.ok) {
        const err = await res.json().catch(() => ({}));
        setAiText(err.detail || err.error || 'AI explain failed — is ANTHROPIC_API_KEY set?');
        setAiLoading(false);
        return;
      }
      const reader = res.body.getReader();
      const decoder = new TextDecoder();
      let buffer = '';
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        buffer += decoder.decode(value, { stream: true });
        const lines = buffer.split('\n');
        buffer = lines.pop();
        for (const line of lines) {
          if (!line.startsWith('data: ')) continue;
          try {
            const payload = JSON.parse(line.slice(6));
            if (payload.type === 'delta') setAiText(t => t + payload.text);
            if (payload.type === 'done') setAiLoading(false);
          } catch { /* ignore malformed */ }
        }
      }
    } catch (e) {
      setAiText(`Error: ${e.message}`);
    } finally {
      setAiLoading(false);
    }
  }

  async function changeStatus(status) {
    if (status === 'Accepted Risk') { setShowVex(true); return; }
    setChanging(true);
    try { await onStatusChange(vuln.id, status); } finally { setChanging(false); }
  }

  async function acceptRisk() {
    setChanging(true);
    setShowVex(false);
    try { await onStatusChange(vuln.id, 'Accepted Risk', vexNote); } finally { setChanging(false); }
  }

  return (
    <div className="px-5 py-4 border-b border-slate-100 last:border-0 hover:bg-slate-50/70 transition-colors">
      <div className="flex items-start gap-4">
        <div className="flex-1 min-w-0">
          <div className="flex items-center flex-wrap gap-2 mb-1.5">
            <span className="font-mono text-sm font-bold text-slate-900">{vuln.cveId || vuln.id}</span>
            <Badge variant={PRIORITY_BADGE[vuln.priorityLabel] || 'default'}>{vuln.priorityLabel || 'UNKNOWN'}</Badge>
            <Badge variant={STATUS_BADGE[vuln.status] || 'default'}>{vuln.status}</Badge>
          </div>
          <p className="text-xs text-slate-600 mb-2 line-clamp-2 leading-relaxed">{vuln.summary || 'No description available.'}</p>
          <div className="flex flex-wrap items-center gap-4 text-[11px] font-mono text-slate-500">
            <span>Component: <span className="text-slate-800 font-semibold">{vuln.component}@{vuln.version}</span></span>
            <span>CVSS: <span className="text-amber-700 font-semibold">{vuln.severity ?? 'N/A'}</span></span>
            <span>EPSS: <span className="text-rose-600 font-semibold">{vuln.epss != null ? `${(vuln.epss * 100).toFixed(1)}%` : 'N/A'}</span></span>
            <span>Priority: <span className="text-slate-900 font-semibold">{vuln.priorityScore ?? 'N/A'}</span></span>
            {vuln.fixedVersions?.length > 0 && (
              <span>Fix: <span className="text-emerald-700 font-semibold">{vuln.fixedVersions.join(', ')}</span></span>
            )}
          </div>
          {showVex && (
            <div className="mt-3 flex gap-2">
              <input value={vexNote} onChange={e => setVexNote(e.target.value)} placeholder="VEX justification (required for audit trail)"
                className="flex-1 text-xs bg-white border border-slate-300 rounded-lg px-3 py-1.5 text-slate-900 placeholder-slate-400 focus:outline-none focus:border-slate-900 shadow-2xs" />
              <Button size="sm" variant="ghost" onClick={acceptRisk} loading={changing}>Accept risk</Button>
              <Button size="sm" variant="ghost" onClick={() => setShowVex(false)}>Cancel</Button>
            </div>
          )}

          {/* AI Explain panel */}
          {showAi && (
            <div className="mt-3 p-3.5 rounded-xl bg-slate-50 border border-slate-200 text-xs text-slate-700 leading-relaxed font-mono whitespace-pre-wrap shadow-2xs">
              {aiText || (aiLoading ? <span className="text-slate-800 animate-pulse font-semibold">Generating AI Security explanation…</span> : '')}
              {aiLoading && aiText && <span className="inline-block w-1.5 h-3 bg-emerald-600 ml-0.5 animate-pulse" />}
            </div>
          )}
        </div>
        <div className="flex items-center gap-2 shrink-0">
          <button
            onClick={explainWithAi}
            className="text-[11px] font-mono font-semibold px-2.5 py-1 rounded-lg border border-slate-300 bg-white text-slate-700 hover:bg-slate-50 shadow-2xs transition-colors cursor-pointer"
            title="AI explain (requires GEMINI_API_KEY)"
          >
            ◈ AI
          </button>
          <select
            value={vuln.status}
            onChange={e => changeStatus(e.target.value)}
            disabled={changing}
            className="text-xs bg-white border border-slate-300 text-slate-800 rounded-lg px-2.5 py-1.5 focus:outline-none focus:border-slate-900 cursor-pointer shadow-2xs"
          >
            {STATUSES.map(s => <option key={s} value={s}>{s}</option>)}
          </select>
        </div>
      </div>
    </div>
  );
}

export default function Vulnerabilities() {
  const [searchParams, setSearchParams] = useSearchParams();
  const repoIdParam = searchParams.get('repoId');

  const [repos, setRepos] = useState([]);
  const [selectedRepoId, setSelectedRepoId] = useState(repoIdParam || 'all');
  const [vulns, setVulns] = useState([]);
  const [loading, setLoading] = useState(true);
  const [downloading, setDownloading] = useState(false);
  const [err, setErr] = useState('');
  const [filter, setFilter] = useState('All');

  async function handleDownloadReport() {
    try {
      setDownloading(true);
      await api.downloadVulnerabilities(selectedRepoId);
    } catch (e) {
      setErr(e.message || 'Report download failed');
    } finally {
      setDownloading(false);
    }
  }

  async function loadData() {
    setLoading(true);
    setErr('');
    try {
      const [reposList, vulnsList] = await Promise.all([
        api.connectedRepos().catch(() => []),
        api.listVulnerabilities(selectedRepoId),
      ]);
      setRepos(reposList);
      setVulns(vulnsList);
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

  async function handleStatusChange(id, status, vexJustification) {
    const updated = await api.updateVulnerabilityStatus(id, status, vexJustification);
    setVulns(prev => prev.map(v => v.id === id ? { ...v, ...updated } : v));
  }

  const filtered = filter === 'All' ? vulns : vulns.filter(v => v.status === filter || v.priorityLabel === filter);

  const counts = {
    P0_CRITICAL: vulns.filter(v => v.priorityLabel === 'P0_CRITICAL').length,
    P1_HIGH: vulns.filter(v => v.priorityLabel === 'P1_HIGH').length,
    Open: vulns.filter(v => v.status === 'Open').length,
  };

  return (
    <div className="space-y-6 w-full">
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-black font-['Space_Grotesk'] text-slate-900">Vulnerabilities</h1>
          <p className="text-slate-500 text-sm mt-1">CVE findings, EPSS-CVSS priority fusion, VEX workflow.</p>
        </div>
        <div className="flex items-center gap-2">
          <Badge variant="critical">{counts.P0_CRITICAL} P0</Badge>
          <Badge variant="high">{counts.P1_HIGH} P1</Badge>
          <Badge variant="default">{counts.Open} Open</Badge>
          <Button size="sm" variant="ghost" loading={downloading} onClick={handleDownloadReport}>
            ↓ Export JSON
          </Button>
        </div>
      </div>

      <ErrorBanner message={err} onRetry={loadData} />

      {/* Repo Dropdown Selector */}
      <Card className="p-4 flex flex-wrap items-center justify-between gap-4">
        <SectionLabel>Filter by Repository / Package</SectionLabel>
        <div className="flex items-center gap-3 flex-1 min-w-[280px]">
          <select
            value={selectedRepoId}
            onChange={e => handleRepoChange(e.target.value)}
            className="flex-1 bg-white border border-slate-300 rounded-lg px-3.5 py-2 text-xs text-slate-900 focus:outline-none focus:border-slate-900 font-mono cursor-pointer shadow-2xs"
          >
            <option value="all">All Scanned Repositories & Packages</option>
            {repos.map(r => (
              <option key={r.id} value={r.id}>
                {r.fullName} ({r.openVulnCount} vulns, risk score: {r.riskScore ?? 'N/A'})
              </option>
            ))}
          </select>
          <Button size="sm" variant="ghost" onClick={loadData}>↺ Refresh</Button>
        </div>
      </Card>

      {/* Filter tabs */}
      <div className="flex flex-wrap gap-2">
        {['All', 'P0_CRITICAL', 'P1_HIGH', 'Open', 'Resolved', 'Accepted Risk'].map(f => (
          <button key={f} onClick={() => setFilter(f)}
            className={`px-3 py-1.5 text-xs font-mono font-medium rounded-lg transition-colors cursor-pointer ${
              filter === f
                ? 'bg-slate-900 text-white shadow-2xs'
                : 'text-slate-600 hover:text-slate-900 bg-white border border-slate-200 hover:bg-slate-50'
            }`}>
            {f}
          </button>
        ))}
      </div>

      {loading ? (
        <div className="flex items-center justify-center h-48"><Spinner size={28} color="#0f172a" /></div>
      ) : filtered.length === 0 ? (
        <EmptyState icon="◈" title="No vulnerabilities found" body={selectedRepoId !== 'all' ? 'This repository passed all vulnerability checks clean.' : 'No vulnerabilities detected across scanned repositories.'} />
      ) : (
        <Card className="p-0 overflow-hidden shadow-xs divide-y divide-slate-100">
          {filtered.map(v => (
            <VulnRow key={v.id} vuln={v} onStatusChange={handleStatusChange} />
          ))}
        </Card>
      )}
    </div>
  );
}

