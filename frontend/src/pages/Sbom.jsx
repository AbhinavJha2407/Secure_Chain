import { useState, useEffect } from 'react';
import { useSearchParams } from 'react-router-dom';
import { api } from '../lib/api';
import { Button, Badge, Card, Spinner, SectionLabel, EmptyState, ErrorBanner } from '../components/ui';

function ComponentRow({ comp }) {
  return (
    <div className="px-5 py-3 border-b border-slate-100 last:border-0 flex flex-wrap items-center justify-between gap-4 hover:bg-slate-50/70 transition-colors group">
      <div className="flex-1 min-w-[200px]">
        <div className="flex items-center gap-2 flex-wrap">
          <span className="font-mono text-xs font-bold text-slate-900">{comp.name}</span>
          <span className="font-mono text-xs text-slate-500">@{comp.version}</span>
          {comp.hasInstallScripts && <Badge variant="high">install script</Badge>}
          {!comp.resolved && <Badge variant="default">unresolved</Badge>}
        </div>
        <div className="flex items-center gap-3 mt-1 flex-wrap">
          <span className="text-[11px] font-mono text-slate-400 break-all">{comp.purl}</span>
          {comp.licence && <Badge variant="default">{comp.licence}</Badge>}
        </div>
      </div>
      {comp.publishDate && (
        <span className="text-[11px] font-mono text-slate-400 shrink-0">
          Published: {comp.publishDate.slice(0, 10)}
        </span>
      )}
    </div>
  );
}

export default function SbomPage() {
  const [searchParams, setSearchParams] = useSearchParams();
  const repoIdParam = searchParams.get('repoId');
  const sbomIdParam = searchParams.get('sbomId');

  const [sbomList, setSbomList] = useState([]);
  const [repos, setRepos] = useState([]);
  const [selectedSbomId, setSelectedSbomId] = useState('');
  const [selectedRepoId, setSelectedRepoId] = useState('');
  
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(true);
  const [scanLoading, setScanLoading] = useState(false);
  const [err, setErr] = useState('');
  
  const [search, setSearch] = useState('');
  const [filterType, setFilterType] = useState('all'); // all | scripts | unresolved
  const [viewTab, setViewTab] = useState('components'); // components | cyclonedx | spdx | diff
  const [copied, setCopied] = useState(false);
  const [downloadingFormat, setDownloadingFormat] = useState('');

  async function handleDownload(format) {
    if (!result?.id) return;
    try {
      setDownloadingFormat(format);
      await api.downloadSbom(result.id, format);
    } catch (e) {
      setErr(e.message || 'Download failed');
    } finally {
      setDownloadingFormat('');
    }
  }

  // Load repositories and SBOM history
  async function loadData() {
    setLoading(true);
    setErr('');
    try {
      const [sbomsData, reposData] = await Promise.all([
        api.listSboms().catch(() => []),
        api.connectedRepos().catch(() => []),
      ]);
      setSbomList(sbomsData);
      setRepos(reposData);

      let targetSbomId = sbomIdParam;
      let targetRepoId = repoIdParam;

      if (targetSbomId) {
        await loadSbomById(targetSbomId);
      } else if (targetRepoId) {
        await loadSbomForRepo(targetRepoId);
      } else if (sbomsData.length > 0) {
        targetSbomId = sbomsData[0].id;
        await loadSbomById(targetSbomId);
      }
    } catch (e) {
      setErr(e.message);
    } finally {
      setLoading(false);
    }
  }

  async function loadSbomById(id) {
    if (!id) return;
    setLoading(true);
    setErr('');
    try {
      const fullSbom = await api.getSbom(id);
      setResult(fullSbom);
      setSelectedSbomId(fullSbom.id);
      setSelectedRepoId(fullSbom.repoId);
    } catch (e) {
      if (e.status === 404) {
        setResult(null);
      } else {
        setErr(e.message);
      }
    } finally {
      setLoading(false);
    }
  }


  async function loadSbomForRepo(repoId) {
    if (!repoId) return;
    setLoading(true);
    setErr('');
    try {
      const fullSbom = await api.getLatestSbom(repoId);
      setResult(fullSbom);
      setSelectedSbomId(fullSbom.id);
      setSelectedRepoId(fullSbom.repoId);
    } catch (e) {
      if (e.status === 404) {
        setResult(null);
      } else {
        setErr(e.message || 'No SBOM found for this repository.');
      }
    } finally {
      setLoading(false);
    }
  }

  async function runScan() {
    const targetRepo = selectedRepoId || repoIdParam;
    if (!targetRepo) {
      setErr('Select or enter a repository to generate an SBOM');
      return;
    }
    setScanLoading(true);
    setErr('');
    try {
      const scanRes = await api.scanRepo(targetRepo, { maxDepth: 2 });
      if (scanRes.sbomId) {
        await loadSbomById(scanRes.sbomId);
      } else {
        setResult(scanRes);
      }
      // Refresh list
      const updatedList = await api.listSboms().catch(() => []);
      setSbomList(updatedList);
    } catch (e) {
      setErr(e.message);
    } finally {
      setScanLoading(false);
    }
  }

  useEffect(() => {
    loadData();
  }, [repoIdParam, sbomIdParam]);

  function handleSelectSbom(id) {
    if (!id) return;
    setSearchParams({ sbomId: id });
    loadSbomById(id);
  }

  function handleSelectRepo(rId) {
    if (!rId) return;
    setSelectedRepoId(rId);
    setSearchParams({ repoId: rId });
    loadSbomForRepo(rId);
  }

  function handleCopyJson(content) {
    navigator.clipboard.writeText(JSON.stringify(content, null, 2));
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  }

  // Component filtering logic
  const rawComponents = result?.components || [];
  const filteredComponents = rawComponents.filter(c => {
    const query = search.toLowerCase().trim();
    const matchesSearch = !query || 
      (c.name && c.name.toLowerCase().includes(query)) ||
      (c.purl && c.purl.toLowerCase().includes(query)) ||
      (c.licence && c.licence.toLowerCase().includes(query));

    if (!matchesSearch) return false;

    if (filterType === 'scripts') return !!c.hasInstallScripts;
    if (filterType === 'unresolved') return !c.resolved;
    return true;
  });

  return (
    <div className="space-y-6 w-full">
      {/* Header */}
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-black font-['Space_Grotesk'] text-slate-900">Software Bill of Materials (SBOM)</h1>
          <p className="text-slate-500 text-sm mt-1">
            Transitive dependency graph in CycloneDX 1.5 & SPDX 2.3 format — generated automatically on every repository scan.
          </p>
        </div>
        <Button size="sm" variant="ghost" onClick={loadData}>↺ Refresh</Button>
      </div>

      <ErrorBanner message={err} onRetry={() => setErr('')} retryLabel="Dismiss" />

      {/* Selector and Generator Card */}
      <Card className="p-5 space-y-4">
        <div className="flex flex-wrap items-center justify-between gap-4">
          <SectionLabel>Select Scanned Repository / Package</SectionLabel>
          {result?.createdAt && (
            <span className="text-xs font-mono text-slate-400">
              Generated: {new Date(result.createdAt).toLocaleString()}
            </span>
          )}
        </div>

        <div className="flex flex-wrap gap-3">
          {/* SBOM / Repo Dropdown */}
          <select
            value={selectedSbomId}
            onChange={(e) => handleSelectSbom(e.target.value)}
            className="flex-1 min-w-[280px] bg-white border border-slate-300 rounded-lg px-4 py-2.5 text-xs text-slate-900 focus:outline-none focus:border-slate-900 font-mono cursor-pointer shadow-2xs"
          >
            {sbomList.length === 0 && <option value="">No SBOMs generated yet</option>}
            {sbomList.map((s) => (
              <option key={s.id} value={s.id}>
                {s.repoName} — {s.componentCount} components ({new Date(s.createdAt).toLocaleDateString()})
              </option>
            ))}
          </select>

          {/* Connected repos selector */}
          <select
            value={selectedRepoId}
            onChange={(e) => handleSelectRepo(e.target.value)}
            className="w-52 bg-white border border-slate-300 rounded-lg px-3 py-2.5 text-xs text-slate-800 focus:outline-none focus:border-slate-900 cursor-pointer shadow-2xs"
          >
            <option value="">Choose connected repo…</option>
            {repos.map((r) => (
              <option key={r.id} value={r.id}>
                {r.fullName}
              </option>
            ))}
          </select>

          <Button onClick={runScan} loading={scanLoading} disabled={!selectedRepoId && !repoIdParam}>
            {scanLoading ? 'Scanning…' : 'Generate / Rescan'}
          </Button>
        </div>
      </Card>

      {/* Loading state */}
      {loading && (
        <div className="flex flex-col items-center justify-center gap-4 py-16">
          <Spinner size={32} color="#0f172a" />
          <div className="text-center">
            <p className="text-slate-800 font-semibold text-sm">Loading SBOM data…</p>
            <p className="text-slate-400 text-xs mt-1">Resolving package components and license declarations</p>
          </div>
        </div>
      )}

      {/* Active SBOM Details */}
      {!loading && result && (
        <div className="space-y-6">
          {/* Summary metrics */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            {[
              { label: 'Total components', value: result.sbomSummary?.totalComponents ?? rawComponents.length, color: '#0f172a' },
              { label: 'Resolved components', value: result.sbomSummary?.resolved ?? rawComponents.filter(c => c.resolved !== false).length, color: '#059669' },
              { label: 'Vulnerabilities', value: result.vulnerabilities?.length ?? 0, color: (result.vulnerabilities?.length ?? 0) > 0 ? '#e11d48' : '#059669' },
              { label: 'Malicious pkgs', value: result.maliciousPackages?.length ?? 0, color: (result.maliciousPackages?.length ?? 0) > 0 ? '#e11d48' : '#059669' },
            ].map(s => (
              <Card key={s.label} className="p-4 text-center">
                <SectionLabel>{s.label}</SectionLabel>
                <div className="text-3xl font-black font-['Space_Grotesk'] mt-2" style={{ color: s.color }}>{s.value}</div>
              </Card>
            ))}
          </div>

          {/* Sub-navigation tabs */}
          <div className="flex flex-wrap items-center justify-between gap-4 border-b border-slate-200 pb-0">
            <div className="flex gap-2">
              {[
                { id: 'components', label: `Components (${rawComponents.length})` },
                { id: 'threat-ranking', label: `Threat & Harmness Ranking (${(result.vulnerabilities?.length || 0) + (result.maliciousPackages?.length || 0)})` },
                { id: 'cyclonedx', label: 'CycloneDX 1.5 JSON' },
                { id: 'spdx', label: 'SPDX 2.3 JSON' },
                ...(result.diff && (result.diff.added?.length > 0 || result.diff.removed?.length > 0 || result.diff.changed?.length > 0)
                  ? [{ id: 'diff', label: 'SBOM Diff' }]
                  : []),
              ].map(t => (
                <button
                  key={t.id}
                  onClick={() => setViewTab(t.id)}
                  className={`px-4 py-2.5 text-xs font-semibold transition-colors border-b-2 -mb-px cursor-pointer ${
                    viewTab === t.id
                      ? 'border-slate-900 text-slate-900'
                      : 'border-transparent text-slate-500 hover:text-slate-800'
                  }`}
                >
                  {t.label}
                </button>
              ))}
            </div>

            {/* Quick Export Downloads */}
            {result.id && (
              <div className="flex items-center gap-2 mb-2">
                <Button
                  size="sm"
                  variant="ghost"
                  loading={downloadingFormat === 'cyclonedx'}
                  onClick={() => handleDownload('cyclonedx')}
                >
                  ↓ CycloneDX
                </Button>
                <Button
                  size="sm"
                  variant="ghost"
                  loading={downloadingFormat === 'spdx'}
                  onClick={() => handleDownload('spdx')}
                >
                  ↓ SPDX
                </Button>
              </div>
            )}
          </div>

          {/* ── Tab: Components List ── */}
          {viewTab === 'components' && (
            <Card className="p-0 overflow-hidden shadow-xs">
              {/* Search & filter bar */}
              <div className="p-4 border-b border-slate-100 flex flex-wrap items-center justify-between gap-3 bg-slate-50">
                <input
                  value={search}
                  onChange={e => setSearch(e.target.value)}
                  placeholder="Filter components by name, purl, or license…"
                  className="flex-1 min-w-[240px] bg-white border border-slate-300 rounded-lg px-3 py-2 text-xs text-slate-900 placeholder-slate-400 focus:outline-none focus:border-slate-900 font-mono shadow-2xs"
                />
                <div className="flex items-center gap-2">
                  <span className="text-xs text-slate-500 font-mono">Filter:</span>
                  {[
                    { id: 'all', label: 'All' },
                    { id: 'scripts', label: 'Install Scripts' },
                    { id: 'unresolved', label: 'Unresolved' },
                  ].map(f => (
                    <button
                      key={f.id}
                      onClick={() => setFilterType(f.id)}
                      className={`px-2.5 py-1 text-xs rounded-lg font-mono transition-colors border cursor-pointer ${
                        filterType === f.id
                          ? 'border-slate-900 bg-slate-900 text-white shadow-2xs'
                          : 'border-slate-200 bg-white text-slate-600 hover:bg-slate-50'
                      }`}
                    >
                      {f.label}
                    </button>
                  ))}
                </div>
              </div>

              {/* Component Rows */}
              {filteredComponents.length === 0 ? (
                <div className="p-8 text-center text-slate-400 text-xs">
                  No components match the applied filters.
                </div>
              ) : (
                <div className="divide-y divide-slate-100 max-h-[600px] overflow-y-auto">
                  {filteredComponents.map((comp, idx) => (
                    <ComponentRow key={comp.purl || `${comp.name}@${comp.version}-${idx}`} comp={comp} />
                  ))}
                </div>
              )}
            </Card>
          )}

          {/* ── Tab: Threat & Harmness Ranking ── */}
          {viewTab === 'threat-ranking' && (
            <div className="space-y-4">
              <Card className="p-5 bg-white border border-slate-200">
                <div className="flex items-center justify-between mb-4">
                  <div>
                    <h3 className="text-base font-bold text-slate-900 font-['Space_Grotesk']">
                      Package Harmness & Project Damage Ranking
                    </h3>
                    <p className="text-xs text-slate-500 mt-0.5">
                      Packages sorted by potential to damage your codebase — calculated using CVSS severity, ML maliciousness probability, and dependency depth.
                    </p>
                  </div>
                  <Badge variant="high">Dual Engine Active</Badge>
                </div>

                {/* List of Malware & Vulnerability Findings Ranked */}
                {(!result.maliciousPackages?.length && !result.vulnerabilities?.length) ? (
                  <div className="p-8 text-center border border-dashed border-emerald-200 bg-emerald-50/20 rounded-xl text-xs text-emerald-700 font-semibold">
                    ✓ No malicious packages or severe vulnerabilities detected in this scan! All packages passed the security gate.
                  </div>
                ) : (
                  <div className="space-y-3">
                    {/* Malicious Packages First */}
                    {result.maliciousPackages?.map((m, idx) => (
                      <div key={m.id || idx} className="p-4 rounded-xl border border-rose-200 bg-rose-50/20 flex flex-col sm:flex-row sm:items-center justify-between gap-4">
                        <div className="flex items-start gap-3">
                          <div className="w-10 h-10 rounded-xl bg-rose-100 text-rose-700 font-black flex items-center justify-center text-sm font-mono shrink-0">
                            #{m.damageRank || idx + 1}
                          </div>
                          <div>
                            <div className="flex items-center gap-2">
                              <span className="font-bold text-slate-900 font-['Space_Grotesk']">{m.packageName}</span>
                              <span className="text-xs text-slate-500 font-mono">@{m.version}</span>
                              <span className="text-[10px] bg-rose-600 text-white font-bold uppercase px-2 py-0.5 rounded-full">
                                Malicious ({m.type || 'MALWARE'})
                              </span>
                            </div>
                            <p className="text-xs text-rose-700 mt-1 font-semibold">{m.detail || 'Malicious package activity detected'}</p>
                            <p className="text-[11px] text-slate-500 mt-0.5 font-mono">{m.damagePotential || 'Catastrophic (Code Execution Risk)'}</p>
                          </div>
                        </div>

                        <div className="text-right shrink-0">
                          <div className="text-2xl font-black text-rose-600 font-['Space_Grotesk']">
                            {m.harmnessScore || 95}<span className="text-xs text-slate-400">/100</span>
                          </div>
                          <span className="text-[10px] text-rose-700 uppercase font-bold tracking-wider">
                            ML Prob: {((m.maliciousProbability || 0.9) * 100).toFixed(1)}%
                          </span>
                        </div>
                      </div>
                    ))}

                    {/* Vulnerabilities Ranked */}
                    {result.vulnerabilities?.map((v, idx) => (
                      <div key={v.id || idx} className="p-4 rounded-xl border border-slate-200 bg-white hover:border-slate-300 flex flex-col sm:flex-row sm:items-center justify-between gap-4 shadow-2xs">
                        <div className="flex items-start gap-3">
                          <div className="w-10 h-10 rounded-xl bg-slate-100 border border-slate-200 text-slate-800 font-bold flex items-center justify-center text-sm font-mono shrink-0">
                            #{v.damageRank || (result.maliciousPackages?.length || 0) + idx + 1}
                          </div>
                          <div>
                            <div className="flex items-center gap-2">
                              <span className="font-bold text-slate-900 font-['Space_Grotesk']">{v.component}</span>
                              <span className="text-xs text-slate-500 font-mono">@{v.version}</span>
                              <span className={`text-[10px] font-bold px-2 py-0.5 rounded-full uppercase ${
                                v.priorityLabel === 'P0_CRITICAL' ? 'bg-rose-50 text-rose-700 border border-rose-200' :
                                v.priorityLabel === 'P1_HIGH' ? 'bg-amber-50 text-amber-700 border border-amber-200' :
                                'bg-slate-100 text-slate-800 border border-slate-200'
                              }`}>
                                {v.priorityLabel || 'VULNERABILITY'}
                              </span>
                            </div>
                            <p className="text-xs text-slate-600 mt-1">{v.summary || v.id}</p>
                            <p className="text-[11px] text-slate-400 mt-0.5 font-mono">{v.damagePotential || 'Moderate Impact Flaw'}</p>
                          </div>
                        </div>

                        <div className="text-right shrink-0">
                          <div className="text-2xl font-black font-['Space_Grotesk']" style={{ color: v.harmnessScore >= 75 ? '#e11d48' : v.harmnessScore >= 50 ? '#d97706' : '#0f172a' }}>
                            {v.harmnessScore || 50}<span className="text-xs text-slate-400">/100</span>
                          </div>
                          <span className="text-[10px] text-slate-500 font-mono block">
                            CVSS: {v.severity || 'N/A'} {v.cveId ? `(${v.cveId})` : ''}
                          </span>
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </Card>
            </div>
          )}

          {/* ── Tab: CycloneDX JSON ── */}
          {viewTab === 'cyclonedx' && (
            <Card className="p-5 space-y-3">
              <div className="flex items-center justify-between">
                <SectionLabel>CycloneDX 1.5 JSON Specification</SectionLabel>
                <div className="flex items-center gap-2">
                  <Button
                    size="sm"
                    variant="ghost"
                    loading={downloadingFormat === 'cyclonedx'}
                    onClick={() => handleDownload('cyclonedx')}
                  >
                    ↓ Download JSON
                  </Button>
                  <Button size="sm" variant="ghost" onClick={() => handleCopyJson(result.cycloneDX)}>
                    {copied ? '✓ Copied' : 'Copy JSON'}
                  </Button>
                </div>
              </div>
              <pre className="bg-slate-50 border border-slate-200 rounded-lg p-4 text-xs font-mono text-slate-800 overflow-x-auto max-h-[500px]">
                {JSON.stringify(result.cycloneDX, null, 2) || '// CycloneDX spec unavailable'}
              </pre>
            </Card>
          )}

          {/* ── Tab: SPDX JSON ── */}
          {viewTab === 'spdx' && (
            <Card className="p-5 space-y-3">
              <div className="flex items-center justify-between">
                <SectionLabel>SPDX 2.3 JSON Specification</SectionLabel>
                <div className="flex items-center gap-2">
                  <Button
                    size="sm"
                    variant="ghost"
                    loading={downloadingFormat === 'spdx'}
                    onClick={() => handleDownload('spdx')}
                  >
                    ↓ Download JSON
                  </Button>
                  <Button size="sm" variant="ghost" onClick={() => handleCopyJson(result.spdx)}>
                    {copied ? '✓ Copied' : 'Copy JSON'}
                  </Button>
                </div>
              </div>
              <pre className="bg-slate-50 border border-slate-200 rounded-lg p-4 text-xs font-mono text-slate-800 overflow-x-auto max-h-[500px]">
                {JSON.stringify(result.spdx, null, 2) || '// SPDX spec unavailable'}
              </pre>
            </Card>
          )}

          {/* ── Tab: SBOM Diff ── */}
          {viewTab === 'diff' && result.diff && (
            <Card className="p-5 space-y-3">
              <SectionLabel>SBOM Diff vs Previous Build</SectionLabel>
              <div className="mt-3 space-y-2">
                {result.diff.added?.map(c => (
                  <div key={c.name} className="flex items-center gap-2 text-xs font-mono p-2 rounded-lg bg-emerald-50 border border-emerald-200">
                    <span className="text-emerald-700 font-bold">+</span>
                    <span className="text-slate-900 font-semibold">{c.name}@{c.version}</span>
                    <Badge variant="safe">added</Badge>
                  </div>
                ))}
                {result.diff.removed?.map(c => (
                  <div key={c.name} className="flex items-center gap-2 text-xs font-mono p-2 rounded-lg bg-rose-50 border border-rose-200">
                    <span className="text-rose-700 font-bold">−</span>
                    <span className="text-slate-900">{c.name}@{c.version}</span>
                    <Badge variant="critical">removed</Badge>
                  </div>
                ))}
                {result.diff.changed?.map(c => (
                  <div key={c.name} className="flex items-center gap-2 text-xs font-mono p-2 rounded-lg bg-amber-50 border border-amber-200">
                    <span className="text-amber-700 font-bold">~</span>
                    <span className="text-slate-900 font-semibold">{c.name}</span>
                    <span className="text-slate-500">{c.from} → {c.to}</span>
                    <Badge variant="high">changed</Badge>
                  </div>
                ))}
              </div>
            </Card>
          )}
        </div>
      )}

      {/* Empty state when no SBOMs exist */}
      {!loading && !result && (
        <EmptyState
          icon="◫"
          title="No SBOM generated yet"
          body="Scan any repository or paste a package.json manifest to generate an SBOM automatically."
        />
      )}
    </div>
  );
}

