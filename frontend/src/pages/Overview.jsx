import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { api } from '../lib/api';
import { useAuth } from '../hooks/useAuth';
import { useThreatFeed } from '../hooks/useThreatFeed';
import { Card, Badge, Spinner, RiskGauge, SectionLabel, ErrorBanner } from '../components/ui';

function CountUp({ end, duration = 1500 }) {
  const [count, setCount] = useState(0);
  useEffect(() => {
    if (typeof end !== 'number') return;
    const startTime = performance.now();
    let raf;
    const animate = (time) => {
      const progress = Math.min((time - startTime) / duration, 1);
      const ease = progress === 1 ? 1 : 1 - Math.pow(2, -10 * progress);
      setCount(Math.floor(ease * end));
      if (progress < 1) raf = requestAnimationFrame(animate);
    };
    raf = requestAnimationFrame(animate);
    return () => cancelAnimationFrame(raf);
  }, [end, duration]);
  return typeof end === 'number' ? count : end;
}

function StatCard({ label, value, sub, color = '#0f172a', to }) {
  const inner = (
    <div className="bg-white border border-slate-200 h-full flex flex-col rounded-xl p-5 hover:border-slate-300 hover:-translate-y-0.5 hover:shadow-md transition-all duration-200 group cursor-pointer relative shadow-xs">
      <div className="block font-semibold text-slate-500 tracking-wider text-xs uppercase font-mono">{label}</div>
      <div className={`flex-1 flex items-center justify-start relative mt-3 ${label === 'Security score' ? 'top-1' : ''}`}>
        <span className="text-4xl font-black font-['Space_Grotesk'] text-slate-900">
          {typeof value === 'number' ? <CountUp end={value} /> : (value ?? '—')}
        </span>
      </div>
      {sub && <span className="text-xs text-slate-400 font-medium mt-2">{sub}</span>}
    </div>
  );
  return to ? <Link to={to} className="block h-full">{inner}</Link> : <div className="h-full">{inner}</div>;
}

export default function Overview() {
  const [summary, setSummary] = useState(null);
  const [loading, setLoading] = useState(true);
  const [err, setErr] = useState('');
  const [imgErr, setImgErr] = useState(false);
  const { events } = useThreatFeed();
  const { user } = useAuth();

  useEffect(() => {
    api.dashboardSummary()
      .then(setSummary)
      .catch(e => setErr(e.message))
      .finally(() => setLoading(false));
  }, []);

  const hour = new Date().getHours();
  const greeting = hour < 12 ? 'Good morning' : hour < 17 ? 'Good afternoon' : 'Good evening';
  const displayName = user?.name || user?.login || 'Developer';
  const initials = displayName.split(/[\s_-]+/).slice(0,2).map(w => w[0]?.toUpperCase() || '').join('');

  if (loading) return <div className="flex items-center justify-center h-64"><Spinner size={28} color="#0f172a" /></div>;

  return (
    <div className="space-y-8 max-w-6xl">
      {/* Personalized header */}
      <div className="flex items-center gap-4">
        {/* Profile picture */}
        <div className="relative shrink-0">
          {user?.avatar && !imgErr ? (
            <img
              src={user.avatar}
              alt={displayName}
              onError={() => setImgErr(true)}
              referrerPolicy="no-referrer"
              className="w-12 h-12 rounded-full border border-slate-200 object-cover shadow-xs"
            />
          ) : (
            <div className="w-12 h-12 rounded-full border border-slate-200 flex items-center justify-center font-bold text-white text-base bg-slate-900 shadow-xs">
              {initials}
            </div>
          )}
          {/* Provider badge */}
          {user && (
            <span
              className="absolute -bottom-0.5 -right-0.5 w-4 h-4 rounded-full border-2 border-white flex items-center justify-center text-[8px] font-bold text-white shadow-2xs"
              style={{ background: user.provider === 'google' || user.googleId ? '#4285F4' : '#24292e' }}
            >
              {user.provider === 'google' || user.googleId ? 'G' : 'GH'}
            </span>
          )}
        </div>

        <div className="flex-1 min-w-0">
          <h1 className="text-2xl font-black font-['Space_Grotesk'] text-slate-900 leading-tight">
            {greeting}, {displayName.split(' ')[0]} 👋
          </h1>
          <div className="flex items-center gap-2 mt-1">
            <p className="text-slate-500 text-sm">Real-time supply chain security posture.</p>
            {summary?.teamName && (
              <span className="text-[10px] font-mono px-2 py-0.5 rounded-full border border-slate-200 text-slate-700 bg-slate-100">
                👥 {summary.teamName}
              </span>
            )}
          </div>
        </div>
      </div>

      <ErrorBanner message={err} onRetry={() => window.location.reload()} />

      {summary && (
        <div className="grid grid-cols-2 lg:grid-cols-3 xl:grid-cols-5 gap-4">
          <StatCard label="Security score" value={<RiskGauge score={summary.averageRiskScore} />} to="/dashboard/repos" />
          <StatCard label="Active threats" value={summary.activeThreats} color="#e11d48" to="/dashboard/vulns" />
          <StatCard label="Critical CVEs" value={summary.criticalVulnerabilities} color="#d97706" to="/dashboard/vulns" />
          <StatCard label="Repositories" value={summary.monitoredRepositories} color="#059669" to="/dashboard/repos" />
          <StatCard label="Total scans" value={summary.totalScans} color="#0f172a" />
        </div>
      )}

      {/* Live threat feed strip */}
      <div>
        <div className="flex items-center justify-between mb-4">
          <SectionLabel>Live threat feed</SectionLabel>
          <Badge variant="cyan">{events.length} events</Badge>
        </div>
        {events.length === 0 ? (
          <Card className="p-8 text-center text-slate-400 text-xs font-mono">
            No new threat events in this session — background feed actively monitoring.
          </Card>
        ) : (
          <Card className="divide-y divide-slate-100 overflow-hidden shadow-xs">
            {events.slice(0, 8).map((e, i) => (
              <div key={i} className="flex items-center gap-4 px-5 py-3 hover:bg-slate-50 transition-colors">
                <span className={`w-2 h-2 rounded-full shrink-0 ${e.type === 'NEW_VULNERABILITY' ? 'bg-rose-500' : 'bg-slate-400'}`} />
                <span className="font-mono text-xs text-slate-400 w-36 shrink-0">{e.timestamp?.slice(11, 19) || ''}</span>
                <span className="text-xs font-medium text-slate-800 flex-1 truncate">
                  {e.type === 'NEW_VULNERABILITY' ? `New CVE: ${e.id} affects ${e.package}` : e.type}
                </span>
                {e.type === 'NEW_VULNERABILITY' && <Badge variant="critical">CVE</Badge>}
              </div>
            ))}
          </Card>
        )}
      </div>

      {/* Quick-start guide for empty state */}
      {summary?.monitoredRepositories === 0 && (
        <Card className="p-8 text-center bg-white border border-slate-200">
          <p className="text-3xl mb-3 text-slate-400">◈</p>
          <h3 className="font-bold text-slate-900 mb-2 font-['Space_Grotesk'] text-lg">Connect your first repository</h3>
          <p className="text-slate-500 text-xs mb-6 max-w-sm mx-auto leading-relaxed">SecureChain will automatically generate SBOMs, scan for vulnerabilities, and block malicious packages on every git push.</p>
          <Link to="/dashboard/repos">
            <button className="bg-slate-900 text-white font-semibold px-6 py-2.5 rounded-lg text-xs hover:bg-slate-800 transition-colors shadow-xs cursor-pointer">
              Add repository →
            </button>
          </Link>
        </Card>
      )}
    </div>
  );
}

