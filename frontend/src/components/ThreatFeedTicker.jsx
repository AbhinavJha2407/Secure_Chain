import { useThreatFeed } from '../hooks/useThreatFeed';

export default function ThreatFeedTicker() {
  const { events, connected } = useThreatFeed();

  return (
    <div className="h-9 border-b border-slate-200 bg-white flex items-center overflow-hidden shadow-2xs">
      <div className="px-4 flex items-center gap-2 shrink-0 border-r border-slate-200 bg-slate-50/50 h-full">
        <span className={`w-1.5 h-1.5 rounded-full ${connected ? 'bg-emerald-500 animate-pulse' : 'bg-slate-400'}`} />
        <span className="text-[10px] font-mono text-slate-600 font-semibold uppercase tracking-wider">Threat Feed</span>
      </div>
      <div className="flex-1 overflow-hidden relative">
        {events.length === 0 ? (
          <span className="px-4 text-[11px] font-mono text-slate-500">
            {connected ? 'Monitoring global threat sources — continuous SBOM feed active' : 'Connecting to threat feed…'}
          </span>
        ) : (
          <div className="flex animate-[scroll_20s_linear_infinite] gap-16 whitespace-nowrap">
            {[...events, ...events].map((e, i) => (
              <span key={i} className="text-[11px] font-mono text-slate-700 px-4">
                <span className="text-rose-600 mr-2 font-bold">▸</span>
                {e.type === 'NEW_VULNERABILITY'
                  ? `${e.id} · ${e.package}`
                  : e.type === 'FEED_ERROR'
                  ? `Feed notice: ${e.source}`
                  : `${e.type}`}
              </span>
            ))}
          </div>
        )}
      </div>
      <style>{`
        @keyframes scroll {
          from { transform: translateX(0); }
          to { transform: translateX(-50%); }
        }
      `}</style>
    </div>
  );
}

