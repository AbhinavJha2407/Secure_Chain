// ── Shared primitives (Modern Light Theme — Zero Blue Buttons) ───────────────

export function Badge({ children, variant = 'default', className = '' }) {
  const variants = {
    critical: 'bg-rose-50 text-rose-700 border-rose-200/80',
    high: 'bg-amber-50 text-amber-700 border-amber-200/80',
    medium: 'bg-orange-50 text-orange-700 border-orange-200/80',
    low: 'bg-emerald-50 text-emerald-700 border-emerald-200/80',
    safe: 'bg-emerald-50 text-emerald-700 border-emerald-200/80',
    blocked: 'bg-rose-50 text-rose-700 border-rose-200/80',
    failed: 'bg-amber-50 text-amber-700 border-amber-200/80',
    pass: 'bg-emerald-50 text-emerald-700 border-emerald-200/80',
    default: 'bg-slate-100 text-slate-700 border-slate-200',
    cyan: 'bg-teal-50 text-teal-700 border-teal-200/80',
    violet: 'bg-purple-50 text-purple-700 border-purple-200/80',
  };
  return (
    <span className={`inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-[10px] font-mono font-semibold uppercase tracking-wider border ${variants[variant] || variants.default} ${className}`}>
      {children}
    </span>
  );
}

export function Button({ children, variant = 'primary', size = 'md', loading = false, className = '', ...props }) {
  // Focus ring uses obsidian/slate (NO BLUE)
  const base = 'inline-flex items-center justify-center gap-2 font-medium rounded-lg transition-all duration-150 cursor-pointer disabled:opacity-50 disabled:cursor-not-allowed focus-visible:outline-2 focus-visible:outline-slate-900 focus-visible:outline-offset-2 overflow-hidden relative group';
  const sizes = {
    sm: 'px-3 py-1.5 text-xs',
    md: 'px-4 py-2 text-sm',
    lg: 'px-6 py-2.5 text-base',
  };
  // Strictly NO blue buttons! Premium obsidian slate, crisp white ghost, security emerald, or rose
  const variants = {
    primary: 'bg-slate-900 text-white hover:bg-slate-800 active:scale-[0.98] shadow-xs font-semibold',
    emerald: 'bg-emerald-600 text-white hover:bg-emerald-700 active:scale-[0.98] shadow-xs font-semibold',
    ghost: 'bg-white text-slate-700 hover:bg-slate-50 hover:text-slate-900 border border-slate-300 shadow-2xs active:scale-[0.98]',
    secondary: 'bg-slate-100 text-slate-800 hover:bg-slate-200 border border-slate-200 active:scale-[0.98]',
    danger: 'bg-rose-50 text-rose-700 border border-rose-200 hover:bg-rose-100 active:scale-[0.98]',
    dark: 'bg-slate-900 text-white hover:bg-slate-800 active:scale-[0.98] shadow-xs font-semibold',
  };
  return (
    <button disabled={loading || props.disabled} className={`${base} ${sizes[size]} ${variants[variant] || variants.primary} ${className}`} {...props}>
      {loading && <Spinner size={14} color="currentColor" />}
      {children}
    </button>
  );
}

export function Spinner({ size = 18, color = 'currentColor' }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke={color} strokeWidth="2.5" className="animate-spin">
      <path d="M12 2v4M12 18v4M4.93 4.93l2.83 2.83M16.24 16.24l2.83 2.83M2 12h4M18 12h4M4.93 19.07l2.83-2.83M16.24 7.76l2.83-2.83" strokeLinecap="round" />
    </svg>
  );
}

export function Card({ children, className = '', glow = false }) {
  return (
    <div className={`bg-white rounded-xl border border-slate-200 text-slate-900 shadow-xs transition-shadow duration-200 ${glow ? 'hover:shadow-md hover:border-slate-300' : ''} ${className}`}>
      {children}
    </div>
  );
}

export function SectionLabel({ children, className = '' }) {
  return (
    <span className={`text-xs font-mono uppercase tracking-wider text-slate-500 font-semibold ${className}`}>{children}</span>
  );
}

export function Divider({ className = '' }) {
  return <div className={`h-px bg-slate-200 ${className}`} />;
}

export function StatusDot({ status }) {
  const colors = {
    online: 'bg-emerald-500',
    warning: 'bg-amber-500',
    critical: 'bg-rose-500',
    offline: 'bg-slate-300',
  };
  return <span className={`inline-block w-2 h-2 rounded-full ${colors[status] || colors.offline}`} />;
}

export function EmptyState({ icon, title, body, action }) {
  return (
    <div className="flex flex-col items-center justify-center gap-4 py-16 text-center">
      {icon && <div className="text-4xl text-slate-400 opacity-60">{icon}</div>}
      <div>
        <p className="text-slate-800 font-semibold text-base">{title}</p>
        {body && <p className="text-slate-500 text-xs mt-1 max-w-xs">{body}</p>}
      </div>
      {action}
    </div>
  );
}

export function ErrorBanner({ message, onRetry, retryLabel = 'Retry' }) {
  if (!message) return null;
  return (
    <div className="flex items-center justify-between gap-4 px-4 py-3 rounded-xl bg-rose-50 border border-rose-200 text-rose-700 text-xs">
      <span className="font-medium">⚠ {message}</span>
      {onRetry && <button onClick={onRetry} className="underline text-xs shrink-0 font-semibold hover:text-rose-900">{retryLabel}</button>}
    </div>
  );
}

export function RiskGauge({ score }) {
  const radius = 42;
  const circ = 2 * Math.PI * radius;
  const dashOffset = circ - (score / 100) * circ;
  const color = score >= 75 ? '#059669' : score >= 50 ? '#d97706' : '#e11d48';
  const label = score >= 75 ? 'Good' : score >= 50 ? 'Fair' : 'Poor';
  return (
    <div className="relative inline-flex flex-col items-center">
      <svg width="90" height="90" viewBox="0 0 100 100">
        <circle cx="50" cy="50" r={radius} fill="none" stroke="#f1f5f9" strokeWidth="8" />
        <circle cx="50" cy="50" r={radius} fill="none" stroke={color} strokeWidth="8"
          strokeDasharray={circ} strokeDashoffset={dashOffset} strokeLinecap="round"
          transform="rotate(-90 50 50)"
          style={{ transition: 'stroke-dashoffset 0.8s ease, stroke 0.4s ease' }} />
        <text x="50" y="46" textAnchor="middle" fontSize="17" fontWeight="700" fill="#0f172a" fontFamily="Inter, sans-serif">{score}</text>
        <text x="50" y="61" textAnchor="middle" fontSize="10" fontWeight="600" fill="#64748b" fontFamily="Inter, sans-serif">{label}</text>
      </svg>
    </div>
  );
}