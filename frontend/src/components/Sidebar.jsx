import { NavLink } from 'react-router-dom';
import { useAuth } from '../hooks/useAuth';
import { StatusDot } from './ui';
import { useThreatFeed } from '../hooks/useThreatFeed';
import { useState } from 'react';

/**
 * UserAvatar — shows the OAuth provider's profile picture.
 * Falls back to coloured initials if the image fails to load.
 * provider: 'github' | 'google' | undefined
 */
function UserAvatar({ src, name, provider, size = 28 }) {
  const [imgError, setImgError] = useState(false);

  // Derive initials from name or login
  const initials = (name || '?')
    .split(/[\s_-]+/)
    .slice(0, 2)
    .map(w => w[0]?.toUpperCase() || '')
    .join('');

  // Provider badge colours
  const badge = provider === 'google'
    ? { bg: '#4285F4', label: 'G' }
    : provider === 'github'
    ? { bg: '#24292e', label: '⌥' }
    : null;

  const dim = `${size}px`;

  return (
    <div className="relative shrink-0" style={{ width: dim, height: dim }}>
      {src && !imgError ? (
        <img
          src={src}
          alt={name || 'avatar'}
          onError={() => setImgError(true)}
          className="rounded-full border border-slate-200 object-cover w-full h-full shadow-2xs"
          referrerPolicy="no-referrer"
        />
      ) : (
        <div
          className="rounded-full border border-slate-200 flex items-center justify-center font-bold text-white w-full h-full bg-slate-900 shadow-2xs"
          style={{ fontSize: size * 0.38 }}
        >
          {initials}
        </div>
      )}
      {badge && (
        <span
          className="absolute -bottom-0.5 -right-0.5 rounded-full flex items-center justify-center text-white font-bold shadow-2xs"
          style={{ background: badge.bg, width: size * 0.45, height: size * 0.45, fontSize: size * 0.22 }}
        >
          {badge.label}
        </span>
      )}
    </div>
  );
}

const NAV = [
  { to: '/dashboard',            icon: '⬡', label: 'Overview' },
  { to: '/dashboard/repos',      icon: '⊞', label: 'Repositories' },
  { to: '/dashboard/sbom',       icon: '◫', label: 'SBOM' },
  { to: '/dashboard/vulns',      icon: '◈', label: 'Vulnerabilities' },
  { to: '/dashboard/malware',    icon: '◬', label: 'Malicious Pkgs' },
  { to: '/dashboard/cicd',       icon: '⊙', label: 'CI/CD' },
  { to: '/dashboard/alerts',     icon: '◎', label: 'Alerts' },
  { to: '/dashboard/compliance', icon: '◻', label: 'Compliance' },
  { to: '/dashboard/admin',      icon: '◧', label: 'Admin' },
];

export default function Sidebar() {
  const { user, logout } = useAuth();
  const { connected } = useThreatFeed();

  return (
    <aside className="fixed left-0 top-0 h-full w-56 bg-white border-r border-slate-200 flex flex-col z-40 shadow-xs">
      {/* Logo */}
      <div className="px-5 py-4 border-b border-slate-100">
        <div className="flex items-center gap-2.5">
          <div className="w-7 h-7 rounded-lg bg-slate-900 flex items-center justify-center shadow-xs">
            <span className="text-white text-xs font-black">SC</span>
          </div>
          <div>
            <div className="text-sm font-bold text-slate-900 font-['Space_Grotesk'] tracking-tight">SecureChain</div>
            <div className="flex items-center gap-1.5 mt-0.5">
              <StatusDot status={connected ? 'online' : 'offline'} />
              <span className="text-[10px] text-slate-400 font-mono">{connected ? 'Live feed' : 'Connecting…'}</span>
            </div>
          </div>
        </div>
      </div>

      {/* Nav */}
      <nav className="flex-1 overflow-y-auto px-3 py-4 space-y-1">
        {NAV.map(({ to, icon, label }) => (
          <NavLink
            key={to}
            to={to}
            end={to === '/dashboard'}
            className={({ isActive }) =>
              `group flex items-center gap-3 px-3.5 py-2.5 rounded-lg text-xs transition-all duration-150 relative ${
                isActive
                  ? 'text-slate-900 bg-slate-100 font-semibold shadow-2xs'
                  : 'text-slate-600 hover:text-slate-900 hover:bg-slate-50 font-medium'
              }`
            }
          >
            {({ isActive }) => (
              <>
                {isActive && (
                  <div className="absolute left-0 top-2 bottom-2 w-1 bg-emerald-600 rounded-r-full" />
                )}
                <span className={`text-[15px] transition-transform duration-150 ${isActive ? 'text-emerald-700' : 'text-slate-400 group-hover:text-slate-700'}`}>
                  {icon}
                </span>
                <span className="tracking-tight">
                  {label}
                </span>
              </>
            )}
          </NavLink>
        ))}
      </nav>

      {/* User footer */}
      {user && (
        <div className="px-4 py-3.5 border-t border-slate-100 bg-slate-50/60">
          <div className="flex items-center gap-2.5">
            <UserAvatar
              src={user.avatar}
              name={user.name || user.login}
              provider={user.provider || (user.googleId ? 'google' : 'github')}
              size={28}
            />
            <div className="flex-1 min-w-0">
              <p className="text-xs font-semibold text-slate-800 truncate">{user.name || user.login}</p>
              <p className="text-[10px] text-slate-400">{user.role || 'Admin'}</p>
            </div>
            <button
              onClick={() => logout()}
              className="text-slate-400 hover:text-rose-600 text-xs p-1 rounded hover:bg-slate-100 transition-colors cursor-pointer"
              title="Sign out"
            >
              ⏻
            </button>
          </div>
        </div>
      )}
    </aside>
  );
}


