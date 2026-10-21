import { useEffect, useState } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { useAuth } from '../hooks/useAuth';
import { api } from '../lib/api';
import { Badge, Spinner } from '../components/ui';
import { Mail, Lock, User, ArrowRight, Eye, EyeOff, ShieldCheck, Check } from 'lucide-react';

export function LoginPage() {
  const { user, loading, login: authLogin } = useAuth();
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();

  // Mode: 'signin' | 'signup'
  const [mode, setMode] = useState('signin');

  // Form states
  const [name, setName] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [busy, setBusy] = useState(false); // boolean for form submit or 'github' | 'google'
  const [err, setErr] = useState('');
  const [successMsg, setSuccessMsg] = useState('');

  useEffect(() => {
    if (!loading && user) navigate('/dashboard', { replace: true });
  }, [user, loading, navigate]);

  useEffect(() => {
    const urlErr = searchParams.get('error');
    if (urlErr === 'oauth_failed') setErr('OAuth sign-in failed. Please try again.');
  }, [searchParams]);

  async function handleSubmit(e) {
    e.preventDefault();
    setErr('');
    setSuccessMsg('');

    if (!email || !password) {
      setErr('Please fill out all required fields.');
      return;
    }

    if (password.length < 6) {
      setErr('Password must be at least 6 characters.');
      return;
    }

    setBusy(true);
    try {
      if (mode === 'signup') {
        const res = await api.register(name, email, password);
        setSuccessMsg('Account created successfully! Logging you in...');
        setTimeout(() => {
          authLogin(res.token);
          navigate('/dashboard', { replace: true });
        }, 500);
      } else {
        const res = await api.login(email, password);
        authLogin(res.token);
        navigate('/dashboard', { replace: true });
      }
    } catch (error) {
      setErr(error.message || 'Authentication failed. Please check your credentials.');
      setBusy(false);
    }
  }

  async function handleGitHub() {
    setBusy('github');
    setErr('');
    try {
      const { authorizeUrl } = await api.githubAuthorizeUrl();
      window.location.href = authorizeUrl;
    } catch (e) {
      setErr(e.message || 'Failed to reach backend. Is it running on :4000?');
      setBusy(false);
    }
  }

  async function handleGoogle() {
    setBusy('google');
    setErr('');
    try {
      const { authorizeUrl } = await api.googleAuthorizeUrl();
      window.location.href = authorizeUrl;
    } catch (e) {
      setErr(e.message || 'Google OAuth not configured on the backend.');
      setBusy(false);
    }
  }

  if (loading) {
    return (
      <div className="h-screen flex items-center justify-center bg-[#12101B]">
        <Spinner size={32} color="#FF2E93" />
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-[#12101B] flex flex-col items-center justify-center px-4 py-10 relative overflow-hidden font-['Inter'] text-slate-100 selection:bg-[#FF2E93]/30 selection:text-white">
      {/* Background ambient lighting */}
      <div className="absolute top-1/4 left-1/4 w-96 h-96 rounded-full bg-[#8B5CF6]/15 blur-[120px] pointer-events-none" />
      <div className="absolute bottom-1/4 right-1/4 w-96 h-96 rounded-full bg-[#FF2E93]/15 blur-[120px] pointer-events-none" />

      {/* Decorative coordinate grid lines matching landing page */}
      <div
        className="absolute inset-0 pointer-events-none opacity-20"
        style={{
          backgroundImage: 'linear-gradient(to right, #2A223E 1px, transparent 1px), linear-gradient(to bottom, #2A223E 1px, transparent 1px)',
          backgroundSize: '58px 58px',
        }}
      />

      <div className="relative z-10 w-full max-w-[420px]">
        {/* Header / Brand matching app design system */}
        <div className="text-center mb-6">
          <div className="inline-flex items-center gap-2.5 mb-2 cursor-pointer" onClick={() => navigate('/')}>
            <div className="w-9 h-9 rounded-xl bg-gradient-to-tr from-[#FF2E93] via-[#D946EF] to-[#8B5CF6] flex items-center justify-center text-white shadow-[0_0_15px_rgba(255,46,147,0.4)]">
              <span className="text-white text-xs font-black font-['Space_Grotesk']">SC</span>
            </div>
            <h1 className="text-2xl font-black tracking-tight text-white font-['Space_Grotesk']">
              SecureChain
            </h1>
          </div>
          <p className="text-xs font-medium text-slate-400 transition-all duration-200">
            {mode === 'signin'
              ? 'Sign in to access your dashboard'
              : 'Create an account to get started'}
          </p>
        </div>

        {/* Feature Card styling from Landing Page (dark obsidian, frosted glass blur, glowing border) */}
        <div className="bg-[#181326]/85 backdrop-blur-2xl border border-[#2D2345] shadow-[0_10px_40px_rgba(0,0,0,0.8)] rounded-3xl p-7 sm:p-8">

          {/* Segmented Pill Toggle [ Sign In | Sign Up ] */}
          <div className="bg-[#130F1F] p-1 rounded-xl flex items-center mb-6 border border-[#261E38]">
            <button
              type="button"
              onClick={() => {
                setMode('signin');
                setErr('');
                setSuccessMsg('');
              }}
              className={`flex-1 py-2 text-xs font-semibold rounded-lg transition-all duration-150 text-center cursor-pointer ${mode === 'signin'
                ? 'bg-[#241C3B] text-white shadow-sm border border-[#443566]'
                : 'text-slate-400 hover:text-white'
                }`}
            >
              Sign In
            </button>
            <button
              type="button"
              onClick={() => {
                setMode('signup');
                setErr('');
                setSuccessMsg('');
              }}
              className={`flex-1 py-2 text-xs font-semibold rounded-lg transition-all duration-150 text-center cursor-pointer ${mode === 'signup'
                ? 'bg-[#241C3B] text-white shadow-sm border border-[#443566]'
                : 'text-slate-400 hover:text-white'
                }`}
            >
              Sign Up
            </button>
          </div>

          {/* Form */}
          <form onSubmit={handleSubmit} className="space-y-3.5">
            {/* Full Name field (only on Sign Up mode) */}
            {mode === 'signup' && (
              <div className="relative group transition-all">
                <div className="flex items-center bg-[#130F1F] rounded-xl px-3.5 py-3 border border-[#2D2345] hover:border-[#4B3970] focus-within:border-[#D946EF] focus-within:ring-2 focus-within:ring-[#D946EF]/20 transition-all duration-150">
                  <User className="w-4 h-4 text-slate-400 mr-2.5 shrink-0" />
                  <input
                    type="text"
                    required
                    value={name}
                    onChange={(e) => setName(e.target.value)}
                    placeholder="Full Name"
                    className="w-full bg-transparent text-sm text-slate-100 placeholder-slate-500 border-0 border-none outline-none focus:outline-none focus:ring-0 focus:border-none shadow-none ring-0"
                    style={{ border: 'none', outline: 'none', boxShadow: 'none' }}
                  />
                </div>
              </div>
            )}

            {/* Email field */}
            <div className="relative group transition-all">
              <div className="flex items-center bg-[#130F1F] rounded-xl px-3.5 py-3 border border-[#2D2345] hover:border-[#4B3970] focus-within:border-[#D946EF] focus-within:ring-2 focus-within:ring-[#D946EF]/20 transition-all duration-150">
                <Mail className="w-4 h-4 text-slate-400 mr-2.5 shrink-0" />
                <input
                  type="email"
                  required
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  placeholder="Email address"
                  className="w-full bg-transparent text-sm text-slate-100 placeholder-slate-500 border-0 border-none outline-none focus:outline-none focus:ring-0 focus:border-none shadow-none ring-0"
                  style={{ border: 'none', outline: 'none', boxShadow: 'none' }}
                />
              </div>
            </div>

            {/* Password field */}
            <div className="relative group transition-all">
              <div className="flex items-center bg-[#130F1F] rounded-xl px-3.5 py-3 border border-[#2D2345] hover:border-[#4B3970] focus-within:border-[#D946EF] focus-within:ring-2 focus-within:ring-[#D946EF]/20 transition-all duration-150">
                <Lock className="w-4 h-4 text-slate-400 mr-2.5 shrink-0" />
                <input
                  type={showPassword ? 'text' : 'password'}
                  required
                  minLength={6}
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="Password (min 6 characters)"
                  className="w-full bg-transparent text-sm text-slate-100 placeholder-slate-500 border-0 border-none outline-none focus:outline-none focus:ring-0 focus:border-none shadow-none ring-0"
                  style={{ border: 'none', outline: 'none', boxShadow: 'none' }}
                />
                <button
                  type="button"
                  onClick={() => setShowPassword(!showPassword)}
                  className="text-slate-400 hover:text-slate-200 focus:outline-none ml-2 transition-colors cursor-pointer"
                  tabIndex={-1}
                >
                  {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                </button>
              </div>
            </div>

            {/* Error Message */}
            {err && (
              <div className="p-3 rounded-xl bg-rose-950/40 border border-rose-800/60 text-rose-300 text-xs leading-relaxed animate-in fade-in">
                {err}
              </div>
            )}

            {/* Success Message */}
            {successMsg && (
              <div className="p-3 rounded-xl bg-emerald-950/40 border border-emerald-800/60 text-emerald-300 text-xs flex items-center gap-2 animate-in fade-in">
                <Check className="w-4 h-4 text-emerald-400 shrink-0" />
                <span>{successMsg}</span>
              </div>
            )}

            {/* Primary Action Button (White high-contrast button matching Landing Page CTA) */}
            <div className="pt-2">
              <button
                type="submit"
                disabled={busy}
                className="w-full bg-white hover:bg-slate-100 active:scale-[0.98] text-slate-950 py-3.5 px-6 rounded-xl font-bold text-sm flex items-center justify-center gap-2 shadow-[0_0_20px_rgba(255,255,255,0.2)] transition-all cursor-pointer disabled:opacity-50"
              >
                {busy === true ? (
                  <Spinner size={18} color="#0f172a" />
                ) : (
                  <>
                    <span>{mode === 'signin' ? 'Sign In' : 'Create Account'}</span>
                    <ArrowRight className="w-4 h-4" />
                  </>
                )}
              </button>
            </div>
          </form>

          {/* Social Divider */}
          <div className="flex items-center gap-3 my-5">
            <div className="flex-1 h-px bg-[#261E38]" />
            <span className="text-[10px] text-slate-400 font-mono uppercase tracking-wider">or continue with</span>
            <div className="flex-1 h-px bg-[#261E38]" />
          </div>

          {/* OAuth Buttons (GitHub & Google) */}
          <div className="grid grid-cols-2 gap-3">
            <button
              type="button"
              onClick={handleGitHub}
              disabled={busy}
              className="flex items-center justify-center gap-2 bg-[#1A142A] hover:bg-[#231B39] text-slate-200 hover:text-white border border-[#2D2345] hover:border-[#4A3870] rounded-xl py-2.5 px-3 text-xs font-semibold shadow-sm transition-all cursor-pointer disabled:opacity-50"
            >
              {busy === 'github' ? (
                <Spinner size={16} color="#FFFFFF" />
              ) : (
                <>
                  <svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor">
                    <path d="M12 0C5.37 0 0 5.37 0 12c0 5.31 3.435 9.795 8.205 11.385.6.105.825-.255.825-.57 0-.285-.015-1.23-.015-2.235-3.015.555-3.795-.735-4.035-1.41-.135-.345-.72-1.41-1.23-1.695-.42-.225-1.02-.78-.015-.795.945-.015 1.62.87 1.845 1.23 1.08 1.815 2.805 1.305 3.495.99.105-.78.42-1.305.765-1.605-2.67-.3-5.46-1.335-5.46-5.925 0-1.305.465-2.385 1.23-3.225-.12-.3-.54-1.53.12-3.18 0 0 1.005-.315 3.3 1.23.96-.27 1.98-.405 3-.405s2.04.135 3 .405c2.295-1.56 3.3-1.23 3.3-1.23.66 1.65.24 2.88.12 3.18.765.84 1.23 1.905 1.23 3.225 0 4.605-2.805 5.625-5.475 5.925.435.375.81 1.095.81 2.22 0 1.605-.015 2.895-.015 3.3 0 .315.225.69.825.57A12.02 12.02 0 0024 12c0-6.63-5.37-12-12-12z" />
                  </svg>
                  <span>GitHub</span>
                </>
              )}
            </button>

            <button
              type="button"
              onClick={handleGoogle}
              disabled={busy}
              className="flex items-center justify-center gap-2 bg-[#1A142A] hover:bg-[#231B39] text-slate-200 hover:text-white border border-[#2D2345] hover:border-[#4A3870] rounded-xl py-2.5 px-3 text-xs font-semibold shadow-sm transition-all cursor-pointer disabled:opacity-50"
            >
              {busy === 'google' ? (
                <Spinner size={16} color="#FFFFFF" />
              ) : (
                <>
                  <svg width="16" height="16" viewBox="0 0 24 24">
                    <path fill="#4285F4" d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z" />
                    <path fill="#34A853" d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z" />
                    <path fill="#FBBC05" d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z" />
                    <path fill="#EA4335" d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z" />
                  </svg>
                  <span>Google</span>
                </>
              )}
            </button>
          </div>

          {/* Bottom Switcher */}
          <div className="mt-6 pt-5 border-t border-[#261E38] text-center text-xs text-slate-400">
            {mode === 'signin' ? (
              <p>
                Don't have an account?{' '}
                <button
                  type="button"
                  onClick={() => {
                    setMode('signup');
                    setErr('');
                    setSuccessMsg('');
                  }}
                  className="font-semibold text-[#D946EF] hover:text-[#FF2E93] underline underline-offset-2 cursor-pointer transition-colors"
                >
                  Register
                </button>
              </p>
            ) : (
              <p>
                Already have an account?{' '}
                <button
                  type="button"
                  onClick={() => {
                    setMode('signin');
                    setErr('');
                    setSuccessMsg('');
                  }}
                  className="font-semibold text-[#D946EF] hover:text-[#FF2E93] underline underline-offset-2 cursor-pointer transition-colors"
                >
                  Sign In
                </button>
              </p>
            )}
          </div>
        </div>

        {/* Footer info */}
        <p className="text-center mt-5 text-[11px] text-slate-500">
          SecureChain reads manifest dependencies for real-time SBOM & CVE threat detection.
        </p>
      </div>
    </div>
  );
}

export function OAuthCallbackPage() {
  const [searchParams] = useSearchParams();
  const { login } = useAuth();
  const navigate = useNavigate();

  useEffect(() => {
    const token = searchParams.get('token');
    if (token) {
      login(token);
      navigate('/dashboard', { replace: true });
    } else {
      navigate('/login?error=oauth_failed', { replace: true });
    }
  }, [searchParams, login, navigate]);

  return (
    <div className="h-screen flex items-center justify-center bg-[#12101B] gap-3 font-['Inter']">
      <Spinner size={24} color="#FF2E93" />
      <span className="text-slate-300 font-mono text-sm">Completing sign-in…</span>
    </div>
  );
}
