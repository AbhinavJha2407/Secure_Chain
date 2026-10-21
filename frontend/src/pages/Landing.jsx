import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import LaserBlockScanner from '../components/LaserBlockScanner';
import { Button, Badge } from '../components/ui';
import { api } from '../lib/api';

// ── Animated Threat & Scan Counter (Original SecureChain Metrics) ──────────────
function ThreatCounter() {
  const [count, setCount] = useState(0);
  const [target, setTarget] = useState(0);
  const [scans, setScans] = useState(0);
  const [scansTarget, setScansTarget] = useState(0);

  useEffect(() => {
    api.cveCount()
      .then((res) => {
        if (res && typeof res.count === 'number') {
          setTarget(res.count);
        } else {
          setTarget(318492);
        }
        if (res && typeof res.scansCount === 'number') {
          setScansTarget(res.scansCount);
        } else {
          setScansTarget(142850);
        }
      })
      .catch(() => {
        setTarget(318492);
        setScansTarget(142850);
      });
  }, []);

  useEffect(() => {
    if (target === 0) return;
    const step = Math.ceil(target / 80) || 1;
    const t = setInterval(() => {
      setCount((c) => {
        if (c + step >= target) {
          clearInterval(t);
          return target;
        }
        return c + step;
      });
    }, 16);
    return () => clearInterval(t);
  }, [target]);

  useEffect(() => {
    if (scansTarget === 0) return;
    const step = Math.ceil(scansTarget / 80) || 1;
    const t = setInterval(() => {
      setScans((c) => {
        if (c + step >= scansTarget) {
          clearInterval(t);
          return scansTarget;
        }
        return c + step;
      });
    }, 16);
    return () => clearInterval(t);
  }, [scansTarget]);

  return (
    <div className="py-16 relative overflow-hidden bg-[#161224] border-y border-[#261E38] flex flex-col md:flex-row items-center justify-center gap-16 md:gap-32 shadow-xl">
      <div className="relative z-10 text-center">
        <p className="text-slate-400 font-bold font-mono text-xs uppercase tracking-[0.2em] mb-3">
          Total Scans Performed
        </p>
        <div className="text-6xl md:text-7xl font-black font-['Space_Grotesk'] text-white tabular-nums tracking-tight">
          {scans.toLocaleString()}
        </div>
        <p className="text-slate-400 mt-2 text-xs font-semibold">
          across all connected repositories
        </p>
      </div>

      <div className="hidden md:block w-px h-28 bg-[#2C2344]"></div>

      <div className="relative z-10 text-center">
        <p className="text-slate-400 font-bold font-mono text-xs uppercase tracking-[0.2em] mb-3">
          CVEs tracked in real time
        </p>
        <div className="text-6xl md:text-7xl font-black font-['Space_Grotesk'] bg-gradient-to-r from-[#FF2E93] via-[#D946EF] to-[#8B5CF6] text-transparent bg-clip-text tabular-nums tracking-tight">
          {count.toLocaleString()}
        </div>
        <p className="text-slate-400 mt-2 text-xs font-semibold">
          across NVD · OSV · GitHub Advisory · Snyk
        </p>
      </div>
    </div>
  );
}

// ── Stepped Pixel Mosaic Transition Divider (From landing.mp4) ────────────────
function SteppedPixelMosaic() {
  const pixelColors = [
    '#12101B', '#12101B', '#2A233C', '#FFE600', '#FF2E93', '#161224', '#12101B', '#FFE600',
    '#161224', '#FF2E93', '#2A233C', '#12101B', '#FFE600', '#161224', '#FF2E93', '#12101B',
  ];

  return (
    <div className="w-full overflow-hidden leading-none select-none -my-1 z-20 relative">
      <div className="grid grid-cols-16 h-4 w-full">
        {pixelColors.map((color, i) => (
          <div key={i} style={{ backgroundColor: color }} className="h-full w-full" />
        ))}
      </div>
      <div className="grid grid-cols-16 h-3 w-full opacity-90">
        {pixelColors.slice().reverse().map((color, i) => (
          <div key={i} style={{ backgroundColor: color }} className="h-full w-full" />
        ))}
      </div>
    </div>
  );
}

// ── Original SecureChain Features ─────────────────────────────────────────────
const FEATURES = [
  {
    icon: '◫',
    title: 'Auto-SBOM Generation',
    body: 'CycloneDX 1.5 and SPDX 2.3 output, full transitive graph resolved from the real npm/PyPI/Maven registries on every push.',
    tag: 'SBOM',
  },
  {
    icon: '◈',
    title: 'Real-Time CVE Correlation',
    body: 'Polls NVD, OSV, GitHub Advisory, and Snyk every 5 minutes. Mean time to detect a newly published CVE: under 15 minutes.',
    tag: 'DETECTION',
  },
  {
    icon: '◬',
    title: 'Typosquat Detection',
    body: 'Levenshtein edit-distance analysis across the top 1,000 packages per ecosystem. Catches lodahs → lodash before it reaches your build.',
    tag: 'ML',
  },
  {
    icon: '⊙',
    title: 'CI/CD Policy Gate',
    body: 'A binary pass/fail verdict the pipeline acts on. BLOCKED fires before any malicious package reaches your artifact store.',
    tag: 'CI/CD',
  },
  {
    icon: '◎',
    title: 'EPSS-CVSS Fusion',
    body: 'Priority Score = CVSS × (1 + EPSS × 2). A CVSS 7.5 with 85% exploitation probability outranks a CVSS 9.8 with 1%.',
    tag: 'SCORING',
  },
  {
    icon: '◻',
    title: 'SLSA + NIST SSDF Reports',
    body: 'Compliance artifacts generated as a byproduct of every scan. No separate audit run needed — the report writes itself.',
    tag: 'COMPLIANCE',
  },
];

// ── Original Architecture Layers ──────────────────────────────────────────────
const ARCH_LAYERS = [
  { label: 'Ingestion', items: ['GitHub Webhooks', 'GitLab CI Events', 'Jenkins Posts', 'CI Plugin Direct'], color: '#8B5CF6' },
  { label: 'Processing', items: ['SBOM Engine', 'Vuln Correlation', 'Malicious Pkg Analyzer', 'Policy Gate'], color: '#FF2E93' },
  { label: 'Intelligence', items: ['NVD', 'OSV.dev', 'GitHub Advisory', 'Snyk · Socket.dev'], color: '#FFE600' },
  { label: 'Delivery', items: ['Slack Alerts', 'Jira Tickets', 'PagerDuty', 'Email · Dashboard'], color: '#10B981' },
];

// ── Original Developer Testimonials ───────────────────────────────────────────
const TESTIMONIALS = [
  {
    quote: 'We caught a typosquat in a transitive dep 4 levels deep. Without SecureChain, that package would have shipped to prod.',
    name: 'Aditya R.',
    role: 'Security Engineer · Fintech startup',
  },
  {
    quote: 'The EPSS-CVSS fusion actually works. Our triage queue dropped by 60% because we stopped chasing CVSS 9.8s with near-zero exploitation probability.',
    name: 'Priya S.',
    role: 'DevSecOps Lead · HealthTech SaaS',
  },
  {
    quote: "We went from weekly manual SCA scans to sub-15-minute CVE detection. The CI gate means nothing ships that the security team hasn't already seen.",
    name: 'Marcus W.',
    role: 'Platform Engineering · Enterprise',
  },
];

// ── Main Landing Page ─────────────────────────────────────────────────────────
export default function Landing() {
  const navigate = useNavigate();

  function handleLogin() {
    navigate('/login');
  }

  return (
    <div className="min-h-screen bg-[#12101B] text-slate-100 font-['Inter'] selection:bg-[#FF2E93]/30 selection:text-white relative overflow-x-hidden">

      {/* ── Top Navigation Bar (#12101B Theme) ── */}
      <header className="fixed top-0 inset-x-0 z-50 h-16 flex items-center px-6 md:px-10 border-b border-[#231D38] bg-[#12101B]/90 backdrop-blur-md">
        <div className="flex items-center gap-3 mr-auto">
          {/* Monogram with radiant gradient */}
          <div className="w-8 h-8 rounded-xl bg-gradient-to-tr from-[#FF2E93] via-[#D946EF] to-[#8B5CF6] flex items-center justify-center text-white shadow-[0_0_15px_rgba(255,46,147,0.4)]">
            <span className="text-white text-xs font-black font-['Space_Grotesk']">SC</span>
          </div>
          <span className="font-bold text-base text-white font-['Space_Grotesk'] tracking-tight">
            SecureChain
          </span>
          <span className="px-2 py-0.5 rounded-full text-[10px] font-mono font-bold bg-[#241D3B] text-[#D946EF] border border-[#3D305F] ml-1">
            v1.0
          </span>
        </div>

        <nav className="hidden md:flex items-center gap-8 text-xs font-semibold text-slate-300 mr-8">
          {['Features', 'Architecture', 'Docs'].map((l) => (
            <a
              key={l}
              href={`#${l.toLowerCase()}`}
              className="hover:text-white transition-colors inline-block"
            >
              {l}
            </a>
          ))}
        </nav>

        <div className="flex items-center gap-2">
          <button
            onClick={handleLogin}
            className="bg-white hover:bg-slate-100 text-slate-950 font-bold px-5 py-2 rounded-full text-xs transition-all shadow-[0_0_20px_rgba(255,255,255,0.2)] hover:scale-105 active:scale-95 cursor-pointer flex items-center gap-1.5"
          >
            <span>Get Started</span>
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
              <path d="M5 12h14M12 5l7 7-7 7" />
            </svg>
          </button>
        </div>
      </header>

      {/* ── FULL FIRST PAGE (Hero Section with Full-Screen Laser Block Scanner) ── */}
      <section className="relative min-h-screen flex items-center pt-16 pb-12 px-6 md:px-12 overflow-hidden">
        {/* Full First Page Laser Block Scanner Canvas */}
        <LaserBlockScanner />

        {/* Ambient background glows */}
        <div className="absolute top-20 left-1/4 w-96 h-96 rounded-full bg-[#8B5CF6]/10 blur-[130px] pointer-events-none" />
        <div className="absolute top-40 right-1/4 w-96 h-96 rounded-full bg-[#FF2E93]/10 blur-[130px] pointer-events-none" />

        {/* Hero Overlay Content */}
        <div className="relative z-10 max-w-7xl mx-auto w-full grid grid-cols-1 lg:grid-cols-12 gap-8 items-center pointer-events-none">
          {/* Left Column Copy with less blurry, more translucent glass */}
          <div
            id="hero-text-content"
            className="lg:col-span-6 pointer-events-auto text-center lg:text-left bg-[#12101B]/40 backdrop-blur-md p-6 lg:p-8 rounded-3xl border border-[#2D2345]/70 shadow-[0_10px_40px_rgba(0,0,0,0.6)] relative z-10 translate-y-[10px] translate-x-[-20px]"
          >
            <div className="inline-flex items-center gap-2 px-3.5 py-1.5 rounded-full bg-[#1C172E] border border-[#342955] text-slate-300 font-semibold text-xs font-mono mb-6 shadow-md cursor-default">
              <span className="w-2 h-2 bg-emerald-400 rounded-full animate-pulse" />
              Real-time threat feed active
            </div>

            <h1 className="text-5xl md:text-6xl lg:text-[4.75rem] font-black font-['Space_Grotesk'] leading-[1.06] tracking-tight mb-6 text-white drop-shadow-md">
              Secure your
              <br />
              <span className="bg-gradient-to-r from-[#FF2E93] via-[#D946EF] to-[#8B5CF6] text-transparent bg-clip-text">
                supply chain.
              </span>
              <br />
              Before it ships.
            </h1>

            <p className="text-slate-300 text-base md:text-lg leading-relaxed mb-8 max-w-xl">
              SecureChain detects vulnerable dependencies, typosquatted packages, and compromised build pipelines in under 15 minutes from CVE publication.
            </p>

            <div className="flex flex-col sm:flex-row gap-3.5 justify-center lg:justify-start">
              <button
                onClick={handleLogin}
                className="bg-white hover:bg-slate-100 text-slate-950 font-bold px-7 py-3.5 rounded-full text-sm transition-all shadow-[0_0_25px_rgba(255,255,255,0.25)] hover:scale-105 active:scale-95 flex items-center justify-center gap-2 cursor-pointer"
              >
                <svg width="18" height="18" viewBox="0 0 24 24" fill="currentColor">
                  <path d="M12 0C5.37 0 0 5.37 0 12c0 5.31 3.435 9.795 8.205 11.385.6.105.825-.255.825-.57 0-.285-.015-1.23-.015-2.235-3.015.555-3.795-.735-4.035-1.41-.135-.345-.72-1.41-1.23-1.695-.42-.225-1.02-.78-.015-.795.945-.015 1.62.87 1.845 1.23 1.08 1.815 2.805 1.305 3.495.99.105-.78.42-1.305.765-1.605-2.67-.3-5.46-1.335-5.46-5.925 0-1.305.465-2.385 1.23-3.225-.12-.3-.54-1.53.12-3.18 0 0 1.005-.315 3.3 1.23.96-.27 1.98-.405 3-.405s2.04.135 3 .405c2.295-1.56 3.3-1.23 3.3-1.23.66 1.65.24 2.88.12 3.18.765.84 1.23 1.905 1.23 3.225 0 4.605-2.805 5.625-5.475 5.925.435.375.81 1.095.81 2.22 0 1.605-.015 2.895-.015 3.3 0 .315.225.69.825.57A12.02 12.02 0 0024 12c0-6.63-5.37-12-12-12z" />
                </svg>
                <span className="font-semibold">Sign in to get started</span>
              </button>

              <button
                onClick={() => document.getElementById('features')?.scrollIntoView({ behavior: 'smooth' })}
                className="bg-[#241D3B] hover:bg-[#31274F] border border-[#44366A] text-white font-semibold px-7 py-3.5 rounded-full text-sm transition-all hover:scale-105 active:scale-95 cursor-pointer"
              >
                See how it works →
              </button>
            </div>
          </div>

          {/* Right Column empty space so the full-screen laser scanner and incoming blocks shine through */}
          <div className="lg:col-span-6 hidden lg:block" />
        </div>
      </section>

      {/* ── Stepped Pixel Mosaic Transition Strip ── */}
      <SteppedPixelMosaic />

      {/* ── Real Threat & Scan Counters ── */}
      <section className="relative overflow-hidden">
        <ThreatCounter />
      </section>

      {/* ── Features Section (Original Content Preserved, Dark Theme #12101B) ── */}
      <section id="features" className="py-24 px-6 md:px-12 bg-[#12101B]">
        <div className="max-w-6xl mx-auto">
          <div className="text-center mb-16">
            <p className="text-[#D946EF] font-mono text-xs uppercase tracking-widest mb-3 font-bold">
              What SecureChain does
            </p>
            <h2 className="text-4xl font-black font-['Space_Grotesk'] text-white">
              One platform. Every attack surface.
            </h2>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
            {FEATURES.map((f) => (
              <div
                key={f.title}
                className="rounded-2xl p-7 bg-[#1A1528] border border-[#2D2345] hover:border-[#4B3B73] transition-all shadow-lg group hover:-translate-y-1"
              >
                <div className="flex items-start justify-between mb-5">
                  <div className="w-10 h-10 rounded-xl bg-[#251D3A] flex items-center justify-center text-xl text-[#FF2E93] font-bold group-hover:scale-110 transition-transform">
                    {f.icon}
                  </div>
                  <span className="text-[10px] font-mono font-bold px-2.5 py-1 rounded-full bg-[#291F44] text-[#D946EF] border border-[#3E3063]">
                    {f.tag}
                  </span>
                </div>
                <h3 className="font-bold text-base text-white mb-2 font-['Space_Grotesk']">
                  {f.title}
                </h3>
                <p className="text-xs text-slate-400 leading-relaxed">
                  {f.body}
                </p>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* ── Architecture Section (Original Content Preserved #161224) ── */}
      <section id="architecture" className="py-24 px-6 md:px-12 bg-[#161224] border-y border-[#261E3A]">
        <div className="max-w-5xl mx-auto">
          <div className="text-center mb-16">
            <p className="text-cyan-400 font-mono text-xs uppercase tracking-widest mb-3 font-bold">
              System design
            </p>
            <h2 className="text-4xl font-black font-['Space_Grotesk'] text-white">
              Five layers. One verdict.
            </h2>
          </div>

          <div className="grid grid-cols-2 md:grid-cols-4 gap-5">
            {ARCH_LAYERS.map((layer) => (
              <div
                key={layer.label}
                className="rounded-2xl p-6 bg-[#1F1735] border border-[#342857] shadow-md"
              >
                <div className="text-xs font-mono uppercase tracking-widest mb-4 font-bold text-white flex items-center gap-2">
                  <span className="w-2 h-2 rounded-full" style={{ backgroundColor: layer.color }} />
                  {layer.label}
                </div>
                <div className="space-y-3">
                  {layer.items.map((item) => (
                    <div key={item} className="flex items-center gap-2 text-xs text-slate-300 font-medium">
                      <span className="w-1 h-1 rounded-full bg-slate-500" />
                      {item}
                    </div>
                  ))}
                </div>
              </div>
            ))}
          </div>

          <div className="mt-8 text-center text-xs font-mono text-slate-400">
            ↑ Ingestion → Processing → Intelligence → Storage → Platform & Delivery ↓
          </div>
        </div>
      </section>

      {/* ── Testimonials (Original Content Preserved #12101B) ── */}
      <section id="testimonials" className="py-24 px-6 md:px-12 bg-[#12101B]">
        <div className="max-w-6xl mx-auto">
          <div className="text-center mb-16">
            <p className="text-[#FF2E93] font-mono text-xs font-bold uppercase tracking-widest mb-3">
              From the field
            </p>
            <h2 className="text-4xl font-black font-['Space_Grotesk'] text-white">
              Teams that ship faster<br />because they caught threats early.
            </h2>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
            {TESTIMONIALS.map((t, i) => (
              <div
                key={i}
                className="rounded-2xl p-8 bg-[#1A1528] border border-[#2E2448] shadow-lg flex flex-col justify-between"
              >
                <div>
                  <div className="text-3xl text-[#FF2E93] mb-3 font-serif font-bold">“</div>
                  <p className="text-slate-300 text-sm leading-relaxed mb-6 font-normal">
                    "{t.quote}"
                  </p>
                </div>
                <div className="flex items-center gap-3 pt-4 border-t border-[#2A2142]">
                  <div className="w-9 h-9 rounded-full bg-gradient-to-tr from-[#FF2E93] to-[#8B5CF6] text-white font-bold flex items-center justify-center text-xs shadow-md">
                    {t.name.charAt(0)}
                  </div>
                  <div>
                    <div className="font-bold text-xs text-white">{t.name}</div>
                    <div className="text-[11px] text-slate-400 mt-0.5">{t.role}</div>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Pre-footer CTA */}
        <div className="mt-28 max-w-4xl mx-auto text-center rounded-3xl p-12 bg-gradient-to-br from-[#1F1735] to-[#140F24] border border-[#3A2D5C] text-white shadow-2xl relative overflow-hidden">
          <h2 className="text-3xl md:text-4xl font-black font-['Space_Grotesk'] text-white mb-4">
            Ready to secure your pipeline?
          </h2>
          <p className="text-slate-300 text-sm mb-8 max-w-xl mx-auto leading-relaxed">
            Get continuous visibility into your supply chain vulnerabilities before they ever reach production.
          </p>
          <button
            onClick={handleLogin}
            className="bg-white hover:bg-slate-100 text-slate-950 font-bold px-8 py-3.5 rounded-full text-sm transition-all shadow-xl hover:scale-105 active:scale-95 cursor-pointer"
          >
            Start Scanning Now
          </button>
        </div>
      </section>

      {/* ── Comprehensive Enterprise Footer ── */}
      <footer className="border-t border-[#231D38] bg-[#0E0C17] text-slate-400 text-xs pt-16 pb-12 px-6 md:px-12">
        <div className="max-w-6xl mx-auto">
          {/* Main Footer Directory Columns */}
          <div className="grid grid-cols-2 md:grid-cols-6 gap-8 mb-16">
            {/* Column 1: Products */}
            <div className="space-y-2.5">
              <p className="font-mono text-[11px] font-bold text-white uppercase tracking-wider mb-4">
                Products
              </p>
              <ul className="space-y-2 text-xs">
                <li><a href="#features" className="hover:text-white transition-colors">SecureChain for GitHub</a></li>
                <li><a href="#features" className="hover:text-white transition-colors">SecureChain CLI</a></li>
                <li><a href="#features" className="hover:text-white transition-colors">SBOM Studio</a></li>
                <li><a href="#features" className="hover:text-white transition-colors">CI/CD Policy Gate</a></li>
                <li><a href="#features" className="hover:text-white transition-colors">Reachability Engine</a></li>
                <li><a href="#features" className="hover:text-white transition-colors">Dependency Search</a></li>
              </ul>
            </div>

            {/* Column 2: Ecosystems */}
            <div className="space-y-2.5">
              <p className="font-mono text-[11px] font-bold text-white uppercase tracking-wider mb-4">
                Languages
              </p>
              <ul className="space-y-2 text-xs">
                <li className="flex items-center gap-1.5"><span className="text-[#FF2E93]">●</span> JavaScript / TypeScript</li>
                <li className="flex items-center gap-1.5"><span className="text-cyan-400">●</span> Python (PyPI)</li>
                <li className="flex items-center gap-1.5"><span className="text-amber-400">●</span> Java (Maven)</li>
                <li className="flex items-center gap-1.5"><span className="text-cyan-300">●</span> Go (Golang)</li>
                <li className="flex items-center gap-1.5"><span className="text-rose-400">●</span> Ruby (Gems)</li>
                <li className="flex items-center gap-1.5"><span className="text-orange-400">●</span> Rust (Cargo)</li>
              </ul>
            </div>

            {/* Column 3: Integrations */}
            <div className="space-y-2.5">
              <p className="font-mono text-[11px] font-bold text-white uppercase tracking-wider mb-4">
                Integrations
              </p>
              <ul className="space-y-2 text-xs">
                <li><a href="#architecture" className="hover:text-white transition-colors">GitHub Actions</a></li>
                <li><a href="#architecture" className="hover:text-white transition-colors">GitLab CI</a></li>
                <li><a href="#architecture" className="hover:text-white transition-colors">Jenkins Pipelines</a></li>
                <li><a href="#architecture" className="hover:text-white transition-colors">Slack & PagerDuty</a></li>
                <li><a href="#architecture" className="hover:text-white transition-colors">Jira & Webhooks</a></li>
                <li><a href="#architecture" className="hover:text-white transition-colors">SIEM Streaming</a></li>
              </ul>
            </div>

            {/* Column 4: Resources */}
            <div className="space-y-2.5">
              <p className="font-mono text-[11px] font-bold text-white uppercase tracking-wider mb-4">
                Resources
              </p>
              <ul className="space-y-2 text-xs">
                <li><a href="#features" className="hover:text-white transition-colors">Documentation</a></li>
                <li><a href="#features" className="hover:text-white transition-colors">Threat Intel Advisory</a></li>
                <li><a href="#features" className="hover:text-white transition-colors">API Reference</a></li>
                <li><a href="#features" className="hover:text-white transition-colors">Package Alerts</a></li>
                <li><a href="#features" className="hover:text-white transition-colors">Changelog</a></li>
                <li><a href="#features" className="hover:text-white transition-colors">Security Glossary</a></li>
              </ul>
            </div>

            {/* Column 5: Compliance */}
            <div className="space-y-2.5">
              <p className="font-mono text-[11px] font-bold text-white uppercase tracking-wider mb-4">
                Compliance
              </p>
              <ul className="space-y-2 text-xs">
                <li><span className="text-white font-medium">SOC 2 Type 2</span></li>
                <li><span className="text-white font-medium">SLSA Level 3</span></li>
                <li><span className="text-white font-medium">NIST SSDF SP 800-218</span></li>
                <li><span className="text-white font-medium">ISO/IEC 27001</span></li>
                <li><span className="text-white font-medium">CycloneDX 1.5 & SPDX</span></li>
                <li><span className="text-white font-medium">Fortune Cyber 60</span></li>
              </ul>
            </div>

            {/* Column 6: Newsletter Subscribe */}
            <div className="col-span-2 md:col-span-1 space-y-3">
              <p className="font-mono text-[11px] font-bold text-white uppercase tracking-wider mb-2">
                Stay in touch
              </p>
              <p className="text-[11px] text-slate-400">
                Get open source security intelligence delivered straight into your inbox.
              </p>
              <div className="flex items-center gap-1.5 bg-[#1B152B] p-1.5 rounded-xl border border-[#31264E]">
                <input
                  type="email"
                  placeholder="Enter email"
                  className="bg-transparent text-xs text-white placeholder-slate-500 px-2.5 py-1 w-full outline-none"
                />
                <button
                  type="button"
                  onClick={() => alert('Thank you for subscribing to SecureChain Threat Intelligence!')}
                  className="bg-[#FF2E93] hover:bg-[#E02681] text-white px-2.5 py-1 rounded-lg text-xs font-bold transition-colors cursor-pointer"
                >
                  →
                </button>
              </div>
            </div>
          </div>

          {/* Bottom Bar: Logo, Socials, Patents, Legal */}
          <div className="pt-8 border-t border-[#1F1932] flex flex-col md:flex-row items-center justify-between gap-6">
            <div className="flex items-center gap-3">
              <div className="w-6 h-6 rounded-lg bg-gradient-to-tr from-[#FF2E93] via-[#D946EF] to-[#8B5CF6] flex items-center justify-center text-white">
                <span className="text-[10px] font-black font-['Space_Grotesk']">SC</span>
              </div>
              <span className="font-bold text-sm text-white font-['Space_Grotesk']">
                SecureChain Inc.
              </span>
              <span className="text-slate-500 font-mono text-[11px] hidden sm:inline">
                © {new Date().getFullYear()} · All rights reserved.
              </span>
            </div>

            {/* Social Icons & Status Indicator */}
            <div className="flex items-center gap-6 text-xs text-slate-400">
              <div className="flex items-center gap-1.5 text-emerald-400 font-mono text-[11px]">
                <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
                All Systems Operational
              </div>
              <a href="https://github.com" target="_blank" rel="noreferrer" className="hover:text-white transition-colors">GitHub</a>
              <a href="#" className="hover:text-white transition-colors">Terms</a>
              <a href="#" className="hover:text-white transition-colors">Privacy</a>
              <a href="#" className="hover:text-white transition-colors">Security</a>
            </div>
          </div>
        </div>
      </footer>
    </div>
  );
}
