import { useState, useEffect } from 'react';
import { api } from '../lib/api';

const PRIMARY_STACKS = [
  { id: 'Node.js (npm)', label: 'Node.js / npm', icon: '⚡' },
  { id: 'Python (PyPI)', label: 'Python / PyPI', icon: '🐍' },
  { id: 'Go Modules', label: 'Go Modules', icon: '🐹' },
  { id: 'Java (Maven)', label: 'Java / Maven', icon: '☕' },
  { id: 'Docker', label: 'Docker / Containers', icon: '🐳' },
];

const SCAN_FREQUENCIES = [
  { id: 'realtime', label: 'Real-time Continuous', desc: 'Auto-scans on every commit & PR' },
  { id: 'daily', label: 'Daily Scheduled', desc: 'Nightly vulnerability & malware audit' },
  { id: 'ondemand', label: 'On-demand Manual', desc: 'Manual scans when initiated' },
];

const TEAM_CATEGORIES = [
  'FinTech & Banking',
  'Cybersecurity & Defense',
  'E-Commerce & SaaS',
  'Open Source Initiative',
  'Cloud Infrastructure',
  'HealthTech & Data',
];

const SECURITY_POLICIES = [
  { id: 'Strict Zero-Trust (Block P0/P1)', label: 'Strict Zero-Trust', desc: 'Block deployment on any Critical/High threat' },
  { id: 'Standard OWASP Compliance', label: 'Standard OWASP Policy', desc: 'Warn on High, block only on verified exploits' },
  { id: 'Audit & Advisory Only', label: 'Audit & Advisory Only', desc: 'Report vulnerabilities without blocking builds' },
];

export default function OnboardingModal({ onComplete }) {
  // Navigation steps: 'choose' | 'solo-form' | 'team-choose' | 'team-search' | 'team-create' | 'request-sent'
  const [step, setStep] = useState('choose');

  // Solo state
  const [projectTitle, setProjectTitle] = useState('');
  const [projectIntro, setProjectIntro] = useState('');
  const [primaryStack, setPrimaryStack] = useState('Node.js (npm)');
  const [scanFrequency, setScanFrequency] = useState('realtime');

  // Team Create state
  const [teamName, setTeamName] = useState('');
  const [projectName, setProjectName] = useState('');
  const [projectDescription, setProjectDescription] = useState('');
  const [category, setCategory] = useState('FinTech & Banking');
  const [securityPolicy, setSecurityPolicy] = useState('Strict Zero-Trust (Block P0/P1)');

  // Team Search / Join state
  const [searchQuery, setSearchQuery] = useState('');
  const [availableTeams, setAvailableTeams] = useState([]);
  const [searching, setSearching] = useState(false);
  const [selectedTeam, setSelectedTeam] = useState(null);
  const [requestNote, setRequestNote] = useState('');
  const [inviteToken, setInviteToken] = useState('');
  const [useTokenMode, setUseTokenMode] = useState(false);
  const [sentOrgName, setSentOrgName] = useState('');

  // UI state
  const [loading, setLoading] = useState(false);
  const [err, setErr] = useState('');

  // Fetch directory of teams when entering team-search step
  useEffect(() => {
    if (step === 'team-search') {
      loadTeams('');
    }
  }, [step]);

  async function loadTeams(q) {
    setSearching(true);
    try {
      const teams = await api.searchTeams(q);
      setAvailableTeams(teams || []);
    } catch {
      setAvailableTeams([]);
    } finally {
      setSearching(false);
    }
  }

  // Handle Solo submission
  async function submitSolo() {
    if (!projectTitle.trim()) {
      return setErr('Please enter a project title');
    }
    setLoading(true);
    setErr('');
    try {
      const res = await api.completeOnboarding({
        mode: 'solo',
        projectTitle: projectTitle.trim(),
        projectIntro: projectIntro.trim(),
        primaryStack,
        scanFrequency,
      });
      onComplete({ mode: 'solo', soloProject: res.soloProject });
    } catch (e) {
      setErr(e.message || 'Failed to complete solo setup');
    } finally {
      setLoading(false);
    }
  }

  // Handle Create Team submission
  async function submitCreateTeam() {
    if (!teamName.trim()) return setErr('Please enter a team workspace name');
    if (!projectName.trim()) return setErr('Please enter your primary project name');

    setLoading(true);
    setErr('');
    try {
      const res = await api.completeOnboarding({
        mode: 'team_create',
        teamName: teamName.trim(),
        projectName: projectName.trim(),
        projectDescription: projectDescription.trim(),
        category,
        securityPolicy,
      });
      onComplete({ mode: 'team', org: res.org });
    } catch (e) {
      setErr(e.message || 'Failed to create team workspace');
    } finally {
      setLoading(false);
    }
  }

  // Handle Join Team Request
  async function submitJoinRequest() {
    if (useTokenMode) {
      const token = inviteToken.trim().split('/').pop();
      if (!token) return setErr('Please enter a valid invite token or link');
      setLoading(true);
      setErr('');
      try {
        const result = await api.acceptInvite(token);
        onComplete({ mode: 'team', org: result.org });
      } catch (e) {
        setErr(e.message || 'Invalid or expired invite token');
      } finally {
        setLoading(false);
      }
      return;
    }

    if (!selectedTeam) return setErr('Please select a team from the list to join');

    setLoading(true);
    setErr('');
    try {
      await api.requestJoinTeam(selectedTeam.id, requestNote.trim());
      setSentOrgName(selectedTeam.name);
      setStep('request-sent');
    } catch (e) {
      setErr(e.message || 'Failed to transmit join request');
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-900/40 backdrop-blur-sm animate-fade-in">
      <div className="relative w-full max-w-2xl bg-white border border-slate-200 rounded-2xl shadow-2xl overflow-hidden text-slate-900">

        {/* Modal Header */}
        <div className="px-8 py-5 border-b border-slate-100 bg-slate-50 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-9 h-9 rounded-xl bg-slate-900 text-white flex items-center justify-center font-black text-sm shadow-xs">
              ⬡
            </div>
            <div>
              <h2 className="text-lg font-black text-slate-900 font-['Space_Grotesk'] flex items-center gap-2">
                SecureChain Setup
                <span className="text-[10px] uppercase font-bold tracking-wider px-2 py-0.5 rounded-full bg-emerald-50 text-emerald-800 border border-emerald-200">
                  v2.4 Pro
                </span>
              </h2>
              <p className="text-xs text-slate-500">Configure your security scanning engine & workspace</p>
            </div>
          </div>

          {step !== 'choose' && step !== 'request-sent' && (
            <button
              onClick={() => {
                setErr('');
                if (step === 'solo-form' || step === 'team-choose') setStep('choose');
                else if (step === 'team-search' || step === 'team-create') setStep('team-choose');
              }}
              className="text-xs text-slate-500 hover:text-slate-900 transition-colors flex items-center gap-1 font-mono font-medium cursor-pointer"
            >
              ← Back
            </button>
          )}
        </div>

        {/* Content Body */}
        <div className="p-8">

          {/* ════════════════ Step 1: Mode Selection (Solo vs Team) ════════════════ */}
          {step === 'choose' && (
            <div className="space-y-6">
              <div className="text-center max-w-md mx-auto mb-2">
                <h3 className="text-xl font-bold text-slate-900 font-['Space_Grotesk']">Choose Workspace Architecture</h3>
                <p className="text-xs text-slate-500 mt-1">Select how you intend to operate and monitor third-party packages</p>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
                {/* Solo Developer Option */}
                <button
                  onClick={() => { setStep('solo-form'); setErr(''); }}
                  className="text-left p-6 rounded-2xl border border-slate-200 bg-white hover:border-slate-400 hover:shadow-md transition-all group relative overflow-hidden flex flex-col justify-between cursor-pointer shadow-xs"
                >
                  <div>
                    <div className="w-12 h-12 rounded-xl bg-slate-100 border border-slate-200 flex items-center justify-center text-2xl mb-4 group-hover:bg-slate-200 transition-colors">
                      👤
                    </div>
                    <span className="text-[10px] font-bold uppercase tracking-wider text-slate-800 bg-slate-100 px-2 py-0.5 rounded-full border border-slate-200">
                      Independent Dev
                    </span>
                    <h4 className="text-lg font-bold text-slate-900 font-['Space_Grotesk'] mt-2">Solo Developer</h4>
                    <p className="text-xs text-slate-600 mt-2 leading-relaxed">
                      Scan your local projects, manage custom dependencies, generate SBOMs, and view personalized vulnerability metrics.
                    </p>
                  </div>
                  <div className="mt-6 pt-4 border-t border-slate-100 flex items-center justify-between text-xs font-bold text-slate-900">
                    <span>Configure Project</span>
                    <span>→</span>
                  </div>
                </button>

                {/* Team Workspace Option */}
                <button
                  onClick={() => { setStep('team-choose'); setErr(''); }}
                  className="text-left p-6 rounded-2xl border border-slate-200 bg-white hover:border-slate-400 hover:shadow-md transition-all group relative overflow-hidden flex flex-col justify-between cursor-pointer shadow-xs"
                >
                  <div>
                    <div className="w-12 h-12 rounded-xl bg-slate-100 border border-slate-200 flex items-center justify-center text-2xl mb-4 group-hover:bg-slate-200 transition-colors">
                      👥
                    </div>
                    <span className="text-[10px] font-bold uppercase tracking-wider text-emerald-800 bg-emerald-50 px-2 py-0.5 rounded-full border border-emerald-200">
                      Collaborative Team
                    </span>
                    <h4 className="text-lg font-bold text-slate-900 font-['Space_Grotesk'] mt-2">Team Workspace</h4>
                    <p className="text-xs text-slate-600 mt-2 leading-relaxed">
                      Collaborate with engineers and security analysts. Search & join existing teams or create a centralized team workspace.
                    </p>
                  </div>
                  <div className="mt-6 pt-4 border-t border-slate-100 flex items-center justify-between text-xs font-bold text-slate-900">
                    <span>Explore Teams</span>
                    <span>→</span>
                  </div>
                </button>
              </div>

              {err && (
                <div className="p-3 rounded-xl bg-rose-50 border border-rose-200 text-xs text-rose-700 font-medium">
                  {err}
                </div>
              )}
            </div>
          )}

          {/* ════════════════ Step 2A: Solo Developer Configuration ════════════════ */}
          {step === 'solo-form' && (
            <div className="space-y-5">
              <div>
                <h3 className="text-lg font-bold text-slate-900 font-['Space_Grotesk']">Solo Developer Project Details</h3>
                <p className="text-xs text-slate-500">Enter details about the main project you'll be auditing with SecureChain.</p>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                  <label className="text-xs font-semibold text-slate-700 block mb-1.5">Project Title *</label>
                  <input
                    type="text"
                    value={projectTitle}
                    onChange={(e) => { setProjectTitle(e.target.value); setErr(''); }}
                    placeholder="e.g. SecureAuth Microservice"
                    className="w-full bg-white border border-slate-200 rounded-xl px-4 py-2.5 text-sm text-slate-900 placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-slate-900/10 focus:border-slate-800 transition-colors shadow-xs"
                  />
                </div>

                <div>
                  <label className="text-xs font-semibold text-slate-700 block mb-1.5">Primary Tech Stack</label>
                  <select
                    value={primaryStack}
                    onChange={(e) => setPrimaryStack(e.target.value)}
                    className="w-full bg-white border border-slate-200 rounded-xl px-4 py-2.5 text-sm text-slate-900 focus:outline-none focus:ring-2 focus:ring-slate-900/10 focus:border-slate-800 transition-colors shadow-xs cursor-pointer font-medium"
                  >
                    {PRIMARY_STACKS.map((st) => (
                      <option key={st.id} value={st.id}>
                        {st.icon} {st.label}
                      </option>
                    ))}
                  </select>
                </div>
              </div>

              <div>
                <label className="text-xs font-semibold text-slate-700 block mb-1.5">Project Introduction / Description</label>
                <textarea
                  rows={2}
                  value={projectIntro}
                  onChange={(e) => setProjectIntro(e.target.value)}
                  placeholder="Brief summary of what this application does and why third-party package security is vital..."
                  className="w-full bg-white border border-slate-200 rounded-xl px-4 py-2 text-sm text-slate-900 placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-slate-900/10 focus:border-slate-800 transition-colors resize-none shadow-xs"
                />
              </div>

              <div>
                <label className="text-xs font-semibold text-slate-700 block mb-2">Automated Scanning Preference</label>
                <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                  {SCAN_FREQUENCIES.map((sf) => (
                    <button
                      key={sf.id}
                      type="button"
                      onClick={() => setScanFrequency(sf.id)}
                      className={`text-left p-3 rounded-xl border text-xs transition-all cursor-pointer ${
                        scanFrequency === sf.id
                          ? 'border-slate-900 bg-slate-900 text-white shadow-xs'
                          : 'border-slate-200 bg-slate-50 text-slate-700 hover:border-slate-300'
                      }`}
                    >
                      <span className={`font-bold block ${scanFrequency === sf.id ? 'text-white' : 'text-slate-900'}`}>{sf.label}</span>
                      <span className={`text-[10px] mt-1 block leading-tight ${scanFrequency === sf.id ? 'text-slate-300' : 'text-slate-500'}`}>{sf.desc}</span>
                    </button>
                  ))}
                </div>
              </div>

              {err && (
                <div className="p-3 rounded-xl bg-rose-50 border border-rose-200 text-xs text-rose-700 font-medium">
                  {err}
                </div>
              )}

              <div className="pt-3">
                <button
                  onClick={submitSolo}
                  disabled={loading || !projectTitle.trim()}
                  className="w-full py-3.5 rounded-xl bg-slate-900 hover:bg-slate-800 disabled:opacity-40 disabled:cursor-not-allowed text-white font-bold font-['Space_Grotesk'] text-sm shadow-xs transition-all flex items-center justify-center gap-2 cursor-pointer"
                >
                  {loading ? 'Initializing Solo Workspace...' : 'Launch Solo Dashboard →'}
                </button>
              </div>
            </div>
          )}

          {/* ════════════════ Step 2B: Team Option Choice ════════════════ */}
          {step === 'team-choose' && (
            <div className="space-y-6">
              <div>
                <h3 className="text-xl font-bold text-slate-900 font-['Space_Grotesk']">Team Workspace Mode</h3>
                <p className="text-xs text-slate-500 mt-1">Would you like to search & request to join an existing team, or register a new team?</p>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
                {/* Path 1: Join Existing Team */}
                <button
                  onClick={() => { setStep('team-search'); setErr(''); }}
                  className="text-left p-6 rounded-2xl border border-slate-200 bg-white hover:border-slate-400 hover:shadow-md transition-all group flex flex-col justify-between cursor-pointer shadow-xs"
                >
                  <div>
                    <div className="w-10 h-10 rounded-xl bg-slate-100 text-slate-800 flex items-center justify-center text-xl mb-4 font-bold">
                      🔍
                    </div>
                    <h4 className="text-base font-bold text-slate-900 font-['Space_Grotesk']">Join an Existing Team</h4>
                    <p className="text-xs text-slate-600 mt-2 leading-relaxed">
                      Search the organisation directory for your company or project team, select it, and submit a join request to the Team Admin.
                    </p>
                  </div>
                  <div className="mt-6 font-bold text-xs text-slate-900 flex items-center gap-1">
                    <span>Search Available Teams</span>
                    <span>→</span>
                  </div>
                </button>

                {/* Path 2: Create New Team */}
                <button
                  onClick={() => { setStep('team-create'); setErr(''); }}
                  className="text-left p-6 rounded-2xl border border-slate-200 bg-white hover:border-slate-400 hover:shadow-md transition-all group flex flex-col justify-between cursor-pointer shadow-xs"
                >
                  <div>
                    <div className="w-10 h-10 rounded-xl bg-emerald-50 text-emerald-800 flex items-center justify-center text-xl mb-4 font-bold border border-emerald-200">
                      ⚡
                    </div>
                    <h4 className="text-base font-bold text-slate-900 font-['Space_Grotesk']">Create a New Team</h4>
                    <p className="text-xs text-slate-600 mt-2 leading-relaxed">
                      Initialize a new team workspace, assign security policies, set up projects, and manage team member access.
                    </p>
                  </div>
                  <div className="mt-6 font-bold text-xs text-slate-900 flex items-center gap-1">
                    <span>Build Team Workspace</span>
                    <span>→</span>
                  </div>
                </button>
              </div>
            </div>
          )}

          {/* ════════════════ Step 3B-Join: Search & Join Team ════════════════ */}
          {step === 'team-search' && (
            <div className="space-y-5">
              <div className="flex items-center justify-between">
                <div>
                  <h3 className="text-lg font-bold text-slate-900 font-['Space_Grotesk']">Search & Join Team</h3>
                  <p className="text-xs text-slate-500">Find your organization in the team directory or enter an invite token.</p>
                </div>

                <button
                  onClick={() => setUseTokenMode(!useTokenMode)}
                  className="text-xs text-slate-700 underline hover:text-slate-900 transition-opacity font-mono font-medium cursor-pointer"
                >
                  {useTokenMode ? '← Search Directory' : 'Have Invite Token?'}
                </button>
              </div>

              {/* Mode A: Directory Search */}
              {!useTokenMode ? (
                <div className="space-y-4">
                  {/* Search Input */}
                  <div className="relative">
                    <input
                      type="text"
                      value={searchQuery}
                      onChange={(e) => {
                        setSearchQuery(e.target.value);
                        loadTeams(e.target.value);
                      }}
                      placeholder="Search teams by name or category (e.g. Acme, FinTech)..."
                      className="w-full bg-white border border-slate-200 rounded-xl pl-10 pr-4 py-2.5 text-sm text-slate-900 placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-slate-900/10 focus:border-slate-800 transition-colors shadow-xs"
                    />
                    <span className="absolute left-3.5 top-3 text-slate-400 text-sm">🔍</span>
                  </div>

                  {/* Team List Results */}
                  <div className="max-h-52 overflow-y-auto space-y-2 pr-1 custom-scrollbar">
                    {searching ? (
                      <div className="text-center py-8 text-xs text-slate-500">Searching directory...</div>
                    ) : availableTeams.length === 0 ? (
                      <div className="text-center py-8 text-xs text-slate-500 border border-dashed border-slate-200 rounded-xl bg-slate-50">
                        No matching teams found. Try another search term or click "Create a New Team".
                      </div>
                    ) : (
                      availableTeams.map((t) => (
                        <div
                          key={t.id}
                          onClick={() => { setSelectedTeam(t); setErr(''); }}
                          className={`p-3.5 rounded-xl border text-left cursor-pointer transition-all ${
                            selectedTeam?.id === t.id
                              ? 'border-slate-900 bg-slate-50 shadow-xs'
                              : 'border-slate-200 bg-white hover:border-slate-300'
                          }`}
                        >
                          <div className="flex items-center justify-between">
                            <div className="flex items-center gap-3">
                              <div className="w-8 h-8 rounded-lg bg-slate-900 text-white flex items-center justify-center font-bold text-xs">
                                {t.name.slice(0, 2).toUpperCase()}
                              </div>
                              <div>
                                <p className="text-sm font-bold text-slate-900 font-['Space_Grotesk']">{t.name}</p>
                                <p className="text-[10px] text-slate-500">{t.description}</p>
                              </div>
                            </div>
                            <div className="text-right">
                              <span className="text-[10px] bg-slate-100 border border-slate-200 text-slate-700 px-2 py-0.5 rounded-full font-medium">
                                👥 {t.memberCount} member{t.memberCount !== 1 ? 's' : ''}
                              </span>
                              <span className="text-[10px] text-slate-600 block mt-1 font-mono font-medium">{t.category}</span>
                            </div>
                          </div>
                        </div>
                      ))
                    )}
                  </div>

                  {/* Note to admin input if team selected */}
                  {selectedTeam && (
                    <div className="pt-2">
                      <label className="text-xs font-semibold text-slate-700 block mb-1">
                        Optional Note to {selectedTeam.name} Admin
                      </label>
                      <input
                        type="text"
                        value={requestNote}
                        onChange={(e) => setRequestNote(e.target.value)}
                        placeholder="e.g. Senior Backend Engineer joining the security audit team..."
                        className="w-full bg-white border border-slate-200 rounded-xl px-4 py-2 text-xs text-slate-900 placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-slate-900/10 focus:border-slate-800 shadow-xs"
                      />
                    </div>
                  )}

                  {err && (
                    <div className="p-3 rounded-xl bg-rose-50 border border-rose-200 text-xs text-rose-700 font-medium">
                      {err}
                    </div>
                  )}

                  <button
                    onClick={submitJoinRequest}
                    disabled={loading || !selectedTeam}
                    className="w-full py-3.5 rounded-xl bg-slate-900 hover:bg-slate-800 disabled:opacity-40 disabled:cursor-not-allowed text-white font-bold font-['Space_Grotesk'] text-sm transition-all shadow-xs cursor-pointer"
                  >
                    {loading ? 'Submitting Join Request...' : `Send Request to Join ${selectedTeam ? selectedTeam.name : 'Team'} →`}
                  </button>
                </div>
              ) : (
                /* Mode B: Direct Invite Token */
                <div className="space-y-4">
                  <p className="text-xs text-slate-600">Paste the shareable invite link or token generated by your Team Admin.</p>

                  <div>
                    <label className="text-xs font-semibold text-slate-700 mb-1 block">Invite Link or Secret Token</label>
                    <input
                      type="text"
                      value={inviteToken}
                      onChange={(e) => { setInviteToken(e.target.value); setErr(''); }}
                      placeholder="https://securechain.dev/invite/... or raw token"
                      className="w-full bg-white border border-slate-200 rounded-xl px-4 py-2.5 text-sm text-slate-900 font-mono focus:outline-none focus:ring-2 focus:ring-slate-900/10 focus:border-slate-800 shadow-xs"
                    />
                  </div>

                  {err && (
                    <div className="p-3 rounded-xl bg-rose-50 border border-rose-200 text-xs text-rose-700 font-medium">
                      {err}
                    </div>
                  )}

                  <button
                    onClick={submitJoinRequest}
                    disabled={loading || !inviteToken.trim()}
                    className="w-full py-3.5 rounded-xl bg-slate-900 text-white font-bold font-['Space_Grotesk'] text-sm hover:bg-slate-800 transition-all shadow-xs cursor-pointer disabled:opacity-40"
                  >
                    {loading ? 'Joining Team...' : 'Verify Token & Join Workspace →'}
                  </button>
                </div>
              )}
            </div>
          )}

          {/* ════════════════ Step 3B-Create: Create New Team ════════════════ */}
          {step === 'team-create' && (
            <div className="space-y-4">
              <div>
                <h3 className="text-lg font-bold text-slate-900 font-['Space_Grotesk']">Create Team Workspace</h3>
                <p className="text-xs text-slate-500">Register your organisation team and configure initial governance policies.</p>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                  <label className="text-xs font-semibold text-slate-700 block mb-1">Team / Company Name *</label>
                  <input
                    type="text"
                    value={teamName}
                    onChange={(e) => { setTeamName(e.target.value); setErr(''); }}
                    placeholder="e.g. CyberGuard Security"
                    className="w-full bg-white border border-slate-200 rounded-xl px-4 py-2 text-sm text-slate-900 focus:outline-none focus:ring-2 focus:ring-slate-900/10 focus:border-slate-800 shadow-xs"
                  />
                </div>

                <div>
                  <label className="text-xs font-semibold text-slate-700 block mb-1">Industry / Category</label>
                  <select
                    value={category}
                    onChange={(e) => setCategory(e.target.value)}
                    className="w-full bg-white border border-slate-200 rounded-xl px-4 py-2 text-sm text-slate-900 focus:outline-none focus:ring-2 focus:ring-slate-900/10 focus:border-slate-800 shadow-xs cursor-pointer font-medium"
                  >
                    {TEAM_CATEGORIES.map((cat) => (
                      <option key={cat} value={cat}>{cat}</option>
                    ))}
                  </select>
                </div>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                  <label className="text-xs font-semibold text-slate-700 block mb-1">Primary Project Name *</label>
                  <input
                    type="text"
                    value={projectName}
                    onChange={(e) => { setProjectName(e.target.value); setErr(''); }}
                    placeholder="e.g. Payment Gateway API"
                    className="w-full bg-white border border-slate-200 rounded-xl px-4 py-2 text-sm text-slate-900 focus:outline-none focus:ring-2 focus:ring-slate-900/10 focus:border-slate-800 shadow-xs"
                  />
                </div>

                <div>
                  <label className="text-xs font-semibold text-slate-700 block mb-1">Security Policy Standard</label>
                  <select
                    value={securityPolicy}
                    onChange={(e) => setSecurityPolicy(e.target.value)}
                    className="w-full bg-white border border-slate-200 rounded-xl px-4 py-2 text-sm text-slate-900 focus:outline-none focus:ring-2 focus:ring-slate-900/10 focus:border-slate-800 shadow-xs cursor-pointer font-medium"
                  >
                    {SECURITY_POLICIES.map((sp) => (
                      <option key={sp.id} value={sp.id}>{sp.label}</option>
                    ))}
                  </select>
                </div>
              </div>

              <div>
                <label className="text-xs font-semibold text-slate-700 block mb-1">Project Description & Scope</label>
                <textarea
                  rows={2}
                  value={projectDescription}
                  onChange={(e) => setProjectDescription(e.target.value)}
                  placeholder="Describe your project repository infrastructure and security expectations..."
                  className="w-full bg-white border border-slate-200 rounded-xl px-4 py-2 text-xs text-slate-900 placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-slate-900/10 focus:border-slate-800 resize-none shadow-xs"
                />
              </div>

              {err && (
                <div className="p-3 rounded-xl bg-rose-50 border border-rose-200 text-xs text-rose-700 font-medium">
                  {err}
                </div>
              )}

              <div className="pt-2">
                <button
                  onClick={submitCreateTeam}
                  disabled={loading || !teamName.trim() || !projectName.trim()}
                  className="w-full py-3.5 rounded-xl bg-slate-900 hover:bg-slate-800 text-white font-bold font-['Space_Grotesk'] text-sm disabled:opacity-40 disabled:cursor-not-allowed shadow-xs transition-all cursor-pointer"
                >
                  {loading ? 'Creating Team Workspace...' : 'Create Team & Become Admin →'}
                </button>
              </div>
            </div>
          )}

          {/* ════════════════ Step 4: Request Sent Confirmation ════════════════ */}
          {step === 'request-sent' && (
            <div className="text-center py-6 space-y-4">
              <div className="w-16 h-16 rounded-full bg-emerald-50 border border-emerald-200 text-emerald-700 flex items-center justify-center text-3xl mx-auto shadow-xs">
                ✓
              </div>
              <h3 className="text-xl font-bold text-slate-900 font-['Space_Grotesk']">Join Request Submitted</h3>
              <p className="text-xs text-slate-600 max-w-md mx-auto leading-relaxed">
                Your request to join <strong className="text-slate-900 font-bold">{sentOrgName}</strong> has been transmitted to the Team Admin. Once approved, your account will unlock full team workspace access.
              </p>

              <div className="pt-4 flex flex-col sm:flex-row gap-3 justify-center">
                <button
                  onClick={() => onComplete({ mode: 'pending_request' })}
                  className="px-6 py-2.5 rounded-xl bg-slate-900 hover:bg-slate-800 text-white font-bold font-['Space_Grotesk'] text-xs transition-colors shadow-xs cursor-pointer"
                >
                  Proceed to Dashboard (Read-Only Mode)
                </button>
              </div>
            </div>
          )}
        </div>

        {/* Modal Footer */}
        <div className="px-8 py-3.5 border-t border-slate-100 bg-slate-50 flex items-center justify-between text-[11px] text-slate-500 font-medium">
          <span>Protected by SecureChain Zero-Trust Engine</span>
          <span className="font-mono text-slate-400">NIST SSDF & SLSA L2 Compliant</span>
        </div>
      </div>
    </div>
  );
}
