import { useState, useEffect } from 'react';
import { Outlet, Navigate } from 'react-router-dom';
import Sidebar from './Sidebar';
import ThreatFeedTicker from './ThreatFeedTicker';
import AiChatbot from './AiChatbot';
import OnboardingModal from './OnboardingModal';
import { useAuth } from '../hooks/useAuth';
import { api } from '../lib/api';
import { Spinner } from './ui';

export default function DashboardLayout() {
  const { user, loading } = useAuth();
  const [showOnboarding, setShowOnboarding] = useState(false);
  const [onboardingChecked, setOnboardingChecked] = useState(false);

  // Check if the user needs onboarding (only once per session)
  useEffect(() => {
    if (!user) return;
    api.dashboardSummary()
      .then(summary => {
        setShowOnboarding(!summary.onboardingComplete);
      })
      .catch(() => setShowOnboarding(false))
      .finally(() => setOnboardingChecked(true));
  }, [user]);

  if (loading || (user && !onboardingChecked)) return (
    <div className="h-screen flex items-center justify-center bg-slate-50">
      <Spinner size={32} color="#0f172a" />
    </div>
  );

  // No user = no token or expired token — always force login
  if (!user) return <Navigate to="/login" replace state={{ from: 'auth-guard' }} />;

  return (
    <div className="flex h-screen bg-slate-50 text-slate-900 overflow-hidden">
      <Sidebar />
      <div className="flex-1 flex flex-col ml-56 overflow-hidden relative z-10 bg-slate-50">
        <ThreatFeedTicker />
        <main className="flex-1 overflow-y-auto p-8 bg-slate-50">
          <Outlet />
        </main>
      </div>
      <AiChatbot />

      {/* Onboarding modal — shown only once on first login */}
      {showOnboarding && (
        <OnboardingModal onComplete={() => setShowOnboarding(false)} />
      )}
    </div>
  );
}

