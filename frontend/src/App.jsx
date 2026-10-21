import { Routes, Route, Navigate } from 'react-router-dom'

// Layout
import DashboardLayout from './components/DashboardLayout'

// Pages
import Landing from './pages/Landing'
import { LoginPage, OAuthCallbackPage } from './pages/Auth'
import Overview from './pages/Overview'
import Repositories from './pages/Repositories'
import SbomPage from './pages/Sbom'
import Vulnerabilities from './pages/Vulnerabilities'
import {
  MaliciousPackages,
  CicdPage,
  AlertsPage,
  CompliancePage,
  AdminPage,
} from './pages/OtherPages'

export default function App() {
  return (
    <Routes>
      {/* Public */}
      <Route path="/" element={<Landing />} />
      <Route path="/login" element={<LoginPage />} />
      <Route path="/auth/callback" element={<OAuthCallbackPage />} />

      {/* Protected dashboard — DashboardLayout handles auth guard */}
      <Route path="/dashboard" element={<DashboardLayout />}>
        <Route index element={<Overview />} />
        <Route path="repos"      element={<Repositories />} />
        <Route path="sbom"       element={<SbomPage />} />
        <Route path="vulns"      element={<Vulnerabilities />} />
        <Route path="malware"    element={<MaliciousPackages />} />
        <Route path="cicd"       element={<CicdPage />} />
        <Route path="alerts"     element={<AlertsPage />} />
        <Route path="compliance" element={<CompliancePage />} />
        <Route path="admin"      element={<AdminPage />} />
      </Route>

      {/* Catch-all */}
      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  )
}
