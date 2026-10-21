# SecureChain Frontend

React + Vite + Tailwind v4 dashboard for the SecureChain backend.
**Build verified: zero errors, zero warnings (35 modules, ~91 KB gzipped).**

## Stack

| Piece | What |
|---|---|
| React 19 + Vite 8 | Core framework + dev server |
| Tailwind CSS v4 | Design tokens (via `@tailwindcss/vite` — no config file needed) |
| React Router v7 | Client-side routing |
| Framer Motion + Recharts + Lucide | Available for charts / micro-animations |
| `useAuth` | JWT session hook (reads from localStorage, refreshes on load) |
| `useThreatFeed` | Live WebSocket hook with 3 s auto-reconnect |

## Setup

```bash
cd securechain-frontend
npm install
cp .env.example .env      # set VITE_API_URL if backend is not on :4000
npm run dev               # http://localhost:5173
```

Backend must be running on :4000 first (`cd securechain-backend && npm start`).

## Build

```bash
npm run build    # → dist/  (300 KB JS / 91 KB gzipped)
npm run preview  # serve production build locally
```

## Route map

| URL | Page | Auth |
|---|---|---|
| `/` | Landing (hero, features, architecture, pricing, testimonials, contact) | Public |
| `/login` | GitHub OAuth sign-in | Public |
| `/auth/callback` | OAuth callback — reads `?token=` from backend redirect | Public |
| `/dashboard` | Overview — stat cards + live threat feed | ✓ |
| `/dashboard/repos` | Repositories — connect repos, trigger scans, risk scores | ✓ |
| `/dashboard/sbom` | SBOM — generate CycloneDX/SPDX, download, diff | ✓ |
| `/dashboard/vulns` | Vulnerabilities — EPSS·CVSS list, VEX status workflow | ✓ |
| `/dashboard/malware` | Malicious Packages — typosquat + heuristic findings | ✓ |
| `/dashboard/cicd` | CI/CD — CI API key, build integrity, pipeline snippets | ✓ |
| `/dashboard/alerts` | Alert Channels — Slack / PagerDuty / email config + test-send | ✓ |
| `/dashboard/compliance` | Compliance — SLSA / NIST SSDF / OWASP scores | ✓ |
| `/dashboard/admin` | Admin — session info, roadmap | ✓ |

## What's real vs static

| Feature | Status |
|---|---|
| GitHub OAuth login | Real — needs `GITHUB_CLIENT_ID/SECRET` in backend `.env` |
| Live threat feed ticker | Real WebSocket (shows "Connecting…" if backend is down) |
| Repo scan (SBOM + vulns + malware) | Real — hits npm registry + OSV.dev |
| Vulnerability status / VEX workflow | Real PATCH → backend → persisted |
| SBOM JSON export | Real file download from backend |
| Alert channel test-send | Real HTTP → Slack / Jira / PagerDuty |
| Compliance scores | Static display (full report gen is v1.1) |
| Admin user management | Static roadmap display (v1.1) |
