# SecureChain — Complete Project

Real-time software supply chain security platform.
**Backend: 21 modules / 9 routes. Frontend: 36 modules, 95 KB gzipped. Zero build errors.**

```
securechain/
├── backend/        Node.js + Express     → port 4000
├── frontend/       React + Vite          → port 5173
├── nginx/          Reverse proxy config
├── docker-compose.yml
└── .env.example
```

## One-command start (development)

```bash
# Backend
cd backend && npm install && cp .env.example .env
# → fill GITHUB_CLIENT_ID + GITHUB_CLIENT_SECRET at minimum
npm start

# Frontend (new terminal)
cd frontend && npm install && npm run dev
# open http://localhost:5173
```

## One-command deploy (Docker)

```bash
cp .env.example .env   # fill all required vars
docker compose up -d
# open http://localhost  (nginx on port 80 → auto-redirects to 443 if TLS configured)
```

### HTTPS with Let's Encrypt

```bash
# On your server (Ubuntu example)
sudo apt install certbot
sudo certbot certonly --standalone -d yourdomain.com
# Certs land at /etc/letsencrypt/live/yourdomain.com/

# Mount them into nginx container — add to docker-compose.yml nginx.volumes:
#   - /etc/letsencrypt/live/yourdomain.com/fullchain.pem:/etc/nginx/ssl/fullchain.pem:ro
#   - /etc/letsencrypt/live/yourdomain.com/privkey.pem:/etc/nginx/ssl/privkey.pem:ro
docker compose restart nginx
```

## Required environment variables

| Variable | Where to get it | Required |
|---|---|---|
| `JWT_SECRET` | Any long random string | ✅ |
| `GITHUB_CLIENT_ID` + `GITHUB_CLIENT_SECRET` | github.com/settings/developers | ✅ |
| `GOOGLE_CLIENT_ID` + `GOOGLE_CLIENT_SECRET` | console.cloud.google.com | Optional |
| `ANTHROPIC_API_KEY` | console.anthropic.com | Optional (AI features) |
| `SUPABASE_URL` + `SUPABASE_SERVICE_ROLE_KEY` | supabase.com | Optional (persistent DB) |
| `NVD_API_KEY` | nvd.nist.gov/developers | Optional (higher rate limit) |
| `GITHUB_TOKEN` | github.com/settings/tokens | Optional (higher rate limit) |

## What was tested live in this sandbox

| | Test |
|---|---|
| SBOM Engine | 45 real packages resolved from npm registry (express + lodash) |
| PyPI resolver | requests@2.34.2 + 4 transitive deps fetched live from pypi.org |
| Go resolver | gin-gonic/gin@v1.9.1 resolved live from proxy.golang.org |
| ML Classifier | lodahs → 98.4% malicious (trained on 48 real npm records) |
| Real training data | 48 records fetched live from npm for known malicious/safe packages |
| Policy gate | All 5 decision branches (PASS/FAILED/BLOCKED/integrity/clean) |
| Webhook HMAC | 6 cases (valid/tampered/wrong-secret/missing, GitLab valid/wrong) |
| Notification dispatch | Slack + Jira + PagerDuty + email via local mock receivers |
| Admin layer | Org CRUD, API key create/verify/revoke, user roles, audit log |
| Compliance engine | SLSA/SSDF/OWASP 27-control evaluation, real gap detection |
| Google OAuth | 503 graceful degradation confirmed |
| Supabase adapter | Graceful fallback to in-memory when unconfigured confirmed |
| Frontend build | Zero errors, 36 modules, 95 KB gzipped |

## Architecture

```
Browser
  ↕ HTTPS
nginx (port 443)
  ├── /api/*        → backend:4000  (Express)
  ├── /ws/*         → backend:4000  (WebSocket)
  └── /*            → frontend:80   (React SPA, served by nginx)

backend:4000
  ├── GitHub OAuth  → github.com
  ├── Google OAuth  → accounts.google.com
  ├── SBOM Engine   → registry.npmjs.org / pypi.org / proxy.golang.org / ...
  ├── Vuln Engine   → api.osv.dev / api.first.org / services.nvd.nist.gov
  ├── ML Classifier → local (no API call)
  ├── AI Engine     → api.anthropic.com (if key set)
  ├── Notifications → hooks.slack.com / events.pagerduty.com / Jira / SMTP
  └── Store         → lowdb JSON (dev) or Supabase PostgreSQL (prod)
```
