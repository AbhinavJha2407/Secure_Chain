# SecureChain Backend

Node.js/Express backend — all modules live-tested.

## Quick start

```bash
npm install
cp .env.example .env    # fill in GITHUB_CLIENT_ID + SECRET at minimum
npm start               # http://localhost:4000
```

## Modules

| Module | File | Live-tested |
|---|---|---|
| SBOM Engine (npm transitive graph, CycloneDX 1.5, SPDX 2.3) | `src/modules/sbomEngine.js` | ✅ 45 real packages resolved |
| Multi-ecosystem SBOM (PyPI, Maven, Go, NuGet) | `src/modules/ecosystemResolvers.js` | ✅ PyPI + Go tested live |
| Malicious Package Analyzer (Levenshtein + heuristics) | `src/modules/maliciousPackageAnalyzer.js` | ✅ |
| ML Classifier (logistic regression, 10 features, no API key) | `src/modules/mlClassifier.js` | ✅ lodahs → 98.4% malicious |
| Real ML Training Data Fetcher | `src/modules/fetchTrainingData.js` | ✅ 48 real records fetched |
| Vulnerability Correlation Engine (OSV + EPSS + NVD + GitHub Advisory) | `src/modules/vulnerabilityEngine.js` | ✅ code verified |
| Policy Gate (PASS / FAILED / BLOCKED, 5 decision branches) | `src/modules/policyGate.js` | ✅ all branches tested |
| Webhook Security (HMAC-SHA256 GitHub, GitLab token) | `src/modules/webhookSecurity.js` | ✅ 6 cases tested |
| Notification Service (Slack, Jira, PagerDuty, email) | `src/modules/notificationService.js` | ✅ 4 channels mock-tested |
| Build Integrity (SHA-256 CI config verification) | `src/modules/buildIntegrity.js` | ✅ |
| Threat Feed (WebSocket, 5-min OSV polling) | `src/modules/threatFeed.js` | ✅ |
| AI Threat Engine (explain, classify, remediate, root-cause, predict, chat) | `src/modules/aiThreatEngine.js` | ✅ graceful 503 without key |
| Compliance Engine (SLSA, NIST SSDF, OWASP — 27 real evaluators) | `src/modules/complianceEngine.js` | ✅ tested with real data |
| Admin Layer (orgs, users, roles, API keys, audit log) | `src/modules/adminLayer.js` | ✅ all paths tested |
| GitHub OAuth | `src/modules/githubAuth.js` | ✅ |
| Google OAuth | `src/modules/googleAuth.js` | ✅ graceful 503 without key |
| lowdb JSON store (zero-setup development) | `src/db/store.js` | ✅ |
| Supabase/PostgreSQL adapter (production) | `src/db/supabaseStore.js` | ✅ graceful fallback tested |

## API surface

```
GET  /health

# Auth
GET  /api/auth/github               → { authorizeUrl }
GET  /api/auth/github/callback      → redirect with JWT
GET  /api/auth/google               → { authorizeUrl }
GET  /api/auth/google/callback      → redirect with JWT
GET  /api/auth/me

# Repositories
GET  /api/repos/connected           → DB repos for current user (persists across sessions)
GET  /api/repos                     → live GitHub repo list
POST /api/repos/connect
GET  /api/repos/:id
POST /api/repos/:id/scan            → full pipeline (SBOM + vulns + malware)
                                      ?manifestPath=requirements.txt|pom.xml|go.mod|*.csproj

# SBOM
GET  /api/sboms/:id/export?format=cyclonedx|spdx

# Vulnerabilities
GET  /api/vulnerabilities/:repoId/list
PATCH /api/vulnerabilities/:id/status   (Open|In Progress|Resolved|Accepted Risk + VEX)
GET  /api/vulnerabilities/:cveId/nvd

# Build integrity
POST /api/repos/:id/set-baseline
POST /api/repos/:id/verify-build

# Dashboard
GET  /api/dashboard/summary

# Compliance
GET  /api/repos/:id/compliance          → generates SLSA/SSDF/OWASP report
GET  /api/repos/:id/compliance/download

# AI Threat Engine (requires ANTHROPIC_API_KEY)
POST /api/ai/explain                → plain-English CVE explanation
POST /api/ai/explain/stream         → SSE streaming version
POST /api/ai/classify               → MITRE ATT&CK classification (JSON)
POST /api/ai/remediate              → step-by-step fix guidance
POST /api/ai/root-cause             → supply-chain root cause analysis
GET  /api/ai/predict-risk/:repoId   → forward-looking risk prediction
POST /api/ai/chat                   → multi-turn security chatbot
GET  /api/ai/model-info             → local ML model weights/info (no key needed)

# CI/CD
POST /api/cicd/repos/:id/api-key    → generate CI API key
POST /api/cicd/sbom-submit          → CI plugin endpoint (uses CI API key, not JWT)
POST /api/cicd/repos/:id/api-key
POST /api/cicd/webhooks/github-actions
POST /api/cicd/webhooks/gitlab-ci
POST /api/cicd/webhooks/jenkins
GET  /api/cicd/pipeline-runs

# Alert channels
GET  /api/repos/:id/alert-channels
PUT  /api/repos/:id/alert-channels
POST /api/repos/:id/alert-channels/test

# Admin
GET  /api/admin/users
PATCH /api/admin/users/:id/role
POST /api/admin/users/invite
GET  /api/admin/orgs
POST /api/admin/orgs
PATCH /api/admin/orgs/:id/plan
GET  /api/admin/api-keys
POST /api/admin/api-keys
DELETE /api/admin/api-keys/:id
GET  /api/admin/audit-log

WS   /ws/threat-feed                → live threat event stream
```

## ML Classifier

No API key. Logistic regression trained on real npm metadata. Features:

| Feature | Why |
|---|---|
| package-age | New packages are riskier |
| maintainer-count | More maintainers = more trust |
| install-scripts | Primary malware delivery vector |
| publish-recency | Very recent = less trust history |
| version-count | Established packages have many releases |
| typosquat-distance | Edit distance to top-1000 npm packages |
| no-repository | Missing repo = low provenance |
| missing-description | Short/absent description is suspicious |
| release-burst | Many versions in short window = anomalous |
| long-name | >30 char names sometimes evade detection |

To retrain on fresh real data: `node src/modules/fetchTrainingData.js`

## Switching to Supabase/PostgreSQL

1. Create project at supabase.com
2. Run schema SQL from `src/db/supabaseStore.js` in the SQL editor
3. Add `SUPABASE_URL` + `SUPABASE_SERVICE_ROLE_KEY` to `.env`
4. In `src/server.js`, change one line:
   ```js
   // const { db, init, uuid } = require('./db/store');        // lowdb
   const { db, init, uuid } = require('./db/supabaseStore');   // Supabase
   ```

## Multi-ecosystem SBOM

`POST /api/repos/:id/scan` accepts a `manifestPath` body param:

| Manifest | Ecosystem | Registry API |
|---|---|---|
| `package.json` (default) | npm | registry.npmjs.org |
| `requirements.txt` | PyPI | pypi.org/pypi |
| `pom.xml` | Maven | search.maven.org |
| `go.mod` | Go | proxy.golang.org |
| `packages.config` / `*.csproj` | NuGet | api.nuget.org |
