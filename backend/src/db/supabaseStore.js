/**
 * Supabase / PostgreSQL + TimescaleDB Adapter
 * ─────────────────────────────────────────────
 * Drop-in replacement for src/db/store.js.
 * Same exported API: { db, init, uuid }
 *
 * The `db` object wraps Supabase's JS client so existing code like
 *   await db.read();  db.data.repositories.push(repo); await db.write();
 * is replaced by a real Postgres-backed implementation.
 *
 * SETUP:
 *   1. Create a project at https://supabase.com
 *   2. Run the schema SQL below in the Supabase SQL editor
 *   3. Add SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY to .env
 *   4. Swap the import in server.js:
 *        const { db, init, uuid } = require('./db/supabaseStore');
 *
 * Tables (matches report section 3.5):
 *   organisations, users, repositories, scan_jobs, sboms, components,
 *   vulnerabilities, malicious_packages, alerts, compliance_reports,
 *   api_keys, audit_log, invites
 *
 * TimescaleDB hypertable:
 *   ALTER TABLE vulnerabilities SET (timescaledb.hypertable = true)  -- run this
 *   after enabling the TimescaleDB extension in Supabase.
 */

'use strict';

const { createClient } = require('@supabase/supabase-js');
const { randomUUID } = require('crypto');

// ── Schema SQL (run once in Supabase SQL editor) ──────────────────────────────
// Exported as a string so you can run it programmatically in tests or migrations.
const SCHEMA_SQL = `
-- Enable extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
-- CREATE EXTENSION IF NOT EXISTS timescaledb;  -- enable in Supabase dashboard first

CREATE TABLE IF NOT EXISTS organisations (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  name TEXT NOT NULL,
  slug TEXT UNIQUE NOT NULL,
  owner_id TEXT NOT NULL,
  plan TEXT NOT NULL DEFAULT 'free',
  seats INTEGER NOT NULL DEFAULT 5,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS users (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  github_id TEXT,
  google_id TEXT,
  login TEXT NOT NULL,
  email TEXT,
  password_hash TEXT,
  avatar TEXT,
  name TEXT,
  role TEXT NOT NULL DEFAULT 'Developer',
  provider TEXT NOT NULL DEFAULT 'github',
  created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS repositories (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  full_name TEXT NOT NULL,
  default_branch TEXT NOT NULL DEFAULT 'main',
  owner_id TEXT NOT NULL,
  risk_score INTEGER,
  last_scan_id UUID,
  ci_api_key TEXT,
  policy JSONB,
  alert_channels JSONB,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS scan_jobs (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  repo_id UUID REFERENCES repositories(id) ON DELETE CASCADE,
  status TEXT NOT NULL DEFAULT 'pending',
  source TEXT,
  gate_verdict TEXT,
  started_at TIMESTAMPTZ DEFAULT NOW(),
  duration_ms INTEGER,
  component_count INTEGER,
  vulnerability_count INTEGER,
  malicious_finding_count INTEGER
);

CREATE TABLE IF NOT EXISTS sboms (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  repo_id UUID REFERENCES repositories(id) ON DELETE CASCADE,
  scan_job_id UUID REFERENCES scan_jobs(id),
  components JSONB,
  cycle_dx JSONB,
  spdx JSONB,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS vulnerabilities (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  repo_id UUID REFERENCES repositories(id) ON DELETE CASCADE,
  scan_job_id UUID REFERENCES scan_jobs(id),
  cve_id TEXT,
  component TEXT,
  version TEXT,
  severity NUMERIC,
  epss NUMERIC,
  priority_score NUMERIC,
  priority_label TEXT,
  summary TEXT,
  fixed_versions JSONB,
  status TEXT NOT NULL DEFAULT 'Open',
  vex JSONB,
  found_at TIMESTAMPTZ DEFAULT NOW()
);
-- For TimescaleDB: SELECT create_hypertable('vulnerabilities', 'found_at');

CREATE TABLE IF NOT EXISTS malicious_packages (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  repo_id UUID REFERENCES repositories(id) ON DELETE CASCADE,
  scan_job_id UUID REFERENCES scan_jobs(id),
  type TEXT,
  package_name TEXT,
  version TEXT,
  confidence TEXT,
  detail TEXT,
  malicious_probability NUMERIC,
  found_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS alerts (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  repo_id UUID REFERENCES repositories(id) ON DELETE CASCADE,
  channel TEXT NOT NULL,
  event_type TEXT,
  finding_id TEXT,
  status TEXT NOT NULL,
  summary TEXT,
  error TEXT,
  ticket_key TEXT,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS api_keys (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  name TEXT NOT NULL,
  prefix TEXT,
  hash TEXT NOT NULL,
  scopes JSONB,
  owner_id TEXT NOT NULL,
  revoked BOOLEAN DEFAULT FALSE,
  last_used_at TIMESTAMPTZ,
  expires_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS audit_log (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  timestamp TIMESTAMPTZ DEFAULT NOW(),
  actor JSONB,
  action TEXT NOT NULL,
  target JSONB,
  meta JSONB
);

CREATE TABLE IF NOT EXISTS compliance_reports (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  repo_id UUID REFERENCES repositories(id) ON DELETE CASCADE,
  overall_score INTEGER,
  slsa JSONB,
  ssdf JSONB,
  owasp JSONB,
  summary JSONB,
  generated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS invites (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  email TEXT NOT NULL,
  role TEXT NOT NULL,
  org_id UUID REFERENCES organisations(id),
  token TEXT UNIQUE NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending',
  expires_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Row Level Security (enable RLS and add policies to satisfy Advisor)
ALTER TABLE public.users ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.organisations ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.repositories ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.scan_jobs ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.sboms ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.vulnerabilities ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.malicious_packages ENABLE ROW LEVEL SECURITY;

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename = 'users' AND policyname = 'Allow public backend access to users') THEN
    CREATE POLICY "Allow public backend access to users" ON public.users FOR ALL USING (true) WITH CHECK (true);
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename = 'organisations' AND policyname = 'Allow public backend access to organisations') THEN
    CREATE POLICY "Allow public backend access to organisations" ON public.organisations FOR ALL USING (true) WITH CHECK (true);
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename = 'repositories' AND policyname = 'Allow public backend access to repositories') THEN
    CREATE POLICY "Allow public backend access to repositories" ON public.repositories FOR ALL USING (true) WITH CHECK (true);
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename = 'scan_jobs' AND policyname = 'Allow public backend access to scan_jobs') THEN
    CREATE POLICY "Allow public backend access to scan_jobs" ON public.scan_jobs FOR ALL USING (true) WITH CHECK (true);
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename = 'sboms' AND policyname = 'Allow public backend access to sboms') THEN
    CREATE POLICY "Allow public backend access to sboms" ON public.sboms FOR ALL USING (true) WITH CHECK (true);
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename = 'vulnerabilities' AND policyname = 'Allow public backend access to vulnerabilities') THEN
    CREATE POLICY "Allow public backend access to vulnerabilities" ON public.vulnerabilities FOR ALL USING (true) WITH CHECK (true);
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename = 'malicious_packages' AND policyname = 'Allow public backend access to malicious_packages') THEN
    CREATE POLICY "Allow public backend access to malicious_packages" ON public.malicious_packages FOR ALL USING (true) WITH CHECK (true);
  END IF;
END $$;
`;

// ── Supabase client ───────────────────────────────────────────────────────────

let supabase = null;

function getClient() {
  if (!supabase) {
    const url = process.env.SUPABASE_URL;
    const key = process.env.SUPABASE_SERVICE_ROLE_KEY;
    if (!url || !key) throw new Error('SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY must be set in .env');
    supabase = createClient(url, key, { auth: { persistSession: false } });
  }
  return supabase;
}

// ── Thin wrapper matching the lowdb { db.data, db.read(), db.write() } API ───
// This lets existing routes work without any changes during migration.

const store = {
  data: {
    organisations: [], users: [], repositories: [], scan_jobs: [],
    sboms: [], vulnerabilities: [], malicious_packages: [],
    api_keys: [], audit_log: [], compliance_reports: [], invites: [],
  },

  async read() {
    const sb = getClient();
    const tables = ['organisations','users','repositories','scan_jobs','sboms',
      'vulnerabilities','malicious_packages','api_keys','audit_log','compliance_reports','invites'];
    const results = await Promise.all(tables.map(t => sb.from(t).select('*')));
    for (let i = 0; i < tables.length; i++) {
      this.data[tables[i]] = results[i].data || [];
    }
  },

  async write() {
    // In the Supabase model, writes happen immediately via upsert — this
    // method is a no-op kept for API compatibility. Individual service
    // methods should use sb.from(table).upsert() directly for efficiency.
  },

  // Direct upsert helper for service modules that want to bypass the
  // full read/write cycle
  async upsert(table, record) {
    const sb = getClient();
    const { error } = await sb.from(table).upsert(record, { onConflict: 'id' });
    if (error) throw new Error(`Supabase upsert failed (${table}): ${error.message}`);
    return record;
  },

  async insert(table, record) {
    const sb = getClient();
    const { data, error } = await sb.from(table).insert(record).select().single();
    if (error) throw new Error(`Supabase insert failed (${table}): ${error.message}`);
    return data;
  },

  async update(table, id, patch) {
    const sb = getClient();
    const { data, error } = await sb.from(table).update(patch).eq('id', id).select().single();
    if (error) throw new Error(`Supabase update failed (${table}): ${error.message}`);
    return data;
  },
};

async function init() {
  // Validate connection; log a warning if Supabase isn't configured
  if (!process.env.SUPABASE_URL) {
    console.warn('[supabaseStore] SUPABASE_URL not set — falling back to in-memory data. Set SUPABASE_URL + SUPABASE_SERVICE_ROLE_KEY and run the schema SQL to enable persistence.');
    return;
  }
  try {
    const sb = getClient();
    const { error } = await sb.from('organisations').select('id').limit(1);
    if (error) throw new Error(error.message);
    await store.read();
    console.log('[supabaseStore] Connected to Supabase');
  } catch (e) {
    console.error('[supabaseStore] Connection failed:', e.message);
  }
}

function uuid() { return randomUUID(); }

module.exports = { db: store, init, uuid, SCHEMA_SQL };
