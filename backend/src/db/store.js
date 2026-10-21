/**
 * SecureChain Unified Datastore (Supabase + local lowdb fallback)
 * ────────────────────────────────────────────────────────────────
 * Supports both:
 * 1. Cloud-native Supabase PostgreSQL database (configured via SUPABASE_URL + SUPABASE_SERVICE_ROLE_KEY)
 * 2. Local JSON datastore (lowdb) fallback for local offline development.
 *
 * Provides instant persistence, bidirectional syncing, and direct table upserts.
 */

'use strict';

const { Low } = require('lowdb');
const { JSONFile } = require('lowdb/node');
const path = require('path');
const fs = require('fs');
const { randomUUID } = require('crypto');
const { createClient } = require('@supabase/supabase-js');
const { SCHEMA_SQL } = require('./supabaseStore');

const defaultDbPath = path.join(__dirname, 'securechain.db.json');
const file = process.env.DATA_PATH || process.env.DB_FILE || defaultDbPath;
try {
  fs.mkdirSync(path.dirname(file), { recursive: true });
} catch {
  // directory already exists or read-only
}
const adapter = new JSONFile(file);
const defaultData = {
  organisations: [],
  users: [],
  repositories: [],
  scan_jobs: [],
  sboms: [],
  vulnerabilities: [],
  malicious_packages: [],
  alerts: [],
  compliance_reports: [],
  api_keys: [],
  audit_log: [],
  team_requests: [],
};

const lowDb = new Low(adapter, defaultData);

let writeQueue = Promise.resolve();

let supabaseClient = null;
let supabaseConnected = false;

function getSupabase() {
  if (supabaseClient) return supabaseClient;
  const url = process.env.SUPABASE_URL?.trim();
  const key = (process.env.SUPABASE_SERVICE_ROLE_KEY || process.env.SUPABASE_ANON_KEY)?.trim();
  if (url && key) {
    try {
      supabaseClient = createClient(url, key, { auth: { persistSession: false } });
      return supabaseClient;
    } catch (e) {
      console.warn('[db] Supabase client init error:', e.message);
    }
  }
  return null;
}

// Convert user object to Supabase users table schema
function formatUserForSupabase(user) {
  return {
    id: user.id,
    github_id: user.githubId ? String(user.githubId) : null,
    google_id: user.googleId ? String(user.googleId) : null,
    login: user.login || (user.email ? user.email.split('@')[0] : 'user'),
    email: user.email || null,
    password_hash: user.passwordHash || null,
    avatar: user.avatar || null,
    name: user.name || null,
    role: user.role || 'Developer',
    provider: user.provider || 'email',
    created_at: user.createdAt || new Date().toISOString(),
  };
}

// Convert Supabase users row to in-memory user object
function formatUserFromSupabase(row) {
  return {
    id: row.id,
    githubId: row.github_id ? (isNaN(row.github_id) ? row.github_id : Number(row.github_id)) : null,
    googleId: row.google_id || null,
    login: row.login,
    email: row.email,
    passwordHash: row.password_hash,
    avatar: row.avatar,
    name: row.name,
    role: row.role || 'Developer',
    provider: row.provider || 'email',
    createdAt: row.created_at,
  };
}

async function syncFromSupabase() {
  const sb = getSupabase();
  if (!sb) return;

  try {
    const { data: users, error: userErr } = await sb.from('users').select('*');
    if (!userErr && Array.isArray(users)) {
      const existingUserMap = new Map((lowDb.data.users || []).map((u) => [u.id, u]));
      for (const row of users) {
        existingUserMap.set(row.id, formatUserFromSupabase(row));
      }
      lowDb.data.users = Array.from(existingUserMap.values());
    }

    const { data: repos, error: repoErr } = await sb.from('repositories').select('*');
    if (!repoErr && Array.isArray(repos)) {
      const existingRepoMap = new Map((lowDb.data.repositories || []).map((r) => [r.id, r]));
      for (const row of repos) {
        existingRepoMap.set(row.id, {
          id: row.id,
          fullName: row.full_name,
          defaultBranch: row.default_branch,
          ownerId: row.owner_id,
          riskScore: row.risk_score,
          lastScanId: row.last_scan_id,
          policy: row.policy,
          alertChannels: row.alert_channels,
          createdAt: row.created_at,
        });
      }
      lowDb.data.repositories = Array.from(existingRepoMap.values());
    }

    supabaseConnected = true;
  } catch (err) {
    console.warn('[db] Sync from Supabase encountered issue:', err.message);
  }
}

async function saveUser(user) {
  await db.read();
  const existingIdx = db.data.users.findIndex((u) => u.id === user.id || (user.email && u.email && u.email.toLowerCase() === user.email.toLowerCase()));
  if (existingIdx >= 0) {
    db.data.users[existingIdx] = { ...db.data.users[existingIdx], ...user };
  } else {
    db.data.users.push(user);
  }
  await db.write();

  const sb = getSupabase();
  if (sb) {
    try {
      const row = formatUserForSupabase(user);
      const { error } = await sb.from('users').upsert(row, { onConflict: 'id' });
      if (error) console.warn('[db] Supabase upsert user error:', error.message);
      else supabaseConnected = true;
    } catch (e) {
      console.warn('[db] Supabase user write exception:', e.message);
    }
  }
  return user;
}

// Wrap db to provide consistent lowdb API with Supabase persistence
const db = {
  get data() {
    return lowDb.data;
  },
  set data(val) {
    lowDb.data = val;
  },
  async read() {
    await lowDb.read();
    lowDb.data ||= defaultData;
    for (const key of Object.keys(defaultData)) {
      if (!lowDb.data[key]) lowDb.data[key] = [];
    }
  },
  async write() {
    // Serialize local file writes to prevent race conditions & lost updates
    writeQueue = writeQueue.then(async () => {
      await lowDb.write();
    }).catch((err) => {
      console.error('[db] Error persisting database file:', err.message);
    });
    await writeQueue;

    // Asynchronously sync entities to Supabase if configured
    const sb = getSupabase();
    if (sb) {
      try {
        if (Array.isArray(lowDb.data.users) && lowDb.data.users.length > 0) {
          const userMap = new Map();
          for (const u of lowDb.data.users) {
            if (u.id) userMap.set(u.id, formatUserForSupabase(u));
          }
          const userRows = Array.from(userMap.values());
          sb.from('users').upsert(userRows, { onConflict: 'id' }).catch(() => {});
        }

        if (Array.isArray(lowDb.data.repositories) && lowDb.data.repositories.length > 0) {
          const repoRows = lowDb.data.repositories.map(r => ({
            id: r.id,
            full_name: r.fullName,
            default_branch: r.defaultBranch || 'main',
            owner_id: r.ownerId,
            risk_score: r.riskScore,
            last_scan_id: r.lastScanId,
            policy: r.policy,
            alert_channels: r.alertChannels,
            created_at: r.createdAt || new Date().toISOString(),
          }));
          sb.from('repositories').upsert(repoRows, { onConflict: 'id' }).catch(() => {});
        }
      } catch {
        // non-blocking
      }
    }
  },
  get supabase() {
    return getSupabase();
  },
  isSupabaseConnected() {
    return supabaseConnected || !!getSupabase();
  },
  saveUser,
  SCHEMA_SQL,
};

async function init() {
  await db.read();
  if (Array.isArray(lowDb.data.users)) {
    lowDb.data.users.forEach((u) => {
      if (u.role && u.role.toLowerCase() === 'admin') {
        u.role = 'admin';
      }
    });
  }
  await db.write();

  const sb = getSupabase();
  if (sb) {
    console.log('[store] ⚡ Connecting to Supabase at:', process.env.SUPABASE_URL);
    try {
      await syncFromSupabase();
      console.log(`[store] ✅ Connected to Supabase. Loaded ${db.data.users.length} users, ${db.data.repositories.length} repos.`);
    } catch (e) {
      console.warn('[store] ⚠️ Supabase connection warning (continuing with local cache):', e.message);
    }
  } else {
    console.log('[store] ℹ️ Supabase credentials not set in .env — using local JSON persistence (lowdb).');
  }
}

function uuid() {
  return randomUUID();
}

module.exports = { db, init, uuid, saveUser, SCHEMA_SQL };
