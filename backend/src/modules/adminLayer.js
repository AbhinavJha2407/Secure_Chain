/**
 * Admin Layer
 * Organisation management, user role assignment, subscription plans,
 * API key lifecycle (create/list/revoke), and an append-only audit log.
 *
 * Every mutating action writes an audit event — the log is the source of
 * truth for "who did what when" required by NIST SSDF DS.1 and SLSA L2+.
 */

const { db, uuid } = require('../db/store');
const crypto = require('crypto');

// ── Audit log ─────────────────────────────────────────────────────────────────

async function writeAuditEvent(actor, action, target, meta = {}) {
  await db.read();
  db.data.audit_log = db.data.audit_log || [];
  db.data.audit_log.push({
    id: uuid(),
    timestamp: new Date().toISOString(),
    actor,   // { id, login }
    action,  // e.g. 'REPO_CONNECTED', 'SCAN_TRIGGERED', 'KEY_REVOKED'
    target,  // e.g. { type: 'repository', id: '...' }
    meta,
  });
  await db.write();
}

// ── Organisation management ───────────────────────────────────────────────────

async function createOrganisation(name, ownerId) {
  await db.read();
  const existing = db.data.organisations.find(o => o.slug === name.toLowerCase().replace(/\s+/g, '-'));
  if (existing) throw new Error(`Organisation "${name}" already exists`);

  const org = {
    id: uuid(),
    name,
    slug: name.toLowerCase().replace(/\s+/g, '-'),
    ownerId,
    plan: 'free',
    seats: 5,
    createdAt: new Date().toISOString(),
  };
  db.data.organisations.push(org);
  await db.write();
  return org;
}

async function getOrganisation(orgId) {
  await db.read();
  return db.data.organisations.find(o => o.id === orgId) || null;
}

async function listOrganisations() {
  await db.read();
  return db.data.organisations;
}

async function updateOrganisationPlan(orgId, plan) {
  const validPlans = ['free', 'team', 'enterprise'];
  if (!validPlans.includes(plan)) throw new Error(`Plan must be one of: ${validPlans.join(', ')}`);

  await db.read();
  const org = db.data.organisations.find(o => o.id === orgId);
  if (!org) throw new Error('Organisation not found');

  const seatsByPlan = { free: 5, team: 25, enterprise: Infinity };
  org.plan = plan;
  org.seats = seatsByPlan[plan];
  await db.write();
  return org;
}

// ── User role management ──────────────────────────────────────────────────────

const VALID_ROLES = ['Admin', 'Developer', 'SecurityAnalyst', 'DevOpsEngineer', 'Viewer'];

async function setUserRole(targetUserId, role, actorUser) {
  if (!actorUser || (actorUser.role !== 'Admin' && actorUser.role !== 'admin')) {
    throw new Error('Unauthorized: Only administrators can modify user roles');
  }
  if (!VALID_ROLES.includes(role)) throw new Error(`Role must be one of: ${VALID_ROLES.join(', ')}`);

  await db.read();
  const user = db.data.users.find(u => u.id === targetUserId);
  if (!user) throw new Error('User not found');

  const previousRole = user.role;
  if (previousRole === 'Admin' && role !== 'Admin') {
    const adminCount = db.data.users.filter(u => u.role === 'Admin').length;
    if (adminCount <= 1) {
      throw new Error('Cannot demote the last remaining administrator');
    }
  }
  user.role = role;
  await db.write();

  await writeAuditEvent(
    { id: actorUser.id, login: actorUser.login },
    'USER_ROLE_CHANGED',
    { type: 'user', id: targetUserId },
    { previousRole, newRole: role }
  );

  return user;
}

async function listUsers() {
  await db.read();
  return db.data.users.map(u => {
    const { githubAccessToken, ...safe } = u;
    return safe;
  });
}

async function inviteUser(email, role, orgId, actorUser) {
  if (!VALID_ROLES.includes(role)) throw new Error(`Role must be one of: ${VALID_ROLES.join(', ')}`);

  await db.read();
  const inviteToken = crypto.randomBytes(24).toString('hex');
  const invite = {
    id: uuid(),
    email,
    role,
    orgId,
    token: inviteToken,
    expiresAt: new Date(Date.now() + 72 * 60 * 60 * 1000).toISOString(), // 72h
    createdAt: new Date().toISOString(),
    status: 'pending',
  };
  db.data.invites = db.data.invites || [];
  db.data.invites.push(invite);
  await db.write();

  await writeAuditEvent(
    { id: actorUser.sub, login: actorUser.login },
    'USER_INVITED',
    { type: 'invite', id: invite.id },
    { email, role, orgId }
  );

  return { invite: { ...invite, token: undefined }, inviteLink: `/invite/${inviteToken}` };
}

// ── API key management ────────────────────────────────────────────────────────

/**
 * Generates a new platform-level API key (distinct from the per-repo CI keys
 * in cicd.js — these are for accessing the REST API programmatically from
 * external tools, dashboards, or scripts).
 */
async function createApiKey(name, scopes, ownerId, actorUser) {
  const validScopes = ['read:repos', 'write:scans', 'read:vulns', 'write:alerts', 'admin'];
  const invalidScopes = scopes.filter(s => !validScopes.includes(s));
  if (invalidScopes.length) throw new Error(`Invalid scopes: ${invalidScopes.join(', ')}. Valid: ${validScopes.join(', ')}`);

  const raw = `sk_live_${crypto.randomBytes(28).toString('hex')}`;
  const hashed = crypto.createHash('sha256').update(raw).digest('hex');

  await db.read();
  db.data.api_keys = db.data.api_keys || [];
  const keyRecord = {
    id: uuid(),
    name,
    prefix: raw.slice(0, 14) + '…', // safe to display
    hash: hashed,
    scopes,
    ownerId,
    createdAt: new Date().toISOString(),
    lastUsedAt: null,
    expiresAt: null, // null = never
    revoked: false,
  };
  db.data.api_keys.push(keyRecord);
  await db.write();

  await writeAuditEvent(
    { id: actorUser.sub, login: actorUser.login },
    'API_KEY_CREATED',
    { type: 'api_key', id: keyRecord.id },
    { name, scopes }
  );

  // Return raw key ONLY on creation — never stored in plaintext, never returned again
  return { ...keyRecord, raw };
}

async function listApiKeys(ownerId) {
  await db.read();
  return (db.data.api_keys || [])
    .filter(k => k.ownerId === ownerId && !k.revoked)
    .map(({ hash, raw, ...safe }) => safe);
}

async function revokeApiKey(keyId, actorUser) {
  await db.read();
  const key = (db.data.api_keys || []).find(k => k.id === keyId);
  if (!key) throw new Error('API key not found');

  key.revoked = true;
  key.revokedAt = new Date().toISOString();
  await db.write();

  await writeAuditEvent(
    { id: actorUser.sub, login: actorUser.login },
    'API_KEY_REVOKED',
    { type: 'api_key', id: keyId },
    { name: key.name }
  );

  return { revoked: true, id: keyId };
}

/**
 * Verifies a platform API key (used as middleware in api.js for machine-to-
 * machine calls, as an alternative to the human-session JWT).
 */
async function verifyApiKey(raw) {
  if (!raw) return null;
  const hashed = crypto.createHash('sha256').update(raw).digest('hex');
  await db.read();
  const key = (db.data.api_keys || []).find(k => k.hash === hashed && !k.revoked);
  if (!key) return null;
  if (key.expiresAt && new Date(key.expiresAt) < new Date()) return null;

  // Update last-used timestamp (non-blocking)
  key.lastUsedAt = new Date().toISOString();
  db.write().catch(() => {});

  return key;
}

// ── Audit log queries ─────────────────────────────────────────────────────────

async function getAuditLog({ limit = 50, action, targetId, actorId } = {}) {
  await db.read();
  let log = db.data.audit_log || [];

  if (action) log = log.filter(e => e.action === action);
  if (targetId) log = log.filter(e => e.target?.id === targetId);
  if (actorId) log = log.filter(e => e.actor?.id === actorId);

  return log
    .sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp))
    .slice(0, limit);
}

module.exports = {
  writeAuditEvent,
  createOrganisation,
  getOrganisation,
  listOrganisations,
  updateOrganisationPlan,
  setUserRole,
  listUsers,
  inviteUser,
  createApiKey,
  listApiKeys,
  revokeApiKey,
  verifyApiKey,
  getAuditLog,
  VALID_ROLES,
};
