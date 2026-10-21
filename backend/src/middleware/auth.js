const jwt = require('jsonwebtoken');

function requireAuth(req, res, next) {
  const header = req.headers.authorization || '';
  let token = header.startsWith('Bearer ') ? header.slice(7) : null;
  if (!token && req.query?.token) {
    token = String(req.query.token).trim();
  }
  if (!token) return res.status(401).json({ error: 'Missing bearer token' });
  try {
    req.user = jwt.verify(token, process.env.JWT_SECRET);
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
}

const authenticateToken = requireAuth;

function requireAdmin(req, res, next) {
  let userRole = req.user?.role?.toLowerCase();
  if (!userRole && req.user?.sub) {
    try {
      const { db } = require('../db/store');
      const u = db?.data?.users?.find(
        (usr) => usr.id === req.user.sub || String(usr.githubId) === req.user.sub || usr.googleId === req.user.sub || (req.user.email && usr.email && usr.email.toLowerCase() === req.user.email.toLowerCase())
      );
      if (u?.role) {
        userRole = u.role.toLowerCase();
        req.user.role = userRole;
      }
    } catch {
      // non-blocking
    }
  }
  if (userRole !== 'admin') {
    return res.status(403).json({ error: 'Admin role required' });
  }
  next();
}

function requireRole(allowedRoles = []) {
  const normalizedAllowed = allowedRoles.map((r) => r.toLowerCase());
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({ error: 'Authentication required' });
    }
    let userRole = req.user.role?.toLowerCase();
    if (!userRole && req.user.sub) {
      try {
        const { db } = require('../db/store');
        const u = db?.data?.users?.find(
          (usr) => usr.id === req.user.sub || String(usr.githubId) === req.user.sub || usr.googleId === req.user.sub || (req.user.email && usr.email && usr.email.toLowerCase() === req.user.email.toLowerCase())
        );
        if (u?.role) {
          userRole = u.role.toLowerCase();
          req.user.role = userRole;
        }
      } catch {
        // non-blocking
      }
    }
    if (userRole === 'admin') {
      return next(); // Admins have super-user permission across all roles
    }
    if (!normalizedAllowed.includes(userRole)) {
      return res.status(403).json({
        error: `Access denied: Requires one of [${allowedRoles.join(', ')}]`,
      });
    }
    next();
  };
}

const checkRole = requireRole;

function requireOperationalRole(req, res, next) {
  const userRole = req.user?.role?.toLowerCase();
  if (userRole === 'viewer') {
    return res.status(403).json({
      error: 'Access denied: Read-only viewer role cannot perform this action',
    });
  }
  return requireRole(['admin', 'developer', 'securityanalyst', 'devopsengineer'])(req, res, next);
}

function blockViewers(req, res, next) {
  const userRole = req.user?.role?.toLowerCase();
  if (userRole === 'viewer') {
    return res.status(403).json({ error: 'Access denied: Read-only viewer role cannot perform write actions' });
  }
  next();
}

function isRepoAuthorized(repo, user, db) {
  if (!repo || !user) return false;
  if (user.role?.toLowerCase() === 'admin') return true;
  if (repo.ownerId === user.sub) return true;
  const currentUser = db?.data?.users?.find(
    (u) => String(u.githubId) === user.sub || u.googleId === user.sub || u.id === user.sub
  );
  if (currentUser?.orgId) {
    const ownerUser = db?.data?.users?.find(
      (u) => String(u.githubId) === repo.ownerId || u.googleId === repo.ownerId || u.id === repo.ownerId
    );
    if (ownerUser && ownerUser.orgId === currentUser.orgId) return true;
  }
  return false;
}

function getAllowedRepoIds(user, db) {
  if (!user) return new Set();
  if (user.role?.toLowerCase() === 'admin') {
    return new Set((db?.data?.repositories || []).map((r) => r.id));
  }
  const currentUser = db?.data?.users?.find(
    (u) => String(u.githubId) === user.sub || u.googleId === user.sub || u.id === user.sub
  );
  const allowedOwnerIds = new Set([user.sub]);
  if (currentUser?.orgId) {
    (db?.data?.users || [])
      .filter((u) => u.orgId === currentUser.orgId)
      .forEach((u) => {
        if (u.id) allowedOwnerIds.add(u.id);
        if (u.githubId) allowedOwnerIds.add(String(u.githubId));
        if (u.googleId) allowedOwnerIds.add(u.googleId);
      });
  }
  const allowedRepos = (db?.data?.repositories || []).filter((r) => allowedOwnerIds.has(r.ownerId));
  return new Set(allowedRepos.map((r) => r.id));
}

module.exports = {
  requireAuth,
  authenticateToken,
  requireAdmin,
  requireRole,
  checkRole,
  requireOperationalRole,
  blockViewers,
  isRepoAuthorized,
  getAllowedRepoIds,
};
