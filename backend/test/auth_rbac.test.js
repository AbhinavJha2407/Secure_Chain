const { test, describe } = require('node:test');
const assert = require('node:assert/strict');
const { requireAuth, authenticateToken, requireAdmin, requireRole, requireOperationalRole, blockViewers } = require('../src/middleware/auth');
const adminLayer = require('../src/modules/adminLayer');
const { db } = require('../src/db/store');
const jwt = require('jsonwebtoken');

describe('Auth & RBAC Enforcement', () => {
  test('requireAdmin rejects unauthenticated or non-admin requests with 403', () => {
    let statusCode = null;
    let jsonBody = null;
    let nextCalled = false;

    const res = {
      status(code) {
        statusCode = code;
        return {
          json(b) { jsonBody = b; }
        };
      }
    };

    // Case 1: No user
    requireAdmin({ user: null }, res, () => { nextCalled = true; });
    assert.equal(statusCode, 403);
    assert.equal(nextCalled, false);

    // Case 2: Viewer role
    statusCode = null;
    requireAdmin({ user: { role: 'Viewer' } }, res, () => { nextCalled = true; });
    assert.equal(statusCode, 403);
    assert.equal(nextCalled, false);

    // Case 3: Developer role
    statusCode = null;
    requireAdmin({ user: { role: 'Developer' } }, res, () => { nextCalled = true; });
    assert.equal(statusCode, 403);
    assert.equal(nextCalled, false);

    // Case 4: Admin role succeeds
    statusCode = null;
    requireAdmin({ user: { role: 'Admin' } }, res, () => { nextCalled = true; });
    assert.equal(statusCode, null);
    assert.equal(nextCalled, true);

    // Case 5: Lowercase admin succeeds
    nextCalled = false;
    statusCode = null;
    requireAdmin({ user: { role: 'admin' } }, res, () => { nextCalled = true; });
    assert.equal(statusCode, null);
    assert.equal(nextCalled, true);

    // Case 6: Uppercase ADMIN succeeds
    nextCalled = false;
    statusCode = null;
    requireAdmin({ user: { role: 'ADMIN' } }, res, () => { nextCalled = true; });
    assert.equal(statusCode, null);
    assert.equal(nextCalled, true);
  });

  test('requireRole enforces allowed role sets', () => {
    const middleware = requireRole(['SecurityAnalyst', 'DevOpsEngineer']);
    let passed = false;
    let status = null;

    const res = {
      status(code) {
        status = code;
        return { json() {} };
      }
    };

    // Deny viewer
    middleware({ user: { role: 'Viewer' } }, res, () => { passed = true; });
    assert.equal(status, 403);
    assert.equal(passed, false);

    // Allow SecurityAnalyst
    status = null;
    middleware({ user: { role: 'SecurityAnalyst' } }, res, () => { passed = true; });
    assert.equal(passed, true);

    // Admin always allowed
    passed = false;
    middleware({ user: { role: 'Admin' } }, res, () => { passed = true; });
    assert.equal(passed, true);
  });

  test('requireOperationalRole blocks viewer and allows developer and admin', () => {
    let passed = false;
    let status = null;
    let jsonBody = null;

    const res = {
      status(code) {
        status = code;
        return {
          json(b) { jsonBody = b; }
        };
      }
    };

    // Case 1: Viewer blocked with 403
    requireOperationalRole({ user: { role: 'Viewer' } }, res, () => { passed = true; });
    assert.equal(status, 403);
    assert.equal(passed, false);
    assert.match(jsonBody?.error, /viewer/i);

    // Case 2: Lowercase viewer blocked with 403
    status = null;
    passed = false;
    requireOperationalRole({ user: { role: 'viewer' } }, res, () => { passed = true; });
    assert.equal(status, 403);
    assert.equal(passed, false);

    // Case 3: Developer allowed
    status = null;
    passed = false;
    requireOperationalRole({ user: { role: 'Developer' } }, res, () => { passed = true; });
    assert.equal(status, null);
    assert.equal(passed, true);

    // Case 4: Admin allowed
    status = null;
    passed = false;
    requireOperationalRole({ user: { role: 'Admin' } }, res, () => { passed = true; });
    assert.equal(status, null);
    assert.equal(passed, true);

    // Case 5: SecurityAnalyst and DevOpsEngineer allowed
    status = null;
    passed = false;
    requireOperationalRole({ user: { role: 'SecurityAnalyst' } }, res, () => { passed = true; });
    assert.equal(status, null);
    assert.equal(passed, true);
  });

  test('adminLayer.setUserRole prevents non-admin modification and last-admin demotion', async () => {
    await db.read();
    const originalUsers = [...(db.data.users || [])];
    db.data.users.push(
      { id: 'test-admin-1', login: 'superadmin', role: 'Admin' },
      { id: 'test-user-1', login: 'devuser', role: 'Developer' }
    );
    await db.write();

    try {
      // Non-admin attempting modification throws unauthorized
      await assert.rejects(
        async () => {
          await adminLayer.setUserRole('test-user-1', 'Admin', { id: 'test-user-1', login: 'devuser', role: 'Developer' });
        },
        /Unauthorized/
      );

      // Admin modifying developer succeeds
      const updated = await adminLayer.setUserRole('test-user-1', 'SecurityAnalyst', { id: 'test-admin-1', login: 'superadmin', role: 'Admin' });
      assert.equal(updated.role, 'SecurityAnalyst');

      // Attempting to demote the only remaining Admin when adminCount <= 1
      const allAdmins = db.data.users.filter(u => u.role === 'Admin');
      if (allAdmins.length <= 1) {
        await assert.rejects(
          async () => {
            await adminLayer.setUserRole(allAdmins[0].id, 'Developer', { id: 'test-admin-1', login: 'superadmin', role: 'Admin' });
          },
          /Cannot demote the last remaining administrator/
        );
      }
    } finally {
      db.data.users = originalUsers;
      await db.write();
    }
  });

  test('authenticateToken middleware correctly verifies bearer token and rejects missing token', () => {
    process.env.JWT_SECRET = process.env.JWT_SECRET || 'test-secret-key-123';
    const validToken = jwt.sign({ sub: 'user-123', login: 'alice', role: 'developer' }, process.env.JWT_SECRET);

    let status = null;
    let jsonBody = null;
    let nextCalled = false;

    const res = {
      status(code) {
        status = code;
        return { json(b) { jsonBody = b; } };
      }
    };

    // Case 1: Missing token returns 401 Missing bearer token
    authenticateToken({ headers: {} }, res, () => { nextCalled = true; });
    assert.equal(status, 401);
    assert.equal(jsonBody?.error, 'Missing bearer token');
    assert.equal(nextCalled, false);

    // Case 2: Valid Authorization: Bearer <token> passes
    status = null;
    jsonBody = null;
    nextCalled = false;
    const req = { headers: { authorization: `Bearer ${validToken}` } };
    authenticateToken(req, res, () => { nextCalled = true; });
    assert.equal(status, null);
    assert.equal(nextCalled, true);
    assert.equal(req.user.sub, 'user-123');

    // Case 3: Fallback query parameter ?token=<token> passes
    status = null;
    jsonBody = null;
    nextCalled = false;
    const reqQuery = { headers: {}, query: { token: validToken } };
    authenticateToken(reqQuery, res, () => { nextCalled = true; });
    assert.equal(status, null);
    assert.equal(nextCalled, true);
    assert.equal(reqQuery.user.sub, 'user-123');
  });
});
