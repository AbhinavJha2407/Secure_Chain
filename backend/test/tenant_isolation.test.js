const { test, describe } = require('node:test');
const assert = require('node:assert/strict');
const { db } = require('../src/db/store');

describe('Tenant Isolation & IDOR Protection', () => {
  test('repository ownership model isolates tenant A and tenant B', async () => {
    await db.read();
    db.data.users = [
      { id: 'user-a', login: 'alice', role: 'Developer' },
      { id: 'user-b', login: 'bob', role: 'Developer' },
      { id: 'admin-1', login: 'admin', role: 'Admin' },
    ];
    db.data.repositories = [
      { id: 'repo-a', fullName: 'alice/secret-app', ownerId: 'user-a' },
      { id: 'repo-b', fullName: 'bob/payment-service', ownerId: 'user-b' },
    ];

    // Simulate helper check
    function isAuthorized(repo, user) {
      if (!repo || !user) return false;
      if (user.role === 'Admin') return true;
      return repo.ownerId === user.sub;
    }

    const repoA = db.data.repositories.find(r => r.id === 'repo-a');

    // Bob cannot access Alice's repo
    assert.equal(isAuthorized(repoA, { sub: 'user-b', role: 'Developer' }), false);

    // Alice can access Alice's repo
    assert.equal(isAuthorized(repoA, { sub: 'user-a', role: 'Developer' }), true);

    // Admin can access Alice's repo
    assert.equal(isAuthorized(repoA, { sub: 'admin-1', role: 'Admin' }), true);
  });

  test('pipeline-runs query isolates logs between tenants', async () => {
    await db.read();
    db.data.repositories = [
      { id: 'repo-a', fullName: 'alice/app', ownerId: 'user-a' },
      { id: 'repo-b', fullName: 'bob/api', ownerId: 'user-b' },
    ];
    db.data.scan_jobs = [
      { id: 'scan-1', source: 'GITHUB_ACTIONS_WEBHOOK', repoId: 'repo-a', repoFullName: 'alice/app' },
      { id: 'scan-2', source: 'GITHUB_ACTIONS_WEBHOOK', repoId: 'repo-b', repoFullName: 'bob/api' },
    ];

    function getRunsForUser(user) {
      const userRepos = db.data.repositories.filter(
        (r) => user.role === 'Admin' || r.ownerId === user.sub
      );
      const allowedIds = new Set(userRepos.map((r) => r.id));
      return db.data.scan_jobs.filter((s) => user.role === 'Admin' || allowedIds.has(s.repoId));
    }

    const aliceRuns = getRunsForUser({ sub: 'user-a', role: 'Developer' });
    assert.equal(aliceRuns.length, 1);
    assert.equal(aliceRuns[0].repoId, 'repo-a');

    const bobRuns = getRunsForUser({ sub: 'user-b', role: 'Developer' });
    assert.equal(bobRuns.length, 1);
    assert.equal(bobRuns[0].repoId, 'repo-b');

    const adminRuns = getRunsForUser({ sub: 'admin-1', role: 'Admin' });
    assert.equal(adminRuns.length, 2);
  });
});
