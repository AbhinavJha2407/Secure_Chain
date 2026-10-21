const { test, describe } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('crypto');
const { verifyGitHubSignature, verifyGitLabToken } = require('../src/modules/webhookSecurity');

describe('Webhook Signature & Security Verification', () => {
  const secret = 'super-secret-ci-webhook-key-12345';
  const payload = JSON.stringify({ action: 'completed', workflow_run: { id: 98765, conclusion: 'success' } });
  const rawBody = Buffer.from(payload, 'utf-8');

  test('accepts valid GitHub HMAC-SHA256 signature', () => {
    const validHmac = 'sha256=' + crypto.createHmac('sha256', secret).update(rawBody).digest('hex');
    const result = verifyGitHubSignature(rawBody, validHmac, secret);
    assert.equal(result, true);
  });

  test('rejects tampered body or invalid signature', () => {
    const validHmac = 'sha256=' + crypto.createHmac('sha256', secret).update(rawBody).digest('hex');
    const tamperedBody = Buffer.from(JSON.stringify({ action: 'tampered' }), 'utf-8');

    // Tampered body with original signature
    assert.equal(verifyGitHubSignature(tamperedBody, validHmac, secret), false);

    // Wrong signature header
    assert.equal(verifyGitHubSignature(rawBody, 'sha256=badbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadb', secret), false);

    // Wrong secret
    assert.equal(verifyGitHubSignature(rawBody, validHmac, 'wrong-secret'), false);
  });

  test('rejects missing signature or missing secret safely without throwing', () => {
    assert.equal(verifyGitHubSignature(rawBody, null, secret), false);
    assert.equal(verifyGitHubSignature(rawBody, '', secret), false);
    assert.equal(verifyGitHubSignature(rawBody, 'sha256=123', null), false);
    assert.equal(verifyGitHubSignature(null, 'sha256=123', secret), false);
    assert.equal(verifyGitHubSignature(undefined, undefined, undefined), false);
  });

  test('validates GitLab token with constant time comparison', () => {
    assert.equal(verifyGitLabToken('token-abc', 'token-abc'), true);
    assert.equal(verifyGitLabToken('token-abc', 'wrong-token'), false);
    assert.equal(verifyGitLabToken(null, 'token-abc'), false);
    assert.equal(verifyGitLabToken('token-abc', null), false);
  });
});
