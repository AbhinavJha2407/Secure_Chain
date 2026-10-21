/**
 * Webhook signature verification.
 * GitHub signs webhook payloads with HMAC-SHA256 over the raw body, sent as
 * `X-Hub-Signature-256: sha256=<hex>`. This is the exact verification
 * algorithm GitHub documents — testable locally without any external call.
 * https://docs.github.com/en/webhooks/using-webhooks/validating-webhook-deliveries
 */

const crypto = require('crypto');

function verifyGitHubSignature(rawBody, signatureHeader, secret) {
  if (!signatureHeader || !secret || rawBody == null) return false;
  try {
    const bodyBuffer = Buffer.isBuffer(rawBody) ? rawBody : Buffer.from(String(rawBody), 'utf-8');
    const expected = 'sha256=' + crypto.createHmac('sha256', secret).update(bodyBuffer).digest('hex');
    const sigBuf = Buffer.from(signatureHeader);
    const expBuf = Buffer.from(expected);
    if (sigBuf.length !== expBuf.length) return false;
    return crypto.timingSafeEqual(sigBuf, expBuf);
  } catch {
    return false;
  }
}

/**
 * GitLab sends a static secret token in `X-Gitlab-Token`, not an HMAC —
 * verification is a direct (constant-time) comparison against the
 * configured webhook secret.
 */
function verifyGitLabToken(tokenHeader, secret) {
  if (!tokenHeader || !secret) return false;
  try {
    const a = Buffer.from(String(tokenHeader));
    const b = Buffer.from(String(secret));
    if (a.length !== b.length) return false;
    return crypto.timingSafeEqual(a, b);
  } catch {
    return false;
  }
}

/**
 * Jenkins has no built-in webhook signing standard; SecureChain's Jenkins
 * plugin instead authenticates via a per-repo API key passed as a Bearer
 * token (see bin/securechain-cli.js), verified the same way as dashboard
 * API calls.
 */

module.exports = { verifyGitHubSignature, verifyGitLabToken };
