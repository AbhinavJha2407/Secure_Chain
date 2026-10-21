/**
 * CI/CD Build Integrity Module
 * Verifies CI config file hashes against an approved baseline (report 3.2.4).
 */

const crypto = require('crypto');

function sha256(content) {
  return crypto.createHash('sha256').update(content, 'utf-8').digest('hex');
}

/**
 * Compares the current CI config content's hash against a stored baseline
 * hash. Returns a verdict object, never throws.
 */
function verifyBuildIntegrity(currentContent, baselineHash) {
  if (!currentContent || !baselineHash) {
    return {
      match: false,
      currentHash: null,
      baselineHash: baselineHash || null,
      verdict: 'MISMATCH',
      detail: 'Missing build configuration content or approved baseline hash',
    };
  }

  try {
    const currentHash = sha256(currentContent);
    const bufA = Buffer.from(currentHash);
    const bufB = Buffer.from(String(baselineHash).trim());
    const match = bufA.length === bufB.length && crypto.timingSafeEqual(bufA, bufB);

    return {
      match,
      currentHash,
      baselineHash,
      verdict: match ? 'VERIFIED' : 'MISMATCH',
      detail: match
        ? 'CI configuration matches approved baseline'
        : 'CI configuration hash differs from approved baseline — possible tampering',
    };
  } catch (err) {
    return {
      match: false,
      currentHash: null,
      baselineHash,
      verdict: 'MISMATCH',
      detail: `Verification error: ${err.message}`,
    };
  }
}

function setBaseline(content) {
  return sha256(content);
}

module.exports = { sha256, verifyBuildIntegrity, setBaseline };
