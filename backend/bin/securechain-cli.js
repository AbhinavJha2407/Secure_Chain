#!/usr/bin/env node
/**
 * SecureChain CI CLI
 * The actual binary CI pipelines run post-`npm install`. Reads the
 * project's package.json, optionally hashes the CI config file for build
 * integrity verification, POSTs both to SecureChain's /api/cicd/sbom-submit
 * endpoint, prints a human-readable verdict, and exits non-zero if the
 * Policy Gate did not PASS — which is what actually fails a CI job.
 *
 * Usage:
 *   securechain-scan \
 *     --api-url https://securechain.example.com \
 *     --api-key $SECURECHAIN_API_KEY \
 *     [--manifest ./package.json] \
 *     [--ci-config .github/workflows/ci.yml] \
 *     [--ci-baseline-hash <sha256>]
 *
 * Env vars (alternative to flags): SECURECHAIN_API_URL, SECURECHAIN_API_KEY
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const https = require('https');
const http = require('http');

function parseArgs(argv) {
  const args = {};
  for (let i = 0; i < argv.length; i++) {
    if (argv[i].startsWith('--')) {
      const key = argv[i].slice(2);
      const val = argv[i + 1] && !argv[i + 1].startsWith('--') ? argv[++i] : true;
      args[key] = val;
    }
  }
  return args;
}

function postJson(urlStr, body, headers) {
  return new Promise((resolve, reject) => {
    const url = new URL(urlStr);
    const lib = url.protocol === 'https:' ? https : http;
    const data = JSON.stringify(body);
    const req = lib.request(
      url,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(data), ...headers },
      },
      (res) => {
        let raw = '';
        res.on('data', (c) => (raw += c));
        res.on('end', () => {
          try {
            resolve({ status: res.statusCode, body: JSON.parse(raw) });
          } catch (e) {
            resolve({ status: res.statusCode, body: raw });
          }
        });
      }
    );
    req.on('error', reject);
    req.write(data);
    req.end();
  });
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const apiUrl = args['api-url'] || process.env.SECURECHAIN_API_URL;
  const apiKey = args['api-key'] || process.env.SECURECHAIN_API_KEY;
  const manifestPath = args['manifest'] || path.join(process.cwd(), 'package.json');
  const ciConfigPath = args['ci-config'];
  const ciBaselineHash = args['ci-baseline-hash'];

  if (!apiUrl || !apiKey) {
    console.error('[SecureChain] ERROR: --api-url and --api-key (or SECURECHAIN_API_URL / SECURECHAIN_API_KEY) are required');
    process.exit(2);
  }
  if (!fs.existsSync(manifestPath)) {
    console.error(`[SecureChain] ERROR: manifest not found at ${manifestPath}`);
    process.exit(2);
  }

  const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf-8'));
  const payload = { manifest };

  if (ciConfigPath && fs.existsSync(ciConfigPath)) {
    const content = fs.readFileSync(ciConfigPath, 'utf-8');
    payload.ciConfigContent = content;
    payload.ciConfigBaselineHash = ciBaselineHash || crypto.createHash('sha256').update(content, 'utf-8').digest('hex');
  }

  console.log(`[SecureChain] Submitting ${manifest.name || 'project'} (${Object.keys(manifest.dependencies || {}).length} direct deps) to ${apiUrl}...`);

  let result;
  try {
    result = await postJson(`${apiUrl.replace(/\/$/, '')}/api/cicd/sbom-submit`, payload, { Authorization: `Bearer ${apiKey}` });
  } catch (err) {
    console.error(`[SecureChain] ERROR: failed to reach SecureChain API: ${err.message}`);
    process.exit(2);
  }

  if (result.status >= 400) {
    console.error(`[SecureChain] ERROR: API returned ${result.status}:`, result.body);
    process.exit(2);
  }

  const { verdict, reasons, summary } = result.body;
  console.log('');
  console.log(`[SecureChain] Components scanned : ${summary.components}`);
  console.log(`[SecureChain] Vulnerabilities     : ${summary.vulnerabilities} (P0: ${summary.p0Count})`);
  console.log(`[SecureChain] Malicious packages  : ${summary.maliciousPackages}`);
  console.log(`[SecureChain] VERDICT             : ${verdict}`);
  if (reasons && reasons.length) {
    console.log('[SecureChain] Reasons:');
    for (const r of reasons) console.log(`  - [${r.type}] ${r.detail}`);
  }
  console.log('');

  if (verdict === 'PASS') {
    console.log('[SecureChain] ✅ Security gate passed.');
    process.exit(0);
  } else {
    console.error(`[SecureChain] ❌ Security gate ${verdict.toLowerCase()} the build.`);
    process.exit(1);
  }
}

main();
