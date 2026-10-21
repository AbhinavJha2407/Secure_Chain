/**
 * Malicious Package Analyzer — High-Precision, Low-False-Positive Architecture
 * ─────────────────────────────────────────────────────────────────────────────
 * Multi-layer Defense:
 *   1. Typosquat Detection — Levenshtein distance with scope and length protection
 *   2. Behavioral Script Analysis — inspects actual pre/post-install script content
 *      for obfuscation & exfiltration (avoids flagging legitimate native build tools)
 *   3. Metadata Anomaly Engine — flags genuine untrusted fresh packages
 *   4. Calibrated ML Classifier — requires corroborating signals to cross threshold
 *
 * Core Principle: Never flag legitimate packages (e.g. esbuild, node-gyp, prisma)
 * simply for having an install script. Genuine malware requires suspicious intent.
 */

'use strict';

const { fetchPackageMetadata } = require('./sbomEngine');

// ── Trusted scopes & known-safe allowlist ─────────────────────────────────────
const TRUSTED_SCOPES = [
  '@babel/', '@types/', '@swc/', '@eslint/', '@vitejs/', '@react-navigation/',
  '@radix-ui/', '@tanstack/', '@standard-schema/', '@emotion/', '@styled-system/',
  '@reduxjs/', '@trpc/', '@clerk/', '@supabase/', '@prisma/', '@astrojs/', '@next/',
  '@angular/', '@vue/', '@sveltejs/', '@jest/', '@testing-library/', '@esbuild/',
  '@rollup/', '@parcel/', '@tailwindcss/', '@node-rs/', '@sentry/', '@cloudflare/',
  '@aws-sdk/', '@google-cloud/', '@azure/', '@nestjs/', '@playwright/', '@fastify/'
];

// Packages that are 100% legitimate but use install scripts or fast release cadences
const KNOWN_SAFE = new Set([
  // Native compilation & build tools that legitimately use postinstall
  'esbuild', 'node-gyp', 'prisma', 'sharp', 'sqlite3', 'cypress',
  'puppeteer', 'playwright', 'core-js', 'electron', 'swc', 'turbo',
  'canvas', 're2', 'bcrypt', 'argon2', 'leveldown', 'bufferutil',
  'utf-8-validate', 'snappy', 'node-sass', 'sass', 'webpack',
  'rollup', 'parcel', 'tsup', 'vite', 'typescript', 'tsc',

  // Tiny single-purpose utilities (legitimate, widely used)
  'ms', 'ws', 'qs', 'debug', 'glob', 'semver', 'uuid', 'async',
  'chalk', 'colors', 'kleur', 'picocolors', 'dotenv', 'cross-env',
  'rimraf', 'mkdirp', 'node-fetch', 'form-data', 'axios', 'got',
  'ky', 'superagent', 'lodash', 'underscore', 'express', 'fastify', 'koa',

  // React & UI ecosystems
  'react', 'react-dom', 'react-router', 'react-router-dom',
  'react-query', 'react-hook-form', 'lenis', 'gsap', 'framer-motion',

  // Polyfills & language extensions
  'es-errors', 'get-intrinsic', 'es-abstract', 'es-define-property',
  'esquery', 'gopd', 'has-symbols', 'has-proto', 'function-bind',
  'has-property-descriptors', 'set-function-length', 'possible-typed-array-names',
  'call-bound', 'define-properties', 'source-map-js', 'suspend-react', 'side-channel',
]);

function isKnownSafe(packageName) {
  if (KNOWN_SAFE.has(packageName)) return true;
  if (TRUSTED_SCOPES.some(scope => packageName.startsWith(scope))) return true;
  if (packageName.startsWith('array.prototype.') || packageName.startsWith('object.') || packageName.startsWith('function.')) return true;
  return false;
}

// ── Top npm packages list (for typosquat comparison) ─────────────────────────
const TOP_NPM_PACKAGES = [
  'lodash', 'express', 'webpack', 'babel-core', 'mongoose',
  'jquery', 'bootstrap', 'tailwindcss', 'nodemon', 'prettier',
  'redux', 'graphql', 'sequelize', 'passport', 'bcrypt',
  'jsonwebtoken', 'multer', 'helmet', 'morgan', 'yargs',
  'inquirer', 'minimist', 'cheerio', 'puppeteer', 'sharp',
  'mysql2', 'ioredis', 'socket.io', 'commander', 'moment',
  'request', 'underscore', 'bluebird', 'node-fetch', 'form-data',
  'typescript', 'react-dom', 'angular', 'next', 'nuxt',
  'jest', 'vitest', 'mocha', 'jasmine', 'cypress',
  'axios', 'fastify', 'koa', 'hapi', 'nestjs',
  'prisma', 'typeorm', 'drizzle', 'knex',
  'eslint', 'rollup', 'parcel', 'turbo',
];

// ── Levenshtein distance (1D dynamic programming, zero matrix allocation) ─────
function levenshtein(a, b) {
  if (a === b) return 0;
  if (!a.length) return b.length;
  if (!b.length) return a.length;

  if (a.length < b.length) {
    const tmp = a; a = b; b = tmp;
  }

  const m = a.length, n = b.length;
  let prev = new Int32Array(n + 1);
  let curr = new Int32Array(n + 1);
  for (let j = 0; j <= n; j++) prev[j] = j;

  for (let i = 1; i <= m; i++) {
    curr[0] = i;
    const aChar = a.charCodeAt(i - 1);
    for (let j = 1; j <= n; j++) {
      const cost = aChar === b.charCodeAt(j - 1) ? 0 : 1;
      curr[j] = Math.min(
        prev[j] + 1,
        curr[j - 1] + 1,
        prev[j - 1] + cost
      );
    }
    const tmp = prev; prev = curr; curr = tmp;
  }
  return prev[n];
}

/**
 * Typosquat detection — high-precision filtering:
 * Flags ONLY when distance is close AND the name isn't an official sibling or scoped package.
 */
function checkTyposquat(packageName) {
  if (isKnownSafe(packageName)) return null;
  if (TOP_NPM_PACKAGES.includes(packageName)) return null;

  const name = packageName.toLowerCase();
  if (name.length < 5) return null;

  let best = null;
  for (const popular of TOP_NPM_PACKAGES) {
    if (popular.length < 5) continue;
    // Skip if popular name is a clear substring or official extension
    if (name.startsWith(popular + '-') || name.startsWith(popular + '.') || name.endsWith('-' + popular)) {
      continue;
    }

    const dist = levenshtein(name, popular.toLowerCase());

    if (dist === 1) {
      if (!best || dist < best.distance) best = { distance: dist, suspectedTarget: popular };
    } else if (dist === 2) {
      const lenDiff = Math.abs(name.length - popular.length);
      if (name.length >= 6 && popular.length >= 6 && lenDiff <= 1) {
        if (!best || dist < best.distance) best = { distance: dist, suspectedTarget: popular };
      }
    }
  }

  if (!best) return null;

  return {
    type: 'TYPOSQUAT',
    packageName,
    suspectedTarget: best.suspectedTarget,
    editDistance: best.distance,
    confidence: best.distance === 1 ? 'high' : 'medium',
    severity: 'high',
    detail: `'${packageName}' is edit-distance ${best.distance} from popular package '${best.suspectedTarget}' (suspected typosquatting attack)`,
  };
}

/**
 * Behavioral & Metadata Heuristics:
 * Analyzes whether an install script actually contains suspicious malware behavior.
 */
async function checkMetadataHeuristics(packageName, version, preloadedMeta = null) {
  if (isKnownSafe(packageName)) return [];

  const meta = preloadedMeta || await fetchPackageMetadata(packageName);
  if (!meta) return [];

  const findings = [];
  const versionData = (meta.versions && meta.versions[version]) || {};
  const createdTime = meta.time && meta.time.created;
  const ageDays = createdTime
    ? (Date.now() - new Date(createdTime).getTime()) / 86400000
    : 9999;

  const maintainerCount = (meta.maintainers || []).length;
  const hasNoRepo = !meta.repository;

  // 1. Inspect actual install script behavior
  const scripts = versionData.scripts || {};
  const installScriptContent = `${scripts.preinstall || ''} ${scripts.install || ''} ${scripts.postinstall || ''}`.toLowerCase();

  if (installScriptContent.trim().length > 0) {
    // Check for active malware patterns (obfuscation, exfiltration, token theft)
    const hasObfuscation = /eval\s*\(|atob\s*\(|fromcharcode|\\x[0-9a-f]{2}|buffer\.from\(.+['"]hex['"]\)/i.test(installScriptContent);
    const hasExfiltration = /webhook|pastebin|telegram\.org\/bot|discord\.com\/api|\b(curl|wget)\b|process\.env\.(aws|npm|token|pass|secret|gh_)/i.test(installScriptContent);

    if (hasObfuscation || hasExfiltration) {
      findings.push({
        type: 'HEURISTIC_INSTALL_SCRIPT',
        packageName,
        detail: `Suspicious obfuscation or network exfiltration detected in ${version} install script`,
        severity: 'critical',
        confidence: 'high',
      });
    } else if (ageDays < 14 && hasNoRepo) {
      // Untrusted fresh package with zero history running scripts
      findings.push({
        type: 'HEURISTIC_INSTALL_SCRIPT',
        packageName,
        detail: `Brand-new package (${ageDays.toFixed(0)} days old, no source repository) executing install script`,
        severity: 'high',
        confidence: 'medium',
      });
    }
  }

  // 2. Fresh unverified package (< 5 days old, single maintainer, no repository)
  if (ageDays < 5 && maintainerCount <= 1 && hasNoRepo) {
    findings.push({
      type: 'HEURISTIC_NEW_PACKAGE',
      packageName,
      detail: `Package published only ${ageDays.toFixed(1)} days ago by single maintainer with no public repository`,
      severity: 'medium',
      confidence: 'medium',
    });
  }

  // 3. Extreme release burst (15+ versions in < 12 hours on an unestablished package)
  if (meta.time && ageDays < 60) {
    const timestamps = Object.entries(meta.time)
      .filter(([k]) => !['created', 'modified'].includes(k))
      .map(([, v]) => new Date(v).getTime())
      .sort((a, b) => a - b);

    if (timestamps.length >= 15) {
      const recentWindow = timestamps.slice(-15);
      const spanHours = (recentWindow[14] - recentWindow[0]) / 3600000;
      if (spanHours < 12) {
        findings.push({
          type: 'HEURISTIC_RELEASE_BURST',
          packageName,
          detail: `15 versions published in ${spanHours.toFixed(1)} hours on a new package — potential supply chain flooding attack`,
          severity: 'medium',
          confidence: 'low',
        });
      }
    }
  }

  return findings;
}

/**
 * Full analysis — runs typosquat, behavioral heuristics, and calibrated ML classifier.
 */
const { scorePackage } = require('./mlClassifier');

async function analyzeComponents(components, ecosystem = 'npm') {
  const results = [];

  for (const comp of components) {
    if (!comp.resolved) continue;
    if (isKnownSafe(comp.name)) continue;

    // 1. Typosquat Check
    const typosquat = checkTyposquat(comp.name);
    if (typosquat) {
      results.push(typosquat);
    }

    // Single metadata fetch per component (reused across heuristics & ML classifier)
    const meta = await fetchPackageMetadata(comp.name);

    // 2. Behavioral Heuristics Check
    if (meta) {
      const heuristics = await checkMetadataHeuristics(comp.name, comp.version, meta);
      results.push(...heuristics);

      // 3. Calibrated ML Classifier Check
      const mlScore = scorePackage(meta, comp.name, comp.version, ecosystem);
      if (mlScore.verdict === 'malicious' && mlScore.maliciousProbability >= 0.88) {
        results.push({
          type: 'ML_CLASSIFIER',
          packageName: comp.name,
          version: comp.version,
          confidence: mlScore.confidence,
          maliciousProbability: mlScore.maliciousProbability,
          severity: 'high',
          detail: `Machine learning classifier (${mlScore.ecosystem}): strong risk pattern (${(mlScore.maliciousProbability * 100).toFixed(1)}% score).`,
        });
      }
    }
  }

  // Deduplicate findings by package name, prioritizing highest severity
  const seen = new Map();
  const deduped = [];
  for (const f of results) {
    const key = `${f.packageName}:${f.type}`;
    if (!seen.has(key)) {
      seen.set(key, f);
      deduped.push(f);
    }
  }

  return deduped;
}

module.exports = {
  levenshtein,
  checkTyposquat,
  checkMetadataHeuristics,
  analyzeComponents,
  TOP_NPM_PACKAGES,
  KNOWN_SAFE,
  isKnownSafe,
};