/**
 * Method 2: OSV.dev Bulk Dataset Downloader & Parser
 *
 * Downloads the complete npm vulnerability dataset export zip from OSV.dev GCS bucket:
 *   https://osv-vulnerabilities.storage.googleapis.com/npm/all.zip
 *
 * Unpacks JSON records, extracts confirmed malicious packages & vulnerabilities,
 * and builds feature dataset for training the ML Classifier.
 *
 * Usage: node src/modules/downloadOSVBulk.js
 */

'use strict';

const fs = require('fs');
const path = require('path');
const https = require('https');
const { execSync } = require('child_process');
const { extractFeatures } = require('./mlClassifier');
const { fetchPackageMetadata } = require('./sbomEngine');

const ZIP_URL = 'https://osv-vulnerabilities.storage.googleapis.com/npm/all.zip';
const MODULES_DIR = __dirname;
const ZIP_FILE = path.join(MODULES_DIR, 'osv_npm_all.zip');
const EXTRACT_DIR = path.join(MODULES_DIR, 'osv_temp_extracted');
const OUT_FILE = path.join(MODULES_DIR, 'training-data.json');

// Known safe seed packages for negative training class
const KNOWN_SAFE_SEEDS = [
  'lodash', 'express', 'react', 'axios', 'chalk', 'commander',
  'moment', 'webpack', 'eslint', 'jest', 'typescript', 'vue',
  'angular', 'next', 'socket.io', 'mongoose', 'jquery', 'bootstrap',
  'tailwindcss', 'uuid', 'dotenv', 'cors', 'body-parser', 'nodemon',
  'prettier', 'redux', 'rxjs', 'graphql', 'sequelize', 'knex',
  'passport', 'bcrypt', 'jsonwebtoken', 'multer', 'helmet', 'morgan',
];

function downloadZip() {
  return new Promise((resolve, reject) => {
    if (fs.existsSync(ZIP_FILE) && fs.statSync(ZIP_FILE).size > 1000) {
      console.log(`📦 Bulk zip found at ${ZIP_FILE} (${(fs.statSync(ZIP_FILE).size / 1024 / 1024).toFixed(2)} MB). Skipping download!`);
      return resolve();
    }

    console.log(`📥 Downloading OSV bulk npm export from ${ZIP_URL}...`);
    try {
      // Use PowerShell Invoke-WebRequest for fast, reliable download on Windows
      execSync(`powershell -Command "Invoke-WebRequest -Uri '${ZIP_URL}' -OutFile '${ZIP_FILE}'"`, { stdio: 'inherit' });
      console.log('✅ Download finished successfully!');
      resolve();
    } catch (err) {
      console.error('Failed to download zip automatically:', err.message);
      reject(err);
    }
  });
}

function extractZip() {
  console.log(`📂 Extracting ${ZIP_FILE}...`);
  if (!fs.existsSync(EXTRACT_DIR)) {
    fs.mkdirSync(EXTRACT_DIR, { recursive: true });
  }

  try {
    // PowerShell Expand-Archive for Windows
    execSync(`powershell -Command "Expand-Archive -Path '${ZIP_FILE}' -DestinationPath '${EXTRACT_DIR}' -Force"`, { stdio: 'inherit' });
    console.log('✅ Extraction complete.');
  } catch (err) {
    console.error('\n❌ ERROR: The zip file is corrupted or incomplete!');
    console.error('Deleting corrupted zip file so a fresh download can be performed...');
    try { fs.unlinkSync(ZIP_FILE); } catch (e) {}
    throw new Error('Zip extraction failed because the downloaded file was incomplete/corrupted. Please download the file again.');
  }
}

function parseVulnerabilityRecords() {
  console.log('🔍 Parsing OSV JSON files...');
  const files = fs.readdirSync(EXTRACT_DIR).filter(f => f.endsWith('.json'));
  console.log(`Found ${files.length} vulnerability records in total.`);

  const maliciousPackages = new Set();
  const advisoryPackages = new Set();

  for (const file of files) {
    try {
      const content = fs.readFileSync(path.join(EXTRACT_DIR, file), 'utf8');
      const record = JSON.parse(content);

      const isMalware = record.database_specific?.type === 'MALWARE' ||
                        (record.summary && record.summary.toLowerCase().includes('malicious')) ||
                        (record.details && record.details.toLowerCase().includes('malicious package'));

      for (const affected of record.affected || []) {
        const pkgName = affected.package?.name;
        if (pkgName && affected.package?.ecosystem === 'npm') {
          if (isMalware) {
            maliciousPackages.add(pkgName);
          } else {
            advisoryPackages.add(pkgName);
          }
        }
      }
    } catch (e) {
      // Ignore invalid JSON files
    }
  }

  console.log(`📊 Extracted:`);
  console.log(`   - Confirmed Malicious NPM Packages: ${maliciousPackages.size}`);
  console.log(`   - Packages with Security Advisories: ${advisoryPackages.size}`);

  return {
    malicious: Array.from(maliciousPackages),
    advisories: Array.from(advisoryPackages)
  };
}

async function buildFeatureRecord(packageName, label) {
  try {
    const meta = await fetchPackageMetadata(packageName);
    if (!meta) return null;
    const version = meta['dist-tags']?.latest || Object.keys(meta.versions || {})[0];
    if (!version) return null;
    const features = extractFeatures(meta, packageName, version);
    return { packageName, version, features, label };
  } catch {
    return null;
  }
}

async function generateMLDataset() {
  await downloadZip();
  extractZip();
  const { malicious } = parseVulnerabilityRecords();

  console.log('\n🧠 Building Feature Vectors for ML Model...');

  // Limit malicious sample size for feature extraction (npm rate limits)
  const sampleMalicious = malicious.slice(0, 50);
  console.log(`Fetching metadata for top ${sampleMalicious.length} malicious packages...`);
  const maliciousRecords = (await Promise.all(sampleMalicious.map(p => buildFeatureRecord(p, 1)))).filter(Boolean);

  console.log(`Fetching metadata for ${KNOWN_SAFE_SEEDS.length} safe packages...`);
  const safeRecords = (await Promise.all(KNOWN_SAFE_SEEDS.map(p => buildFeatureRecord(p, 0)))).filter(Boolean);

  const dataset = {
    generatedAt: new Date().toISOString(),
    source: 'OSV.dev Bulk Export (npm/all.zip)',
    totalOSVRecordsParsed: malicious.length,
    maliciousCount: maliciousRecords.length,
    safeCount: safeRecords.length,
    records: [...maliciousRecords, ...safeRecords],
  };

  fs.writeFileSync(OUT_FILE, JSON.stringify(dataset, null, 2));
  console.log(`\n🎉 Success! ML Training dataset saved to: ${OUT_FILE}`);
  console.log(`   Total Training Samples: ${dataset.records.length} (${maliciousRecords.length} Malicious, ${safeRecords.length} Safe)`);

  // Clean up temporary extracted folder
  try {
    fs.rmSync(EXTRACT_DIR, { recursive: true, force: true });
    console.log('🧹 Cleaned up temporary extracted files.');
  } catch (e) {}
}

if (require.main === module) {
  generateMLDataset().catch(err => {
    console.error('Error generating bulk dataset:', err);
    process.exit(1);
  });
}

module.exports = { generateMLDataset, downloadZip, parseVulnerabilityRecords };
