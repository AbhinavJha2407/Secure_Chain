const { test, describe } = require('node:test');
const assert = require('node:assert/strict');
const { evaluateGate, DEFAULT_POLICY } = require('../src/modules/policyGate');

describe('Policy Gate Decision Engine', () => {
  test('passes clean scan with no findings', () => {
    const scan = {
      vulnerabilities: [],
      maliciousPackages: [],
    };
    const decision = evaluateGate(scan);
    assert.equal(decision.verdict, 'PASS');
    assert.equal(decision.passed, true);
    assert.equal(decision.reasons.length, 0);
  });

  test('blocks immediately on typosquat or malicious package finding', () => {
    const scan = {
      vulnerabilities: [],
      maliciousPackages: [
        { type: 'TYPOSQUAT', packageName: 'lodahs', editDistance: 1 },
      ],
    };
    const decision = evaluateGate(scan);
    assert.equal(decision.verdict, 'BLOCKED');
    assert.equal(decision.passed, false);
    assert.equal(decision.reasons[0].type, 'MALICIOUS_PACKAGE_DETECTED');
  });

  test('blocks on high-confidence critical ML classifier finding', () => {
    const scan = {
      vulnerabilities: [],
      maliciousPackages: [
        { type: 'ML_CLASSIFIER', packageName: 'evil-pkg', confidence: 'high', maliciousProbability: 0.95, severity: 'critical' },
      ],
    };
    const decision = evaluateGate(scan);
    assert.equal(decision.verdict, 'BLOCKED');
    assert.equal(decision.passed, false);
    assert.equal(decision.reasons[0].type, 'MALICIOUS_PACKAGE_DETECTED');
  });

  test('blocks on build integrity mismatch', () => {
    const scan = { vulnerabilities: [], maliciousPackages: [] };
    const integrityVerdict = { verdict: 'MISMATCH', detail: 'Hash altered' };
    const decision = evaluateGate(scan, {}, integrityVerdict);
    assert.equal(decision.verdict, 'BLOCKED');
    assert.equal(decision.passed, false);
    assert.equal(decision.reasons[0].type, 'BUILD_INTEGRITY_MISMATCH');
  });

  test('fails gate when critical vulnerability limit (0) is exceeded', () => {
    const scan = {
      vulnerabilities: [
        { id: 'CVE-2024-9999', priorityLabel: 'P0_CRITICAL', severity: 9.8 },
      ],
      maliciousPackages: [],
    };
    const decision = evaluateGate(scan);
    assert.equal(decision.verdict, 'FAILED');
    assert.equal(decision.passed, false);
    assert.equal(decision.reasons[0].type, 'CRITICAL_VULNERABILITY_LIMIT_EXCEEDED');
  });

  test('fails gate when high vulnerabilities exceed limit (2)', () => {
    const scan = {
      vulnerabilities: [
        { id: 'CVE-1', priorityLabel: 'P1_HIGH', severity: 7.5 },
        { id: 'CVE-2', priorityLabel: 'P1_HIGH', severity: 7.2 },
        { id: 'CVE-3', priorityLabel: 'P1_HIGH', severity: 7.0 },
      ],
      maliciousPackages: [],
    };
    const decision = evaluateGate(scan);
    assert.equal(decision.verdict, 'FAILED');
    assert.equal(decision.passed, false);
    assert.equal(decision.reasons[0].type, 'HIGH_VULNERABILITY_LIMIT_EXCEEDED');
  });

  test('fails gate when EPSS exploit probability exceeds threshold (0.60)', () => {
    const scan = {
      vulnerabilities: [
        { id: 'CVE-EXPLOITED', priorityLabel: 'P2_MEDIUM', severity: 6.0, epss: 0.75 },
      ],
      maliciousPackages: [],
    };
    const decision = evaluateGate(scan);
    assert.equal(decision.verdict, 'FAILED');
    assert.equal(decision.passed, false);
    assert.equal(decision.reasons[0].type, 'EPSS_EXPLOIT_RISK_EXCEEDED');
  });

  test('fails closed on incomplete or error scan', () => {
    const scan = {
      error: 'Upstream OSV registry query timed out',
      incomplete: true,
      vulnerabilities: [],
    };
    const decision = evaluateGate(scan);
    assert.equal(decision.verdict, 'FAILED');
    assert.equal(decision.passed, false);
    assert.equal(decision.reasons[0].type, 'ANALYSIS_INCOMPLETE');
  });

  test('forces BLOCKED verdict and 0 risk score on manifestCorrupted flag or parseError', () => {
    const scan = {
      manifestCorrupted: true,
      parseError: 'Unexpected token } in JSON at position 142',
      vulnerabilities: [],
      maliciousPackages: [],
      components: [{ name: 'lodash', version: '4.17.15' }],
    };
    const decision = evaluateGate(scan);
    assert.equal(decision.verdict, 'BLOCKED');
    assert.equal(decision.passed, false);
    assert.equal(decision.riskScore, 0);
    assert.equal(decision.reasons[0].type, 'MANIFEST_CORRUPTED_OR_EMPTY');
  });

  test('forces BLOCKED verdict and 0 risk score on corruptEntry component', () => {
    const scan = {
      vulnerabilities: [],
      maliciousPackages: [],
      components: [
        { name: 'lodash', version: '4.17.21' },
        { name: 'bad-pkg', version: '0.0.0', corruptEntry: true },
      ],
    };
    const decision = evaluateGate(scan);
    assert.equal(decision.verdict, 'BLOCKED');
    assert.equal(decision.passed, false);
    assert.equal(decision.riskScore, 0);
    assert.equal(decision.reasons[0].type, 'MANIFEST_CORRUPTED_OR_EMPTY');
  });

  test('forces BLOCKED verdict and 0 risk score on empty components list', () => {
    const scan = {
      vulnerabilities: [],
      maliciousPackages: [],
      components: [],
    };
    const decision = evaluateGate(scan);
    assert.equal(decision.verdict, 'BLOCKED');
    assert.equal(decision.passed, false);
    assert.equal(decision.riskScore, 0);
    assert.equal(decision.reasons[0].type, 'MANIFEST_CORRUPTED_OR_EMPTY');
  });

  test('sets gateVerdict to BLOCKED and returns affected packages and CVE IDs on critical vulnerabilities', () => {
    const scan = {
      vulnerabilities: [
        { id: 'CVE-2021-23337', cveId: 'CVE-2021-23337', component: 'lodash', version: '4.17.15', priorityLabel: 'P0_CRITICAL', severity: 7.1 },
      ],
      maliciousPackages: [],
      components: [{ name: 'lodash', version: '4.17.15', resolved: true }],
    };
    const decision = evaluateGate(scan);
    assert.equal(decision.passed, false);
    assert.equal(decision.gateVerdict, 'BLOCKED');
    assert.ok(decision.reasons[0].packages.includes('lodash'));
    assert.ok(decision.reasons[0].cveIds.includes('CVE-2021-23337'));
    assert.ok(decision.reasons[0].detail.includes('lodash@4.17.15'));
  });

  test('respects blockOnCriticalVulns override to set verdict directly to BLOCKED', () => {
    const scan = {
      vulnerabilities: [
        { id: 'CVE-2021-23337', cveId: 'CVE-2021-23337', component: 'lodash', version: '4.17.15', priorityLabel: 'P0_CRITICAL', severity: 7.1 },
      ],
      maliciousPackages: [],
      components: [{ name: 'lodash', version: '4.17.15', resolved: true }],
    };
    const decision = evaluateGate(scan, { blockOnCriticalVulns: true });
    assert.equal(decision.verdict, 'BLOCKED');
    assert.equal(decision.passed, false);
  });
});
