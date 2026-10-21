'use strict';

const { test, describe } = require('node:test');
const assert = require('node:assert/strict');
const { extractDependenciesFromCorruptJson, resolveDependencyTree } = require('../src/modules/sbomEngine');
const { evaluateGate } = require('../src/modules/policyGate');

describe('Corrupt Manifest Parser & Gate Hardening Suite', () => {
  test('extractDependenciesFromCorruptJson extracts valid dependencies from truncated/malformed JSON', () => {
    const corruptJson = `{
      "name": "vulnerable-app",
      "version": "1.0.0",
      "dependencies": {
        "lodash": "4.17.15",
        "axios": "^0.18.0",
        "@angular/core": "~12.0.0"
      // syntax error: missing closing brace, trailing comma
    `;

    const extracted = extractDependenciesFromCorruptJson(corruptJson);
    assert.equal(extracted['lodash'], '4.17.15');
    assert.equal(extracted['axios'], '^0.18.0');
    assert.equal(extracted['@angular/core'], '~12.0.0');
    // Ensure metadata keys like name, version are excluded
    assert.equal(extracted['name'], undefined);
    assert.equal(extracted['version'], undefined);
  });

  test('resolveDependencyTree flags corrupt dependency entries with corruptEntry: true', async () => {
    const rootDeps = {
      'lodash': '4.17.21',
      'malformed-dep': { invalid: 123 }, // Non-string version
      'dirty-version-pkg': '1.2.3; drop table;', // Invalid characters
    };

    const tree = await resolveDependencyTree(rootDeps, { maxDepth: 1 });
    const corrupt = tree.components.filter(c => c.corruptEntry === true);

    assert.ok(corrupt.length >= 2);
    const malformed = corrupt.find(c => c.name === 'malformed-dep');
    assert.ok(malformed);
    assert.equal(malformed.corruptEntry, true);

    const dirty = corrupt.find(c => c.name === 'dirty-version-pkg');
    assert.ok(dirty);
    assert.equal(dirty.corruptEntry, true);
    // Stripped version without invalid characters
    assert.equal(dirty.version, '1.2.3droptable');
  });

  test('corrupt manifest with vulnerable dependencies is forced to BLOCKED verdict and 0 risk score', () => {
    // Simulated scan result of a corrupt manifest with vulnerable packages
    const scanResult = {
      manifestCorrupted: true,
      parseError: 'Unexpected end of JSON input',
      vulnerabilities: [
        { id: 'CVE-2019-10744', component: 'lodash', version: '4.17.15', priorityLabel: 'P0_CRITICAL', severity: 9.8 },
      ],
      maliciousPackages: [],
      components: [
        { name: 'lodash', version: '4.17.15' },
      ],
    };

    const gate = evaluateGate(scanResult);
    assert.equal(gate.verdict, 'BLOCKED');
    assert.equal(gate.passed, false);
    assert.equal(gate.riskScore, 0);
    assert.ok(gate.reasons.some(r => r.type === 'MANIFEST_CORRUPTED_OR_EMPTY'));
  });
});
