const { test, describe } = require('node:test');
const assert = require('node:assert/strict');
const { scorePackage, extractFeatures, FEATURE_NAMES } = require('../src/modules/mlClassifier');
const { levenshtein, checkTyposquat, isKnownSafe } = require('../src/modules/maliciousPackageAnalyzer');

describe('ML Classifier & Levenshtein Performance & Correctness', () => {
  test('levenshtein computes exact edit distance without allocations', () => {
    assert.equal(levenshtein('', ''), 0);
    assert.equal(levenshtein('a', ''), 1);
    assert.equal(levenshtein('', 'b'), 1);
    assert.equal(levenshtein('lodash', 'lodash'), 0);
    assert.equal(levenshtein('lodash', 'lodahs'), 2); // 2 substitutions
    assert.equal(levenshtein('express', 'expres'), 1);  // 1 deletion
    assert.equal(levenshtein('react', 'preact'), 1);    // 1 insertion
    assert.equal(levenshtein('kitten', 'sitting'), 3);
  });

  test('extractFeatures returns properly bounded 16-element feature vector', () => {
    const meta = {
      name: 'test-package',
      time: { created: new Date(Date.now() - 365 * 86400000).toISOString() },
      maintainers: [{ name: 'alice' }, { name: 'bob' }],
      versions: { '1.0.0': { scripts: {} } },
    };
    const features = extractFeatures(meta, 'test-package', '1.0.0');
    assert.equal(Array.isArray(features), true);
    assert.equal(features.length, 16);
    for (let i = 0; i < features.length; i++) {
      assert.equal(typeof features[i], 'number');
      assert.ok(features[i] >= 0 && features[i] <= 1, `Feature ${FEATURE_NAMES[i]} out of [0, 1] bounds: ${features[i]}`);
    }
  });

  test('known safe packages and trusted scopes are suppressed', () => {
    assert.equal(isKnownSafe('react'), true);
    assert.equal(isKnownSafe('express'), true);
    assert.equal(isKnownSafe('@types/node'), true);
    assert.equal(isKnownSafe('@prisma/client'), true);
    assert.equal(isKnownSafe('totally-unknown-package-xyz'), false);

    const score = scorePackage({}, 'react', '19.0.0');
    assert.equal(score.verdict, 'clean');
    assert.equal(score.riskScore, 0);
  });

  test('typosquat detector flags genuine typosquats of top packages', () => {
    const finding = checkTyposquat('lodahs');
    assert.ok(finding);
    assert.equal(finding.type, 'TYPOSQUAT');
    assert.equal(finding.suspectedTarget, 'lodash');
    assert.equal(finding.editDistance, 2);

    // Official package should not be flagged
    assert.equal(checkTyposquat('lodash'), null);
    assert.equal(checkTyposquat('express'), null);
  });
});
