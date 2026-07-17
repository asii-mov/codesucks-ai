'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { add } = require('../app.js');

test('add works', () => {
  assert.strictEqual(add(1, 2), 3);
});

// Intentionally failing test: establishes a non-zero baseline so gates must
// tolerate pre-existing failures ("no new failures") rather than requiring a
// fully green suite.
test('known pre-existing failure', () => {
  assert.strictEqual(add(1, 1), 3);
});
