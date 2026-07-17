'use strict';

// Intentionally vulnerable sample application used by tests.

// Vulnerable: user-controlled input flows into eval (code injection).
function runExpression(req) {
  return eval(req.query.x);
}

function add(a, b) {
  return a + b;
}

module.exports = { runExpression, add };
