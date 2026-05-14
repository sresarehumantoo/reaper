import { test } from 'node:test';
import { strict as assert } from 'node:assert';
import { analyzeDeadBranches } from '../src/analyzers/branches';
import { parseCode } from '../src/parser';

function findingsFor(src: string) {
  return analyzeDeadBranches(parseCode(src, 'inline.js'), 'inline.js');
}

test('branches: flags if(false) { ... }', () => {
  const f = findingsFor('if (false) { console.log("dead") }');
  assert.ok(f.length >= 1, 'expected at least one finding');
  assert.ok(f.some(x => x.type === 'dead-branch'));
});

test('branches: flags 1 === 2 dead branch', () => {
  const f = findingsFor('if (1 === 2) { console.log("never") } else { console.log("always") }');
  assert.ok(f.some(x => x.type === 'dead-branch'));
});

test('branches: flags if(true) { ... } else { dead }', () => {
  const f = findingsFor('if (true) { good() } else { dead() }');
  assert.ok(f.some(x => x.type === 'dead-branch'));
});

test('branches: does not flag dynamic conditions', () => {
  const f = findingsFor('if (Math.random() > 0.5) { a() } else { b() }');
  assert.equal(f.length, 0);
});

test('branches: handles unary ! folding', () => {
  const f = findingsFor('if (!true) { dead() }');
  assert.ok(f.some(x => x.type === 'dead-branch'));
});
