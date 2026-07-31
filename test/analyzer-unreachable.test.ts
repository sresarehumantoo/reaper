import { test } from 'node:test';
import { strict as assert } from 'node:assert';
import { analyzeUnreachable } from '../src/analyzers/unreachable';
import { parseCode } from '../src/parser';

const run = (src: string) => analyzeUnreachable(parseCode(src, 'u.js'), 'u.js');

test('unreachable: flags code after return in a block', () => {
  const f = run('function g(){ return 1; console.log("dead"); }');
  assert.equal(f.length, 1);
  assert.equal(f[0].type, 'unreachable');
});

test('unreachable: flags code after return inside a switch case', () => {
  const f = run('function g(x){ switch(x){ case 1: return 1; sideEffect(); } }');
  assert.equal(f.length, 1, 'switch-case consequent should be scanned');
  assert.match(f[0].message, /after return/);
});

test('unreachable: clean switch case produces no finding', () => {
  const f = run('function g(x){ switch(x){ case 1: doThing(); break; default: other(); } }');
  assert.equal(f.length, 0);
});
