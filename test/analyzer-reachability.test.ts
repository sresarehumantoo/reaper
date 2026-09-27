import { test } from 'node:test';
import { strict as assert } from 'node:assert';
import fs from 'fs';
import path from 'path';
import { analyzeReachability } from '../src/analyzers/reachability';
import { withTempDir } from './helpers';

test('reachability: folded strings attach only to their enclosing dead fn', async () => {
  const src = [
    'function used(){ return helper(); }',
    'function helper(){ return 1; }',
    "function dead1(){ var a = 'AA' + 'BB'; return a; }",
    "function dead2(){ var b = 'CC' + 'DD'; return b; }",
    'used();',
  ].join('\n');

  await withTempDir((dir) => {
    const p = path.join(dir, 'sample.js');
    fs.writeFileSync(p, src);
    const r = analyzeReachability(p, ['used']);

    const d1 = r.deadFns.find(f => f.name === 'dead1');
    const d2 = r.deadFns.find(f => f.name === 'dead2');
    assert.ok(d1 && d2, 'both dead functions detected');

    const v1 = d1!.reconstructed.map(f => f.value);
    const v2 = d2!.reconstructed.map(f => f.value);
    assert.deepEqual(v1, ['AABB'], 'dead1 gets only its own fold');
    assert.deepEqual(v2, ['CCDD'], 'dead2 gets only its own fold');
  });
});

test('evalscope: captures atob-fed eval, Function without new, prototype and async ctors, string timers', async () => {
  const { captureEvalScope } = await import('../src/analyzers/evalscope');
  await withTempDir(dir => {
    const file = path.join(dir, 'layers.js');
    fs.writeFileSync(file, [
      'Function("var l1 = 1;");',
      'eval(atob("dmFyIGwyID0gMjs="));',
      '[].constructor.constructor("var l3 = 3;");',
      'setTimeout("var l4 = 4;", 0);',
      '(async function () {}).constructor("var l5 = 5;");',
    ].join('\n'));
    const r = captureEvalScope(file);
    assert.equal(r.error, null);
    const sources = r.layers.map(l => l.source).join('\n');
    for (const n of [1, 2, 3, 4, 5]) assert.ok(sources.includes(`var l${n} = ${n};`), `missing layer ${n}`);
  });
});
