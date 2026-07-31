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
