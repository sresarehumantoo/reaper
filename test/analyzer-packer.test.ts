import { test } from 'node:test';
import { strict as assert } from 'node:assert';
import { detectPacker } from '../src/analyzers/packer';
import { parseCode } from '../src/parser';
import { readExample } from './helpers';

test('packer: detects + statically unpacks the deadcode02 flag fixture', () => {
  const src = readExample('deadcode02/flag.js');
  const ast = parseCode(src, 'flag.js');
  const results = detectPacker(ast);

  assert.equal(results.length, 1);
  const p = results[0];
  assert.equal(p.detected, true);
  assert.equal(p.base,  14);
  assert.equal(p.count, 14);
  assert.equal(p.keys.length, 14);
  assert.equal(p.error, null);
  assert.ok(p.unpacked, 'should have produced unpacked output');
  // Unpacked source is the inner template with packer tokens substituted —
  // the flag is split across many concatenated literals, not joined here.
  // Verify each fragment is present.
  for (const piece of ['HTB{y', '0u_5h', '0uld_', 'n3v3r', '_run_', 'un7ru', '573d_', '0bfu5', 'c473d', '_c0d3']) {
    assert.ok(p.unpacked!.includes(`'${piece}'`),
      `expected fragment '${piece}' in unpacked output: ${p.unpacked!.slice(0, 200)}`);
  }
});

test('packer: returns empty array for non-packed input', () => {
  const ast = parseCode('console.log("hello");', 'plain.js');
  const results = detectPacker(ast);
  assert.equal(results.length, 0);
});

test('packer: handles split("|") key array form', () => {
  // p,a,c,k,e,d shell with keys as 'a|b|c'.split('|')
  // We feed a synthetic example: maps token '0' -> 'a', '1' -> 'b', '2' -> 'c'
  // Encoded packed string: "0(1+2)" → "a(b+c)"
  const src = `eval(function(p,a,c,k,e,d){
    e=function(c){return c.toString(a)};
    if(!''.replace(/^/,String)){
      while(c--)d[e(c)]=k[c]||e(c);
      k=[function(e){return d[e]}];e=function(){return'\\\\w+'};c=1
    }
    while(c--)if(k[c])p=p.replace(new RegExp('\\\\b'+e(c)+'\\\\b','g'),k[c]);
    return p
  }('0(1+2)',16,3,'a|b|c'.split('|'),0,{}))`;
  const ast = parseCode(src, 'split-keys.js');
  const results = detectPacker(ast);

  assert.equal(results.length, 1);
  assert.equal(results[0].keys.length, 3);
  assert.deepEqual(results[0].keys, ['a', 'b', 'c']);
  assert.ok(results[0].unpacked, 'should unpack with split-form keys');
  assert.match(results[0].unpacked!, /a\(b\+c\)/);
});

test('packer: clamps an implausible count so it cannot OOM/hang', () => {
  // Hostile "packer": count = 1e9 with an empty key array. Without the clamp,
  // staticUnpack would loop a billion times building a multi-GB lookup object.
  const src = `eval((function(p,a,c,k,e,d){return p})('x', 62, 1000000000, []))`;
  const ast = parseCode(src, 'bomb.js');
  const start = Date.now();
  const results = detectPacker(ast);
  assert.ok(Date.now() - start < 2000, 'must not spin on a huge count');
  assert.equal(results.length, 1);
  assert.equal(results[0].detected, true);
  assert.match(results[0].error ?? '', /clamped/);
  assert.equal(results[0].unpacked, 'x');
});

test('packer: rejects out-of-range base', () => {
  const src = `eval((function(p,a,c,k,e,d){return p})('x', 999, 3, []))`;
  const ast = parseCode(src, 'badbase.js');
  assert.equal(detectPacker(ast).length, 0);
});
