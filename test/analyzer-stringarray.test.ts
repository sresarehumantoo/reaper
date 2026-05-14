import { test } from 'node:test';
import { strict as assert } from 'node:assert';
import { detectAndRewriteStringArray } from '../src/analyzers/stringarray';
import { readFixture, readExample } from './helpers';

test('stringarray: detects + rewrites the minimal synthetic fixture', () => {
  const src = readFixture('string-array-minimal.js');
  const r = detectAndRewriteStringArray(src, 'string-array-minimal.js');

  assert.equal(r.detected, true);
  assert.equal(r.arrayFn,  '_0xarr');
  assert.equal(r.decoderFn, '_0xdec');
  assert.equal(r.error, null);

  // The 'greet' function makes two wrapper-equivalent calls: _0xdec(0x0,..) and _0xdec(0x1,..).
  // Note: in this fixture there are NO outer wrapper fns — the decoder is called directly.
  // So the rewriter walks `wrappers` (empty) and doesn't substitute decoder calls (we only
  // substitute wrapper calls, not the root decoder). The fixture exercises the
  // detection + scaffolding-strip path.
  assert.ok(r.rewritten);
  assert.ok(!r.rewritten!.includes('function _0xarr'), 'array fn should be stripped');
  assert.ok(!r.rewritten!.includes('function _0xdec'), 'decoder should be stripped');
});

test('stringarray: rewrites the EtherHiding stage-1 loader with 28/28 wrapper substitutions', () => {
  const src = readExample('etherhiding/artifacts/stage1/payload.js');
  const r = detectAndRewriteStringArray(src, 'payload.js');

  assert.equal(r.detected, true);
  assert.equal(r.error, null);
  assert.equal(r.attempted,     28);
  assert.equal(r.substitutions, 28);
  // 4 wrappers expected: _0x56d43c, _0x4afb57, _0x136db2, _0x56104e
  assert.equal(r.wrappers.length, 4);

  // Output should expose the plaintext strings the obfuscator hid
  assert.match(r.rewritten!, /eth_call/);
  assert.match(r.rewritten!, /bsc-testnet-rpc\.publicnode\.com/);
  assert.match(r.rewritten!, /0xA1decFB75C8C0CA28C10517ce56B710baf727d2e/);
  assert.match(r.rewritten!, /eval\(atob/);
});

test('stringarray: rewrite output is stable across runs', () => {
  const src = readExample('etherhiding/artifacts/stage1/payload.js');
  const a = detectAndRewriteStringArray(src, 'payload.js');
  const b = detectAndRewriteStringArray(src, 'payload.js');
  assert.equal(a.rewritten, b.rewritten);
});

test('stringarray: rewrite output matches committed deobf artifact', () => {
  const src      = readExample('etherhiding/artifacts/stage1/payload.js');
  const expected = readExample('etherhiding/artifacts/stage1/payload.deobf.js');
  const r        = detectAndRewriteStringArray(src, 'payload.js');
  assert.equal(r.rewritten, expected, 'deobf output drifted from committed artifact');
});

test('stringarray: returns detected:false on plain non-obfuscated JS', () => {
  const r = detectAndRewriteStringArray(
    'function add(a, b) { return a + b; }\nconsole.log(add(1, 2));',
    'plain.js'
  );
  assert.equal(r.detected, false);
  assert.equal(r.rewritten, null);
  assert.equal(r.error, null);
});

test('stringarray: returns error on unparseable input rather than throwing', () => {
  const r = detectAndRewriteStringArray('this is not valid javascript {{{', 'broken.js');
  assert.equal(r.detected, false);
  assert.ok(r.error && r.error.includes('parse failed'), `expected parse error, got: ${r.error}`);
});
