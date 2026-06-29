import { test } from 'node:test';
import { strict as assert } from 'node:assert';
import { triageSource } from '../src/triage';
import { readExample } from './helpers';

test('triage: propellerads sfp.js — string-array rewrite + fold regression', () => {
  const src = readExample('propellerads-sfp/artifacts/payload.js');
  const r = triageSource(src, 'payload.js', 'payload.js');

  assert.ok(r.stringArray?.detected, 'string-array should be detected');
  // Locks the rewriter: every wrapper call must still resolve.
  assert.equal(r.stringArray!.substitutions, 2355, `substitutions drifted: ${r.stringArray!.substitutions}`);
  assert.equal(r.stringArray!.substitutions, r.stringArray!.attempted, 'some substitutions failed');
  assert.ok(r.folds > 0, 'constant-folder should have collapsed expressions');
  assert.notEqual(r.verdict, 'clean');
  assert.match(r.sha256, /^[0-9a-f]{64}$/);
});

test('triage: EtherHiding loader — recovers C2 URL, contract, selector + verdict', () => {
  const src = readExample('etherhiding/artifacts/stage1/payload.deobf.js');
  const r = triageSource(src, 'payload.deobf.js', 'payload.deobf.js');

  const urls = r.iocs.filter(i => i.type === 'url').map(i => i.value);
  const evm  = r.iocs.filter(i => i.type === 'evm-address').map(i => i.value);
  assert.ok(urls.some(u => u.includes('bsc-testnet-rpc.publicnode.com')), `urls: ${urls.join(',')}`);
  assert.ok(evm.includes('0xA1decFB75C8C0CA28C10517ce56B710baf727d2e'), `evm: ${evm.join(',')}`);
  assert.notEqual(r.verdict, 'clean');
});

test('triage: benign source scores clean', () => {
  const r = triageSource('export function add(a, b) { return a + b; }', 'ok.js', 'ok.js');
  assert.equal(r.verdict, 'clean');
  assert.equal(r.iocs.length, 0);
});
