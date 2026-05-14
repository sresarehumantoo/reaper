import { test } from 'node:test';
import { strict as assert } from 'node:assert';
import { extractIocs } from '../src/analyzers/iocs';
import { parseCode } from '../src/parser';
import { readExample } from './helpers';

function iocsFor(src: string) {
  return extractIocs(parseCode(src, 'inline.js'), 'inline.js');
}

test('iocs: extracts a plain URL', () => {
  const i = iocsFor("fetch('https://example.com/path?q=1')");
  assert.ok(i.some(x => x.type === 'url' && x.value === 'https://example.com/path?q=1'));
});

test('iocs: extracts EVM address from a string literal', () => {
  const i = iocsFor("const c = '0xA1decFB75C8C0CA28C10517ce56B710baf727d2e';");
  assert.ok(i.some(x => x.type === 'evm-address' && x.value === '0xA1decFB75C8C0CA28C10517ce56B710baf727d2e'));
});

test('iocs: extracts EVM function selector when string is JUST the selector', () => {
  const i = iocsFor("const data = '0x6d4ce63c';");
  assert.ok(i.some(x => x.type === 'evm-selector' && x.value === '0x6d4ce63c'));
});

test('iocs: extracts IPv4', () => {
  const i = iocsFor("var c2 = '192.0.2.42';");
  assert.ok(i.some(x => x.type === 'ipv4' && x.value === '192.0.2.42'));
});

test('iocs: dedupes repeated occurrences', () => {
  const i = iocsFor("a('https://evil.test/'); b('https://evil.test/');");
  const urls = i.filter(x => x.type === 'url');
  assert.equal(urls.length, 1);
});

test('iocs: denylist suppresses common analyst-host noise', () => {
  const i = iocsFor("a = 'http://www.w3.org/2000/svg'");
  // The URL itself is extracted (it IS a URL) — but the bare domain w3.org
  // should NOT also appear as a separate domain finding.
  const domains = i.filter(x => x.type === 'domain' && x.value === 'w3.org');
  assert.equal(domains.length, 0);
});

test('iocs: end-to-end against the deobfuscated EtherHiding loader', () => {
  const src = readExample('etherhiding/artifacts/stage1/payload.deobf.js');
  const i = extractIocs(parseCode(src, 'payload.deobf.js'), 'payload.deobf.js');

  const urls       = i.filter(x => x.type === 'url').map(x => x.value);
  const evmAddrs   = i.filter(x => x.type === 'evm-address').map(x => x.value);
  const selectors  = i.filter(x => x.type === 'evm-selector').map(x => x.value);

  assert.ok(urls.some(u => u.includes('bsc-testnet-rpc.publicnode.com')),
    `expected BSC RPC URL, got: ${urls.join(', ')}`);
  assert.ok(evmAddrs.includes('0xA1decFB75C8C0CA28C10517ce56B710baf727d2e'),
    `expected dispatcher contract address, got: ${evmAddrs.join(', ')}`);
  assert.ok(selectors.includes('0x6d4ce63c'),
    `expected function selector, got: ${selectors.join(', ')}`);
});

test('iocs: extracts long base64 blob as base64 IOC', () => {
  // 96-char base64 (length passes the >= 80 threshold)
  const blob = 'YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXowMTIzNDU2Nzg5K2Ev'
             + 'YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXowMTIzNDU2Nzg5K2E=';
  const i = iocsFor(`const x = "${blob}"`);
  assert.ok(i.some(x => x.type === 'base64'));
});
