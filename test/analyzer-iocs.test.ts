import { test } from 'node:test';
import { strict as assert } from 'node:assert';
import { extractIocs } from '../src/analyzers/iocs';
import { parseCode } from '../src/parser';
import { defang } from '../src/util';
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

test('iocs: extracts Telegram bot token', () => {
  // Synthetic token assembled at runtime: the bot-id:secret literal never
  // appears contiguously in source, so secret scanners don't false-positive,
  // while the value still matches the detector's <8-10 digits>:<35 chars> shape.
  const tgToken = ['1234567890', 'A'.repeat(35)].join(':');
  const i = iocsFor(`var t = '${tgToken}';`);
  assert.ok(i.some(x => x.type === 'telegram-bot-token'));
});

test('iocs: extracts Discord webhook', () => {
  const i = iocsFor("u='https://discord.com/api/webhooks/123456789012345678/AbCdEfGhIjKlMnOpQrStUvWx'");
  assert.ok(i.some(x => x.type === 'discord-webhook'));
});

test('iocs: extracts AWS access key id', () => {
  const i = iocsFor("k='AKIAIOSFODNN7EXAMPLE'");
  assert.ok(i.some(x => x.type === 'aws-key' && x.value === 'AKIAIOSFODNN7EXAMPLE'));
});

test('iocs: flags suspicious PowerShell command', () => {
  const i = iocsFor("run('powershell -nop -WindowStyle Hidden -enc SQBFAFgA')");
  assert.ok(i.some(x => x.type === 'suspicious-command'));
});

test('iocs: registry key', () => {
  const i = iocsFor("p='HKCU\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run'");
  assert.ok(i.some(x => x.type === 'registry-key'));
});

test('iocs: registrable domain denylist handles multi-label TLDs', () => {
  // a real C2 on a multi-label TLD IS reported...
  const evil = iocsFor("x='login.evil-bank.co.uk'");
  assert.ok(evil.some(x => x.type === 'domain' && x.value === 'login.evil-bank.co.uk'));
});

test('iocs: decodes a short atob() argument and recovers nested URL', () => {
  // base64 of "https://hidden.bad/x" — under the 80-char blob threshold,
  // but the atob() call site is the signal.
  const b64 = Buffer.from('https://hidden.bad/x').toString('base64');
  const i = iocsFor(`atob('${b64}')`);
  assert.ok(i.some(x => x.type === 'url' && x.value === 'https://hidden.bad/x'),
    `expected nested URL, got: ${i.map(x => x.type + ':' + x.value).join(', ')}`);
});

test('iocs: defang renders network indicators safely', () => {
  const i = iocsFor("fetch('http://evil.test/a')");
  const url = i.find(x => x.type === 'url');
  assert.ok(url);
  assert.equal(defang(url!.value), 'hxxp[://]evil[.]test/a');
});

test('iocs: extracts long base64 blob as base64 IOC', () => {
  // 96-char base64 (length passes the >= 80 threshold)
  const blob = 'YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXowMTIzNDU2Nzg5K2Ev'
             + 'YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXowMTIzNDU2Nzg5K2E=';
  const i = iocsFor(`const x = "${blob}"`);
  assert.ok(i.some(x => x.type === 'base64'));
});

test('iocs: email regex does not backtrack catastrophically', () => {
  // Pathological for the old /[a-z0-9.-]+\.[a-z]{2,24}/ domain part.
  const evil = 'x@' + 'a.'.repeat(50000) + '!';
  const start = Date.now();
  iocsFor(`const s = ${JSON.stringify(evil)};`);
  assert.ok(Date.now() - start < 1000, 'email scan must stay near-linear');
});

test('iocs: still extracts a normal email', () => {
  const i = iocsFor("const e = 'attacker@evil-domain.co.uk';");
  assert.ok(i.some(x => x.type === 'email' && x.value === 'attacker@evil-domain.co.uk'));
});

test('iocs: oversized base64 blob is recorded but not decoded/recursed', () => {
  // A >1 MiB base64 blob that decodes to a URL. It should be recorded as a
  // base64 IOC, but the nested URL must NOT be surfaced (decode is capped).
  const inner = Buffer.from('http://nested-c2.example/x').toString('base64');
  const blob  = 'A'.repeat(1_100_000) + inner;   // > MAX_DECODE_BASE64_LEN
  const start = Date.now();
  const i = iocsFor(`const b = '${blob}';`);
  assert.ok(Date.now() - start < 2000, 'must not decode+rescan a giant blob');
  assert.ok(i.some(x => x.type === 'base64'), 'blob still recorded');
  assert.ok(!i.some(x => x.type === 'url' && x.value.includes('nested-c2')),
    'nested URL must not be decoded out of an oversized blob');
});
