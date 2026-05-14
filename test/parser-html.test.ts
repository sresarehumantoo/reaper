import { test } from 'node:test';
import { strict as assert } from 'node:assert';
import { extractScriptsFromHtml, isHtmlPath } from '../src/parser/html';
import { example, fixture } from './helpers';

test('isHtmlPath: recognises .html and .htm', () => {
  assert.equal(isHtmlPath('foo.html'), true);
  assert.equal(isHtmlPath('foo.HTM'), true);
  assert.equal(isHtmlPath('foo.htm'), true);
  assert.equal(isHtmlPath('foo.js'),  false);
  assert.equal(isHtmlPath('foo.ts'),  false);
});

test('extractScriptsFromHtml: extracts inline, base64 data URI, and percent-encoded data URI', () => {
  const scripts = extractScriptsFromHtml(fixture('html-with-scripts.html'));

  // Should find: 2 inline + 1 base64 data URI + 1 raw data URI = 4 scripts
  // The external src, the JSON script, and the trap inside the comment should all be skipped.
  assert.equal(scripts.length, 4, `expected 4 scripts, got ${scripts.length}: ${scripts.map(s => s.origin).join(', ')}`);

  const byOrigin = Object.fromEntries(scripts.map(s => [s.origin, s.source]));
  assert.match(byOrigin['inline'],          /inline-a|inline-d/);
  assert.match(byOrigin['data-uri-base64'], /data-uri-b/);
  assert.match(byOrigin['data-uri-raw'],    /data-uri-c/);
});

test('extractScriptsFromHtml: comment containing <script src=...> does NOT trigger extraction', () => {
  const scripts = extractScriptsFromHtml(fixture('html-with-scripts.html'));
  // The comment contains literal "<script src="trap.js">". If extraction were
  // fooled, we'd see an extra entry whose src is "trap.js" or similar.
  for (const s of scripts) {
    assert.doesNotMatch(s.source, /trap\.js/, `script body should not contain trap content: ${s.source.slice(0, 80)}`);
  }
});

test('extractScriptsFromHtml: EtherHiding sample yields exactly one base64 data-URI script', () => {
  const scripts = extractScriptsFromHtml(example('etherhiding/sample.html'));
  assert.equal(scripts.length, 1);
  assert.equal(scripts[0].origin, 'data-uri-base64');
  // Decoded payload should be ~3.8 KB of JS that mentions eth_call after deobfuscation.
  // Here we just sanity-check it decoded to non-empty JS.
  assert.ok(scripts[0].source.length > 1000, `expected >1KB decoded JS, got ${scripts[0].source.length} bytes`);
  assert.match(scripts[0].source, /function/);
});

test('extractScriptsFromHtml: returns empty array for a JS-free HTML file', () => {
  const scripts = extractScriptsFromHtml(fixture('html-no-scripts.html'));
  assert.equal(scripts.length, 0);
});
