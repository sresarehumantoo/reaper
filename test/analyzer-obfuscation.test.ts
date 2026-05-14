import { test } from 'node:test';
import { strict as assert } from 'node:assert';
import { analyzeObfuscation } from '../src/analyzers/obfuscation';
import { parseCode } from '../src/parser';

function findingsFor(src: string) {
  return analyzeObfuscation(parseCode(src, 'inline.js'), 'inline.js');
}

test('obfuscation: flags direct eval()', () => {
  const f = findingsFor('eval("1+1")');
  assert.equal(f.length, 1);
  assert.equal(f[0].type, 'eval-usage');
  assert.equal(f[0].confidence, 'high');
});

test('obfuscation: flags new Function() and Function constructor', () => {
  const f = findingsFor('var x = new Function("return 1")');
  assert.ok(f.some(x => x.type === 'eval-usage'),
    'expected eval-usage finding for new Function');
});

test('obfuscation: flags setTimeout/setInterval with string arg', () => {
  const f = findingsFor('setTimeout("malicious()", 1000)');
  assert.ok(f.some(x => x.type === 'dynamic-execution'),
    'expected dynamic-execution finding for setTimeout(string)');
});

test('obfuscation: flags atob (base64 staging)', () => {
  const f = findingsFor('atob("aGVsbG8=")');
  assert.ok(f.some(x => x.type === 'obfuscation-pattern' && /atob/.test(x.message)),
    'expected atob obfuscation finding');
});

test('obfuscation: flags String.fromCharCode with many args', () => {
  const f = findingsFor('String.fromCharCode(72, 101, 108, 108, 111, 33)');
  assert.ok(f.some(x => x.type === 'obfuscation-pattern' && /fromCharCode/.test(x.message)),
    'expected fromCharCode finding');
});

test('obfuscation: flags bracket access to dangerous identifiers', () => {
  const f = findingsFor('window["eval"]("1+1")');
  assert.ok(f.some(x => x.type === 'obfuscation-pattern' && /\[.*eval.*\]/.test(x.message)),
    'expected bracket-access finding');
});

test('obfuscation: produces no findings on clean code', () => {
  const f = findingsFor('function add(a, b) { return a + b; }\nadd(1, 2);');
  assert.equal(f.length, 0);
});

test('obfuscation: does not double-fire eval+new Function detection', () => {
  // The implementation has a dedupe step at the end; verify it works.
  const f = findingsFor('var a = new Function("body")');
  const evalFindings = f.filter(x => x.type === 'eval-usage');
  assert.equal(evalFindings.length, 1, `expected exactly 1 eval-usage finding, got ${evalFindings.length}`);
});
