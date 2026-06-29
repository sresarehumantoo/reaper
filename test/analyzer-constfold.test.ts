import { test } from 'node:test';
import { strict as assert } from 'node:assert';
import { foldConstants } from '../src/analyzers/constfold';

const fold = (src: string) => foldConstants(src).code.trim();

test('constfold: String.fromCharCode → string literal', () => {
  assert.match(fold('var x = String.fromCharCode(72, 105);'), /"Hi"/);
});

test('constfold: atob() → decoded string', () => {
  const b64 = Buffer.from('alert(1)').toString('base64');
  assert.match(fold(`var x = atob("${b64}");`), /"alert\(1\)"/);
});

test('constfold: parseInt with radix → number', () => {
  assert.match(fold('var x = parseInt("ff", 16);'), /\b255\b/);
});

test('constfold: string concat chain → single literal', () => {
  assert.match(fold('var x = "ab" + "cd" + "ef";'), /"abcdef"/);
});

test('constfold: array join → string', () => {
  assert.match(fold('var x = ["a","b","c"].join("");'), /"abc"/);
});

test('constfold: pure arithmetic (xor) → number', () => {
  assert.match(fold('var x = 0x1a ^ 0x2b;'), /\b49\b/);
});

test('constfold: bracket member with identifier key → dot', () => {
  assert.match(fold('window["eval"]("x");'), /window\.eval/);
});

test('constfold: !0/![]/!![] truthiness folding', () => {
  assert.match(fold('var a = !0, b = ![], c = !![];'), /a = true/);
  assert.match(fold('var a = !0, b = ![], c = !![];'), /b = false/);
  assert.match(fold('var a = !0, b = ![], c = !![];'), /c = true/);
});

test('constfold: reaches a fixpoint across layers', () => {
  // fromCharCode produces "41", concatenated then... just verify nesting folds.
  const src = 'var x = String.fromCharCode(104) + String.fromCharCode(105);';
  assert.match(fold(src), /"hi"/);
});

test('constfold: leaves non-constant expressions untouched', () => {
  const r = foldConstants('var x = a + b; foo(y);');
  assert.equal(r.changes, 0);
});

test('constfold: does not divide by zero', () => {
  const r = foldConstants('var x = 1 / 0;');
  assert.equal(r.changes, 0);
});
