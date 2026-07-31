import { test } from 'node:test';
import { strict as assert } from 'node:assert';
import { renderIocValue, locLabel, forEachNamedFunction } from '../src/util';
import { parseCode } from '../src/parser';

test('renderIocValue: defangs only defangable types when enabled', () => {
  assert.equal(renderIocValue('url', 'http://evil.com', true), 'hxxp[://]evil[.]com');
  assert.equal(renderIocValue('url', 'http://evil.com', false), 'http://evil.com');
  assert.equal(renderIocValue('evm-address', '0xabc', true), '0xabc'); // not defangable
});

test('locLabel: line:col, with optional end line', () => {
  assert.equal(locLabel(12, 5), '12:5');
  assert.equal(locLabel(12, 5, 20), '12:5-20');
  assert.equal(locLabel(12, 5, 12), '12:5');   // endLine === line collapses
});

test('forEachNamedFunction: yields declarations, expressions, and arrows', () => {
  const ast = parseCode(
    'function a(){}\nconst b = function(){};\nvar c = () => {};\nlet d = 1;',
    'f.js');
  const found: Record<string, string> = {};
  forEachNamedFunction(ast, ({ name, kind }) => { found[name] = kind; });
  assert.deepEqual(found, { a: 'declaration', b: 'expression', c: 'arrow' });
});
