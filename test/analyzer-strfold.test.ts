import { test } from 'node:test';
import { strict as assert } from 'node:assert';
import * as t from '@babel/types';
import { foldStrings } from '../src/analyzers/strfold';
import { parseCode } from '../src/parser';

test('strfold: folds a simple concatenation with char offsets', () => {
  const r = foldStrings(parseCode("var x = 'ab' + 'cd';", 's.js'));
  const x = r.find(f => f.varName === 'x');
  assert.ok(x && x.value === 'abcd' && x.pieces === 2);
  assert.ok(typeof x.start === 'number' && typeof x.end === 'number');
});

test('strfold: folds a left-nested + chain via the iterative spine walk', () => {
  // Built directly so it's a genuine deep left-nested tree. (Depths beyond
  // Babel's own recursion ceiling are bounded by Babel and caught by callers.)
  let expr: t.Expression = t.stringLiteral('a');
  for (let i = 0; i < 500; i++) expr = t.binaryExpression('+', expr, t.stringLiteral('a'));
  const file = t.file(t.program([
    t.variableDeclaration('var', [t.variableDeclarator(t.identifier('x'), expr)]),
  ]));
  const x = foldStrings(file).find(f => f.varName === 'x');
  assert.ok(x && x.value.length === 501, 'chain folds to a single literal');
});
