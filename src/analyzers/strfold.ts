/**
 * Constant string folding.
 *
 * Walks a function body (or any AST subtree) and evaluates any expression
 * that reduces entirely to a string literal via binary `+` concatenation,
 * template literals with no expressions, or nested combinations.
 *
 * Primary use case: reconstructing split/fragmented strings inside dead
 * functions, e.g.
 *   var flag = 'HTB{y' + '0u_5h' + '0uld_' + 'n3v3r' + ... + '}'
 *
 * Returns every variable whose initialiser fully folds to a string, along
 * with the reconstructed value.
 */

import _traverse from '@babel/traverse';
import * as t from '@babel/types';
import type { File } from '@babel/types';

const traverse = (typeof _traverse === 'function'
  ? _traverse
  : (_traverse as any).default) as typeof _traverse;

export interface FoldedString {
  varName: string;
  value:   string;
  line:    number;
  pieces:  number;   // how many string literals were concatenated
  start:   number | null;   // char offset of the declaration/return (for enclosing-fn attribution)
  end:     number | null;
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/** Fold all constant string assignments found anywhere in the given AST. */
export function foldStrings(ast: File): FoldedString[] {
  const results: FoldedString[] = [];

  traverse(ast, {
    VariableDeclarator(path) {
      if (!t.isIdentifier(path.node.id)) return;
      const init = path.node.init;
      if (!init) return;

      const result = evalStringExpr(init);
      if (result === null) return;

      results.push({
        varName: path.node.id.name,
        value:   result.value,
        line:    path.node.loc?.start.line ?? 0,
        pieces:  result.pieces,
        start:   path.node.start ?? null,
        end:     path.node.end ?? null,
      });
    },

    // Also catch: return 'a' + 'b' + ...
    ReturnStatement(path) {
      if (!path.node.argument) return;
      const result = evalStringExpr(path.node.argument);
      if (result === null || result.pieces < 2) return;

      results.push({
        varName: '(return value)',
        value:   result.value,
        line:    path.node.loc?.start.line ?? 0,
        pieces:  result.pieces,
        start:   path.node.start ?? null,
        end:     path.node.end ?? null,
      });
    },
  });

  return results;
}

/** Fold strings found inside a specific named function in the AST. */
export function foldStringsInFunction(ast: File, fnName: string): FoldedString[] {
  const results: FoldedString[] = [];

  traverse(ast, {
    FunctionDeclaration(path) {
      if (path.node.id?.name !== fnName) return;
      results.push(...foldStrings(path.node as unknown as File));
    },
    VariableDeclarator(path) {
      if (!t.isIdentifier(path.node.id) || path.node.id.name !== fnName) return;
      const init = path.node.init;
      if (!init || !t.isFunctionExpression(init)) return;
      results.push(...foldStrings(init as unknown as File));
    },
  });

  return results;
}

// ---------------------------------------------------------------------------
// Core evaluator
// ---------------------------------------------------------------------------

interface EvalResult {
  value:  string;
  pieces: number;
}

function evalStringExpr(node: t.Node): EvalResult | null {
  // Plain string literal
  if (t.isStringLiteral(node)) {
    return { value: node.value, pieces: 1 };
  }

  // Template literal with no expressions: `hello`
  if (t.isTemplateLiteral(node) && node.expressions.length === 0) {
    const cooked = node.quasis[0]?.value.cooked;
    return cooked != null ? { value: cooked, pieces: 1 } : null;
  }

  // Binary + concatenation
  if (t.isBinaryExpression(node) && node.operator === '+') {
    const left  = evalStringExpr(node.left);
    const right = evalStringExpr(node.right);
    if (left === null || right === null) return null;
    return {
      value:  left.value + right.value,
      pieces: left.pieces + right.pieces,
    };
  }

  // Sequence expression: ('a', 'b', 'c') → last value
  if (t.isSequenceExpression(node)) {
    const last = node.expressions.at(-1);
    return last ? evalStringExpr(last) : null;
  }

  // Parenthesised expression — babel usually flattens these but guard anyway
  if (t.isParenthesizedExpression?.(node)) {
    return evalStringExpr((node as any).expression);
  }

  return null;
}
