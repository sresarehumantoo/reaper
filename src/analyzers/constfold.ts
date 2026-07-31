/**
 * Generic constant-folding / partial-evaluation pass.
 *
 * Complements the obfuscator.io string-array rewriter by collapsing the
 * *other* mechanical transforms obfuscators lean on, so a recovered sample
 * reads like source instead of an expression soup:
 *
 *   - atob("...") / unescape / decodeURI(Component)        → string literal
 *   - String.fromCharCode(72, 73)                          → "HI"
 *   - parseInt("0x1f", 16) / Number("42")                  → numeric literal
 *   - "a" + "b" + "c", ["a","b"].join("")                  → concatenated string
 *   - 0x1a ^ 0x2b, 3 * 7, 1 << 4 (pure-literal arithmetic) → numeric literal
 *   - !0 / !1 / !![] , void 0                              → true / false / undefined
 *   - obj["prop"]  (when "prop" is an identifier)          → obj.prop
 *
 * Only pure, literal-operand expressions are evaluated — nothing that touches
 * an identifier, a call to an unknown function, or anything with side effects.
 * Runs to a fixpoint (folding a concat can expose a foldable join, etc.).
 *
 * Hex/unicode string escapes (\x48, H) and numeric-literal obfuscation
 * are normalised for free because the pass re-generates from the AST.
 */

import * as t from '@babel/types';
import { parseCode } from '../parser';
import { traverse, generate } from '../util';

export interface FoldResult {
  code:    string;   // folded source (or the original if nothing changed / parse failed)
  changes: number;   // total node replacements applied
  passes:  number;   // fixpoint iterations performed
  error?:  string;
}

const MAX_PASSES = 6;

export function foldConstants(source: string, filePath = 'input.js'): FoldResult {
  let code = source;
  let total = 0;
  let passes = 0;

  try {
    for (; passes < MAX_PASSES; passes++) {
      // Use the shared parser options so folding sees the same syntax the rest
      // of the pipeline does — JSX, decorators, optional chaining, Flow. The
      // previous inline parse only enabled `typescript`, so any input using
      // those threw and silently returned the source unfolded.
      const ast = parseCode(code, filePath);

      const changed = runPass(ast);
      if (changed === 0) break;
      total += changed;
      code = generate(ast, { comments: true, jsescOption: { minimal: true } }).code;
    }
  } catch (e: any) {
    return { code: source, changes: total, passes, error: e?.message ?? String(e) };
  }

  return { code, changes: total, passes };
}

function runPass(ast: t.File): number {
  let changes = 0;

  traverse(ast, {
    // ── Pure binary arithmetic / string concat ─────────────────────────────
    BinaryExpression: {
      exit(path) {
        const { left, right, operator } = path.node;
        if (!isLiteral(left) || !isLiteral(right)) return;
        const l = literalValue(left), r = literalValue(right);
        const folded = evalBinary(operator, l, r);
        if (folded === undefined) return;
        const node = toNode(folded);
        if (node) { path.replaceWith(node); changes++; }
      },
    },

    // ── Unary !, -, ~, +, void ─────────────────────────────────────────────
    UnaryExpression: {
      exit(path) {
        const { operator, argument } = path.node;
        if (operator === 'void') {
          if (isLiteral(argument)) { path.replaceWith(t.identifier('undefined')); changes++; }
          return;
        }
        if (operator === '!') {
          // Fold !<literal> and !![]/![] style truthiness.
          const v = truthinessOf(argument);
          if (v !== undefined) { path.replaceWith(t.booleanLiteral(!v)); changes++; }
          return;
        }
        if (!isLiteral(argument)) return;
        const a = literalValue(argument);
        if (typeof a !== 'number') return;
        const folded = operator === '-' ? -a : operator === '+' ? +a : operator === '~' ? ~a : undefined;
        if (folded === undefined) return;
        path.replaceWith(t.numericLiteral(folded));
        changes++;
      },
    },

    // ── Calls: atob, fromCharCode, parseInt, join, decode/unescape ─────────
    CallExpression: {
      exit(path) {
        const folded = foldCall(path.node);
        if (folded !== undefined) {
          const node = toNode(folded);
          if (node) { path.replaceWith(node); changes++; }
        }
      },
    },

    // ── obj["ident"] → obj.ident (readability) ─────────────────────────────
    MemberExpression: {
      exit(path) {
        const node = path.node;
        if (!node.computed) return;
        if (!t.isStringLiteral(node.property)) return;
        if (!/^[A-Za-z_$][A-Za-z0-9_$]*$/.test(node.property.value)) return;
        node.property = t.identifier(node.property.value);
        node.computed = false;
        changes++;
      },
    },
  });

  return changes;
}

// ── Call folding ────────────────────────────────────────────────────────────

function foldCall(node: t.CallExpression): string | number | undefined {
  const callee = node.callee;

  // String.fromCharCode(...nums)
  if (t.isMemberExpression(callee) && !callee.computed &&
      t.isIdentifier(callee.object, { name: 'String' }) &&
      t.isIdentifier(callee.property, { name: 'fromCharCode' })) {
    const codes = node.arguments.map(numericArg);
    if (codes.every(c => c !== undefined) && codes.length > 0) {
      return String.fromCharCode(...(codes as number[]));
    }
    return undefined;
  }

  // [literals].join(sep?)
  if (t.isMemberExpression(callee) && !callee.computed &&
      t.isIdentifier(callee.property, { name: 'join' }) &&
      t.isArrayExpression(callee.object)) {
    const parts = callee.object.elements.map(el => (el && isLiteral(el)) ? String(literalValue(el)) : undefined);
    if (parts.every(p => p !== undefined)) {
      const sep = node.arguments.length === 0 ? ','
        : (node.arguments[0] && isLiteral(node.arguments[0] as t.Node) ? String(literalValue(node.arguments[0] as t.Expression)) : undefined);
      if (sep !== undefined) return (parts as string[]).join(sep);
    }
    return undefined;
  }

  if (!t.isIdentifier(callee)) return undefined;
  const fn = callee.name;
  const a0 = node.arguments[0];

  // atob("base64") → decoded (latin1, matching browser atob semantics)
  if (fn === 'atob' && t.isStringLiteral(a0)) {
    try { return Buffer.from(a0.value, 'base64').toString('latin1'); } catch { return undefined; }
  }
  // btoa("text") → base64
  if (fn === 'btoa' && t.isStringLiteral(a0)) {
    try { return Buffer.from(a0.value, 'latin1').toString('base64'); } catch { return undefined; }
  }
  // unescape / decodeURI / decodeURIComponent
  if ((fn === 'unescape' || fn === 'decodeURI' || fn === 'decodeURIComponent') && t.isStringLiteral(a0)) {
    try {
      // Each has distinct semantics — decodeURI leaves reserved chars (%2F etc.)
      // intact, decodeURIComponent decodes them; conflating them yields wrong
      // constants.
      const impl = fn === 'unescape' ? globalThis.unescape
                 : fn === 'decodeURI' ? decodeURI
                 : decodeURIComponent;
      return impl(a0.value);
    } catch { return undefined; }
  }
  // parseInt("ff", 16) / parseInt("0x1f")
  if (fn === 'parseInt' && t.isStringLiteral(a0)) {
    const radix = numericArg(node.arguments[1]);
    const v = parseInt(a0.value, radix);
    return Number.isNaN(v) ? undefined : v;
  }
  // Number("42")
  if (fn === 'Number' && t.isStringLiteral(a0)) {
    const v = Number(a0.value);
    return Number.isNaN(v) ? undefined : v;
  }
  return undefined;
}

// ── Literal helpers ───────────────────────────────────────────────────────

function isLiteral(n: t.Node): n is t.StringLiteral | t.NumericLiteral | t.BooleanLiteral {
  return t.isStringLiteral(n) || t.isNumericLiteral(n) || t.isBooleanLiteral(n);
}

function literalValue(n: t.Node): string | number | boolean {
  if (t.isStringLiteral(n) || t.isNumericLiteral(n) || t.isBooleanLiteral(n)) return n.value;
  return undefined as never;
}

function numericArg(n: t.Node | undefined | null): number | undefined {
  if (!n) return undefined;
  if (t.isNumericLiteral(n)) return n.value;
  if (t.isUnaryExpression(n) && n.operator === '-' && t.isNumericLiteral(n.argument)) return -n.argument.value;
  return undefined;
}

// Static truthiness for !-folding. Handles literals and the empty-array /
// array-literal idioms obfuscators use (![] === false, !![] === true).
function truthinessOf(n: t.Node): boolean | undefined {
  if (t.isStringLiteral(n)) return n.value.length > 0;
  if (t.isNumericLiteral(n)) return n.value !== 0;
  if (t.isBooleanLiteral(n)) return n.value;
  if (t.isArrayExpression(n) || t.isObjectExpression(n)) return true; // objects/arrays are truthy
  if (t.isNullLiteral(n)) return false;
  return undefined;
}

function evalBinary(op: string, l: any, r: any): string | number | boolean | undefined {
  switch (op) {
    case '+':   return l + r;   // JS handles string vs numeric coercion
    case '-':   return l - r;
    case '*':   return l * r;
    case '/':   return r === 0 ? undefined : l / r;
    case '%':   return r === 0 ? undefined : l % r;
    case '**':  return l ** r;
    case '^':   return l ^ r;
    case '&':   return l & r;
    case '|':   return l | r;
    case '<<':  return l << r;
    case '>>':  return l >> r;
    case '>>>': return l >>> r;
    default:    return undefined;   // comparisons left alone — they affect control flow
  }
}

function toNode(v: string | number | boolean): t.Expression | undefined {
  if (typeof v === 'string') return t.stringLiteral(v);
  if (typeof v === 'boolean') return t.booleanLiteral(v);
  if (typeof v === 'number' && Number.isFinite(v)) {
    return v < 0 ? t.unaryExpression('-', t.numericLiteral(-v)) : t.numericLiteral(v);
  }
  return undefined;
}
