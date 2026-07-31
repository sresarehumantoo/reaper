/**
 * p,a,c,k,e,r detector and static unpacker.
 *
 * Detects the Dean Edwards / p,a,c,k,e,r format:
 *   eval(function(p,a,c,k,e,d){ ... }('packed', base, count, ['k','e','y',...], 0, {}))
 *
 * Performs a pure-static unpack without executing any code, by reimplementing
 * the substitution algorithm in TypeScript.  This is safer than eval-based
 * unpacking for untrusted malware samples.
 *
 * Also detects variants where the key array is built via .split('|').
 */

import _traverse from '@babel/traverse';
import * as t from '@babel/types';
import type { File } from '@babel/types';

const traverse = (typeof _traverse === 'function'
  ? _traverse
  : (_traverse as any).default) as typeof _traverse;

export interface PackerInfo {
  detected:   boolean;
  base:       number;
  count:      number;
  keys:       string[];
  packed:     string;
  unpacked:   string | null;
  error:      string | null;
}

// ---------------------------------------------------------------------------
// Detection + static unpack
// ---------------------------------------------------------------------------

export function detectPacker(ast: File): PackerInfo[] {
  const results: PackerInfo[] = [];

  traverse(ast, {
    CallExpression(path) {
      // Must be eval(...)
      if (!t.isIdentifier(path.node.callee, { name: 'eval' })) return;
      const outerArg = path.node.arguments[0];

      // Argument must be a call: (function(p,a,c,k,e,d){...})(...)
      if (!outerArg || !t.isCallExpression(outerArg)) return;
      const fn = outerArg.callee;
      if (!t.isFunctionExpression(fn)) return;

      // Parameter names — canonical is p,a,c,k,e,d but may differ
      if (fn.params.length < 4) return;

      const callArgs = outerArg.arguments;
      if (callArgs.length < 4) return;

      // callArgs[0] = packed string p
      // callArgs[1] = base a
      // callArgs[2] = count c
      // callArgs[3] = key array k
      const packedNode = callArgs[0];
      const baseNode   = callArgs[1];
      const countNode  = callArgs[2];
      const keysNode   = callArgs[3];

      if (!t.isStringLiteral(packedNode))  return;
      if (!t.isNumericLiteral(baseNode))   return;
      if (!t.isNumericLiteral(countNode))  return;

      const packed = packedNode.value;
      const base   = baseNode.value;
      const count  = countNode.value;
      const keys   = extractKeyArray(keysNode);

      if (keys === null) return;

      // `base` and `count` are attacker-controlled numeric literals; `count`
      // drives staticUnpack's build loop. A hostile sample can set count to 1e9
      // with an empty key array to OOM/hang the analyzer. Real p,a,c,k,e,d
      // always has count === keys.length, and any index >= keys.length maps a
      // token to its own base-encoding (a no-op in the final replace), so
      // clamping to the dictionary size is loss-free while defusing the bomb.
      if (base < 2 || base > 62) return;
      const maxCount = keys.length > 0 ? keys.length : packed.length;
      const safeCount = Number.isFinite(count) && count > 0 ? Math.min(count, maxCount) : 0;

      const info: PackerInfo = {
        detected: true,
        base,
        count,
        keys,
        packed,
        unpacked: null,
        error:    count !== safeCount ? `count ${count} clamped to ${safeCount}` : null,
      };

      try {
        info.unpacked = staticUnpack(packed, base, safeCount, keys);
      } catch (e: any) {
        info.error = e.message;
      }

      results.push(info);
    },
  });

  return results;
}

// ---------------------------------------------------------------------------
// Key array extraction
// ---------------------------------------------------------------------------

function extractKeyArray(node: t.Node): string[] | null {
  // Direct array literal: ['a', 'b', 'c']
  if (t.isArrayExpression(node)) {
    const els = node.elements;
    if (els.some(e => e === null || !t.isStringLiteral(e))) return null;
    return (els as t.StringLiteral[]).map(e => e.value);
  }

  // 'a|b|c'.split('|')
  if (
    t.isCallExpression(node) &&
    t.isMemberExpression(node.callee) &&
    t.isStringLiteral(node.callee.object) &&
    t.isIdentifier(node.callee.property, { name: 'split' }) &&
    node.arguments.length === 1 &&
    t.isStringLiteral(node.arguments[0])
  ) {
    return node.callee.object.value.split(node.arguments[0].value);
  }

  return null;
}

// ---------------------------------------------------------------------------
// Static substitution (mirrors the packer's runtime algorithm)
// ---------------------------------------------------------------------------

function toBase(n: number, base: number): string {
  // The packer uses c.toString(a) where a is the base (2–62)
  if (base <= 36) return n.toString(base);

  // Bases > 36 use custom alphabet
  const digits = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
  let result = '';
  do {
    result = digits[n % base] + result;
    n = Math.floor(n / base);
  } while (n > 0);
  return result;
}

function staticUnpack(
  packed: string,
  base:   number,
  count:  number,
  keys:   string[],
): string {
  // Build lookup table: d[toBase(i, base)] = keys[i] || toBase(i, base)
  const lookup: Record<string, string> = {};
  for (let i = 0; i < count; i++) {
    const encoded = toBase(i, base);
    lookup[encoded] = keys[i] || encoded;
  }

  // Replace every word token in packed with its lookup value
  return packed.replace(/\w+/g, token => lookup[token] ?? token);
}
