/**
 * Encoded-payload detector + static recoverer.
 *
 * Handles two more families beyond obfuscator.io's string-array:
 *
 *   1. XOR loop with a string key (the skimmer/Magecart staple).
 *      Detects a function whose body is essentially:
 *        for (i in s) out += String.fromCharCode(s.charCodeAt(i) ^ k.charCodeAt(i % k.length))
 *      and a call to that function with two string-literal arguments.
 *      Statically recovers the plaintext.
 *
 *   2. AAEncode (and close JJEncode relatives).
 *      Detects the unmistakable katakana-heavy ASCII-art encoding.
 *      Does NOT statically recover — the encoding is designed to eval to
 *      runnable JS, so recovery requires execution. Use the docker sandbox
 *      or --reachability (which routes through evalscope-worker.cjs) for
 *      that. We emit a Finding flagging the pattern so the analyst knows
 *      to reach for those tools.
 */

import { traverse } from '../util';
import * as t from '@babel/types';
import type { File } from '@babel/types';
import type { Finding } from '../types';

export function analyzeEncoded(ast: File, filePath: string): Finding[] {
  const findings: Finding[] = [];

  // ── (1) AAEncode signature ──────────────────────────────────────────────
  // The encoding uses these katakana/half-width markers heavily.
  // Detection is content-based (regex over the source representation of any
  // string literal that's been left as-is, or comments — but we don't see
  // comments here). Simplest reliable signal: source contains the literal
  // "ﾟωﾟﾉ" or "ﾟДﾟ" with several occurrences. Since we have an AST, we look
  // for an ExpressionStatement that's just a long chain of computed member
  // accesses / index ops with the distinctive parameter shape.
  // Pragmatic alternative: scan the file's source string from the AST's
  // tokens — but we don't have raw source here. So we look at the file
  // first line of code via the program body and check identifiers / string
  // literals for the markers.
  let katakanaHits = 0;
  traverse(ast, {
    Identifier(path) {
      if (/[ｦ-ﾟ]|[゠-ヿ]/.test(path.node.name)) katakanaHits++;
    },
    StringLiteral(path) {
      if (/[ｦ-ﾟ]|[゠-ヿ]/.test(path.node.value)) katakanaHits++;
    },
  });
  if (katakanaHits >= 5) {
    // Report at the first program statement's location.
    const first = ast.program.body[0];
    findings.push({
      type:       'obfuscation-pattern',
      file:       filePath,
      line:       first?.loc?.start.line ?? 1,
      column:     first?.loc?.start.column ?? 0,
      message:    `AAEncode-family encoding detected (${katakanaHits} katakana tokens) — payload requires execution to recover; run via scripts/analyze.sh or --reachability`,
      confidence: 'high',
    });
  }

  // ── (2) XOR decoder loop + static recovery ──────────────────────────────
  // Find function declarations / expressions whose body looks like the
  // canonical XOR-decoder shape, and remember their names so we can
  // statically evaluate calls to them.
  const xorDecoders = new Map<string, XorDecoder>();
  collectXorDecoders(ast, xorDecoders);

  if (xorDecoders.size > 0) {
    // For each call site of a known XOR decoder with two string-literal
    // arguments, attempt static recovery.
    traverse(ast, {
      CallExpression(path) {
        const callee = path.node.callee;
        if (!t.isIdentifier(callee)) return;
        const dec = xorDecoders.get(callee.name);
        if (!dec) return;
        const args = path.node.arguments;
        if (args.length !== 2) return;
        if (!t.isStringLiteral(args[0]) || !t.isStringLiteral(args[1])) return;

        const a = args[0].value;
        const b = args[1].value;
        const s = dec.swapped ? b : a;
        const k = dec.swapped ? a : b;
        if (s.length === 0 || k.length === 0) return;

        let recovered = '';
        for (let i = 0; i < s.length; i++) {
          recovered += String.fromCharCode(s.charCodeAt(i) ^ k.charCodeAt(i % k.length));
        }
        // Only report if the result looks like printable text — otherwise
        // we may have matched something XOR-shaped that isn't a decoder.
        if (!isMostlyPrintable(recovered)) return;

        findings.push({
          type:       'obfuscation-pattern',
          file:       filePath,
          line:       path.node.loc?.start.line   ?? 0,
          column:     path.node.loc?.start.column ?? 0,
          message:    `XOR decoder ${callee.name}(${s.length}-char input, ${k.length}-char key) → ${truncate(recovered, 200)}`,
          confidence: 'high',
        });
      },
    });
  }

  return findings;
}

// ---------------------------------------------------------------------------
// XOR decoder detection
// ---------------------------------------------------------------------------

interface XorDecoder {
  /** True if the function takes (key, ciphertext) instead of (ciphertext, key). */
  swapped: boolean;
}

function collectXorDecoders(ast: File, out: Map<string, XorDecoder>): void {
  traverse(ast, {
    Function(path) {
      const node = path.node;
      let name: string | null = null;
      if (t.isFunctionDeclaration(node) && node.id) name = node.id.name;
      else if ((t.isFunctionExpression(node) || t.isArrowFunctionExpression(node)) &&
               t.isVariableDeclarator(path.parent) && t.isIdentifier(path.parent.id))
        name = path.parent.id.name;
      if (!name) return;

      const params = node.params;
      if (params.length !== 2) return;
      if (!t.isIdentifier(params[0]) || !t.isIdentifier(params[1])) return;
      const p0 = params[0].name;
      const p1 = params[1].name;

      if (!t.isBlockStatement(node.body)) return;

      // Walk the body once (instead of JSON.stringify-ing the whole subtree and
      // running per-function regexes over the text) to detect the XOR-decoder
      // shape: charCodeAt on both params, a `^` op, accumulation via
      // fromCharCode, and a `% key.length` wraparound.
      let usesXor = false, usesCC = false, usesFromCC = false, usesMod = false;
      let refsP0 = false, refsP1 = false;
      let keyParam: string | null = null;

      path.traverse({
        BinaryExpression(inner) {
          if (inner.node.operator === '^') usesXor = true;
          if (inner.node.operator === '%') {
            usesMod = true;
            // The param whose `.length` is the modulus is the KEY.
            const r = inner.node.right;
            if (keyParam === null && t.isMemberExpression(r) && !r.computed &&
                t.isIdentifier(r.object) && t.isIdentifier(r.property) &&
                r.property.name === 'length') {
              keyParam = r.object.name;
            }
          }
        },
        MemberExpression(inner) {
          if (!inner.node.computed && t.isIdentifier(inner.node.property)) {
            if (inner.node.property.name === 'charCodeAt')   usesCC = true;
            if (inner.node.property.name === 'fromCharCode') usesFromCC = true;
          }
        },
        Identifier(inner) {
          if (inner.node.name === p0) refsP0 = true;
          else if (inner.node.name === p1) refsP1 = true;
        },
      });

      if (!(usesXor && usesCC && usesFromCC && usesMod && refsP0 && refsP1)) return;

      // first param is the key → arguments are (key, ciphertext), i.e. swapped
      out.set(name, { swapped: keyParam === p0 });
    },
  });
}

function isMostlyPrintable(s: string): boolean {
  if (s.length === 0) return false;
  let printable = 0;
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if ((c >= 32 && c < 127) || c === 9 || c === 10 || c === 13) printable++;
  }
  return printable / s.length > 0.85;
}

function truncate(s: string, n: number): string {
  if (s.length <= n) return s;
  return s.slice(0, n - 1) + '…';
}
