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

import _traverse from '@babel/traverse';
import * as t from '@babel/types';
import type { File } from '@babel/types';
import type { Finding } from '../types';

const traverse = (typeof _traverse === 'function'
  ? _traverse
  : (_traverse as any).default) as typeof _traverse;

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

      const block = t.isBlockStatement(node.body) ? node.body : null;
      if (!block) return;
      const code = serialize(block);

      // Heuristic: body uses charCodeAt on both params, BinaryExpression
      // with operator '^', and accumulates via String.fromCharCode.
      const usesXor    = /\^/.test(code);
      const usesCC     = /charCodeAt/.test(code);
      const usesFromCC = /fromCharCode/.test(code);
      const usesMod    = /%/.test(code);                    // key wraparound
      const refsP0     = new RegExp(`\\b${escape(p0)}\\b`).test(code);
      const refsP1     = new RegExp(`\\b${escape(p1)}\\b`).test(code);

      if (!(usesXor && usesCC && usesFromCC && refsP0 && refsP1)) return;
      // Mod-by-key-length is the most reliable marker; require it.
      if (!usesMod) return;

      // Decide which param is the ciphertext: whichever is indexed without
      // the modulo wraparound. Heuristic: the param referenced inside a
      // `% paramName.length` is the KEY (the other is the ciphertext).
      const keyParam = /(\w+)\s*\.\s*length\s*\)?\s*[,\)]/.exec(code)?.[1];
      const swapped  = keyParam === p0;     // first param is the key → swapped

      out.set(name, { swapped });
    },
  });
}

function serialize(n: t.Node): string {
  // Cheap "what's in this subtree" check — we look at all string-able
  // tokens via JSON.stringify. Not a real source representation, but
  // good enough for substring tests.
  try { return JSON.stringify(n); } catch { return ''; }
}

function escape(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
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
