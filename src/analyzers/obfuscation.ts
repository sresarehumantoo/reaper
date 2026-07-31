import { traverse } from '../util';
import * as t from '@babel/types';
import type { File } from '@babel/types';
import type { Finding } from '../types';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function isCallee(node: t.CallExpression, name: string): boolean {
  return t.isIdentifier(node.callee, { name });
}

function isMemberCallee(node: t.CallExpression, obj: string, prop: string): boolean {
  return (
    t.isMemberExpression(node.callee) &&
    t.isIdentifier(node.callee.object, { name: obj }) &&
    t.isIdentifier(node.callee.property, { name: prop })
  );
}

// Shannon entropy of a string — high entropy suggests encoded/encrypted content
function entropy(s: string): number {
  const freq = new Map<string, number>();
  for (const c of s) freq.set(c, (freq.get(c) ?? 0) + 1);
  let h = 0;
  for (const count of freq.values()) {
    const p = count / s.length;
    h -= p * Math.log2(p);
  }
  return h;
}

// ---------------------------------------------------------------------------
// Analyzer
// ---------------------------------------------------------------------------

export function analyzeObfuscation(ast: File, filePath: string): Finding[] {
  const findings: Finding[] = [];

  traverse(ast, {
    // ── eval() ──────────────────────────────────────────────────────────────
    CallExpression(path) {
      const node = path.node;
      const loc  = node.loc;

      // eval(...)
      if (isCallee(node, 'eval')) {
        findings.push({
          type: 'eval-usage',
          file: filePath,
          line: loc?.start.line ?? 0,
          column: loc?.start.column ?? 0,
          message: 'Direct eval() call — common malware payload execution vector',
          confidence: 'high',
        });
        return;
      }

      // new Function(...) or Function(...)
      if (
        t.isNewExpression(path.node) &&
        t.isIdentifier((path.node as t.NewExpression).callee, { name: 'Function' })
      ) {
        findings.push({
          type: 'eval-usage',
          file: filePath,
          line: loc?.start.line ?? 0,
          column: loc?.start.column ?? 0,
          message: 'Function constructor used as eval alternative',
          confidence: 'high',
        });
        return;
      }

      // setTimeout / setInterval with string first arg
      if (
        (isCallee(node, 'setTimeout') || isCallee(node, 'setInterval')) &&
        node.arguments.length > 0 &&
        t.isStringLiteral(node.arguments[0])
      ) {
        const fnName = t.isIdentifier(node.callee) ? node.callee.name : 'timer';
        findings.push({
          type: 'dynamic-execution',
          file: filePath,
          line: loc?.start.line ?? 0,
          column: loc?.start.column ?? 0,
          message: `${fnName}(string) — string passed as executable code (implicit eval)`,
          confidence: 'high',
        });
        return;
      }

      // atob() — base64 decode, common for payload staging
      if (isCallee(node, 'atob')) {
        findings.push({
          type: 'obfuscation-pattern',
          file: filePath,
          line: loc?.start.line ?? 0,
          column: loc?.start.column ?? 0,
          message: 'atob() call — base64 decode often used to stage encoded payloads',
          confidence: 'medium',
        });
        return;
      }

      // String.fromCharCode(...) — char-code array technique
      if (isMemberCallee(node, 'String', 'fromCharCode') && node.arguments.length > 3) {
        findings.push({
          type: 'obfuscation-pattern',
          file: filePath,
          line: loc?.start.line ?? 0,
          column: loc?.start.column ?? 0,
          message: `String.fromCharCode() with ${node.arguments.length} args — char-code array string construction`,
          confidence: 'high',
        });
        return;
      }

      // document.write() — DOM injection
      if (isMemberCallee(node, 'document', 'write')) {
        findings.push({
          type: 'obfuscation-pattern',
          file: filePath,
          line: loc?.start.line ?? 0,
          column: loc?.start.column ?? 0,
          message: 'document.write() — commonly used to inject scripts or iframes',
          confidence: 'medium',
        });
        return;
      }
    },

    // ── new Function(...) handled via NewExpression ──────────────────────────
    NewExpression(path) {
      const node = path.node;
      if (t.isIdentifier(node.callee, { name: 'Function' })) {
        findings.push({
          type: 'eval-usage',
          file: filePath,
          line: node.loc?.start.line ?? 0,
          column: node.loc?.start.column ?? 0,
          message: 'new Function() constructor — eval alternative for arbitrary code execution',
          confidence: 'high',
        });
      }
    },

    // ── Computed member access on suspicious targets ─────────────────────────
    // e.g. window['eval'], this['constructor']['constructor']
    MemberExpression(path) {
      if (!path.node.computed) return;
      const prop = path.node.property;
      if (!t.isStringLiteral(prop)) return;

      const dangerous = ['eval', 'Function', 'constructor', 'execScript'];
      if (dangerous.includes(prop.value)) {
        findings.push({
          type: 'obfuscation-pattern',
          file: filePath,
          line: path.node.loc?.start.line ?? 0,
          column: path.node.loc?.start.column ?? 0,
          message: `Bracket access to ['${prop.value}'] — computed property used to evade static analysis`,
          confidence: 'high',
        });
      }
    },

    // ── String literal analysis ───────────────────────────────────────────────
    StringLiteral(path) {
      const { value } = path.node;
      const loc = path.node.loc;

      // Long strings — packed/encoded payload indicator
      if (value.length > 500) {
        const h = entropy(value);
        const label = h > 5.5 ? 'high-entropy (likely encrypted/encoded)' : 'long';
        findings.push({
          type: 'obfuscation-pattern',
          file: filePath,
          line: loc?.start.line ?? 0,
          column: loc?.start.column ?? 0,
          message: `${label} string literal (${value.length} chars, entropy ${h.toFixed(2)}) — possible packed payload`,
          confidence: h > 5.5 ? 'high' : 'medium',
        });
        return;
      }

      // High escape-sequence density — \x41\x42 style encoding
      if (value.length > 10) {
        // Use the raw extra data if available, otherwise estimate from value
        const hexMatches = value.split('').filter(c => c.charCodeAt(0) > 127 || c === '\\').length;
        const ratio = hexMatches / value.length;
        if (ratio > 0.4) {
          findings.push({
            type: 'obfuscation-pattern',
            file: filePath,
            line: loc?.start.line ?? 0,
            column: loc?.start.column ?? 0,
            message: `String with high non-ASCII/escape density — possible hex/unicode obfuscation`,
            confidence: 'medium',
          });
        }
      }
    },
  });

  // Deduplicate: eval detection fires on both CallExpression and NewExpression — keep one
  const seen = new Set<string>();
  return findings.filter(f => {
    const key = `${f.type}:${f.line}:${f.column}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}
