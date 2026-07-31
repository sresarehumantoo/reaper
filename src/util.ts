/**
 * Shared helpers used across analyzers and reporters.
 */
import _traverse from '@babel/traverse';
import _generate from '@babel/generator';
import * as t from '@babel/types';
import type { File } from '@babel/types';

// @babel/traverse and @babel/generator ship as CJS with the real function on
// `.default` under esModuleInterop. Normalise both so every module imports the
// callable form from here instead of repeating the interop dance.
export const traverse = (typeof _traverse === 'function'
  ? _traverse
  : (_traverse as any).default) as typeof _traverse;

export const generate = (typeof _generate === 'function'
  ? _generate
  : (_generate as any).default) as typeof _generate;

/** Shannon entropy (bits/symbol) of a string. High → likely encoded/encrypted. */
export function shannonEntropy(s: string): number {
  if (s.length === 0) return 0;
  const freq = new Map<string, number>();
  for (const c of s) freq.set(c, (freq.get(c) ?? 0) + 1);
  let h = 0;
  for (const count of freq.values()) {
    const p = count / s.length;
    h -= p * Math.log2(p);
  }
  return h;
}

export function truncate(s: string, n: number): string {
  return s.length <= n ? s : s.slice(0, n - 1) + '…';
}

/** `line:column`, or `line:column-endLine` when an end line is given. */
export function locLabel(line: number, column: number, endLine?: number): string {
  return endLine && endLine !== line ? `${line}:${column}-${endLine}` : `${line}:${column}`;
}

/** IOC types that represent network/contact data worth defanging in reports. */
export const DEFANGABLE_IOC_TYPES = new Set<string>([
  'url', 'domain', 'ipv4', 'ipv6', 'email', 'discord-webhook',
]);

/** Render an indicator value, defanging it when enabled and the type warrants. */
export function renderIocValue(type: string, value: string, enable: boolean): string {
  return enable && DEFANGABLE_IOC_TYPES.has(type) ? defang(value) : value;
}

export type NamedFnKind = 'declaration' | 'expression' | 'arrow';

export interface NamedFn {
  name:   string;
  kind:   NamedFnKind;
  /** The function node itself (declaration, expression, or arrow). */
  fnNode: t.Function;
  /** NodePath of the FunctionDeclaration (declarations) or VariableDeclarator (expr/arrow). */
  path:   any /* NodePath */;
}

/**
 * Visit every *named* function in an AST: `function foo(){}` and
 * `var foo = function(){} / () => {}`. Centralises the shape-detection both the
 * function inventory and the call-graph builder used to duplicate; each caller
 * does its own per-function work from the yielded `{name, kind, fnNode, path}`.
 */
export function forEachNamedFunction(ast: File, cb: (fn: NamedFn) => void): void {
  traverse(ast, {
    FunctionDeclaration(path) {
      if (!path.node.id) return;
      cb({ name: path.node.id.name, kind: 'declaration', fnNode: path.node, path });
    },
    VariableDeclarator(path) {
      if (!t.isIdentifier(path.node.id)) return;
      const init = path.node.init;
      if (!init || (!t.isFunctionExpression(init) && !t.isArrowFunctionExpression(init))) return;
      cb({
        name:   path.node.id.name,
        kind:   t.isArrowFunctionExpression(init) ? 'arrow' : 'expression',
        fnNode: init,
        path,
      });
    },
  });
}

/**
 * Defang a network indicator for safe inclusion in reports/tickets:
 * `http://evil.com/x` → `hxxp://evil[.]com/x`, `1.2.3.4` → `1[.]2[.]3[.]4`,
 * `a@b.com` → `a[@]b[.]com`. Idempotent-ish for already-defanged input.
 */
export function defang(s: string): string {
  return s
    .replace(/\bhttps?:\/\//gi, m => m.replace(/^http/i, 'hxxp').replace('://', '[://]'))
    .replace(/@/g, '[@]')
    .replace(/\./g, '[.]');
}
