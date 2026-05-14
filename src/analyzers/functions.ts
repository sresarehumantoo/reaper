/**
 * Function-level inventory analyzer.
 * Walks the AST and for each function declaration/expression collects:
 *   - name, location, size (chars / lines)
 *   - whether it is referenced from outside its own body
 */
import _traverse from '@babel/traverse';
import * as t from '@babel/types';
import type { File } from '@babel/types';

const traverse = (typeof _traverse === 'function'
  ? _traverse
  : (_traverse as any).default) as typeof _traverse;

export interface FunctionEntry {
  name: string;
  line: number;
  endLine: number;
  lines: number;
  chars: number;
  referenced: boolean;
  kind: 'declaration' | 'expression' | 'arrow';
}

export function inventoryFunctions(ast: File, source: string): FunctionEntry[] {
  const entries: FunctionEntry[] = [];
  const seen = new Set<string>(); // dedupe by location

  traverse(ast, {
    // Named function declarations: function foo() {}
    FunctionDeclaration(path) {
      if (!path.node.id) return;
      const name = path.node.id.name;
      const loc  = path.node.loc;
      if (!loc) return;
      const key = `${name}:${loc.start.line}`;
      if (seen.has(key)) return;
      seen.add(key);

      const binding = path.scope.getBinding(name)
        ?? path.parentPath?.scope.getBinding(name);

      entries.push({
        name,
        line:       loc.start.line,
        endLine:    loc.end.line,
        lines:      loc.end.line - loc.start.line + 1,
        chars:      path.node.end! - path.node.start!,
        referenced: binding ? binding.referenced : true,
        kind:       'declaration',
      });
    },

    // Named variable holding a function: var foo = function() {} or () => {}
    VariableDeclarator(path) {
      if (!t.isIdentifier(path.node.id)) return;
      const init = path.node.init;
      if (
        !init ||
        (!t.isFunctionExpression(init) && !t.isArrowFunctionExpression(init))
      ) return;

      const name = path.node.id.name;
      const loc  = path.node.loc;
      if (!loc) return;
      const key = `${name}:${loc.start.line}`;
      if (seen.has(key)) return;
      seen.add(key);

      const binding = path.scope.getBinding(name)
        ?? path.parentPath?.parentPath?.scope.getBinding(name);

      entries.push({
        name,
        line:       loc.start.line,
        endLine:    loc.end.line,
        lines:      loc.end.line - loc.start.line + 1,
        chars:      init.end! - init.start!,
        referenced: binding ? binding.referenced : true,
        kind:       t.isArrowFunctionExpression(init) ? 'arrow' : 'expression',
      });
    },
  });

  return entries.sort((a, b) => a.line - b.line);
}
