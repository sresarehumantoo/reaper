/**
 * Function-level inventory analyzer.
 * Walks the AST and for each function declaration/expression collects:
 *   - name, location, size (chars / lines)
 *   - whether it is referenced from outside its own body
 */
import { forEachNamedFunction } from '../util';
import type { File } from '@babel/types';

export interface FunctionEntry {
  name: string;
  line: number;
  endLine: number;
  lines: number;
  chars: number;
  referenced: boolean;
  kind: 'declaration' | 'expression' | 'arrow';
}

export function inventoryFunctions(ast: File, _source: string): FunctionEntry[] {
  const entries: FunctionEntry[] = [];
  const seen = new Set<string>(); // dedupe by location

  forEachNamedFunction(ast, ({ name, kind, fnNode, path }) => {
    const loc = path.node.loc;
    if (!loc) return;
    const key = `${name}:${loc.start.line}`;
    if (seen.has(key)) return;
    seen.add(key);

    // A declaration binds in its own scope; a declarator binds one scope up
    // through its VariableDeclaration parent — mirror the original lookups.
    const binding = kind === 'declaration'
      ? (path.scope.getBinding(name) ?? path.parentPath?.scope.getBinding(name))
      : (path.scope.getBinding(name) ?? path.parentPath?.parentPath?.scope.getBinding(name));

    entries.push({
      name,
      line:       loc.start.line,
      endLine:    loc.end.line,
      lines:      loc.end.line - loc.start.line + 1,
      chars:      (fnNode.end ?? 0) - (fnNode.start ?? 0),
      referenced: binding ? binding.referenced : true,
      kind,
    });
  });

  return entries.sort((a, b) => a.line - b.line);
}
