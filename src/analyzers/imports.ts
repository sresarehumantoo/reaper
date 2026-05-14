import _traverse from '@babel/traverse';
import type { File } from '@babel/types';
import type { Finding } from '../types';

const traverse = (typeof _traverse === 'function' ? _traverse : (_traverse as any).default) as typeof _traverse;

export function analyzeUnusedImports(ast: File, filePath: string): Finding[] {
  const findings: Finding[] = [];

  traverse(ast, {
    ImportDeclaration(path) {
      // Side-effect-only imports: `import './foo'` — never flag these
      if (path.node.specifiers.length === 0) return;
      // Type-only imports are erased by the TS compiler — not dead code
      if (path.node.importKind === 'type') return;

      for (const specifier of path.node.specifiers) {
        const { name } = specifier.local;

        // Underscore prefix = intentionally unused by convention
        if (name.startsWith('_')) continue;
        // Individual type specifiers: `import { type Foo }`
        if ('importKind' in specifier && (specifier as any).importKind === 'type') continue;

        const binding = path.scope.getBinding(name);
        if (binding && !binding.referenced) {
          findings.push({
            type: 'unused-import',
            file: filePath,
            line: specifier.local.loc?.start.line ?? 0,
            column: specifier.local.loc?.start.column ?? 0,
            message: `Unused import: '${name}' from '${path.node.source.value}'`,
            confidence: 'high',
          });
        }
      }
    },
  });

  return findings;
}
