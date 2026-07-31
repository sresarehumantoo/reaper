import { traverse } from '../util';
import type { File } from '@babel/types';
import type { Finding } from '../types';

// Kinds that indicate a binding came from an import — handled by imports analyzer
const IMPORT_KINDS = new Set(['module']);

export function analyzeUnusedReferences(ast: File, filePath: string): Finding[] {
  const findings: Finding[] = [];
  // Track identifiers already reported to avoid duplicates across nested scopes
  const reported = new Set<string>();

  traverse(ast, {
    Scope(path) {
      for (const [name, binding] of Object.entries(path.scope.bindings)) {
        // Skip intentionally-unused convention
        if (name.startsWith('_')) continue;
        // Skip imports (separate analyzer handles them)
        if (IMPORT_KINDS.has(binding.kind)) continue;
        if (
          binding.path.isImportSpecifier() ||
          binding.path.isImportDefaultSpecifier() ||
          binding.path.isImportNamespaceSpecifier()
        ) continue;
        // Skip already-reported (parent scopes can re-expose the same binding)
        const key = `${filePath}:${binding.identifier.loc?.start.line}:${name}`;
        if (reported.has(key)) continue;
        if (binding.referenced) continue;

        reported.add(key);

        const isFunction =
          binding.path.isFunctionDeclaration() ||
          binding.path.isFunctionExpression() ||
          binding.path.isArrowFunctionExpression();

        findings.push({
          type: isFunction ? 'unused-function' : 'unused-variable',
          file: filePath,
          line: binding.identifier.loc?.start.line ?? 0,
          column: binding.identifier.loc?.start.column ?? 0,
          message: isFunction
            ? `Unused function: '${name}'`
            : `Unused variable: '${name}'`,
          confidence: 'high',
        });
      }
    },
  });

  return findings;
}
