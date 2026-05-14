/**
 * Static call graph builder.
 *
 * For each named function in the AST, records the set of identifiers
 * it references (calls or reads).  This is intentionally over-approximate:
 * we include all identifier references, not just confirmed call targets,
 * so that we don't accidentally mark a function dead because it was passed
 * as a callback rather than called directly.
 */
import _traverse from '@babel/traverse';
import * as t from '@babel/types';
import type { File } from '@babel/types';
import type { NodePath } from '@babel/traverse';

const traverse = (typeof _traverse === 'function'
  ? _traverse
  : (_traverse as any).default) as typeof _traverse;

// fn name → set of names it references
export type CallGraph = Map<string, Set<string>>;

// fn name → { line, endLine, chars }
export interface FnMeta {
  line: number;
  endLine: number;
  chars: number;
}

export interface CallGraphResult {
  graph: CallGraph;
  meta:  Map<string, FnMeta>;
}

/** Collect all identifier names referenced inside a function path */
function collectRefs(path: NodePath<any>, selfName: string): Set<string> {
  const refs = new Set<string>();

  path.traverse({
    Identifier(inner: NodePath<t.Identifier>) {
      const name = inner.node.name;
      if (name !== selfName) refs.add(name);
    },
    StringLiteral(inner: NodePath<t.StringLiteral>) {
      // bracket notation: obj['methodName']() — treat the string as a potential ref
      if (
        t.isMemberExpression(inner.parentPath?.node) &&
        (inner.parentPath?.node as t.MemberExpression).computed
      ) {
        refs.add(inner.node.value);
      }
    },
  });

  return refs;
}

export function buildCallGraph(ast: File): CallGraphResult {
  const graph: CallGraph = new Map();
  const meta:  Map<string, FnMeta> = new Map();

  traverse(ast, {
    FunctionDeclaration(path) {
      if (!path.node.id) return;
      const name = path.node.id.name;
      if (graph.has(name)) return;

      graph.set(name, collectRefs(path, name));
      meta.set(name, {
        line:    path.node.loc?.start.line ?? 0,
        endLine: path.node.loc?.end.line   ?? 0,
        chars:   (path.node.end ?? 0) - (path.node.start ?? 0),
      });
    },

    VariableDeclarator(path) {
      if (!t.isIdentifier(path.node.id)) return;
      const init = path.node.init;
      if (
        !init ||
        (!t.isFunctionExpression(init) && !t.isArrowFunctionExpression(init))
      ) return;

      const name = path.node.id.name;
      if (graph.has(name)) return;

      // Traverse the init (the function body), not the declarator,
      // to avoid capturing the variable's own name as a self-ref.
      const initPath = path.get('init') as NodePath<any>;
      graph.set(name, collectRefs(initPath, name));
      meta.set(name, {
        line:    path.node.loc?.start.line ?? 0,
        endLine: path.node.loc?.end.line   ?? 0,
        chars:   (init.end ?? 0) - (init.start ?? 0),
      });
    },
  });

  return { graph, meta };
}
