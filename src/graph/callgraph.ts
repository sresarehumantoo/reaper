/**
 * Static call graph builder.
 *
 * For each named function in the AST, records the set of identifiers
 * it references (calls or reads).  This is intentionally over-approximate:
 * we include all identifier references, not just confirmed call targets,
 * so that we don't accidentally mark a function dead because it was passed
 * as a callback rather than called directly.
 */
import { forEachNamedFunction } from '../util';
import * as t from '@babel/types';
import type { File } from '@babel/types';
import type { NodePath } from '@babel/traverse';

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

  forEachNamedFunction(ast, ({ name, kind, fnNode, path }) => {
    if (graph.has(name)) return;

    // For a declaration, traverse the FunctionDeclaration path itself; for a
    // declarator, traverse the init (the function body) rather than the
    // declarator, so the variable's own name isn't captured as a self-ref.
    const refsPath = (kind === 'declaration' ? path : path.get('init')) as NodePath<any>;
    graph.set(name, collectRefs(refsPath, name));
    meta.set(name, {
      line:    path.node.loc?.start.line ?? 0,
      endLine: path.node.loc?.end.line   ?? 0,
      chars:   (fnNode.end ?? 0) - (fnNode.start ?? 0),
    });
  });

  return { graph, meta };
}
