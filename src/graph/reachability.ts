/**
 * Reachability analysis over a call graph.
 *
 * Given a set of entry-point function names and a call graph, performs BFS
 * to determine which functions are reachable.  Everything not reachable is
 * considered dead from the entry-point perspective.
 */
import type { CallGraph, FnMeta } from './callgraph';

export interface ReachabilityResult {
  reachable:    Set<string>;
  dead:         Set<string>;
  /** Entry points that were not found in the call graph (likely external) */
  missingRoots: Set<string>;
}

export function computeReachability(
  graph:        CallGraph,
  entryPoints:  string[],
): ReachabilityResult {
  const reachable    = new Set<string>();
  const missingRoots = new Set<string>();
  const queue: string[] = [];

  for (const ep of entryPoints) {
    if (graph.has(ep)) {
      queue.push(ep);
    } else {
      missingRoots.add(ep);
      // Still treat it as reachable — it's external, not dead
      reachable.add(ep);
    }
  }

  while (queue.length > 0) {
    const fn = queue.shift()!;
    if (reachable.has(fn)) continue;
    reachable.add(fn);

    const calls = graph.get(fn) ?? new Set<string>();
    for (const callee of calls) {
      if (!reachable.has(callee)) {
        queue.push(callee);
      }
    }
  }

  const dead = new Set<string>();
  for (const fn of graph.keys()) {
    if (!reachable.has(fn)) dead.add(fn);
  }

  return { reachable, dead, missingRoots };
}

/**
 * Auto-detect entry points: functions that appear in the call graph but are
 * never called BY any other function in the graph (i.e. no in-edges).
 * These are the natural roots of the call forest.
 */
export function detectEntryPoints(graph: CallGraph): string[] {
  const calledByAnyone = new Set<string>();

  for (const [, refs] of graph) {
    for (const ref of refs) {
      if (graph.has(ref)) calledByAnyone.add(ref);
    }
  }

  const roots: string[] = [];
  for (const fn of graph.keys()) {
    if (!calledByAnyone.has(fn)) roots.push(fn);
  }

  return roots;
}
