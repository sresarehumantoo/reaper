/**
 * Cross-scope reachability analyzer.
 *
 * Combines:
 *   1. Static call graph from the file's own AST
 *   2. Eval-captured layers (for packed/obfuscated files)
 *   3. BFS reachability from specified (or auto-detected) entry points
 *   4. String folding inside dead function bodies
 *   5. p,a,c,k,e,r static unpack
 *
 * Returns a ReachabilityReport describing which functions are dead,
 * which are alive, estimated code reduction, and any reconstructed strings.
 */
import fs from 'fs';
import { parseCode, readSourceCapped } from '../parser';
import { buildCallGraph } from '../graph/callgraph';
import { computeReachability, detectEntryPoints } from '../graph/reachability';
import { captureEvalScope } from './evalscope';
import { detectPacker } from './packer';
import { foldStrings } from './strfold';
import type { CallGraph, FnMeta } from '../graph/callgraph';
import type { FoldedString } from './strfold';
import type { PackerInfo } from './packer';

export interface DeadFn {
  name:              string;
  line:              number;
  endLine:           number;
  chars:             number;
  layer:             'static' | number;
  reconstructed:     FoldedString[];  // constant strings found inside this fn
}

export interface AliveFn {
  name:    string;
  line:    number;
  endLine: number;
}

export interface ReachabilityReport {
  file:          string;
  entryPoints:   string[];
  autoDetected:  boolean;
  /** Functions with no callers that were NOT chosen as entry points */
  uncalledFns:   string[];
  totalFns:      number;
  aliveFns:      AliveFn[];
  deadFns:       DeadFn[];
  totalLines:    number;
  totalChars:    number;
  deadChars:     number;
  reductionPct:  number;
  evalLayers:    number;
  packers:       PackerInfo[];
  missingRoots:  string[];
  error:         string | null;
}

export function analyzeReachability(
  filePath:     string,
  entryPoints?: string[],
): ReachabilityReport {
  const source     = readSourceCapped(filePath);
  const totalLines = source.split('\n').length;
  const totalChars = source.length;

  // ── Parse the outer file once and share the AST across analyzers ──────────
  // Previously: detectPacker and buildCallGraph each called parseCode(source)
  // independently, doubling the parse cost on large files.
  let outerAst: File | null = null;
  try {
    outerAst = parseCode(source, filePath);
  } catch { /* non-parseable outer shell is fine — leave outerAst null */ }

  // ── Step 1: detect packers statically ────────────────────────────────────
  let packers: PackerInfo[] = [];
  if (outerAst) {
    try { packers = detectPacker(outerAst); } catch { /* fine */ }
  }

  // ── Step 2: static call graph from the file's own AST ────────────────────
  let staticGraph: CallGraph         = new Map();
  let staticMeta:  Map<string, FnMeta> = new Map();
  if (outerAst) {
    try {
      const result = buildCallGraph(outerAst);
      staticGraph  = result.graph;
      staticMeta   = result.meta;
    } catch { /* fall through with empty graph */ }
  }

  // ── Step 3: eval-aware scope capture ─────────────────────────────────────
  const evalResult  = captureEvalScope(filePath);
  const mergedGraph: CallGraph          = new Map(staticGraph);
  const mergedMeta:  Map<string, FnMeta> = new Map(staticMeta);
  // Map layer index → { source, parsed AST }. Parsing each layer ONCE here
  // and reusing the AST for both call-graph and string-folding passes below.
  const layerAsts: Map<string, { src: string; ast: File }> = new Map();

  for (const layer of evalResult.layers) {
    if (layer.source.length < 20) continue;
    let layerAst: File;
    try {
      layerAst = parseCode(layer.source, `${filePath}#eval${layer.index}`);
    } catch { continue; /* unparseable layer */ }
    layerAsts.set(`eval${layer.index}`, { src: layer.source, ast: layerAst });

    try {
      const { graph: lg, meta: lm } = buildCallGraph(layerAst);
      for (const [fn, refs] of lg) {
        if (!mergedGraph.has(fn)) {
          mergedGraph.set(fn, refs);
          mergedMeta.set(fn, { line: 0, endLine: 0, chars: lm.get(fn)?.chars ?? 0 });
        } else {
          const existing = mergedGraph.get(fn)!;
          for (const r of refs) existing.add(r);
        }
      }
    } catch { /* call-graph extraction failed; we still have the AST for strfold */ }
  }

  // ── Step 4: resolve entry points ─────────────────────────────────────────
  const allRoots  = detectEntryPoints(mergedGraph);
  let roots:        string[];
  let autoDetected: boolean;
  let uncalledFns:  string[];

  if (entryPoints && entryPoints.length > 0) {
    roots        = entryPoints;
    autoDetected = false;
    // Functions that have no callers but were NOT supplied as entry points
    uncalledFns  = allRoots.filter(r => !roots.includes(r));
  } else {
    // Auto-detect: use ALL roots as entry points
    roots        = allRoots;
    autoDetected = true;
    uncalledFns  = [];
  }

  // ── Step 5: BFS reachability ──────────────────────────────────────────────
  const { reachable, dead, missingRoots } = computeReachability(mergedGraph, roots);

  // ── Step 6: string folding inside dead function bodies ───────────────────
  // Fold over the static outer AST *and* every eval layer — a dead function in
  // a plain (non-packed) obfuscated file has its constants reconstructed too,
  // not only functions recovered from eval layers.
  const foldedByFn = new Map<string, FoldedString[]>();

  const foldTargets: File[] = [];
  if (outerAst) foldTargets.push(outerAst);
  for (const [, { ast: layerAst }] of layerAsts) foldTargets.push(layerAst);

  for (const target of foldTargets) {
    try {
      const folded = foldStrings(target);
      attributeFoldedStrings(target, folded, dead, foldedByFn);
    } catch { /* skip */ }
  }

  // ── Step 7: build report ──────────────────────────────────────────────────
  const deadFns: DeadFn[] = [];
  const aliveFns: AliveFn[] = [];

  for (const fn of mergedGraph.keys()) {
    const m = mergedMeta.get(fn);
    if (dead.has(fn)) {
      deadFns.push({
        name:          fn,
        line:          m?.line    ?? 0,
        endLine:       m?.endLine ?? 0,
        chars:         m?.chars   ?? 0,
        layer:         m && m.line > 0 ? 'static' : 0,
        reconstructed: foldedByFn.get(fn) ?? [],
      });
    } else {
      aliveFns.push({ name: fn, line: m?.line ?? 0, endLine: m?.endLine ?? 0 });
    }
  }

  const sortFn = (a: { name: string; line: number }, b: { name: string; line: number }) =>
    a.line === b.line ? a.name.localeCompare(b.name) : (a.line || 999999) - (b.line || 999999);

  deadFns.sort(sortFn);
  aliveFns.sort(sortFn);

  const deadChars = deadFns.reduce((s, f) => s + f.chars, 0);

  return {
    file:         filePath,
    entryPoints:  roots,
    autoDetected,
    uncalledFns,
    totalFns:     mergedGraph.size,
    aliveFns,
    deadFns,
    totalLines,
    totalChars,
    deadChars,
    reductionPct: totalChars > 0 ? (deadChars / totalChars) * 100 : 0,
    evalLayers:   evalResult.layers.length,
    packers,
    missingRoots: [...missingRoots],
    error:        evalResult.error,
  };
}

// ---------------------------------------------------------------------------
// Attribute folded strings to their enclosing dead function
// ---------------------------------------------------------------------------
import _traverse from '@babel/traverse';
import * as t from '@babel/types';
import type { File } from '@babel/types';

const traverse = (typeof _traverse === 'function'
  ? _traverse
  : (_traverse as any).default) as typeof _traverse;

function attributeFoldedStrings(
  ast:       File,
  folded:    FoldedString[],
  dead:      Set<string>,
  out:       Map<string, FoldedString[]>,
): void {
  if (folded.length === 0) return;

  traverse(ast, {
    FunctionDeclaration(path) {
      const name = path.node.id?.name;
      if (!name || !dead.has(name)) return;
      collectFolded(name, path.node.start, path.node.end, folded, out);
    },
    VariableDeclarator(path) {
      if (!t.isIdentifier(path.node.id)) return;
      const name = path.node.id.name;
      if (!dead.has(name)) return;
      const init = path.node.init;
      if (!init || (!t.isFunctionExpression(init) && !t.isArrowFunctionExpression(init))) return;
      collectFolded(name, init.start, init.end, folded, out);
    },
  });
}

function collectFolded(
  fnName: string,
  start:  number | null | undefined,
  end:    number | null | undefined,
  folded: FoldedString[],
  out:    Map<string, FoldedString[]>,
): void {
  if (start == null || end == null) return;
  // Attribute only the folds whose source range falls inside this function's
  // [start, end). Filtering on `f.line >= 0` (always true) previously credited
  // every dead function with every fold in the layer.
  const matches = folded.filter(f =>
    f.start != null && f.end != null && f.start >= start && f.end <= end);
  if (matches.length === 0) return;
  if (!out.has(fnName)) out.set(fnName, []);
  out.get(fnName)!.push(...matches);
}
