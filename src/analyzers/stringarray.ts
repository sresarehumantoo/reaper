/**
 * obfuscator.io string-array detector and static rewriter.
 *
 * Two decoder shapes are handled:
 *
 *   (a) self-rewriting (obfuscator.io ≥ v3):
 *     function _0xARR()        { const _0x... = [...]; _0xARR = ...; return ...; }
 *     function _0xDEC(a,b)     { const arr = _0xARR(); return _0xDEC = function(x){...arr[x-K]...}, _0xDEC(a,b); }
 *     (function(arr, target){ ... while(true){...} }(_0xARR, NNN));     // IIFE shuffle
 *     function _0xWRAP(a,b)    { return _0xDEC(transform(a, b), …); }   // optional wrappers, can be nested
 *
 *   (b) simple-subtract (older obfuscator.io / many commercial packers, e.g. PropellerAds sfp.js):
 *     function _0xDEC(o, k)    { o = o - 0x1ec; var n = _0xARR(); var z = n[o]; return z; }
 *     function _0xARR()        { ... self-rewriting as in (a) ... }
 *     (function(o, k){ ... }(_0xARR, NNN))                              // rotator, may be in a SequenceExpression
 *     var alias = _0xDEC;  alias(0x123);                                // aliases instead of wrapper fns
 *
 * Both shapes can be nested arbitrarily deep inside outer IIFEs — discovery
 * walks the full AST, not just program.body.
 *
 * Strategy (pure-data: returns rewritten source, never mutates the input):
 *   1. Locate arrayFn, root decoder, the IIFE shuffle (anywhere in the AST).
 *   2. Discover every wrapper fn (any depth, any number of passes) AND every
 *      identifier alias `var X = decoder` (transitively). All pure-AST.
 *   3. For each wrapper, inline enclosing-scope const objects/numbers/strings
 *      into a clone of its body so it is self-contained.
 *   4. Collect every wrapper/alias call whose args can be const-evaluated.
 *   5. Hand the boot code + wrappers + collected calls to an ISOLATED child
 *      process (see isolate.ts / stringarray-worker.cjs) which boots the vm and
 *      returns the decoded string for each call. Nothing executes in-process.
 *   6. Substitute each resolved call with its literal string.
 *   7. Strip the dead obfuscator scaffolding from the output AST when it's at
 *      program-body level (nested scaffolding is left in place — safer).
 *
 * Executing sample code in-process (Node's `vm`) is unsafe: `vm` is not a
 * security boundary, its timeout only covers synchronous script, and it shares
 * reaper's heap (so a sample can OOM or hang the analyzer). The child-process
 * boundary in step 5 bounds all of that to a disposable process.
 */

import path from 'path';
import fs from 'fs';
import { parseCode } from '../parser';
import { traverse, generate } from '../util';
import * as t from '@babel/types';
import type { File, Node } from '@babel/types';
import { runIsolated } from './isolate';

// In dev (tsx) __dirname is src/analyzers/; in prod it's dist/analyzers/.
// `npm run build` copies the .cjs worker next to the compiled .js.
const WORKER_PATH = path.join(__dirname, 'stringarray-worker.cjs');

export interface StringArrayInfo {
  detected:       boolean;
  arrayFn:        string | null;
  decoderFn:      string | null;
  wrappers:       string[];
  aliases:        string[];        // identifier aliases of the decoder (e.g. `var Ne = decoder`)
  substitutions:  number;
  attempted:      number;
  rewritten:      string | null;   // full rewritten source, or null if not detected
  error:          string | null;
}

interface DecodeCall { id: number; target: string; args: (number | string)[] }

export function detectAndRewriteStringArray(source: string, filePath: string): StringArrayInfo {
  const info: StringArrayInfo = {
    detected:      false,
    arrayFn:       null,
    decoderFn:     null,
    wrappers:      [],
    aliases:       [],
    substitutions: 0,
    attempted:     0,
    rewritten:     null,
    error:         null,
  };

  let ast: File;
  try {
    ast = parseCode(source, filePath);
  } catch (e: any) {
    info.error = `parse failed: ${e.message}`;
    return info;
  }

  // ── 1. Locate arrayFn and root decoder (anywhere in the AST) ──────────────
  const arrayDecl = findArrayFnDecl(ast);
  const arrayFn   = arrayDecl?.id?.name ?? null;
  const decoderDecl = arrayFn ? findRootDecoderDecl(ast, arrayFn) : null;
  const decoderFn   = decoderDecl?.id?.name ?? null;
  if (!arrayFn || !decoderFn || !arrayDecl || !decoderDecl) return info;

  info.arrayFn   = arrayFn;
  info.decoderFn = decoderFn;

  // ── 2. Locate IIFE shuffle (anywhere in the AST) ──────────────────────────
  const iifeCall = findIifeShuffleCall(ast, arrayFn);

  // ── 3. Build the boot program (arrayFn → decoder → rotator) ───────────────
  // Clone the discovered nodes so we never mutate the source AST.
  const bootBody: t.Statement[] = [
    t.cloneNode(arrayDecl, true),
    t.cloneNode(decoderDecl, true),
  ];
  if (iifeCall) bootBody.push(t.expressionStatement(t.cloneNode(iifeCall, true)));
  const bootCode = generate(t.program(bootBody)).code;

  // ── 4a. Discover identifier aliases of the decoder ────────────────────────
  // Pattern: `var X = decoder` (or `var Y = X` transitively). These are not
  // wrapper functions — they're aliased references the obfuscator scatters
  // through every function scope. A call on an alias is equivalent to a call on
  // the root decoder with the same args.
  const aliasToRoot = new Map<string, string>();   // alias name → root decoder name
  aliasToRoot.set(decoderFn, decoderFn);
  for (let pass = 0; pass < 10; pass++) {
    let added = 0;
    traverse(ast, {
      VariableDeclarator(p) {
        const { id, init } = p.node;
        if (!t.isIdentifier(id) || !t.isIdentifier(init)) return;
        if (aliasToRoot.has(init.name) && !aliasToRoot.has(id.name)) {
          aliasToRoot.set(id.name, decoderFn);
          added++;
        }
      },
    });
    if (added === 0) break;
  }
  const aliasesLocal = [...aliasToRoot.keys()].filter(n => n !== decoderFn);

  // ── 4b. Discover wrapper functions at any depth ───────────────────────────
  // A wrapper is `function w(a,b){ return <decoder-or-alias>(transform(a,b)); }`
  // — it transforms the args before delegating.
  const knownWrappers = new Set<string>([decoderFn]);
  const wrapperNodes  = new Map<string, t.Function>();

  for (let pass = 0; pass < 10; pass++) {
    let added = 0;
    traverse(ast, {
      Function(p) {
        const node = p.node;
        const name = getFnName(node, p.parent);
        if (!name || knownWrappers.has(name) || name === arrayFn) return;
        if (aliasToRoot.has(name)) return;        // it's an alias, not a wrapper
        const resolvable = new Set<string>([...knownWrappers, ...aliasToRoot.keys()]);
        if (!isWrapperShape(node, resolvable)) return;
        knownWrappers.add(name);
        wrapperNodes.set(name, node);
        added++;
      },
    });
    if (added === 0) break;
  }
  const wrappersLocal = [...wrapperNodes.keys()];

  // ── 5a. Materialise wrapper declarations (with scope-env inlined) ─────────
  // One O(n) pass to map every function name → its NodePath, so we don't
  // re-traverse the whole AST once per wrapper.
  const fnPathByName = collectFnPaths(ast);
  const wrapperCodes: string[] = [];
  for (const [name, node] of wrapperNodes) {
    const fnPath = fnPathByName.get(name) ?? null;
    const env    = fnPath ? collectConstEnv(fnPath) : {};
    const cloned = t.cloneNode(node, true) as t.Function;
    inlineEnvIntoFn(cloned, env);

    if (t.isFunctionDeclaration(cloned)) {
      wrapperCodes.push(generate(cloned).code);
    } else if (t.isFunctionExpression(cloned) || t.isArrowFunctionExpression(cloned)) {
      const wrapDecl = t.variableDeclaration('var', [
        t.variableDeclarator(t.identifier(name), cloned),
      ]);
      wrapperCodes.push(generate(wrapDecl).code);
    }
  }

  // ── 5b. Collect every resolvable wrapper/alias call ───────────────────────
  // The root decoder is skipped at its declared name (direct decoder calls are
  // vanishingly rare and would be redundant). `attempted` counts every call
  // site whose callee matched, matching the historical metric.
  const calls: DecodeCall[]      = [];
  const idByNode = new Map<Node, number>();
  let attempted = 0;
  traverse(ast, {
    CallExpression(p) {
      const callee = p.node.callee;
      if (!t.isIdentifier(callee)) return;
      const name = callee.name;

      let target: string | null = null;
      if (aliasToRoot.has(name) && name !== decoderFn) target = decoderFn;
      else if (knownWrappers.has(name) && name !== decoderFn) target = name;
      else return;

      attempted++;
      const env  = collectConstEnv(p);
      const args = p.node.arguments.map(a => evalConstNode(a as Node, env));
      if (args.some(a => a === undefined)) return;
      const id = calls.length;
      idByNode.set(p.node, id);
      calls.push({ id, target, args: args as (number | string)[] });
    },
  });

  // ── 5c. Execute the boot + decode calls in an isolated child process ──────
  if (!fs.existsSync(WORKER_PATH)) {
    info.error = `stringarray worker missing at ${WORKER_PATH} (build did not copy .cjs?)`;
    return info;
  }
  const workerInput = JSON.stringify({ boot: bootCode, decoder: decoderFn, wrappers: wrapperCodes, calls });
  const run = runIsolated(WORKER_PATH, { input: workerInput });
  if (run.error || !run.stdout) {
    info.error = run.error ?? 'worker produced no output';
    return info;
  }
  let workerOut: { ok: boolean; error: string | null; results: { id: number; value: string | null }[] };
  try {
    workerOut = JSON.parse(run.stdout.toString('utf-8'));
  } catch (e: any) {
    info.error = `worker produced unparseable output: ${e?.message ?? String(e)}`;
    return info;
  }
  if (!workerOut.ok) {
    info.error = workerOut.error;
    return info;
  }

  // Boot + decoder confirmed callable in the child.
  info.detected  = true;
  info.aliases   = aliasesLocal;
  info.wrappers  = wrappersLocal;
  info.attempted = attempted;

  // ── 6. Substitute each resolved call with its literal string ──────────────
  const valueById = new Map<number, string | null>();
  for (const r of workerOut.results) valueById.set(r.id, r.value);
  traverse(ast, {
    CallExpression(p) {
      const id = idByNode.get(p.node);
      if (id === undefined) return;
      const v = valueById.get(id);
      if (typeof v === 'string') {
        p.replaceWith(t.stringLiteral(v));
        info.substitutions++;
      }
    },
  });

  // ── 7. Strip dead obfuscator scaffolding ──────────────────────────────────
  // Top-level scaffolding only — when the obfuscator wraps everything in an
  // outer IIFE the scaffold lives inside it; in that case we leave it alone.
  const iifeStmtAtTop = iifeCall
    ? ast.program.body.find(n =>
        t.isExpressionStatement(n) && n.expression === iifeCall
      ) ?? null
    : null;
  ast.program.body = ast.program.body.filter(n => {
    if (t.isFunctionDeclaration(n) && n.id) {
      if (n.id.name === arrayFn || n.id.name === decoderFn) return false;
    }
    if (n === iifeStmtAtTop) return false;
    return true;
  });
  traverse(ast, {
    FunctionDeclaration(p) {
      const nm = p.node.id?.name;
      if (nm && knownWrappers.has(nm) && nm !== decoderFn) p.remove();
    },
    VariableDeclarator(p) {
      if (!t.isIdentifier(p.node.id)) return;
      const nm = p.node.id.name;
      if (knownWrappers.has(nm) && nm !== decoderFn) p.remove();
    },
  });

  info.rewritten = generate(ast, { compact: false }).code;
  return info;
}

// ---------------------------------------------------------------------------
// Pattern detection helpers
// ---------------------------------------------------------------------------

/**
 * Find the string-array function anywhere in the AST. The shape is:
 *   function NAME() {
 *     var arr = [<long string literal array>];
 *     NAME = function () { return arr; };
 *     return NAME();
 *   }
 * The array literal must have > 5 elements (filters out incidental small arrays).
 */
function findArrayFnDecl(ast: File): t.FunctionDeclaration | null {
  let found: t.FunctionDeclaration | null = null;
  traverse(ast, {
    FunctionDeclaration(p) {
      if (found || !p.node.id) return;
      const hasArray = p.node.body.body.some(s =>
        t.isVariableDeclaration(s) &&
        s.declarations[0]?.init &&
        t.isArrayExpression(s.declarations[0].init) &&
        s.declarations[0].init.elements.length > 5
      );
      if (hasArray) found = p.node;
    },
  });
  return found;
}

/**
 * Find the root decoder anywhere in the AST. Accepts two shapes:
 *
 *   (a) Self-rewriting (obfuscator.io ≥ v3):
 *       function NAME(a, b) {
 *         var arr = arrayFn();
 *         return NAME = function (x) { x = x - K; return arr[x]; }, NAME(a, b);
 *       }
 *
 *   (b) Simple-subtract (older obfuscator.io / commercial packers):
 *       function NAME(o, k) {
 *         o = o - 0x1ec;
 *         var n = arrayFn();
 *         var z = n[o];
 *         return z;
 *       }
 *
 * Both call `arrayFn()` and index into it; (a) self-rewrites on first call.
 */
function findRootDecoderDecl(ast: File, arrayFn: string): t.FunctionDeclaration | null {
  let found: t.FunctionDeclaration | null = null;
  traverse(ast, {
    FunctionDeclaration(p) {
      if (found || !p.node.id) return;
      if (p.node.id.name === arrayFn) return;
      if (decoderBodyCallsArrayFn(p.node, arrayFn)) found = p.node;
    },
  });
  return found;
}

function decoderBodyCallsArrayFn(fn: t.FunctionDeclaration, arrayFn: string): boolean {
  // Shape (a): return SELF = function(...){...}, SELF(...)
  for (const stmt of fn.body.body) {
    if (!t.isReturnStatement(stmt)) continue;
    const seq  = stmt.argument;
    const head = t.isSequenceExpression(seq) ? seq.expressions[0] :
                 t.isAssignmentExpression(seq) ? seq : null;
    if (head && t.isAssignmentExpression(head) &&
        t.isIdentifier(head.left) && head.left.name === fn.id!.name &&
        t.isFunctionExpression(head.right)) {
      return true;
    }
  }

  // Shape (b): body somewhere calls arrayFn() and indexes into the result.
  let callsArr = false, indexesResult = false;
  for (const stmt of fn.body.body) {
    if (t.isVariableDeclaration(stmt)) {
      for (const d of stmt.declarations) {
        if (d.init && t.isCallExpression(d.init) &&
            t.isIdentifier(d.init.callee) && d.init.callee.name === arrayFn) {
          callsArr = true;
        }
        if (d.init && t.isMemberExpression(d.init) && d.init.computed) {
          indexesResult = true;
        }
      }
    }
    if (t.isReturnStatement(stmt) && stmt.argument &&
        t.isMemberExpression(stmt.argument) && stmt.argument.computed) {
      indexesResult = true;
    }
  }
  return callsArr && indexesResult;
}

/**
 * Find the rotator/shuffle IIFE call anywhere in the AST. Shape:
 *   (function (o, k) { var Ne = decoder, n = o(); while (...) { ... } }(arrayFn, NNN))
 *
 * Looks for any CallExpression whose callee is a FunctionExpression that takes
 * a reference to arrayFn as one of its arguments. Returns the CallExpression
 * node itself (not the wrapping ExpressionStatement) — boot wraps it as needed.
 */
function findIifeShuffleCall(ast: File, arrayFn: string): t.CallExpression | null {
  let found: t.CallExpression | null = null;
  traverse(ast, {
    CallExpression(p) {
      if (found) return;
      const node = p.node;
      if (!t.isFunctionExpression(node.callee)) return;
      const passesArrayFn = node.arguments.some(a =>
        t.isIdentifier(a) && a.name === arrayFn);
      if (passesArrayFn) found = node;
    },
  });
  return found;
}

function getFnName(node: t.Function, parent: t.Node | null | undefined): string | null {
  if (t.isFunctionDeclaration(node) && node.id) return node.id.name;
  if ((t.isFunctionExpression(node) || t.isArrowFunctionExpression(node)) &&
      parent && t.isVariableDeclarator(parent) && t.isIdentifier(parent.id)) {
    return parent.id.name;
  }
  return null;
}

function isWrapperShape(node: t.Function, knownDecoders: Set<string>): boolean {
  const body = t.isBlockStatement(node.body) ? node.body.body : null;
  if (!body || body.length !== 1) return false;
  const ret = body[0];
  if (!t.isReturnStatement(ret) || !t.isCallExpression(ret.argument)) return false;
  const callee = ret.argument.callee;
  return t.isIdentifier(callee) && knownDecoders.has(callee.name);
}

/** One traversal → map of every named function → its NodePath. */
function collectFnPaths(ast: File): Map<string, any /* NodePath */> {
  const paths = new Map<string, any>();
  traverse(ast, {
    Function(p) {
      const n = getFnName(p.node, p.parent);
      if (n) paths.set(n, p);        // last declaration wins (matches prior findFnPathByName)
    },
  });
  return paths;
}

// ---------------------------------------------------------------------------
// Const-environment + arg evaluation
// ---------------------------------------------------------------------------

type ConstEnv = Record<string, number | string | Record<string, number | string>>;

function collectConstEnv(path: any /* NodePath */): ConstEnv {
  const env: ConstEnv = {};
  let p = path;
  while (p) {
    const scope = p.scope;
    if (scope) {
      for (const [bindingName, binding] of Object.entries(scope.bindings || {}) as any) {
        const bp = binding.path;
        if (!bp || !t.isVariableDeclarator(bp.node)) continue;
        if (bindingName in env) continue;          // inner scopes win
        const init = bp.node.init;
        if (!init) continue;
        if (t.isObjectExpression(init)) {
          const obj: Record<string, number | string> = {};
          for (const prop of init.properties) {
            if (!t.isObjectProperty(prop)) continue;
            const k = t.isIdentifier(prop.key) ? prop.key.name :
                      t.isStringLiteral(prop.key) ? prop.key.value : null;
            if (!k) continue;
            if (t.isNumericLiteral(prop.value)) obj[k] = prop.value.value;
            else if (t.isStringLiteral(prop.value)) obj[k] = prop.value.value;
          }
          if (Object.keys(obj).length > 0) env[bindingName] = obj;
        } else if (t.isNumericLiteral(init)) env[bindingName] = init.value;
        else if (t.isStringLiteral(init))    env[bindingName] = init.value;
      }
    }
    p = p.parentPath;
  }
  return env;
}

function evalConstNode(arg: Node, env: ConstEnv): number | string | undefined {
  if (t.isNumericLiteral(arg)) return arg.value;
  if (t.isStringLiteral(arg))  return arg.value;
  if (t.isUnaryExpression(arg) && arg.operator === '-') {
    const v = evalConstNode(arg.argument, env);
    return typeof v === 'number' ? -v : undefined;
  }
  if (t.isMemberExpression(arg) && !arg.computed &&
      t.isIdentifier(arg.object) && t.isIdentifier(arg.property)) {
    const obj = env[arg.object.name];
    if (obj && typeof obj === 'object') return (obj as any)[arg.property.name];
  }
  if (t.isIdentifier(arg)) {
    const v = env[arg.name];
    if (typeof v === 'number' || typeof v === 'string') return v;
  }
  if (t.isBinaryExpression(arg)) {
    const l = evalConstNode(arg.left as Node, env);
    const r = evalConstNode(arg.right, env);
    if (l === undefined || r === undefined) return undefined;
    switch (arg.operator) {
      case '+': return (l as any) + (r as any);
      case '-': return (l as any) - (r as any);
      case '*': return (l as any) * (r as any);
    }
  }
  return undefined;
}

function inlineEnvIntoFn(fn: t.Function, env: ConstEnv): void {
  // Wrap in a Program so traverse() has a root. The clone shares no nodes
  // with the original AST, so this is safe to mutate.
  const wrapper = t.isStatement(fn)
    ? (fn as t.Statement)
    : t.variableDeclaration('var', [t.variableDeclarator(t.identifier('__tmp'), fn as any)]);
  const program = t.file(t.program([wrapper]));
  traverse(program, {
    MemberExpression(p) {
      if (p.node.computed) return;
      if (!t.isIdentifier(p.node.object) || !t.isIdentifier(p.node.property)) return;
      const obj = env[p.node.object.name];
      if (obj && typeof obj === 'object' && p.node.property.name in (obj as any)) {
        const v = (obj as any)[p.node.property.name];
        p.replaceWith(typeof v === 'number' ? t.numericLiteral(v) : t.stringLiteral(v));
      }
    },
    Identifier(p) {
      // Don't rewrite ids that aren't value references
      if (p.parent && t.isMemberExpression(p.parent) && p.parent.object !== p.node) return;
      if (p.parent && t.isVariableDeclarator(p.parent) && p.parent.id === p.node) return;
      if (p.parent && t.isFunctionDeclaration(p.parent) && p.parent.id === p.node) return;
      if (p.parent && t.isFunction(p.parent) && (p.parent as any).params?.includes(p.node)) return;
      const v = env[p.node.name];
      if (typeof v === 'number') p.replaceWith(t.numericLiteral(v));
      else if (typeof v === 'string') p.replaceWith(t.stringLiteral(v));
    },
  });
}
