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
 *   2. Boot a sandboxed vm with array + decoder + IIFE so the rotation settles.
 *   3. Discover every wrapper fn (any depth, any number of passes) AND every
 *      identifier alias `var X = decoder` (transitively).
 *   4. For each wrapper, inline enclosing-scope const objects/numbers/strings
 *      into a clone of its body, then emit into the vm so it's callable.
 *   5. Walk the AST; for each wrapper or alias call whose args can be
 *      const-evaluated, replace the call with the literal string returned.
 *   6. Strip the dead obfuscator scaffolding from the output AST when it's
 *      at program-body level (nested scaffolding is left in place — safer).
 */

import vm from 'vm';
import { parseCode } from '../parser';
import _traverse from '@babel/traverse';
import _generate from '@babel/generator';
import * as t from '@babel/types';
import type { File, Node } from '@babel/types';

const traverse = (typeof _traverse === 'function' ? _traverse : (_traverse as any).default) as typeof _traverse;
const generate = (typeof (_generate as any) === 'function' ? (_generate as any) : (_generate as any).default) as typeof _generate;

const VM_TIMEOUT_MS = 5000;

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

  // ── 3. Boot the VM with arrayFn + decoder + IIFE ─────────────────────────
  // Synthesise a fresh program: clone the discovered nodes (so we don't mutate
  // the source AST) and emit them in arrayFn → decoder → rotator order.
  const ctx = vm.createContext(Object.create(null));
  const bootBody: t.Statement[] = [
    t.cloneNode(arrayDecl, true),
    t.cloneNode(decoderDecl, true),
  ];
  if (iifeCall) bootBody.push(t.expressionStatement(t.cloneNode(iifeCall, true)));
  try {
    vm.runInContext(generate(t.program(bootBody)).code, ctx, { timeout: VM_TIMEOUT_MS });
  } catch (e: any) {
    info.error = `vm boot failed: ${e.message}`;
    return info;
  }

  // Decoder must be callable now.
  if (typeof (ctx as any)[decoderFn] !== 'function') {
    info.error = 'decoder not callable after boot';
    return info;
  }

  info.detected = true;

  // ── 4a. Discover identifier aliases of the decoder ────────────────────────
  // Pattern: `var X = decoder` (or `var Y = X` transitively). These are not
  // wrapper functions — they're aliased references the obfuscator scatters
  // through every function scope to defeat naive name-based detection.
  // For substitution purposes, a call on an alias is equivalent to a call on
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
  info.aliases = [...aliasToRoot.keys()].filter(n => n !== decoderFn);

  // ── 4b. Discover wrapper functions at any depth ───────────────────────────
  // A wrapper is `function w(a,b){ return <decoder-or-alias>(transform(a,b)); }`
  // — it transforms the args before delegating. Track them separately from
  // aliases because they need to be materialised into the vm individually.
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
        // A wrapper resolves through any known decoder/alias/wrapper.
        const resolvable = new Set<string>([...knownWrappers, ...aliasToRoot.keys()]);
        if (!isWrapperShape(node, resolvable)) return;
        knownWrappers.add(name);
        wrapperNodes.set(name, node);
        added++;
      },
    });
    if (added === 0) break;
  }

  info.wrappers = [...wrapperNodes.keys()];

  // ── 5. Materialise each wrapper into the vm (with scope-env inlined) ──────
  for (const [name, node] of wrapperNodes) {
    const fnPath = findFnPathByName(ast, name);
    const env    = fnPath ? collectConstEnv(fnPath) : {};
    const cloned = t.cloneNode(node, true) as t.Function;
    inlineEnvIntoFn(cloned, env);

    let declCode: string;
    if (t.isFunctionDeclaration(cloned)) {
      declCode = generate(cloned).code;
    } else if (t.isFunctionExpression(cloned) || t.isArrowFunctionExpression(cloned)) {
      const wrapDecl = t.variableDeclaration('var', [
        t.variableDeclarator(t.identifier(name), cloned),
      ]);
      declCode = generate(wrapDecl).code;
    } else continue;

    try {
      vm.runInContext(declCode, ctx, { timeout: VM_TIMEOUT_MS });
    } catch (e: any) {
      // One wrapper failing shouldn't kill the whole pass — continue.
      continue;
    }
  }

  // ── 6. Walk the AST, replace wrapper/alias calls with literal strings ────
  // Two routes:
  //   (i)  callee is an alias of the decoder → call ctx[decoder](...args).
  //   (ii) callee is a wrapper fn we materialised → call ctx[wrapper](...args).
  // The root decoder is skipped at its declared name (the substitution would
  // be redundant — direct decoder calls are vanishingly rare and the boot
  // step already left it defined for alias resolution).
  traverse(ast, {
    CallExpression(p) {
      const callee = p.node.callee;
      if (!t.isIdentifier(callee)) return;
      const name = callee.name;

      let target: string | null = null;
      if (aliasToRoot.has(name) && name !== decoderFn) {
        target = decoderFn;
      } else if (knownWrappers.has(name) && name !== decoderFn) {
        target = name;
      } else {
        return;
      }

      info.attempted++;
      const env  = collectConstEnv(p);
      const args = p.node.arguments.map(a => evalConstNode(a as Node, env));
      if (args.some(a => a === undefined)) return;
      let result: unknown;
      try { result = (ctx as any)[target](...args as any[]); } catch { return; }
      if (typeof result === 'string') {
        p.replaceWith(t.stringLiteral(result));
        info.substitutions++;
      }
    },
  });

  // ── 7. Strip dead obfuscator scaffolding ──────────────────────────────────
  // Top-level scaffolding only — when the obfuscator wraps everything in an
  // outer IIFE the scaffold lives inside it; in that case we leave it alone
  // (the rewritten strings make the file readable without removing structure
  // that other analyses may want to inspect). The IIFE-shuffle ExpressionStatement
  // at program-body level is removed when found.
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
  // Require an explicit `var X = arrayFn()` (or const/let) and a return that
  // either returns an indexed expression or returns an identifier that was
  // assigned an indexed expression.
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

function findFnPathByName(ast: File, name: string): any /* NodePath */ | null {
  let found: any = null;
  traverse(ast, {
    Function(p) {
      const n = getFnName(p.node, p.parent);
      if (n === name) found = p;
    },
  });
  return found;
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
