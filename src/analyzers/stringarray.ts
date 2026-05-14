/**
 * obfuscator.io string-array detector and static rewriter.
 *
 * The pattern:
 *   function _0xARR()        { const _0x... = [...]; _0xARR = ...; return ...; }
 *   function _0xDEC(a,b)     { const arr = _0xARR(); return _0xDEC = function(x){...arr[x-K]...}, _0xDEC(a,b); }
 *   (function(arr, target){ ... while(true){...} }(_0xARR, NNN));     // IIFE shuffle
 *   function _0xWRAP(a,b)    { return _0xDEC(transform(a, b), …); }   // optional wrappers, can be nested
 *
 * Strategy (pure-data: returns rewritten source, never mutates the input):
 *   1. Locate arrayFn, root decoder, the IIFE shuffle.
 *   2. Boot a sandboxed vm with array + decoder + IIFE so the rotation settles.
 *   3. Discover every wrapper fn (any depth, any number of passes).
 *   4. For each wrapper, inline enclosing-scope const objects/numbers/strings
 *      into a clone of its body, then emit into the vm so it's callable.
 *   5. Walk the AST; for each wrapper call whose args can be const-evaluated,
 *      replace the call with the literal string the wrapper returns.
 *   6. Strip the dead obfuscator scaffolding from the output AST.
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

  // ── 1. Locate arrayFn and root decoder ─────────────────────────────────────
  const arrayFn   = findArrayFn(ast);
  const decoderFn = arrayFn ? findRootDecoder(ast, arrayFn) : null;
  if (!arrayFn || !decoderFn) return info;

  info.arrayFn   = arrayFn;
  info.decoderFn = decoderFn;

  // ── 2. Locate IIFE shuffle ────────────────────────────────────────────────
  const iifeNode = findIifeShuffle(ast, arrayFn);

  // ── 3. Boot the VM with arrayFn + decoder + IIFE ─────────────────────────
  const ctx = vm.createContext(Object.create(null));
  const bootStmts = ast.program.body.filter(n =>
    (t.isFunctionDeclaration(n) && (n.id?.name === arrayFn || n.id?.name === decoderFn)) ||
    n === iifeNode
  );
  try {
    vm.runInContext(generate(t.program(bootStmts)).code, ctx, { timeout: VM_TIMEOUT_MS });
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

  // ── 4. Discover all wrappers at any depth ─────────────────────────────────
  const knownWrappers = new Set<string>([decoderFn]);
  const wrapperNodes  = new Map<string, t.Function>();

  for (let pass = 0; pass < 10; pass++) {
    let added = 0;
    traverse(ast, {
      Function(p) {
        const node = p.node;
        const name = getFnName(node, p.parent);
        if (!name || knownWrappers.has(name) || name === arrayFn) return;
        if (!isWrapperShape(node, knownWrappers)) return;
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

  // ── 6. Walk the AST, replace wrapper calls with literal strings ───────────
  traverse(ast, {
    CallExpression(p) {
      const callee = p.node.callee;
      if (!t.isIdentifier(callee)) return;
      if (callee.name === decoderFn || !knownWrappers.has(callee.name)) return;
      info.attempted++;
      const env  = collectConstEnv(p);
      const args = p.node.arguments.map(a => evalConstNode(a as Node, env));
      if (args.some(a => a === undefined)) return;
      let result: unknown;
      try { result = (ctx as any)[callee.name](...args as any[]); } catch { return; }
      if (typeof result === 'string') {
        p.replaceWith(t.stringLiteral(result));
        info.substitutions++;
      }
    },
  });

  // ── 7. Strip dead obfuscator scaffolding ──────────────────────────────────
  ast.program.body = ast.program.body.filter(n => {
    if (t.isFunctionDeclaration(n) && n.id) {
      if (n.id.name === arrayFn || n.id.name === decoderFn) return false;
    }
    if (n === iifeNode) return false;
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

function findArrayFn(ast: File): string | null {
  for (const node of ast.program.body) {
    if (!t.isFunctionDeclaration(node) || !node.id) continue;
    const hasArray = node.body.body.some(s =>
      t.isVariableDeclaration(s) &&
      s.declarations[0]?.init &&
      t.isArrayExpression(s.declarations[0].init) &&
      s.declarations[0].init.elements.length > 5
    );
    if (hasArray) return node.id.name;
  }
  return null;
}

function findRootDecoder(ast: File, arrayFn: string): string | null {
  // Pattern: function NAME(a,b){ const x = arrayFn(); return NAME = function(...){...}, NAME(a,b); }
  for (const node of ast.program.body) {
    if (!t.isFunctionDeclaration(node) || !node.id) continue;
    if (node.id.name === arrayFn) continue;
    for (const stmt of node.body.body) {
      if (!t.isReturnStatement(stmt)) continue;
      const seq  = stmt.argument;
      const head = t.isSequenceExpression(seq) ? seq.expressions[0] :
                   t.isAssignmentExpression(seq) ? seq : null;
      if (!head || !t.isAssignmentExpression(head)) continue;
      if (t.isIdentifier(head.left) && head.left.name === node.id.name &&
          t.isFunctionExpression(head.right)) {
        return node.id.name;
      }
    }
  }
  return null;
}

function findIifeShuffle(ast: File, arrayFn: string): t.ExpressionStatement | null {
  for (const node of ast.program.body) {
    if (!t.isExpressionStatement(node)) continue;
    if (!t.isCallExpression(node.expression)) continue;
    if (!t.isFunctionExpression(node.expression.callee)) continue;
    const passesArrayFn = node.expression.arguments.some(a =>
      t.isIdentifier(a) && a.name === arrayFn);
    if (passesArrayFn) return node;
  }
  return null;
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
