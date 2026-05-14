/**
 * Eval-aware scope capture.
 *
 * Many obfuscated / packed JS files define functions only at runtime via
 * nested eval() calls (p,a,c,k,e,r and similar packers).  Static AST
 * analysis alone cannot see those definitions.
 *
 * This module executes the target file in a Node.js vm sandbox,
 * intercepts every eval() call, collects all unpacked source layers,
 * and returns them as parseable JavaScript strings.
 *
 * The sandbox has:
 *   - No network (child_process / http / https blocked)
 *   - No file-system writes
 *   - Hard timeout
 *   - Mocked browser globals (window, document, XMLHttpRequest, etc.)
 *
 * The collected layers can then be parsed with @babel/parser and fed
 * into the static call-graph builder for full reachability analysis.
 */
import vm from 'vm';
import fs from 'fs';

export interface EvalLayer {
  index:  number;
  length: number;
  source: string;
}

export interface EvalScopeResult {
  layers:     EvalLayer[];
  globals:    string[];   // names of functions defined in the sandbox global
  error:      string | null;
}

const TIMEOUT_MS = 5000;

export function captureEvalScope(filePath: string): EvalScopeResult {
  const source = fs.readFileSync(filePath, 'utf-8');
  const layers: EvalLayer[] = [];
  let   layerIndex = 0;
  let   captureError: string | null = null;

  // ── Sandbox context ──────────────────────────────────────────────────────
  const context: Record<string, any> = {
    // Browser-like globals
    window:    null as any, // set below after context creation
    self:      null as any,
    document: {
      title:   '',
      URL:     'http://localhost/',
      cookie:  '',
      write()  {},
    },
    location:  { href: 'http://localhost/' },
    navigator: { userAgent: 'reaper-sandbox' },
    console: {
      log:   () => {},
      warn:  () => {},
      error: () => {},
    },

    // Block dangerous APIs
    fetch:          undefined,
    XMLHttpRequest: class { open() {} send() {} setRequestHeader() {} },
    setTimeout:     (fn: any) => { if (typeof fn === 'function') { /* noop */ } },
    setInterval:    () => {},
    clearTimeout:   () => {},
    clearInterval:  () => {},

    // Stub process so code that checks it doesn't throw
    process: { env: {}, exit: () => {} },

    // Intercept eval — the core of this module
    eval: function reaperEval(code: string) {
      if (typeof code !== 'string') return undefined;
      layers.push({ index: layerIndex++, length: code.length, source: code });
      try {
        return vm.runInContext(code, vmContext, { timeout: TIMEOUT_MS });
      } catch (e: any) {
        // Swallow — we still want the source
        return undefined;
      }
    },

    // Stub out Function constructor eval-equivalent
    Function: new Proxy(Function, {
      construct(target, args) {
        const body = String(args.at(-1) ?? '');
        layers.push({ index: layerIndex++, length: body.length, source: `(function(){${body}})` });
        return new target(...args);
      },
    }),

    String,
    Number,
    Boolean,
    Array,
    Object,
    Math,
    JSON,
    RegExp,
    Error,
    parseInt,
    parseFloat,
    isNaN,
    isFinite,
    encodeURIComponent,
    decodeURIComponent,
    encodeURI,
    decodeURI,
    undefined,
    NaN,
    Infinity,
  };

  const vmContext = vm.createContext(context);
  context.window = vmContext;
  context.self   = vmContext;

  // ── Execute the file ─────────────────────────────────────────────────────
  try {
    vm.runInContext(source, vmContext, { timeout: TIMEOUT_MS });
  } catch (e: any) {
    captureError = e.message;
  }

  // ── Collect function names defined in the sandbox global ─────────────────
  const globals = Object.keys(vmContext).filter(k => {
    try {
      return typeof vmContext[k] === 'function' &&
        !['eval', 'Function', 'String', 'Number', 'Boolean', 'Array',
          'Object', 'Math', 'JSON', 'RegExp', 'Error', 'XMLHttpRequest'].includes(k);
    } catch {
      return false;
    }
  });

  return { layers, globals, error: captureError };
}
