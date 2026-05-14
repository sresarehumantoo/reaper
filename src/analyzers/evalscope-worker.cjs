'use strict';

/**
 * evalscope-worker — the actual vm.runInContext caller.
 *
 * Spawned as a CHILD PROCESS by evalscope.ts. The whole point of the
 * separation is that if a malicious sample escapes Node's `vm` boundary
 * (which it explicitly can — `vm` is not a security sandbox per the Node
 * docs), the damage is bounded to this short-lived child process. The
 * parent reaper process never imports this file directly.
 *
 * Contract with the parent:
 *   - argv[2] is the absolute path to the source file to capture.
 *   - On success, writes a single line of JSON to stdout matching
 *     EvalScopeResult ({ layers, globals, error }) and exits 0.
 *   - On any unexpected failure, writes an EvalScopeResult with
 *     `error: <message>` and exits 0 (so JSON.parse always succeeds in
 *     the parent — actual failure modes show up in the `error` field).
 *
 * Written in plain CommonJS so it can be copied verbatim to dist/
 * without TS compilation. Keep it dependency-free.
 */

const vm = require('vm');
const fs = require('fs');

const TIMEOUT_MS = 5000;

const filePath = process.argv[2];
if (!filePath) {
  process.stdout.write(JSON.stringify({ layers: [], globals: [], error: 'no input path' }));
  process.exit(0);
}

let source = '';
try {
  source = fs.readFileSync(filePath, 'utf-8');
} catch (e) {
  process.stdout.write(JSON.stringify({ layers: [], globals: [], error: 'read failed: ' + e.message }));
  process.exit(0);
}

const layers = [];
let layerIndex = 0;
let captureError = null;

// Browser-shaped sandbox context. Anything potentially dangerous is stubbed.
const context = {
  window:    null,
  self:      null,
  document: {
    title:  '',
    URL:    'http://localhost/',
    cookie: '',
    write() {},
  },
  location:  { href: 'http://localhost/' },
  navigator: { userAgent: 'reaper-sandbox' },
  console: {
    log:   () => {},
    warn:  () => {},
    error: () => {},
  },

  fetch:          undefined,
  XMLHttpRequest: class { open() {} send() {} setRequestHeader() {} },
  setTimeout:     fn => { if (typeof fn === 'function') { /* noop */ } },
  setInterval:    () => {},
  clearTimeout:   () => {},
  clearInterval:  () => {},

  process: { env: {}, exit: () => {} },

  eval: function reaperEval(code) {
    if (typeof code !== 'string') return undefined;
    layers.push({ index: layerIndex++, length: code.length, source: code });
    try {
      return vm.runInContext(code, vmContext, { timeout: TIMEOUT_MS });
    } catch {
      return undefined;
    }
  },

  Function: new Proxy(Function, {
    construct(target, args) {
      const body = String(args.at(-1) ?? '');
      layers.push({ index: layerIndex++, length: body.length, source: '(function(){' + body + '})' });
      return new target(...args);
    },
  }),

  String, Number, Boolean, Array, Object, Math, JSON, RegExp, Error,
  parseInt, parseFloat, isNaN, isFinite,
  encodeURIComponent, decodeURIComponent, encodeURI, decodeURI,
  undefined, NaN, Infinity,
};

const vmContext = vm.createContext(context);
context.window = vmContext;
context.self   = vmContext;

try {
  vm.runInContext(source, vmContext, { timeout: TIMEOUT_MS });
} catch (e) {
  captureError = e && e.message ? e.message : String(e);
}

const reserved = new Set([
  'eval', 'Function', 'String', 'Number', 'Boolean', 'Array',
  'Object', 'Math', 'JSON', 'RegExp', 'Error', 'XMLHttpRequest',
]);
const globals = Object.keys(vmContext).filter(k => {
  if (reserved.has(k)) return false;
  try { return typeof vmContext[k] === 'function'; } catch { return false; }
});

process.stdout.write(JSON.stringify({ layers, globals, error: captureError }));
