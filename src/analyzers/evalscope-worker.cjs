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
  // String timers are eval in disguise: capture them as layers. Function
  // callbacks stay unscheduled.
  setTimeout:     fn => { if (typeof fn === 'string') context.eval(fn); },
  setInterval:    fn => { if (typeof fn === 'string') context.eval(fn); },
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

  // Browser payloads decode with atob almost universally; without it the
  // capture dies with a ReferenceError before reaching the first layer.
  atob: s => Buffer.from(String(s), 'base64').toString('latin1'),
  btoa: s => Buffer.from(String(s), 'latin1').toString('base64'),

  String, Number, Boolean, Array, Object, Math, JSON, RegExp, Error,
  parseInt, parseFloat, isNaN, isFinite,
  encodeURIComponent, decodeURIComponent, encodeURI, decodeURI,
  undefined, NaN, Infinity,
};

const vmContext = vm.createContext(context);
context.window = vmContext;
context.self   = vmContext;

// Hook the context realm's own Function constructors, reached either as the
// `Function` global (called with or without `new`) or through any function's
// prototype chain (`[].constructor.constructor(...)`, async/generator
// variants). The constructed functions stay in the vm realm.
function recordFunctionLayer(args) {
  const body = String(args.at(-1) ?? '');
  layers.push({ index: layerIndex++, length: body.length, source: '(function(){' + body + '})' });
}
const realmCtors = vm.runInContext(
  '[function () {}, async function () {}, function* () {}, async function* () {}]' +
  '.map(f => Object.getPrototypeOf(f).constructor)',
  vmContext,
);
for (const Ctor of realmCtors) {
  const wrapped = new Proxy(Ctor, {
    construct(target, args) { recordFunctionLayer(args); return Reflect.construct(target, args); },
    apply(target, thisArg, args) { recordFunctionLayer(args); return Reflect.apply(target, thisArg, args); },
  });
  Object.defineProperty(Ctor.prototype, 'constructor', { value: wrapped, writable: true, configurable: true });
  if (Ctor === realmCtors[0]) context.Function = wrapped;
}

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
