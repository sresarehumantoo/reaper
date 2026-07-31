'use strict';

/**
 * reaper sandbox monitoring shim
 *
 * Injected via --require before the target file runs.
 * Intercepts and logs dangerous runtime patterns without blocking them
 * so we capture full behavioral evidence.
 *
 * Output: structured JSON lines on stderr prefixed with [REAPER]
 *
 * Env-driven modes (all opt-in, all default off):
 *   REAPER_OBSERVE_NETWORK=1  install stub fetch/http/https that LOGS the
 *                             attempt and returns a synthetic empty success
 *                             response instead of failing. Combined with
 *                             docker --network none, lets the target script
 *                             advance past network calls so we see the next
 *                             stage of behavior without real egress.
 *   REAPER_BLOCK_EVAL=1       eval()/new Function() throw instead of running
 *                             after logging. Useful for "what would it try
 *                             to execute?" mode.
 *   REAPER_BLOCK_FS=1         file-system writes throw after logging.
 */

const Module  = require('module');
const origLoad = Module._load;

const START = Date.now();
const TIMEOUT_MS      = parseInt(process.env.SANDBOX_TIMEOUT || '10000', 10);
const OBSERVE_NETWORK = process.env.REAPER_OBSERVE_NETWORK === '1';
const BLOCK_EVAL      = process.env.REAPER_BLOCK_EVAL      === '1';
const BLOCK_FS        = process.env.REAPER_BLOCK_FS        === '1';

// ── Structured logging ───────────────────────────────────────────────────────

function log(category, detail) {
  const entry = {
    t:        Date.now() - START,
    category,
    detail:   typeof detail === 'string' ? detail.slice(0, 400) : detail,
  };
  process.stderr.write('[REAPER] ' + JSON.stringify(entry) + '\n');
}

// ── Hard kill timeout ────────────────────────────────────────────────────────

const killTimer = setTimeout(() => {
  log('sandbox', `timeout after ${TIMEOUT_MS}ms — killing`);
  process.exit(124);
}, TIMEOUT_MS);
// Keep timer active even if event loop would otherwise empty
killTimer.ref();

// ── require() interception ───────────────────────────────────────────────────

const BLOCKED_MODULES = new Set(['child_process', 'cluster', 'worker_threads']);

Module._load = function reaperLoad(request, parent, isMain) {
  if (!isMain) {
    log('require', request);
  }

  // Normalise the `node:` prefix so require('node:child_process') can't slip
  // past the bare-name checks below.
  const name = typeof request === 'string' && request.startsWith('node:')
    ? request.slice(5)
    : request;

  if (BLOCKED_MODULES.has(name)) {
    log('blocked', `require('${request}') — module blocked in sandbox`);
    // Return a proxy that throws on any property access
    return new Proxy({}, {
      get(_t, prop) {
        return function () {
          throw new Error(`[reaper sandbox] '${name}.${String(prop)}' is disabled`);
        };
      },
    });
  }

  const mod = origLoad.apply(this, arguments);

  // Wrap net/http/https to log connection attempts (will fail — network=none)
  if (name === 'net' || name === 'http' || name === 'https' || name === 'dgram') {
    return wrapNetworkModule(name, mod);
  }

  // Wrap fs to log file write/delete attempts
  if (name === 'fs' || name === 'fs/promises') {
    return wrapFsModule(name, mod);
  }

  return mod;
};

// ── eval / Function interception ─────────────────────────────────────────────

const _eval = global.eval;
global.eval = function reaperEval(code) {
  log('eval', String(code));
  if (BLOCK_EVAL) throw new Error('[reaper sandbox] eval blocked (REAPER_BLOCK_EVAL=1)');
  return _eval.call(this, code);
};

const _Function = Function;
global.Function = new Proxy(_Function, {
  construct(target, args) {
    log('new-Function', String(args.at(-1) ?? ''));
    if (BLOCK_EVAL) throw new Error('[reaper sandbox] Function constructor blocked (REAPER_BLOCK_EVAL=1)');
    return new target(...args);
  },
  apply(target, thisArg, args) {
    log('Function-call', String(args.at(-1) ?? ''));
    if (BLOCK_EVAL) throw new Error('[reaper sandbox] Function call blocked (REAPER_BLOCK_EVAL=1)');
    return target.apply(thisArg, args);
  },
});

// ── Global fetch interception (observe mode) ────────────────────────────────
// Node 18+ exposes a global `fetch` (undici). In observe mode we replace it
// with a stub that logs URL+method+body and returns a synthetic empty-success
// Response. Without this, fetch() would throw because docker --network none
// drops every connection, and the target script would exit before doing
// anything else interesting.

if (OBSERVE_NETWORK && typeof globalThis.fetch === 'function') {
  globalThis.fetch = async function reaperFetch(input, init) {
    const url    = typeof input === 'string' ? input : (input && input.url) || String(input);
    const method = (init && init.method) || 'GET';
    const body   = (init && init.body) ? String(init.body).slice(0, 400) : '';
    log('fetch', { url, method, body });

    // Empty JSON-RPC-ish response. Real-world malware often parses JSON;
    // returning an empty object lets a few more lines run before it
    // (probably) throws — surfaces more behavior than just `fetch failed`.
    const text = '{"jsonrpc":"2.0","id":0,"result":"0x"}';
    return {
      ok:        true,
      status:    200,
      statusText:'OK',
      headers:   new Map([['content-type', 'application/json']]),
      url,
      text:      async () => text,
      json:      async () => JSON.parse(text),
      arrayBuffer: async () => new TextEncoder().encode(text).buffer,
      clone() { return this; },
    };
  };
}

// ── setTimeout / setInterval with string arg ─────────────────────────────────

const _setTimeout  = global.setTimeout;
const _setInterval = global.setInterval;

global.setTimeout = function reaperSetTimeout(fn, delay, ...rest) {
  if (typeof fn === 'string') log('setTimeout-string', fn);
  return _setTimeout(fn, delay, ...rest);
};

global.setInterval = function reaperSetInterval(fn, delay, ...rest) {
  if (typeof fn === 'string') log('setInterval-string', fn);
  return _setInterval(fn, delay, ...rest);
};

// ── process hardening ────────────────────────────────────────────────────────

const _exit = process.exit.bind(process);
process.exit = function reaperExit(code) {
  log('process.exit', code ?? 0);
  _exit(code);
};

// Log any access to env vars (common for credential harvesting)
process.env = new Proxy(process.env, {
  get(target, prop) {
    if (typeof prop === 'string' && prop !== 'SANDBOX_TIMEOUT') {
      log('env-access', prop);
    }
    return target[prop];
  },
});

// ── Network module wrapper ───────────────────────────────────────────────────

function wrapNetworkModule(name, mod) {
  return new Proxy(mod, {
    get(target, prop) {
      const orig = target[prop];
      if (typeof orig !== 'function') return orig;
      if (OBSERVE_NETWORK && (name === 'http' || name === 'https') &&
          (prop === 'request' || prop === 'get')) {
        return function reaperHttpStub(...args) {
          const opts = typeof args[0] === 'string' ? { url: args[0] } : (args[0] || {});
          log(`${name}.${String(prop)}`, summarizeArgs(args));
          // Return a fake EventEmitter-like req object that emits a stub
          // response on .end() so consumers don't hang.
          const { EventEmitter } = require('events');
          const req = new EventEmitter();
          req.write = () => true;
          req.end = function () {
            setImmediate(() => {
              const res = new EventEmitter();
              res.statusCode = 200;
              res.headers = { 'content-type': 'application/json' };
              const cb = typeof args[args.length - 1] === 'function' ? args[args.length - 1] : null;
              if (cb) cb(res);
              req.emit('response', res);
              res.emit('data', Buffer.from('{"jsonrpc":"2.0","id":0,"result":"0x"}'));
              res.emit('end');
            });
            return this;
          };
          req.setHeader = () => {};
          req.destroy = () => {};
          return req;
        };
      }
      return function (...args) {
        log(`${name}.${String(prop)}`, summarizeArgs(args));
        return orig.apply(target, args);
      };
    },
  });
}

// ── FS module wrapper (log writes/deletes, allow reads) ─────────────────────

const FS_WRITE_OPS = new Set([
  'writeFile', 'writeFileSync', 'appendFile', 'appendFileSync',
  'unlink', 'unlinkSync', 'rm', 'rmSync', 'rmdir', 'rmdirSync',
  'rename', 'renameSync', 'mkdir', 'mkdirSync',
  'open', 'openSync', 'write', 'writeSync',
]);

function wrapFsModule(name, mod) {
  return new Proxy(mod, {
    get(target, prop) {
      const orig = target[prop];
      if (typeof orig !== 'function') return orig;
      if (FS_WRITE_OPS.has(String(prop))) {
        return function (...args) {
          log(`${name}.${String(prop)}`, summarizeArgs(args));
          if (BLOCK_FS) throw new Error(`[reaper sandbox] ${name}.${String(prop)} blocked (REAPER_BLOCK_FS=1)`);
          return orig.apply(target, args);
        };
      }
      return orig;
    },
  });
}

// ── Utility ──────────────────────────────────────────────────────────────────

function summarizeArgs(args) {
  return args
    .slice(0, 3)
    .map(a => {
      if (typeof a === 'string') return a.slice(0, 100);
      if (typeof a === 'number') return a;
      if (a && typeof a === 'object' && a.host) return `${a.host}:${a.port}`;
      return typeof a;
    })
    .join(', ');
}

log('sandbox', {
  initialized:      true,
  observe_network:  OBSERVE_NETWORK,
  block_eval:       BLOCK_EVAL,
  block_fs:         BLOCK_FS,
});
