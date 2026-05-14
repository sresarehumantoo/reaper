'use strict';

/**
 * reaper sandbox monitoring shim
 *
 * Injected via --require before the target file runs.
 * Intercepts and logs dangerous runtime patterns without blocking them
 * so we capture full behavioral evidence.
 *
 * Output: structured JSON lines on stderr prefixed with [REAPER]
 */

const Module  = require('module');
const origLoad = Module._load;

const START = Date.now();
const TIMEOUT_MS = parseInt(process.env.SANDBOX_TIMEOUT || '10000', 10);

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

  if (BLOCKED_MODULES.has(request)) {
    log('blocked', `require('${request}') — module blocked in sandbox`);
    // Return a proxy that throws on any property access
    return new Proxy({}, {
      get(_t, prop) {
        return function () {
          throw new Error(`[reaper sandbox] '${request}.${String(prop)}' is disabled`);
        };
      },
    });
  }

  const mod = origLoad.apply(this, arguments);

  // Wrap net/http/https to log connection attempts (will fail — network=none)
  if (request === 'net' || request === 'http' || request === 'https' || request === 'dgram') {
    return wrapNetworkModule(request, mod);
  }

  // Wrap fs to log file write/delete attempts
  if (request === 'fs' || request === 'fs/promises') {
    return wrapFsModule(request, mod);
  }

  return mod;
};

// ── eval / Function interception ─────────────────────────────────────────────

const _eval = global.eval;
global.eval = function reaperEval(code) {
  log('eval', String(code));
  return _eval.call(this, code);
};

const _Function = Function;
global.Function = new Proxy(_Function, {
  construct(target, args) {
    log('new-Function', String(args.at(-1) ?? ''));
    return new target(...args);
  },
  apply(target, thisArg, args) {
    log('Function-call', String(args.at(-1) ?? ''));
    return target.apply(thisArg, args);
  },
});

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

log('sandbox', 'initialized');
