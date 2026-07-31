'use strict';

/**
 * stringarray-worker — the isolated executor for the obfuscator.io string-array
 * decoder.
 *
 * Spawned as a CHILD PROCESS by stringarray.ts via isolate.ts. All AST work
 * (detection, arg evaluation, substitution) happens in the parent; only the
 * dangerous part — booting the sample's array-fn / decoder / rotator IIFE and
 * calling the decoder to recover strings — runs here, behind the child-process
 * boundary (heap cap, hard timeout, frozen intrinsics, stripped env). If a
 * sample OOMs or hangs, it takes down this disposable child, not reaper.
 *
 * The vm context is a bare `Object.create(null)` — no host objects are exposed,
 * so there is nothing for sample code to climb back to. It still executes with
 * full CPU/heap until the parent's wall-clock kill, hence the child boundary.
 *
 * Protocol (stdin → stdout, both JSON):
 *   in : { boot: string, decoder: string,
 *          wrappers: string[],                       // each a var/function decl
 *          calls: [{ id: number, target: string, args: (string|number)[] }] }
 *   out: { ok: boolean, error: string|null,
 *          results: [{ id: number, value: string|null }] }
 *
 * Dependency-free CommonJS so it can be copied verbatim into dist/.
 */

const vm = require('vm');

const VM_TIMEOUT_MS = 5000;

function emit(obj) {
  process.stdout.write(JSON.stringify(obj));
  process.exit(0);
}

let input;
try {
  input = JSON.parse(require('fs').readFileSync(0, 'utf-8'));
} catch (e) {
  emit({ ok: false, error: 'bad worker input: ' + (e && e.message), results: [] });
}

const { boot, decoder, wrappers = [], calls = [] } = input || {};

const ctx = vm.createContext(Object.create(null));

// ── Boot: array fn + decoder + rotator IIFE ────────────────────────────────
try {
  vm.runInContext(String(boot), ctx, { timeout: VM_TIMEOUT_MS });
} catch (e) {
  emit({ ok: false, error: 'vm boot failed: ' + (e && e.message), results: [] });
}

if (typeof ctx[decoder] !== 'function') {
  emit({ ok: false, error: 'decoder not callable after boot', results: [] });
}

// ── Materialise wrappers (one failing wrapper must not abort the rest) ──────
for (const code of wrappers) {
  try {
    vm.runInContext(String(code), ctx, { timeout: VM_TIMEOUT_MS });
  } catch {
    /* skip this wrapper; its call sites simply won't resolve */
  }
}

// ── Decode every collected call ────────────────────────────────────────────
const results = [];
for (const call of calls) {
  let value = null;
  try {
    const fn = ctx[call.target];
    if (typeof fn === 'function') {
      const out = fn(...call.args);
      if (typeof out === 'string') value = out;
    }
  } catch {
    /* leave value null — parent won't substitute this site */
  }
  results.push({ id: call.id, value });
}

emit({ ok: true, error: null, results });
