/**
 * Eval-aware scope capture.
 *
 * Many obfuscated / packed JS files define functions only at runtime via
 * nested eval() calls (p,a,c,k,e,r and similar packers). Static AST
 * analysis alone cannot see those definitions.
 *
 * This module captures those layers by spawning a CHILD PROCESS that
 * executes the suspect file under Node's `vm` module. The child writes
 * a JSON-serialised EvalScopeResult to stdout and exits.
 *
 * Why a child process — Node's `vm` is NOT a security sandbox (explicitly
 * documented as such). A hostile sample can climb the prototype chain
 * from any non-primitive value in the context (document, console, JSON)
 * back to the host Function constructor and execute arbitrary code in
 * the running process. Putting the vm invocation in a short-lived child
 * bounds the damage to that child: it cannot influence reaper's main
 * process state, cannot interfere with concurrent analyses, and is
 * killed hard on timeout.
 *
 * The child gets:
 *   - --frozen-intrinsics       (built-in prototypes immutable)
 *   - --no-warnings             (clean output)
 *   - --max-old-space-size=128  (memory cap)
 *   - NODE_OPTIONS=''           (defeat env-based code injection)
 *   - PATH only                 (no inherited secrets / tokens)
 *   - 10 s wall-clock from execFileSync timeout
 *
 * For real isolation (kernel namespaces, seccomp, dropped caps), run
 * reaper itself inside the docker sandbox at `docker/Dockerfile` or use
 * `scripts/analyze.sh --dynamic-only`. The child-process boundary here
 * is a meaningful step up from in-process vm but is NOT equivalent.
 */
import path from 'path';
import fs from 'fs';
import { runIsolated } from './isolate';

export interface EvalLayer {
  index:  number;
  length: number;
  source: string;
}

export interface EvalScopeResult {
  layers:     EvalLayer[];
  globals:    string[];
  error:      string | null;
}

// Wall-clock for the entire child invocation, including process spawn,
// vm boot, and execution. Should be > the worker's internal TIMEOUT_MS
// (currently 5s) so the worker can hit its own limit and write a partial
// result rather than being SIGKILL'd halfway through writing JSON.
const CHILD_TIMEOUT_MS = 10_000;
const MAX_OUTPUT_BYTES = 32 * 1024 * 1024;

// In dev (tsx) __dirname is src/analyzers/; in prod it's dist/analyzers/.
// `npm run build` copies the .cjs worker next to the compiled .js, so this
// resolves correctly in both cases.
const WORKER_PATH = path.join(__dirname, 'evalscope-worker.cjs');

export function captureEvalScope(filePath: string): EvalScopeResult {
  if (!fs.existsSync(WORKER_PATH)) {
    return {
      layers:  [],
      globals: [],
      error:   `evalscope worker missing at ${WORKER_PATH} (build did not copy .cjs?)`,
    };
  }

  const run = runIsolated(WORKER_PATH, {
    argv:           [filePath],
    timeoutMs:      CHILD_TIMEOUT_MS,
    maxOutputBytes: MAX_OUTPUT_BYTES,
  });
  if (run.error || !run.stdout) {
    return { layers: [], globals: [], error: run.error ?? 'worker produced no output' };
  }

  try {
    const parsed = JSON.parse(run.stdout.toString('utf-8')) as EvalScopeResult;
    return parsed;
  } catch (e: any) {
    return {
      layers:  [],
      globals: [],
      error:   `worker produced unparseable output: ${e?.message ?? String(e)}`,
    };
  }
}
