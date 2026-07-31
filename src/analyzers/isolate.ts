/**
 * Shared isolation boundary for anything that must *execute* attacker-controlled
 * JavaScript (vm boots, decoder calls, eval-layer capture).
 *
 * Node's `vm` is explicitly NOT a security sandbox, and its `timeout` option
 * only interrupts *synchronous* script — a hostile sample can still OOM the
 * host heap or schedule a microtask that loops forever after `runInContext`
 * returns. Running the vm work in a short-lived CHILD PROCESS bounds every one
 * of those failure modes to a disposable process:
 *
 *   - `--max-old-space-size` caps the heap; runaway allocation kills the child,
 *     not reaper.
 *   - the `timeout` on the spawn is a hard wall-clock kill that covers async /
 *     microtask hangs the in-vm timeout cannot.
 *   - `--frozen-intrinsics` makes built-in prototypes immutable.
 *   - the environment is stripped to PATH so no creds/tokens/NODE_OPTIONS leak
 *     into the child.
 *
 * This is a meaningful boundary but NOT equivalent to real isolation (kernel
 * namespaces, seccomp, dropped caps). For that, run reaper inside the docker
 * sandbox at `docker/Dockerfile` or via `scripts/analyze.sh`.
 *
 * Both the string-array decoder and the eval-scope capture route through here so
 * there is a single hardened path for executing sample code.
 */
import { execFileSync } from 'child_process';

export interface IsolateOptions {
  /** Extra argv passed to the worker after its path. */
  argv?:           string[];
  /** Data written to the child's stdin (for payloads too large for argv). */
  input?:          string;
  /** Hard wall-clock kill for the whole spawn. Default 10s. */
  timeoutMs?:      number;
  /** V8 old-space cap for the child, in MB. Default 128. */
  maxOldSpaceMb?:  number;
  /** Max bytes captured from the child's stdout. Default 32 MiB. */
  maxOutputBytes?: number;
}

export interface IsolateResult {
  stdout: Buffer | null;
  /** null on success; otherwise 'timeout' or a failure message. */
  error:  string | null;
  timedOut: boolean;
}

/**
 * Run `workerPath` in a hardened child process and capture its stdout.
 * Never throws — failures (timeout, non-zero exit, spawn error) come back in
 * `error`, so callers can degrade gracefully instead of crashing on a sample.
 */
export function runIsolated(workerPath: string, opts: IsolateOptions = {}): IsolateResult {
  const timeoutMs = opts.timeoutMs ?? 10_000;
  try {
    const stdout = execFileSync(
      process.execPath,
      [
        '--frozen-intrinsics',
        '--no-warnings',
        `--max-old-space-size=${opts.maxOldSpaceMb ?? 128}`,
        workerPath,
        ...(opts.argv ?? []),
      ],
      {
        timeout:   timeoutMs,
        maxBuffer: opts.maxOutputBytes ?? 32 * 1024 * 1024,
        input:     opts.input,
        stdio:     [opts.input !== undefined ? 'pipe' : 'ignore', 'pipe', 'pipe'],
        // Strip inherited environment: PATH is enough to find shared libs;
        // everything else (creds, tokens, NODE_OPTIONS injection) is dropped.
        env: {
          PATH:         process.env.PATH ?? '/usr/bin:/bin',
          NODE_OPTIONS: '',
        },
      },
    );
    return { stdout, error: null, timedOut: false };
  } catch (e: any) {
    const timedOut = e?.code === 'ETIMEDOUT' || e?.signal === 'SIGTERM';
    const error = timedOut
      ? `worker timed out after ${timeoutMs}ms`
      : `worker failed: ${e?.message ?? String(e)}`;
    return { stdout: null, error, timedOut };
  }
}
