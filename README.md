# reaper

Dead-code and obfuscation analyzer for JavaScript and TypeScript, with an optional hardened Docker sandbox for dynamic behavioral analysis of suspicious scripts.

Originally built to triage JS malware samples — packed payloads, eval layers, char-code arrays, base64 staging — but it works just as well as a plain dead-code finder on regular source trees.

## What it does

**Static analysis (Babel-based AST):**
- Unused imports, variables, functions, and exports
- Unreachable code after `return` / `throw`
- Dead branches via constant folding (`if (false)`, `1 === 2`, etc.)
- Obfuscation patterns: `eval`, `new Function`, `setTimeout("...")`, `atob`, `String.fromCharCode(...)`, bracket access to `['eval']`/`['constructor']`, high-entropy string literals, hex/unicode escape density
- Cross-scope reachability: call-graph BFS from auto-detected or user-supplied entry points
- Eval-aware scope capture — intercepts `eval`'d source and recursively analyses the inner layers
- `p,a,c,k,e,r` static unpack + string folding inside dead function bodies (recovers constant strings from code that won't run)

**Dynamic analysis (Docker sandbox):**
- `node:20-alpine` container, non-root uid 1001, all caps dropped, `no-new-privileges`
- `--network none`, 256 MB memory cap, 0.5 CPU, read-only FS, `noexec` tmpfs
- Pre-loaded monitoring shim logs `eval` / `new Function` / `setTimeout(string)` calls, `require()`s, env-var access, and `net`/`http`/`fs` writes as `[REAPER]` JSON lines on stderr
- Hard wall-clock timeout, `child_process` / `cluster` / `worker_threads` blocked

## Install

```bash
npm install
npm run build      # compiles to dist/
# or run from source:
npx tsx src/cli.ts <pattern>
```

## Usage

```bash
# Default scan — all analyzers on
reaper "src/**/*.ts"

# JSON output
reaper "malware.js" --format json --output report.json

# Function inventory + reduction report
reaper "packed.js" --analyze

# Cross-scope reachability (eval-aware) with auto-detected entry points
reaper "packed.js" --reachability

# Reachability with explicit entry points
reaper "malware.js" --reachability --entry sendCode,init

# Disable specific analyzers
reaper "src/**/*.js" --no-obfuscation --no-dead-branches
```

Exit code is non-zero when findings are present, so it composes with CI.

### Full pipeline (static + sandboxed dynamic)

```bash
./scripts/analyze.sh suspicious.js
./scripts/analyze.sh malware.js --timeout 30 --output-dir ./reports
./scripts/analyze.sh packed.js --static-only
```

The pipeline script runs the static analyzer, then builds and runs the Docker sandbox image (`reaper-sandbox:latest`) against the target.

## Examples

`examples/deadcode01/` — a real-world obfuscated sample (`sendCode.js`) plus its companion files. Good test for reachability + eval-layer capture.

`examples/deadcode02/` — a small `p,a,c,k,e,r` packed flag — try `reaper examples/deadcode02/flag.js --reachability`.

## Project layout

```
src/
  cli.ts                # commander entrypoint
  parser/               # @babel/parser wrapper
  analyzers/
    imports.ts          # unused imports
    references.ts       # unused vars / functions
    unreachable.ts      # code after return/throw
    branches.ts         # constant-folded dead branches
    obfuscation.ts      # eval, Function, atob, fromCharCode, entropy, …
    reachability.ts     # top-level cross-scope reachability analyzer
    evalscope.ts        # eval interception → captured inner-layer sources
    packer.ts           # p,a,c,k,e,r detection + static unpack
    strfold.ts          # constant-string folding inside dead bodies
    functions.ts        # function metadata extraction
  graph/
    callgraph.ts        # build call graph from AST
    reachability.ts     # BFS over the graph, entry-point detection
  reporter/
    console.ts          # default human-readable output
    json.ts             # JSON output
    analysis.ts         # --analyze inventory report
    reachability.ts     # --reachability report
docker/
  Dockerfile            # hardened sandbox image
  runner.js             # --require shim that logs dangerous APIs
scripts/
  analyze.sh            # combined static + dynamic pipeline
examples/               # sample inputs
```

## Requirements

- Node.js 20+
- Docker (only required for `--dynamic` analysis via `scripts/analyze.sh`)

## License

Not yet specified.
