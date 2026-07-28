# reaper

Dead-code and obfuscation analyzer for JavaScript and TypeScript, with an optional hardened Docker sandbox for dynamic behavioral analysis of suspicious scripts.

Originally built to triage JS malware samples - packed payloads, eval layers, char-code arrays, base64 staging, smart-contract-hosted payloads - but it works just as well as a plain dead-code finder on regular source trees.

> [!WARNING]
> **`examples/` contains real, live malware and ad-fraud samples.** The files under `examples/dom01/`, `examples/etherhiding/artifacts/`, `examples/clickfix-xloader/artifacts/`, `examples/propellerads-sfp/artifacts/`, `examples/deadcode01/`, and `examples/deadcode02/` are deobfuscation fixtures and reverse-engineering walkthroughs that ship inert payloads (`.js`, `.b64`, `.hex`, `.ps1`, `.txt`) **as data files**. They will not execute unless you deliberately run them. Do not `node`, `bash`, or `eval` any file under `examples/`. Do not paste the contents of any `clipboard-payload.txt` or `clipboard-command.txt` into a shell.
>
> If you want a code-only clone with no payloads, use a sparse checkout:
>
> ```sh
> git clone --filter=blob:none --no-checkout https://github.com/sresarehumantoo/reaper.git
> cd reaper
> git sparse-checkout init --cone
> git sparse-checkout set src scripts docker
> git checkout
> ```
>
> See `examples/etherhiding/README.md` for the analysis walkthrough and `examples/etherhiding/REPORT.md` for the full report.

## What it does

**Static analysis (Babel-based AST):**
- Unused imports, variables, functions, and exports
- Unreachable code after `return` / `throw`
- Dead branches via constant folding (`if (false)`, `1 === 2`, etc.)
- Obfuscation patterns: `eval`, `new Function`, `setTimeout("...")`, `atob`, `String.fromCharCode(...)`, bracket access to `['eval']`/`['constructor']`, high-entropy string literals, hex/unicode escape density
- Cross-scope reachability: call-graph BFS from auto-detected or user-supplied entry points
- Eval-aware scope capture - intercepts `eval`'d source and recursively analyses the inner layers
- `p,a,c,k,e,r` static unpack + string folding inside dead function bodies (recovers constant strings from code that won't run)
- **obfuscator.io string-array rewriter** - detects the array-fn + decoder + IIFE-shuffle + wrapper-fn pattern (including nested wrappers), boots the decoder in a vm, inlines enclosing-scope const lookups, and substitutes every wrapper call with its plaintext string. Output is a fully rewritten `.deobf.js`
- **Generic constant-folding pass** - a fixpoint partial-evaluator that collapses the mechanical transforms obfuscators rely on beyond the string-array: `atob`/`unescape`/`decodeURIComponent`, `String.fromCharCode`, `parseInt`/`Number`, string concat and `Array.join`, pure-literal arithmetic (`^ & | << >> + - * / %`), `!0`/`![]`/`!![]`/`void` truthiness, and `obj["x"]` → `obj.x`. Runs after the string-array rewrite during `--rewrite` (disable with `--no-fold`)
- **XOR-loop decoder recovery** - detects functions of the form `for (i) out += fromCharCode(s.charCodeAt(i) ^ k.charCodeAt(i % k.length))` and, when callers pass string-literal arguments, statically recovers the plaintext into the finding
- **AAEncode/JJEncode detection** - flags the katakana-heavy ASCII-art encoding family. Recovery requires execution; route through `scripts/analyze.sh` or `--reachability`
- **IOC extraction** (`--iocs`) - pulls a broad indicator set out of any input: URLs, bare domains (public-suffix-correct via `tldts`), IPv4/IPv6, EVM/BTC/XMR addresses, EVM function selectors, Telegram bot tokens, Discord webhooks, AWS keys, JWTs, PEM private keys, Windows paths, registry keys, suspicious LOLBin/PowerShell command lines, base64 blobs, high-entropy strings, and emails. Base64 blobs and `atob()` arguments are decoded and re-scanned so one-layer-nested indicators surface (`via:base64`). Each indicator carries a context hint (`prop:data`, `arg-of:fetch`, `init:varName`) and `--defang` renders network indicators safely (`hxxp://`, `evil[.]com`)
- **One-shot triage** (`--triage`) - chains HTML extraction → string-array rewrite → constant-fold → obfuscation/encoded findings → IOC extraction into a single per-input report with a SHA-256, deobfuscation stats, and a coarse `clean`/`suspicious`/`malicious` verdict

**HTML / data-URI ingestion:**
- `.html` inputs are scanned for inline `<script>` blocks and `data:text/javascript;base64,...` URIs; each script becomes a virtual sub-file the analyzers process independently
- Common in real-world DOM dumps where the malicious payload is smuggled as a base64 data URI in a `<script src=...>`

**Dynamic analysis (Docker sandbox):**
- `node:20-alpine` container, non-root uid 1001, all caps dropped, `no-new-privileges`
- `--network none`, 256 MB memory cap, 0.5 CPU, read-only FS, `noexec` tmpfs
- Pre-loaded monitoring shim logs `eval` / `new Function` / `setTimeout(string)` calls, `require()`s, env-var access, `fetch`/`net`/`http`/`fs` calls as `[REAPER]` JSON lines on stderr
- Hard wall-clock timeout, `child_process` / `cluster` / `worker_threads` blocked
- Runtime modes:
  - `--observe-network` - real egress stays blocked but a stub `fetch`/`http` responder is installed so the script proceeds past network calls; you see the URL/method/body it would have used
  - `--block-eval` - `eval`/`Function` throw after logging
  - `--block-fs` - file-system writes throw after logging

## Install

From npm (once published):

```bash
npm install -g @sresarehumantoo/reaper
reaper "src/**/*.js"
```

From source (development):

```bash
make                  # installs deps, typechecks, compiles to dist/
# or run reaper from source without building:
npx tsx src/cli.ts <pattern>
```

`make help` lists every available target. The common ones: `make build`, `make typecheck`, `make sandbox` (build the docker analysis image), `make demo` (deobfuscate the bundled EtherHiding fixture end-to-end), `make ci` (typecheck + artifact hash verification).

## Usage

### Static scan

```bash
# Default scan - all analyzers on
reaper "src/**/*.ts"

# Scan a captured DOM (extracts inline + data: URI scripts automatically)
reaper page.html

# JSON output
reaper malware.js --format json --output report.json

# Function inventory + reduction report
reaper packed.js --analyze

# Cross-scope reachability (eval-aware) with auto-detected entry points
reaper packed.js --reachability

# Reachability with explicit entry points
reaper malware.js --reachability --entry sendCode,init

# Disable specific analyzers
reaper "src/**/*.js" --no-obfuscation --no-dead-branches
```

Exit code is non-zero when findings are present, so it composes with CI.

### Triage (one-shot)

```bash
# Deobfuscate → findings → IOCs → verdict, in a single report
reaper suspicious.html --triage

# Machine-readable, defanged, for a pipeline / ticket
reaper suspicious.js --triage --format json --defang --output triage.json
```

`--triage` runs the whole static chain over each input (HTML extraction → string-array rewrite → constant-fold → obfuscation/encoded findings → IOC extraction) and prints a per-unit report — SHA-256, deobfuscation stats, findings, IOCs — plus a coarse `clean` / `suspicious` / `malicious` verdict with the reasons that drove it. Exit code is non-zero when anything scores above clean.

### Deobfuscate (rewrite mode)

```bash
# HTML → b64 → string-array rewrite → constant-fold, plaintext written to out/
reaper page.html --rewrite out/

# Same for raw JS
reaper obfuscated.js --rewrite out/

# Skip the constant-folding pass (string-array rewrite only)
reaper obfuscated.js --rewrite out/ --no-fold
```

After the obfuscator.io string-array rewrite, a generic **constant-folding** pass collapses the remaining mechanical obfuscation — `atob`/`unescape`/`decodeURIComponent`, `String.fromCharCode`, `parseInt`/`Number`, string concatenation and `Array.join`, pure-literal arithmetic, `!0`/`![]`/`!![]` truthiness, and `obj["x"]` → `obj.x` — so the output reads like source. For each input the rewriter reports substitutions and folds; outputs are `<name>.deobf.js` (or `<name>.js` pass-through when nothing was recovered).

### Extract IOCs

```bash
# Indicators of compromise, with context hints
reaper sample.js --iocs

# Defanged + machine-readable JSON for downstream pipelines / tickets
reaper sample.js --iocs --defang --format json --output iocs.json
```

Indicator families: URLs, bare domains (public-suffix-correct via `tldts`), IPv4/IPv6, EVM addresses + selectors, BTC/XMR addresses, Telegram bot tokens, Discord webhooks, AWS access keys, JWTs, PEM private keys, Windows paths, registry keys, suspicious LOLBin/PowerShell command lines, base64 blobs, high-entropy strings, and emails — each with a context hint (`prop:data`, `arg-of:fetch`, `init:varName`, `via:base64`). Base64 blobs and `atob()` arguments are decoded and re-scanned, so one-layer-nested indicators surface too. `--defang` rewrites network indicators safely (`hxxp://`, `evil[.]com`).

For best recall, run `--rewrite`/`--triage` first so IOCs hidden behind a string-array decoder or an `atob()` are visible.

### SARIF output (GitHub Code Scanning)

```bash
reaper "src/**/*.js" --format sarif --output reaper.sarif
```

The result is a SARIF 2.1.0 document. Upload it from a workflow with `github/codeql-action/upload-sarif` to get findings rendered in the repo's Code Scanning tab.

### Full pipeline (static + sandboxed dynamic)

```bash
# Static-only
./scripts/analyze.sh suspicious.js --static-only

# Static + dynamic with default constraints (network blocked, hard timeout)
./scripts/analyze.sh malware.js --timeout 30 --output-dir ./reports

# Observe network attempts without real egress (logs URL/method/body of every fetch)
./scripts/analyze.sh etherhiding.js --observe-network --timeout 20

# Log what eval would have executed without actually running it
./scripts/analyze.sh packed.js --observe-network --block-eval
```

The pipeline script runs the static analyzer, then builds and runs the Docker sandbox image (`reaper-sandbox:latest`) against the target.

## Examples

See the warning at the top of this README before opening files under `examples/`.

- **`examples/etherhiding/`** - full walkthrough of an in-the-wild **EtherHiding + ClickFix** sample. The directory contains the minimal HTML fixture, every intermediate stage fetched from BSC testnet contract storage, both OS-specific clipboard payloads, the deobfuscated plaintext of every JavaScript stage, and a step-by-step `README.md` you can follow with no network access. See `examples/etherhiding/REPORT.md` for the analysis report and IOCs.
- **`examples/propellerads-sfp/`** - full walkthrough of a PropellerAds-family **smart popunder / click-hijack tag** (`sfp.js`, build `2026.5.0`). The 97 KB obfuscator.io-obfuscated payload, reaper's plaintext rewrite (2 355/2 355 substitutions), the extracted publisher/network bootstrap config, and an IOC list. Motivated the alias / IIFE-nested / simple-subtract extensions to the string-array rewriter. See `examples/propellerads-sfp/REPORT.md` for the analysis report and IOCs.
- **`examples/dom01/`** - original DOM dump (compromised WordPress page) from which the EtherHiding sample was extracted.
- **`examples/deadcode01/`** - real-world obfuscated sample (`sendCode.js`) plus its companion files. Good test for reachability and eval-layer capture.
- **`examples/deadcode02/`** - small `p,a,c,k,e,r`-packed flag. Try `reaper examples/deadcode02/flag.js --reachability`.

Quick end-to-end against the EtherHiding fixture:

```sh
# 1. Static deobfuscation - recovers the fetch URL, contract address, selector
reaper examples/etherhiding/sample.html --rewrite /tmp/out

# 2. Dynamic run with observe-network - captures the C2 request without egress
./scripts/analyze.sh examples/etherhiding/artifacts/stage1/payload.deobf.js \
  --dynamic-only --observe-network --timeout 8

# 3. (Optional) Re-fetch the next stage from the live contract
./examples/etherhiding/fetch-evm-payload.mjs 0xA1decFB75C8C0CA28C10517ce56B710baf727d2e \
  --out /tmp/dispatcher.js
```

Expected output from step 2 includes a `[REAPER] {"category":"fetch","detail":{"url":"https://bsc-testnet-rpc.publicnode.com/","method":"POST", ...}}` line containing the JSON-RPC `eth_call` body.

## Project layout

```
src/
  cli.ts                # commander entrypoint
  parser/
    index.ts            # @babel/parser wrapper
    html.ts             # .html input → extracted <script> / data: URI subfiles
  analyzers/
    imports.ts          # unused imports
    references.ts       # unused vars / functions
    unreachable.ts      # code after return/throw
    branches.ts         # constant-folded dead branches
    obfuscation.ts      # eval, Function, atob, fromCharCode, entropy
    reachability.ts     # top-level cross-scope reachability analyzer
    evalscope.ts        # eval interception → captured inner-layer sources
    packer.ts           # p,a,c,k,e,r detection + static unpack
    stringarray.ts      # obfuscator.io string-array detect + static rewrite
    constfold.ts        # generic constant-folding / partial-evaluation pass
    iocs.ts             # indicator-of-compromise extractor
    strfold.ts          # constant-string folding inside dead bodies
    functions.ts        # function metadata extraction
  triage.ts             # one-shot deobfuscate → findings → IOCs → verdict
  util.ts               # shared traverse/generate interop, entropy, defang
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
  runner.js             # --require shim - logs eval/fetch/fs/http, supports observe/block modes
scripts/
  analyze.sh            # combined static + dynamic pipeline
examples/               # sample inputs (incl. etherhiding/)
```

## Requirements

- Node.js 20+
- Docker (only required for the dynamic pipeline via `scripts/analyze.sh`)

## License

MIT. See [LICENSE](LICENSE).
