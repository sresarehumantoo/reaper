# Changelog

All notable changes to reaper are recorded here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Security

- **String-array deobfuscation no longer executes sample code in-process.** `detectAndRewriteStringArray` (reached by `--rewrite` and `--triage`) previously booted the sample's array-fn, decoder, and rotator IIFE via an in-process `node:vm`, whose `timeout` only interrupts *synchronous* script — so a crafted sample could OOM reaper's heap or schedule a microtask that hangs the process after `runInContext` returns. All execution now happens in a hardened child process (`src/analyzers/isolate.ts` + `stringarray-worker.cjs`): `--frozen-intrinsics`, `--max-old-space-size=128`, stripped env, and a hard wall-clock kill. Verified against synchronous-loop, unbounded-allocation, and infinite-microtask samples — the analyzer now returns an error instead of hanging/OOMing. All AST work stays in-process; rewrite output is byte-identical to before (existing reproducibility tests still pass). The eval-scope capture path was moved onto the same shared `runIsolated` helper.
- **Packer `count` is clamped to defuse a decompression bomb.** `detectPacker` trusted the attacker-controlled `count` numeric literal that drives `staticUnpack`'s build loop; `eval((function(){})('',99,1e9,[]))` would spin a billion iterations into a multi-GB object. `count` is now clamped to the dictionary size (loss-free: indices past `keys.length` map a token to itself) and `base` is range-checked to 2–62.
- **IOC scanner ReDoS + decode-bomb fixes.** `DOMAIN_RE`'s unbounded `(?:label\.)+` was O(n²) on single-char-label runs (`a.`×N took ~15 s; now bounded to ≤10 labels, ~20 ms) and `EMAIL_RE`'s unbounded local/domain parts re-scanned the whole no-`@` tail at every offset — both quantifier sets are now bounded to RFC-realistic maxima. Base64 blobs above 1 MiB are still recorded as IOCs but no longer decoded-and-rescanned, bounding the decode→rescan→decode amplification.
- **Input-size cap before read + parse.** `readSourceCapped` refuses files above 16 MB (override `REAPER_MAX_SOURCE_MB`) so a file-bloat sample can't OOM the analyzer before analysis starts; wired into the parser, HTML ingester, reachability, and the `--rewrite`/`--triage`/inventory read paths. The HTML ingester's per-tag line counting is now O(n) instead of O(n²).

### Added

- **`examples/clickfix-xloader/`** — new reverse-engineering walkthrough of an in-the-wild **ClearFake / ClickFix** campaign that stages its C2 on **Polygon mainnet** (EtherHiding) and ends in a **XLoader / Formbook** infostealer. Captured 2026-07-28 from the compromised WordPress site `cocobproductions.com`. Ships every JavaScript and PowerShell stage as inert data — the injected `atob`+XOR-12+`new Function` loader and its plaintext decode, the `eth_call` reply that yields the C2 hostname (contract `0xB6bC9e1D…C1f2`, selector `0xb68d1809` → `enter-code-cdn.info`), the 44 KB fake-Cloudflare "verify you are human" overlay (`atob`+XOR-177) with its AES-GCM victim beacon and the clipboard PowerShell lure, and the three-layer PowerShell chain (XOR-42 downloader → XOR-77/base64 stager → 7-Zip dropper). The terminal `xloader.exe` is recorded as hashes + PE metadata only (not committed): a packed PE32+ bloated to 819 MB (~250 KB real) to defeat AV/sandbox size caps. Includes step-by-step `README.md`, analysis `REPORT.md`, and a verifying `SHA256SUMS`. A good contrast to `examples/etherhiding/` (Polygon vs BSC testnet, PowerShell vs rundll32/WebDAV, native payload retrieved vs not) and the first non-BSC use of `fetch-evm-payload.mjs`.
- **`make verify-examples` now checks every example** that ships a `SHA256SUMS` (previously only `examples/etherhiding/`), so `clickfix-xloader` and `propellerads-sfp` artifacts are integrity-verified too.

## [0.2.0] - 2026-06-29

### Added

- **Generic constant-folding deobfuscation pass (`src/analyzers/constfold.ts`).** A fixpoint partial-evaluator that collapses the mechanical transforms obfuscators rely on beyond the string-array: `atob`/`unescape`/`decodeURIComponent`, `String.fromCharCode`, `parseInt`/`Number`, string concatenation and `Array.join`, pure-literal arithmetic (`^ & | << >> + - * / % **`), `!0`/`![]`/`!![]`/`void` truthiness, and `obj["ident"]` → `obj.ident`. Only pure, literal-operand expressions are evaluated (no identifiers, calls to unknown functions, or side effects). Hex/unicode/numeric-literal obfuscation normalises for free via AST re-generation. Wired into `--rewrite` after the string-array rewrite (disable with `--no-fold`); on the PropellerAds sample it collapses ~2.8k expressions on top of the 2355 string substitutions.
- **`reaper --triage` — one-shot triage.** Runs the whole static chain over each input — HTML extraction → string-array rewrite → constant-fold → obfuscation/encoded findings → IOC extraction — and emits a unified per-unit report (SHA-256, deobfuscation stats, findings, IOCs) plus a coarse `clean`/`suspicious`/`malicious` verdict with the contributing reasons. JSON via `--format json`; non-zero exit when anything scores above clean.
- **Expanded IOC engine.** New indicator families: IPv6, BTC/XMR addresses, Telegram bot tokens, Discord webhooks, AWS access keys, JWTs, PEM private keys, Windows paths, registry keys, and suspicious LOLBin/PowerShell command lines. Base64 blobs — and `atob()`/`Buffer.from` arguments of any length — are decoded and re-scanned so one-layer-nested indicators surface (tagged `via:base64`). Registrable-domain handling now uses the public-suffix list (`tldts`), fixing multi-label TLDs like `co.uk`. New `--defang` flag renders network indicators safely (`hxxp://`, `evil[.]com`, `a[@]b[.]com`) for reports and tickets.
- **Packaging/robustness:** `@babel/generator` is now a declared dependency (was only transitively present, so `--rewrite` could break on a strict/global install); `--version` reads from `package.json` instead of a stale constant. Shared helpers consolidated in `src/util.ts`; `parser` gains `loadSource()`/`sourceFromString()` for parse-once `{path, code, ast}` units.
- **String-array rewriter now handles IIFE-nested + identifier-alias variants.** Previously the detector only fired when the array fn, root decoder, and rotator IIFE all lived at program-body level and call sites went through *function* wrappers. The discovery helpers (`findArrayFnDecl`, `findRootDecoderDecl`, `findIifeShuffleCall`) now traverse the full AST, so the trio can be nested inside outer `(function(){...})()` wrappers. The decoder recognises a second shape — simple-subtract `function(o,k){ o = o - K; var n = arrayFn(); var z = n[o]; return z; }` (no self-rewrite) — used by older obfuscator.io builds and commercial packers such as the PropellerAds/Adsterra `sfp.js` family. A new alias-resolution pass walks every `var X = decoder` (transitively `var Y = X`) anywhere in the AST so identifier aliases — the typical per-function alias the obfuscator scatters — are inlined alongside wrapper-fn calls. `StringArrayInfo` gains an `aliases: string[]` field. Verified on a 97 KB PropellerAds `sfp.js` sample: 2355/2355 substitutions, 378 aliases resolved, byte-identical to a hand-written one-off rewriter.
- **`examples/propellerads-sfp/`** — new reverse-engineering walkthrough covering the PropellerAds-family `sfp.js` smart popunder / click-hijack tag (build `2026.5.0`). Ships the original obfuscated 97 KB payload, reaper's plaintext rewrite, the extracted publisher/network bootstrap config (`placement-config.json`), the network IOC list, the step-by-step `README.md` walkthrough, the analysis `REPORT.md`, and a verifying `SHA256SUMS`. The sample is the motivating case for the rewriter extensions above.

## [0.1.1] - 2026-05-15

Maintenance release. Verifies the release pipeline end-to-end (npm publish + GitHub Release auto-creation) and brings in a round of safe dependency updates.

### Changed

- `commander` 12.x → 14.x. Tests pass; CLI surface unchanged.
- `@babel/parser` 7.29.2 → 7.29.3 (patch).
- `actions/checkout` 4 → 6 and `actions/setup-node` 4 → 6 in CI and release workflows (silences the upcoming Node-20-action deprecation warnings).

### Fixed

- Release workflow now creates the corresponding GitHub Release page with notes extracted from the matching `CHANGELOG.md` section. Previously the workflow only published to npm and the repo's Releases tab stayed empty.

### Security

- `.github/dependabot.yml` now holds back major-version bumps that conflict with reaper's current compatibility constraints (`chalk` 5+ is ESM-only, `@types/node` must match the `engines.node` floor of 20, `typescript`/`tsx` major bumps require updating `tsconfig.json`'s `moduleResolution`). These will be revisited as deliberate, focused PRs when reaper migrates each constraint.

## [0.1.0] - 2026-05-15

Initial public release.

### Added

- **Static analyzers.** Unused imports, unused variables, unused functions, unused exports, unreachable code after `return` / `throw`, dead branches via constant folding, obfuscation patterns (`eval`, `new Function`, `setTimeout("...")`, `atob`, `String.fromCharCode`, bracket access to dangerous identifiers, high-entropy literals, hex/unicode escape density).
- **Cross-scope reachability.** Call-graph BFS from auto-detected or user-supplied entry points, eval-aware scope capture, `p,a,c,k,e,r` static unpack, string folding inside dead function bodies.
- **obfuscator.io string-array rewriter.** Detects the array-fn + decoder + IIFE-shuffle + wrapper-fn pattern (including nested wrappers), boots the decoder in a vm, inlines enclosing-scope const lookups, substitutes every wrapper call with its plaintext string, and emits a fully rewritten `.deobf.js`.
- **XOR-loop decoder recovery.** Detects the canonical XOR decode loop and, when callers pass string-literal arguments, statically recovers the plaintext into the finding message.
- **AAEncode / JJEncode detection.** Flags the katakana-heavy ASCII-art encoding family.
- **HTML / data-URI ingestion.** `.html` inputs are scanned for inline `<script>` blocks and `data:text/javascript;base64,...` URIs; each script becomes a virtual sub-file the analyzers process independently.
- **IOC extraction** (`--iocs`). Walks string and template literals and classifies URLs, bare domains, IPv4, EVM addresses, EVM function selectors, long base64 blobs, high-entropy strings, and emails. Each indicator carries a context hint such as `prop:data`, `arg-of:fetch`, or `init:varName`.
- **SARIF 2.1.0 output** via `--format sarif`. Plugs into GitHub Code Scanning and standard SAST aggregators. Confidence maps to SARIF level (low → note, medium → warning, high → error).
- **Hardened Docker sandbox** (`docker/Dockerfile` + `scripts/analyze.sh`). `node:20-alpine` pinned to a digest, non-root uid 1001, `--network none`, `--ipc none`, `--cap-drop ALL`, `--security-opt no-new-privileges`, `--pids-limit 64`, file-descriptor / process / file-size ulimits, `--oom-score-adj 1000`, read-only rootfs with a `noexec,nosuid,nodev` tmpfs, Node `--frozen-intrinsics`, 256 MB memory cap, 0.5 CPU.
- **Sandbox runtime modes.** `--observe-network` installs stub `fetch` / `http` / `https` responders so the script proceeds past network calls and you see the URL/method/body it would have used; `--block-eval` makes `eval` and `Function` throw after logging; `--block-fs` makes filesystem writes throw after logging.
- **Eval-scope capture via child process.** `src/analyzers/evalscope.ts` runs the `vm.runInContext` invocation in a short-lived child Node process so an in-vm escape cannot affect reaper's main process. Child runs with `--frozen-intrinsics`, capped memory, stripped environment, and a 10-second hard timeout.
- **EtherHiding walkthrough.** `examples/etherhiding/` contains a real-world DOM dump, every intermediate contract-staged payload, the deobfuscated forms, both OS-specific clipboard commands, an analysis `REPORT.md`, and a step-by-step `README.md` you can follow with no network access.
- **`fetch-evm-payload.mjs`.** Reads EtherHiding-style payloads out of EVM contract storage via a single `eth_call`. Pure read, never executes. Rejects non-http(s) `--rpc` URLs (SSRF defense).
- **Test suite.** 45 tests under `test/` covering HTML extraction, the stringarray rewriter (including bit-for-bit reproducibility against the committed EtherHiding artifact), the p,a,c,k,e,r unpacker, obfuscation detection, dead-branch folding, encoded-family detection, IOC extraction, and SARIF output. Wired into `make test`, `npm test`, `make ci`, and the GitHub Actions CI workflow.
- **Build tooling.** `Makefile` with `help`, `install`, `build`, `typecheck`, `test`, `clean`, `distclean`, `sandbox`, `sandbox-rebuild`, `sandbox-clean`, `demo`, `verify-examples`, `ci` targets.
- **CI/CD.** GitHub Actions workflow (`ci.yml`) on Node 20 and 22 running typecheck, tests, build, artifact-hash verification, end-to-end smoke test of the deobfuscator, and `npm audit`. Tag-gated release workflow (`release.yml`) that publishes with `npm publish --provenance` via OIDC.
- **Dependabot.** Weekly grouped update PRs for npm dependencies and GitHub Actions.

### Security

- `package.json` `files` whitelist ensures `npm publish` ships only `dist/`, `LICENSE`, and `README.md` - the live malware samples in `examples/` are excluded.
- `SECURITY.md` documents the threat model, what is and isn't an isolation boundary in reaper, and the reporting policy.
- `prepublishOnly` script runs build + typecheck + tests before any publish.

[Unreleased]: https://github.com/sresarehumantoo/reaper/compare/v0.1.1...HEAD
[0.1.1]: https://github.com/sresarehumantoo/reaper/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/sresarehumantoo/reaper/releases/tag/v0.1.0
