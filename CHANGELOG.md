# Changelog

All notable changes to reaper are recorded here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
