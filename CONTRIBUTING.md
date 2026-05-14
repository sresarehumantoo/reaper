# Contributing to reaper

Thanks for taking the time. reaper is a small project and stays that way intentionally — please read this before opening a non-trivial PR.

## Before you start

Two things to know up front:

1. **`examples/` contains real malware samples.** Read the warning in `README.md` and `examples/etherhiding/README.md` if you have not. Do not run anything from `examples/`.
2. **reaper is a defensive security tool.** Contributions that primarily aid offense (e.g. removing detection signatures from samples, building obfuscators) will not be accepted. See `SECURITY.md` for the philosophy.

## Setting up

```sh
git clone https://github.com/sresarehumantoo/reaper.git
cd reaper
make            # installs deps, typechecks, compiles to dist/
make help       # see every target
```

Requirements: Node 20+. Docker is optional but needed for the dynamic sandbox (`scripts/analyze.sh`).

## The development loop

```sh
# Run reaper directly from source (no rebuild)
npx tsx src/cli.ts <pattern>

# Or use the wrapper:
npm run dev -- <pattern>

# Run the checks CI will run:
make ci                       # typecheck + artifact hash verify
```

When you finish a change, run `make ci` locally. CI will run the same plus `npm audit --audit-level=high` and a smoke test against the EtherHiding fixture.

## Code style

- **No tests yet.** When that changes, this section will too.
- **No emojis in source or output.** Console output is monospace and emoji rendering varies.
- **TypeScript strict mode.** `tsconfig.json` has `strict: true`. Prefer narrow types over `any`. The handful of `as any` casts in the codebase are all the same `@babel/traverse` ESM/CJS interop dance — don't add new ones.
- **Comments explain *why*, not *what*.** Code that needs a comment to be understood usually wants refactoring instead. Exceptions: subtle invariants, security boundaries, the `vm`-is-not-a-sandbox kind of caveat.
- **No new dependencies without discussion.** This is a security-adjacent tool; the dependency surface is small on purpose. Open an issue first.

## File layout

- `src/parser/` - input ingestion. Currently `@babel/parser` wrapper + HTML data-URI extractor.
- `src/analyzers/` - one analyzer per file. Each exports a function that takes an AST and returns `Finding[]` (or a richer report for `--reachability` and `--rewrite`).
- `src/graph/` - call-graph construction + BFS reachability over it.
- `src/reporter/` - output formatters (console, JSON, the rich `--reachability` report).
- `docker/` - the hardened sandbox image + the monitoring shim that logs `eval`/`fetch`/`http`/`fs` from inside it.
- `scripts/` - the combined static+dynamic pipeline runner.
- `examples/` - inputs reaper is tested against, plus the EtherHiding walkthrough.

## Adding a new analyzer

1. Create `src/analyzers/yourthing.ts`. Export a function `(ast: File, filePath: string) => Finding[]`.
2. Wire it into `src/analyzers/index.ts` behind an opt-in flag in `AnalyzerOptions` (see `obfuscation.ts` for the pattern).
3. If your finding has a new `type`, add it to the `FindingType` union in `src/types.ts`.
4. Add a CLI flag in `src/cli.ts` to toggle it.
5. Run your analyzer against `examples/deadcode01/` and `examples/deadcode02/` and verify the output is sane.

## Adding an example

Examples are the test corpus. New samples are welcome if they exercise something existing analyzers don't already cover.

- Place inert payloads in `examples/<name>/`. Add a brief README explaining what the sample demonstrates.
- Commit the artifact and a SHA256SUMS file so CI can detect drift.
- Update the main README's "Examples" list.
- Real malware samples are allowed but call them out clearly in their directory's README, list them in the main `README.md`'s warning callout, and never make them executable.

## Reporting bugs

Open an issue at <https://github.com/sresarehumantoo/reaper/issues>. Include:

- the command you ran
- the input file (or a minimal repro)
- what you expected
- what happened instead

If the issue is a security finding in reaper itself, please follow `SECURITY.md` instead.

## Submitting changes

- Branch off `main`. One logical change per PR.
- Run `make ci` before pushing.
- Sign-off is not required.
- Reference any related issue in the PR body.
- PRs should keep `examples/etherhiding/SHA256SUMS` in sync if any committed artifact changes (and the reason for the change should be explained in the PR — those files are supposed to be frozen evidence).
