#!/usr/bin/env node
import { Command } from 'commander';
import glob from 'fast-glob';
import path from 'path';
import fs from 'fs';
import os from 'os';
import { analyzeFile } from './analyzers';
import { printFindings } from './reporter/console';
import { formatJson } from './reporter/json';
import { analyzeFileInventory, printAnalysis } from './reporter/analysis';
import { analyzeReachability } from './analyzers/reachability';
import { printReachability } from './reporter/reachability';
import { extractScriptsFromHtml, isHtmlPath } from './parser/html';
import { detectAndRewriteStringArray } from './analyzers/stringarray';
import { foldConstants } from './analyzers/constfold';
import { triageSource } from './triage';
import { printTriage, formatTriageJson } from './reporter/triage';
import { extractIocs } from './analyzers/iocs';
import { printIocs, formatIocsJson } from './reporter/iocs';
import { formatSarif } from './reporter/sarif';
import { parseFile } from './parser';
import type { Finding, ReaperResult, AnalyzerOptions } from './types';
import type { IocReport } from './reporter/iocs';

// Resolve version from package.json at runtime (works for both tsx-from-src and
// compiled dist/cli.js — package.json sits one dir above either location).
function packageVersion(): string {
  try {
    const pkg = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'package.json'), 'utf-8'));
    return pkg.version ?? '0.0.0';
  } catch {
    return '0.0.0';
  }
}

// Expand .html inputs into virtual JS sub-files on disk so every analyzer
// can treat them as normal inputs. Non-html paths pass through unchanged.
// Returns a parallel map of expanded-path → origin so callers (e.g. --rewrite)
// can name outputs after the original .html, not the temp file.
export interface ExpandedFile {
  path:        string;             // path the analyzer reads from
  originPath:  string;             // user-facing source (.html for extracted scripts, same as path for plain JS)
  originTag:   string | null;      // e.g. "data-uri-0", "script-3", or null for plain JS
}

function expandHtmlInputs(files: string[]): { all: ExpandedFile[]; tempDir: string | null } {
  const hasHtml = files.some(isHtmlPath);
  if (!hasHtml) return {
    all: files.map(p => ({ path: p, originPath: p, originTag: null })),
    tempDir: null,
  };

  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'reaper-'));
  const all: ExpandedFile[] = [];
  for (const f of files) {
    if (!isHtmlPath(f)) {
      all.push({ path: f, originPath: f, originTag: null });
      continue;
    }
    const scripts = extractScriptsFromHtml(f);
    if (scripts.length === 0) continue;
    for (const s of scripts) {
      const tag     = s.virtualPath.split('#').pop()!.replace(/\.js$/, '');
      const outPath = path.join(tempDir, `${path.basename(f, path.extname(f))}.${tag}.js`);
      fs.writeFileSync(outPath, s.source, 'utf-8');
      all.push({ path: outPath, originPath: f, originTag: tag });
    }
  }
  return { all, tempDir };
}

function displayPath(cwd: string, ef: ExpandedFile): string {
  if (ef.originTag) return `${path.relative(cwd, ef.originPath)}#${ef.originTag}`;
  return path.relative(cwd, ef.path);
}

const program = new Command();

// ── Default scan command ──────────────────────────────────────────────────────
program
  .name('reaper')
  .description('Dead code & obfuscation analyzer for JavaScript and TypeScript')
  .version(packageVersion())
  .argument('<pattern>', 'Glob pattern of files to analyze (e.g. "src/**/*.ts" or "malware.js")')
  .option('-f, --format <format>',    'Output format: console | json | sarif', 'console')
  .option('-o, --output <file>',      'Write output to file instead of stdout')
  .option('-a, --analyze',            'Show full function inventory + reduction report')
  .option('-r, --reachability',       'Cross-scope reachability analysis (eval-aware)')
  .option('-e, --entry <functions>',  'Comma-separated entry point(s) for reachability (e.g. sendCode,init)')
  .option('-w, --rewrite <dir>',      'Statically deobfuscate (HTML→b64→string-array→constant-fold) and write .deobf.js to <dir>')
  .option('--no-fold',                'Skip the constant-folding pass during --rewrite')
  .option('-t, --triage',             'One-shot triage: deobfuscate → findings → IOCs → verdict, in one report')
  .option('-i, --iocs',               'Extract indicators (URLs, domains, IPs, EVM addresses, base64 blobs) and emit a report')
  .option('--defang',                 'Defang network indicators in IOC output (hxxp://, evil[.]com)')
  .option('--no-unused-imports',      'Skip unused import analysis')
  .option('--no-unused-vars',         'Skip unused variable/function analysis')
  .option('--no-unreachable',         'Skip unreachable code analysis')
  .option('--no-dead-branches',       'Skip dead branch detection')
  .option('--no-obfuscation',         'Skip obfuscation pattern detection')
  .option('--cwd <dir>',              'Working directory for resolving paths', process.cwd())
  .action(async (pattern: string, opts) => {
    const cwd: string = path.resolve(opts.cwd);

    const matched = await glob(pattern, {
      cwd,
      absolute: true,
      ignore: ['**/node_modules/**', '**/dist/**', '**/build/**', '**/*.d.ts'],
    });

    if (matched.length === 0) {
      console.error(`reaper: no files matched pattern '${pattern}'`);
      process.exit(1);
    }

    const { all: files } = expandHtmlInputs(matched);
    if (files.length === 0) {
      console.error(`reaper: no JS/TS sources found (matched files contained no analysable scripts)`);
      process.exit(1);
    }

    // ── Rewrite mode (--rewrite <dir>) ───────────────────────────────────────
    if (opts.rewrite) {
      const outDir = path.resolve(opts.rewrite);
      fs.mkdirSync(outDir, { recursive: true });

      let detected = 0;
      for (const ef of files) {
        const src  = fs.readFileSync(ef.path, 'utf-8');
        const info = detectAndRewriteStringArray(src, ef.path);

        // Output name: derived from origin so HTML-extracted scripts get a
        // sane name like `sample.data-uri-0.deobf.js`, not the temp-dir mangle.
        // If the input lives outside cwd (path.relative returns ../../…),
        // fall back to the basename — flatter and readable.
        const rel = path.relative(cwd, ef.originPath);
        const baseRel = rel.startsWith('..')
          ? path.basename(ef.originPath)
          : rel;
        const noExt = baseRel.replace(/\.[jt]sx?$|\.html?$/i, '');
        const safe  = noExt.replace(/[\\/]/g, '__');
        const stem  = ef.originTag ? `${safe}.${ef.originTag}` : safe;

        // Start from the string-array rewrite when it fired, else the raw
        // source; then run the generic constant-folder over the result
        // (unless --no-fold) so atob/fromCharCode/concat/arithmetic collapse too.
        const base = (info.detected && info.rewritten) ? info.rewritten : src;
        const fold = opts.fold !== false ? foldConstants(base, ef.path) : { code: base, changes: 0 };
        const finalCode = fold.code;
        const recovered = (info.detected && info.rewritten) || fold.changes > 0;

        if (recovered) {
          detected++;
          const out = path.join(outDir, `${stem}.deobf.js`);
          fs.writeFileSync(out, finalCode, 'utf-8');
          const bits: string[] = [];
          if (info.detected && info.rewritten) {
            bits.push(`${info.substitutions}/${info.attempted} substitutions`);
            bits.push(`${info.wrappers.length} wrapper${info.wrappers.length === 1 ? '' : 's'}`);
          }
          if (fold.changes > 0) bits.push(`${fold.changes} folded`);
          console.log(`${displayPath(cwd, ef)}  →  ${path.relative(cwd, out)}  (${bits.join(', ')})`);
        } else {
          const out = path.join(outDir, `${stem}.js`);
          fs.writeFileSync(out, finalCode, 'utf-8');
          const reason = info.error ? `(${info.error})` : '(no obfuscator.io string-array pattern, nothing to fold)';
          console.log(`${displayPath(cwd, ef)}  →  ${path.relative(cwd, out)}  ${reason}`);
        }
      }
      console.log(`\nRewrote ${detected}/${files.length} file(s) to ${path.relative(cwd, outDir)}/`);
      process.exit(0);
    }

    // ── Triage mode (--triage) ───────────────────────────────────────────────
    if (opts.triage) {
      const reports = [];
      for (const ef of files) {
        try {
          const src = fs.readFileSync(ef.path, 'utf-8');
          reports.push(triageSource(src, ef.path, displayPath(cwd, ef), opts.fold !== false));
        } catch (err: any) {
          console.error(`  error — ${displayPath(cwd, ef)}: ${err.message}`);
        }
      }
      const triageOpts = { defang: !!opts.defang };
      if (opts.format === 'json') {
        const out = formatTriageJson(reports, triageOpts);
        if (opts.output) fs.writeFileSync(opts.output, out, 'utf-8');
        else console.log(out);
      } else {
        printTriage(reports, cwd, triageOpts);
        if (opts.output) fs.writeFileSync(opts.output, formatTriageJson(reports, triageOpts), 'utf-8');
      }
      const worst = reports.some(r => r.verdict === 'malicious') ? 2
        : reports.some(r => r.verdict === 'suspicious') ? 1 : 0;
      process.exit(worst > 0 ? 1 : 0);
    }

    // ── IOC extraction mode (--iocs) ─────────────────────────────────────────
    if (opts.iocs) {
      const reports: IocReport[] = [];
      for (const ef of files) {
        try {
          const ast  = parseFile(ef.path);
          const iocs = extractIocs(ast, ef.path);
          reports.push({ file: ef.originPath + (ef.originTag ? `#${ef.originTag}` : ''), iocs });
        } catch (err: any) {
          console.error(`  parse error — ${displayPath(cwd, ef)}: ${err.message}`);
        }
      }
      const iocOpts = { defang: !!opts.defang };
      if (opts.format === 'json') {
        const out = formatIocsJson(reports, iocOpts);
        if (opts.output) fs.writeFileSync(opts.output, out, 'utf-8');
        else console.log(out);
      } else {
        printIocs(reports, cwd, iocOpts);
        if (opts.output) fs.writeFileSync(opts.output, formatIocsJson(reports, iocOpts), 'utf-8');
      }
      const total = reports.reduce((s, r) => s + r.iocs.length, 0);
      process.exit(total > 0 ? 0 : 1);
    }

    // ── Reachability mode (--reachability) ───────────────────────────────────
    if (opts.reachability) {
      const entryPoints = opts.entry
        ? String(opts.entry).split(',').map((s: string) => s.trim()).filter(Boolean)
        : undefined;

      const reports = [];
      for (const ef of files) {
        try {
          reports.push(analyzeReachability(ef.path, entryPoints));
        } catch (err: any) {
          console.error(`  error — ${displayPath(cwd, ef)}: ${err.message}`);
        }
      }
      printReachability(reports, cwd);

      if (opts.output) {
        fs.writeFileSync(opts.output, JSON.stringify(reports, null, 2), 'utf-8');
        console.log(`Reachability report written to ${opts.output}`);
      }

      const hasDead = reports.some(r => r.deadFns.length > 0);
      process.exit(hasDead ? 1 : 0);
    }

    // ── Analysis mode (--analyze) ─────────────────────────────────────────────
    if (opts.analyze) {
      const analyses = [];
      for (const ef of files) {
        try {
          analyses.push(analyzeFileInventory(ef.path));
        } catch (err: any) {
          console.error(`  parse error — ${displayPath(cwd, ef)}: ${err.message}`);
        }
      }
      printAnalysis(analyses, cwd);

      if (opts.output) {
        fs.writeFileSync(opts.output, JSON.stringify(analyses, null, 2), 'utf-8');
        console.log(`Analysis written to ${opts.output}`);
      }

      const hasDeadCode = analyses.some(a => a.deadFunctions.length > 0);
      process.exit(hasDeadCode ? 1 : 0);
    }

    // ── Standard scan mode ────────────────────────────────────────────────────
    const options: AnalyzerOptions = {
      unusedImports: opts.unusedImports !== false,
      unusedVars:    opts.unusedVars    !== false,
      unreachable:   opts.unreachable   !== false,
      deadBranches:  opts.deadBranches  !== false,
      obfuscation:   opts.obfuscation   !== false,
    };

    const start = Date.now();
    const findings: Finding[] = [];
    const errors: string[] = [];

    for (const ef of files) {
      try {
        findings.push(...analyzeFile(ef.path, options));
      } catch (err: any) {
        errors.push(`${displayPath(cwd, ef)}: ${err.message}`);
      }
    }

    const result: ReaperResult = {
      findings,
      filesScanned: files.length,
      duration: Date.now() - start,
    };

    for (const e of errors) {
      console.error(`  parse error — ${e}`);
    }

    if (opts.format === 'json' || opts.format === 'sarif') {
      const output = opts.format === 'sarif' ? formatSarif(result, cwd) : formatJson(result);
      if (opts.output) {
        fs.writeFileSync(opts.output, output, 'utf-8');
      } else {
        console.log(output);
      }
    } else {
      printFindings(result, cwd);
      if (opts.output) {
        fs.writeFileSync(opts.output, formatJson(result), 'utf-8');
        console.log(`Results written to ${opts.output}`);
      }
    }

    process.exit(findings.length > 0 ? 1 : 0);
  });

program.parse();
