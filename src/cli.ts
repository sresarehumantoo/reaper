#!/usr/bin/env node
import { Command } from 'commander';
import glob from 'fast-glob';
import path from 'path';
import fs from 'fs';
import { analyzeFile } from './analyzers';
import { printFindings } from './reporter/console';
import { formatJson } from './reporter/json';
import { analyzeFileInventory, printAnalysis } from './reporter/analysis';
import { analyzeReachability } from './analyzers/reachability';
import { printReachability } from './reporter/reachability';
import type { Finding, ReaperResult, AnalyzerOptions } from './types';

const program = new Command();

// ── Default scan command ──────────────────────────────────────────────────────
program
  .name('reaper')
  .description('Dead code & obfuscation analyzer for JavaScript and TypeScript')
  .version('0.1.0')
  .argument('<pattern>', 'Glob pattern of files to analyze (e.g. "src/**/*.ts" or "malware.js")')
  .option('-f, --format <format>',    'Output format: console | json', 'console')
  .option('-o, --output <file>',      'Write output to file instead of stdout')
  .option('-a, --analyze',            'Show full function inventory + reduction report')
  .option('-r, --reachability',       'Cross-scope reachability analysis (eval-aware)')
  .option('-e, --entry <functions>',  'Comma-separated entry point(s) for reachability (e.g. sendCode,init)')
  .option('--no-unused-imports',      'Skip unused import analysis')
  .option('--no-unused-vars',         'Skip unused variable/function analysis')
  .option('--no-unreachable',         'Skip unreachable code analysis')
  .option('--no-dead-branches',       'Skip dead branch detection')
  .option('--no-obfuscation',         'Skip obfuscation pattern detection')
  .option('--cwd <dir>',              'Working directory for resolving paths', process.cwd())
  .action(async (pattern: string, opts) => {
    const cwd: string = path.resolve(opts.cwd);

    const files = await glob(pattern, {
      cwd,
      absolute: true,
      ignore: ['**/node_modules/**', '**/dist/**', '**/build/**', '**/*.d.ts'],
    });

    if (files.length === 0) {
      console.error(`reaper: no files matched pattern '${pattern}'`);
      process.exit(1);
    }

    // ── Reachability mode (--reachability) ───────────────────────────────────
    if (opts.reachability) {
      const entryPoints = opts.entry
        ? String(opts.entry).split(',').map((s: string) => s.trim()).filter(Boolean)
        : undefined;

      const reports = [];
      for (const file of files) {
        try {
          reports.push(analyzeReachability(file, entryPoints));
        } catch (err: any) {
          console.error(`  error — ${path.relative(cwd, file)}: ${err.message}`);
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
      for (const file of files) {
        try {
          analyses.push(analyzeFileInventory(file));
        } catch (err: any) {
          console.error(`  parse error — ${path.relative(cwd, file)}: ${err.message}`);
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

    for (const file of files) {
      try {
        findings.push(...analyzeFile(file, options));
      } catch (err: any) {
        errors.push(`${path.relative(cwd, file)}: ${err.message}`);
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

    if (opts.format === 'json') {
      const output = formatJson(result);
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
