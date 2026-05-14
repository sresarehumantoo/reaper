import chalk from 'chalk';
import path from 'path';
import fs from 'fs';
import { parseFile } from '../parser';
import { inventoryFunctions } from '../analyzers/functions';
import type { FunctionEntry } from '../analyzers/functions';

export interface FileAnalysis {
  file: string;
  totalLines: number;
  totalChars: number;
  functions: FunctionEntry[];
  deadFunctions: FunctionEntry[];
  aliveFunctions: FunctionEntry[];
  deadLines: number;
  deadChars: number;
  lineReductionPct: number;
  charReductionPct: number;
}

export function analyzeFileInventory(filePath: string): FileAnalysis {
  const source = fs.readFileSync(filePath, 'utf-8');
  const ast    = parseFile(filePath);
  const fns    = inventoryFunctions(ast, source);

  const totalLines = source.split('\n').length;
  const totalChars = source.length;

  const dead  = fns.filter(f => !f.referenced);
  const alive = fns.filter(f => f.referenced);

  const deadLines = dead.reduce((s, f) => s + f.lines, 0);
  const deadChars = dead.reduce((s, f) => s + f.chars, 0);

  return {
    file:              filePath,
    totalLines,
    totalChars,
    functions:         fns,
    deadFunctions:     dead,
    aliveFunctions:    alive,
    deadLines,
    deadChars,
    lineReductionPct:  totalLines > 0 ? (deadLines / totalLines) * 100 : 0,
    charReductionPct:  totalChars > 0 ? (deadChars / totalChars) * 100 : 0,
  };
}

export function printAnalysis(analyses: FileAnalysis[], cwd: string): void {
  console.log();

  for (const a of analyses) {
    const rel = path.relative(cwd, a.file);

    // ── File header ──────────────────────────────────────────────────────────
    console.log(chalk.bold.underline(rel));
    console.log(
      chalk.dim(`  ${a.totalLines} lines  ${fmt(a.totalChars)} chars  ` +
        `${a.functions.length} function(s) found`)
    );
    console.log();

    if (a.functions.length === 0) {
      console.log(chalk.dim('  No named functions found.\n'));
      continue;
    }

    // ── Function table ───────────────────────────────────────────────────────
    const nameW  = Math.max(8, ...a.functions.map(f => f.name.length));
    const header =
      '  ' +
      chalk.bold(pad('Function', nameW)) + '  ' +
      chalk.bold(pad('Lines', 7))        + '  ' +
      chalk.bold(pad('Chars', 8))        + '  ' +
      chalk.bold('Status');
    console.log(header);
    console.log('  ' + '─'.repeat(nameW + 34));

    for (const fn of a.functions) {
      const status = fn.referenced
        ? chalk.green('  alive ')
        : chalk.red('● DEAD  ');
      const name = fn.referenced
        ? chalk.white(pad(fn.name, nameW))
        : chalk.red(pad(fn.name, nameW));
      const lines = chalk.dim(pad(String(fn.lines), 7));
      const chars = chalk.dim(pad(fmt(fn.chars), 8));
      const loc   = chalk.dim(`${fn.line}–${fn.endLine}`);
      console.log(`  ${name}  ${lines}  ${chars}  ${status}  ${loc}`);
    }

    console.log();

    // ── Dead code summary ────────────────────────────────────────────────────
    if (a.deadFunctions.length === 0) {
      console.log(chalk.green('  No dead functions detected.\n'));
      continue;
    }

    const lastDead = a.deadFunctions[a.deadFunctions.length - 1];

    console.log(chalk.bold('  Dead Function Summary'));
    console.log(chalk.dim('  ─────────────────────────────────────────'));
    console.log(`  Total functions  : ${a.functions.length}`);
    console.log(
      `  Alive            : ${chalk.green(String(a.aliveFunctions.length))}`
    );
    console.log(
      `  Dead             : ${chalk.red(String(a.deadFunctions.length))}`
    );
    console.log(
      `  Last dead fn     : ${chalk.red.bold(lastDead.name)} ` +
      chalk.dim(`(line ${lastDead.line}–${lastDead.endLine})`)
    );
    console.log();

    // ── Reduction metrics ────────────────────────────────────────────────────
    console.log(chalk.bold('  Estimated Reduction (removing dead functions)'));
    console.log(chalk.dim('  ─────────────────────────────────────────'));

    const lineBar = bar(a.lineReductionPct);
    const charBar = bar(a.charReductionPct);

    console.log(
      `  Lines  : ${chalk.red(lineBar)} ${chalk.red.bold(a.lineReductionPct.toFixed(1) + '%')} ` +
      chalk.dim(`(${a.deadLines} / ${a.totalLines} lines)`)
    );
    console.log(
      `  Chars  : ${chalk.red(charBar)} ${chalk.red.bold(a.charReductionPct.toFixed(1) + '%')} ` +
      chalk.dim(`(${fmt(a.deadChars)} / ${fmt(a.totalChars)} chars)`)
    );
    console.log();

    // ── Dead function list ───────────────────────────────────────────────────
    console.log(chalk.bold('  Functions to Remove:'));
    a.deadFunctions.forEach((fn, i) => {
      const last = i === a.deadFunctions.length - 1;
      const prefix = last ? '  └─' : '  ├─';
      console.log(
        `${prefix} ${chalk.red(fn.name)} ` +
        chalk.dim(`line ${fn.line}–${fn.endLine}  (${fn.lines} lines, ${fmt(fn.chars)} chars)`) +
        (last ? chalk.yellow('  ← last') : '')
      );
    });

    console.log();
  }
}

// ── Helpers ──────────────────────────────────────────────────────────────────

function pad(s: string, n: number): string {
  return s.length >= n ? s : s + ' '.repeat(n - s.length);
}

function fmt(n: number): string {
  return n >= 1000 ? `${(n / 1000).toFixed(1)}k` : String(n);
}

function bar(pct: number, width = 20): string {
  const filled = Math.round((pct / 100) * width);
  return '█'.repeat(filled) + '░'.repeat(width - filled);
}
