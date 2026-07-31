import chalk from 'chalk';
import path from 'path';
import type { Finding, ReaperResult } from '../types';
import { locLabel } from '../util';

const TYPE_LABEL: Record<Finding['type'], string> = {
  'unreachable':         'UNREACHABLE    ',
  'unused-import':       'UNUSED IMPORT  ',
  'unused-variable':     'UNUSED VAR     ',
  'unused-function':     'UNUSED FN      ',
  'unused-export':       'UNUSED EXPORT  ',
  'dead-branch':         'DEAD BRANCH    ',
  'eval-usage':          'EVAL           ',
  'dynamic-execution':   'DYNAMIC EXEC   ',
  'obfuscation-pattern': 'OBFUSCATION    ',
};

const TYPE_COLOR: Record<Finding['type'], chalk.Chalk> = {
  'unreachable':         chalk.red,
  'unused-import':       chalk.yellow,
  'unused-variable':     chalk.yellow,
  'unused-function':     chalk.magenta,
  'unused-export':       chalk.cyan,
  'dead-branch':         chalk.red,
  'eval-usage':          chalk.bgRed.white,
  'dynamic-execution':   chalk.bgRed.white,
  'obfuscation-pattern': chalk.bgYellow.black,
};

const CONFIDENCE_BADGE: Record<Finding['confidence'], string> = {
  high:   chalk.red('●'),
  medium: chalk.yellow('●'),
  low:    chalk.dim('●'),
};

function formatLocation(f: Finding): string {
  return chalk.dim(locLabel(f.line, f.column, f.endLine));
}

export function printFindings(result: ReaperResult, cwd: string): void {
  if (result.findings.length === 0) {
    console.log(chalk.green('\n  No issues found.\n'));
    printSummary(result);
    return;
  }

  // Group by file
  const byFile = new Map<string, Finding[]>();
  for (const f of result.findings) {
    const rel = path.relative(cwd, f.file);
    if (!byFile.has(rel)) byFile.set(rel, []);
    byFile.get(rel)!.push(f);
  }

  console.log();
  for (const [file, findings] of byFile) {
    console.log(chalk.bold.underline(file));
    for (const f of findings) {
      const color  = TYPE_COLOR[f.type];
      const label  = color(`[${TYPE_LABEL[f.type]}]`);
      const loc    = formatLocation(f);
      const badge  = CONFIDENCE_BADGE[f.confidence];
      console.log(`  ${badge} ${label} ${loc}  ${f.message}`);
    }
    console.log();
  }

  printSummary(result);
}

function printSummary(result: ReaperResult): void {
  const { findings, filesScanned, duration } = result;
  const counts: Partial<Record<Finding['type'], number>> = {};
  for (const f of findings) counts[f.type] = (counts[f.type] ?? 0) + 1;

  const parts = Object.entries(counts).map(
    ([type, count]) => TYPE_COLOR[type as Finding['type']](`${count} ${type}`)
  );

  console.log(
    chalk.dim(`Scanned ${filesScanned} file(s) in ${duration}ms`) +
    (parts.length ? `  —  ${parts.join(chalk.dim('  '))}` : '')
  );
  console.log();
}
