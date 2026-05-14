import chalk from 'chalk';
import path from 'path';
import type { Ioc } from '../analyzers/iocs';

export interface IocReport {
  file: string;
  iocs: Ioc[];
}

const TYPE_COLOR: Record<Ioc['type'], (s: string) => string> = {
  'url':          chalk.cyan,
  'domain':       chalk.cyan,
  'ipv4':         chalk.magenta,
  'evm-address':  chalk.yellow,
  'evm-selector': chalk.yellow,
  'base64':       chalk.dim,
  'high-entropy': chalk.dim,
  'email':        chalk.green,
};

export function printIocs(reports: IocReport[], cwd: string): void {
  console.log();
  for (const r of reports) {
    const rel = path.relative(cwd, r.file);
    console.log(chalk.bold.underline(rel));

    if (r.iocs.length === 0) {
      console.log(chalk.dim('  (no indicators)'));
      console.log();
      continue;
    }

    for (const i of r.iocs) {
      const color = TYPE_COLOR[i.type] ?? chalk.white;
      const loc   = i.line ? chalk.dim(`${i.line}:${i.column}`.padEnd(8)) : ''.padEnd(8);
      const type  = chalk.bold(`[${i.type.padEnd(13)}]`);
      const value = truncate(i.value, 90);
      const ctx   = i.context ? chalk.dim(`  (${i.context})`) : '';
      console.log(`  ${loc}${type}  ${color(value)}${ctx}`);
    }
    console.log();
  }
}

export function formatIocsJson(reports: IocReport[]): string {
  return JSON.stringify(reports, null, 2);
}

function truncate(s: string, n: number): string {
  if (s.length <= n) return s;
  return s.slice(0, n - 1) + '…';
}
