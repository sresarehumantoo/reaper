import chalk from 'chalk';
import path from 'path';
import type { Ioc, IocType } from '../analyzers/iocs';
import { renderIocValue, truncate, locLabel } from '../util';

export interface IocReport {
  file: string;
  iocs: Ioc[];
}

const TYPE_COLOR: Partial<Record<IocType, (s: string) => string>> = {
  'url':                chalk.cyan,
  'domain':             chalk.cyan,
  'discord-webhook':    chalk.redBright,
  'ipv4':               chalk.magenta,
  'ipv6':               chalk.magenta,
  'evm-address':        chalk.yellow,
  'evm-selector':       chalk.yellow,
  'btc-address':        chalk.yellow,
  'xmr-address':        chalk.yellow,
  'telegram-bot-token': chalk.redBright,
  'aws-key':            chalk.redBright,
  'jwt':                chalk.red,
  'private-key':        chalk.redBright,
  'registry-key':       chalk.blue,
  'windows-path':       chalk.blue,
  'suspicious-command': chalk.red,
  'base64':             chalk.dim,
  'high-entropy':       chalk.dim,
  'email':              chalk.green,
};

export interface IocPrintOptions { defang?: boolean }

const render = (i: Ioc, defang: boolean): string => renderIocValue(i.type, i.value, defang);

export function printIocs(reports: IocReport[], cwd: string, opts: IocPrintOptions = {}): void {
  const defang = opts.defang ?? false;
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
      const loc   = i.line ? chalk.dim(locLabel(i.line, i.column).padEnd(8)) : ''.padEnd(8);
      const type  = chalk.bold(`[${i.type.padEnd(18)}]`);
      const value = truncate(render(i, defang), 90);
      const ctx   = i.context ? chalk.dim(`  (${i.context})`) : '';
      console.log(`  ${loc}${type}  ${color(value)}${ctx}`);
    }
    console.log();
  }
}

export function formatIocsJson(reports: IocReport[], opts: IocPrintOptions = {}): string {
  if (!opts.defang) return JSON.stringify(reports, null, 2);
  const defanged = reports.map(r => ({
    ...r,
    iocs: r.iocs.map(i => ({ ...i, value: render(i, true) })),
  }));
  return JSON.stringify(defanged, null, 2);
}
