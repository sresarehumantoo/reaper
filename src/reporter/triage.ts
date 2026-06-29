import chalk from 'chalk';
import path from 'path';
import type { TriageReport, Verdict } from '../triage';
import { defang as defangStr } from '../util';

const VERDICT_STYLE: Record<Verdict, (s: string) => string> = {
  clean:      chalk.green,
  suspicious: chalk.yellow,
  malicious:  chalk.red.bold,
};

const DEFANGABLE = new Set(['url', 'domain', 'ipv4', 'ipv6', 'email', 'discord-webhook']);

export interface TriagePrintOptions { defang?: boolean }

export function printTriage(reports: TriageReport[], cwd: string, opts: TriagePrintOptions = {}): void {
  const defang = opts.defang ?? false;
  console.log();
  for (const r of reports) {
    const rel = path.relative(cwd, r.file) || r.file;
    const badge = VERDICT_STYLE[r.verdict](` ${r.verdict.toUpperCase()} `);
    console.log(`${chalk.bold.underline(rel)}  ${badge}  ${chalk.dim(`score ${r.score}`)}`);
    console.log(chalk.dim(`  sha256 ${r.sha256}  (${r.bytes} bytes)`));

    if (r.deobfuscated) {
      const parts: string[] = [];
      if (r.stringArray?.detected) parts.push(`string-array ${r.stringArray.substitutions}/${r.stringArray.attempted}`);
      if (r.folds > 0) parts.push(`${r.folds} folded`);
      console.log(chalk.dim(`  deobfuscated: ${parts.join(', ')}`));
    }
    if (r.error) console.log(chalk.red(`  ! ${r.error}`));

    if (r.reasons.length) console.log(`  ${chalk.bold('why:')} ${r.reasons.join('; ')}`);

    if (r.findings.length) {
      console.log(chalk.bold(`  findings (${r.findings.length}):`));
      for (const f of r.findings.slice(0, 12)) {
        console.log(`    ${chalk.dim(`${f.line}:${f.column}`.padEnd(8))}${chalk.bold(`[${f.type}]`)} ${f.message}`);
      }
      if (r.findings.length > 12) console.log(chalk.dim(`    … ${r.findings.length - 12} more`));
    }

    if (r.iocs.length) {
      console.log(chalk.bold(`  iocs (${r.iocs.length}):`));
      for (const i of r.iocs.slice(0, 20)) {
        const v = defang && DEFANGABLE.has(i.type) ? defangStr(i.value) : i.value;
        const ctx = i.context ? chalk.dim(`  (${i.context})`) : '';
        console.log(`    ${chalk.bold(`[${i.type.padEnd(18)}]`)} ${v}${ctx}`);
      }
      if (r.iocs.length > 20) console.log(chalk.dim(`    … ${r.iocs.length - 20} more`));
    }
    console.log();
  }

  const worst = reports.reduce<Verdict>((acc, r) =>
    rank(r.verdict) > rank(acc) ? r.verdict : acc, 'clean');
  console.log(`${chalk.bold('Overall:')} ${VERDICT_STYLE[worst](worst.toUpperCase())} across ${reports.length} unit(s)\n`);
}

export function formatTriageJson(reports: TriageReport[], opts: TriagePrintOptions = {}): string {
  if (!opts.defang) return JSON.stringify(reports, null, 2);
  const out = reports.map(r => ({
    ...r,
    iocs: r.iocs.map(i => DEFANGABLE.has(i.type) ? { ...i, value: defangStr(i.value) } : i),
  }));
  return JSON.stringify(out, null, 2);
}

function rank(v: Verdict): number {
  return v === 'malicious' ? 2 : v === 'suspicious' ? 1 : 0;
}
