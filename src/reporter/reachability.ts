import chalk from 'chalk';
import path from 'path';
import type { ReachabilityReport } from '../analyzers/reachability';

export function printReachability(reports: ReachabilityReport[], cwd: string): void {
  console.log();

  for (const r of reports) {
    const rel = path.relative(cwd, r.file);

    // ── File header ──────────────────────────────────────────────────────────
    console.log(chalk.bold.underline(rel));
    console.log(
      chalk.dim(
        `  ${r.totalLines} lines  ${fmt(r.totalChars)} chars  ` +
        `${r.evalLayers} eval layer(s) unpacked  ` +
        `${r.totalFns} function(s) in scope`
      )
    );
    if (r.error) console.log(chalk.dim(`  note: ${r.error}`));

    // ── Packer detection ─────────────────────────────────────────────────────
    if (r.packers.length > 0) {
      console.log();
      for (const p of r.packers) {
        console.log(
          `  ${chalk.bgYellow.black(' PACKER ')} ` +
          chalk.yellow(`p,a,c,k,e,r detected`) +
          chalk.dim(` — base ${p.base}, ${p.count} tokens, ${p.keys.length} keys`)
        );
        if (p.unpacked) {
          console.log(`  ${chalk.dim('unpacked:')} ${chalk.white(p.unpacked.slice(0, 200))}` +
            (p.unpacked.length > 200 ? chalk.dim('…') : ''));
        }
        if (p.error) console.log(chalk.red(`  unpack error: ${p.error}`));
      }
    }

    // ── Entry points ─────────────────────────────────────────────────────────
    const epLabel = r.autoDetected ? 'auto-detected entry points' : 'entry points';
    console.log(
      `\n  ${chalk.bold(epLabel)}: ` +
      (r.entryPoints.length ? r.entryPoints.map(e => chalk.cyan(e)).join(', ') : chalk.dim('none'))
    );

    if (r.missingRoots.length > 0) {
      console.log(
        chalk.dim(`  (external / not in graph: `) +
        r.missingRoots.map(e => chalk.dim(e)).join(', ') + chalk.dim(')')
      );
    }

    // ── Uncalled functions warning ────────────────────────────────────────────
    if (r.uncalledFns.length > 0) {
      console.log(
        `\n  ${chalk.bgRed.white(' UNCALLED ')} ` +
        chalk.red(`${r.uncalledFns.length} function(s) have no callers and were not given as entry points:`)
      );
      r.uncalledFns.forEach(fn => console.log(`    ${chalk.red('●')} ${chalk.red(fn)}`));
    }

    console.log();

    if (r.totalFns === 0) {
      console.log(chalk.dim('  No named functions found.\n'));
      continue;
    }

    // ── Function table ───────────────────────────────────────────────────────
    const allFns = [
      ...r.aliveFns.map(f => ({ ...f, dead: false, chars: 0, reconstructed: [] as any[] })),
      ...r.deadFns.map(f  => ({ ...f, dead: true })),
    ].sort((a, b) => (a.line || 999999) - (b.line || 999999) || a.name.localeCompare(b.name));

    const nameW = Math.max(8, ...allFns.map(f => f.name.length));

    console.log(
      '  ' + chalk.bold(pad('Function', nameW)) + '  ' +
      chalk.bold(pad('Chars', 7))               + '  ' +
      chalk.bold(pad('Line', 10))               + '  ' +
      chalk.bold('Status')
    );
    console.log('  ' + '─'.repeat(nameW + 36));

    for (const fn of allFns) {
      const status = fn.dead ? chalk.red('✗ dead  ') : chalk.green('✓ alive ');
      const name   = fn.dead ? chalk.red(pad(fn.name, nameW)) : chalk.white(pad(fn.name, nameW));
      const chars  = chalk.dim(pad(fn.chars ? fmt(fn.chars) : '—', 7));
      const loc    = fn.line ? chalk.dim(`${fn.line}–${fn.endLine}`) : chalk.dim('(eval)');
      console.log(`  ${name}  ${chars}  ${pad(loc, 12)}  ${status}`);

      // Show reconstructed strings under dead functions
      if (fn.dead && fn.reconstructed?.length > 0) {
        for (const s of fn.reconstructed) {
          if (s.pieces < 2) continue; // only show multi-part reconstructions
          console.log(
            `    ${chalk.yellow('↳')} ${chalk.dim(s.varName + ' =')} ` +
            chalk.green.bold(`"${s.value}"`) +
            chalk.dim(` (${s.pieces} parts)`)
          );
        }
      }
    }

    console.log();

    // ── Summary ───────────────────────────────────────────────────────────────
    if (r.deadFns.length === 0) {
      console.log(chalk.green('  All functions reachable from entry point(s).\n'));
      continue;
    }

    const lastDead = r.deadFns[r.deadFns.length - 1];

    console.log(chalk.bold('  Reachability Summary'));
    console.log(chalk.dim('  ' + '─'.repeat(48)));
    console.log(`  Total in scope  : ${r.totalFns}`);
    console.log(`  Reachable       : ${chalk.green(String(r.aliveFns.length))}`);
    console.log(`  Dead            : ${chalk.red(String(r.deadFns.length))}`);
    console.log(
      `  Last dead fn    : ${chalk.red.bold(lastDead.name)} ` +
      (lastDead.line ? chalk.dim(`(line ${lastDead.line}–${lastDead.endLine})`) : chalk.dim('(eval layer)'))
    );

    // Reconstructed strings summary
    const allReconstructed = r.deadFns.flatMap(f => f.reconstructed.filter(s => s.pieces >= 2));
    if (allReconstructed.length > 0) {
      console.log();
      console.log(chalk.bold('  Reconstructed Strings (from dead function bodies):'));
      console.log(chalk.dim('  ' + '─'.repeat(48)));
      for (const s of allReconstructed) {
        console.log(
          `  ${chalk.yellow('⚑')} ${chalk.dim(s.varName + ':')} ${chalk.green.bold('"' + s.value + '"')} ` +
          chalk.dim(`(${s.pieces} fragments)`)
        );
      }
    }

    console.log();

    // Reduction bar
    console.log(chalk.bold('  Estimated Reduction'));
    console.log(chalk.dim('  ' + '─'.repeat(48)));
    const barW   = 24;
    const pct    = Math.min(r.reductionPct, 100);
    const filled = Math.min(barW, Math.round((pct / 100) * barW));
    const barStr = chalk.red('█'.repeat(filled)) + chalk.dim('░'.repeat(barW - filled));
    console.log(
      `  ${barStr}  ${chalk.red.bold(r.reductionPct.toFixed(1) + '%')} ` +
      chalk.dim(`(${fmt(r.deadChars)} / ${fmt(r.totalChars)} chars across eval layers)`)
    );
    console.log();

    // Dead function list
    console.log(chalk.bold('  Dead Functions (definition order):'));
    r.deadFns.forEach((fn, i) => {
      const last   = i === r.deadFns.length - 1;
      const prefix = last ? '  └─' : '  ├─';
      const loc    = fn.line ? `line ${fn.line}–${fn.endLine}` : 'eval layer';
      console.log(
        `${prefix} ${chalk.red(fn.name)}  ` +
        chalk.dim(`${loc}${fn.chars ? '  (' + fmt(fn.chars) + ' chars)' : ''}`) +
        (last ? chalk.yellow('  ← last') : '')
      );
    });

    console.log();
  }
}

function pad(s: string, n: number): string {
  const raw = s.replace(/\x1b\[[0-9;]*m/g, '');
  return raw.length >= n ? s : s + ' '.repeat(n - raw.length);
}

function fmt(n: number): string {
  return n >= 1000 ? `${(n / 1000).toFixed(1)}k` : String(n);
}
