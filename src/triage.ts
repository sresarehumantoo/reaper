/**
 * Unified one-shot triage.
 *
 * Runs the whole static pipeline over a single (already HTML-expanded) source:
 *   string-array rewrite → constant-fold → obfuscation/encoded findings →
 *   IOC extraction, then scores a coarse verdict.
 *
 * The deobfuscated form is what gets scanned for findings and IOCs, so
 * indicators hidden behind a decoder or an atob() are surfaced. Optionally
 * writes the recovered .deobf.js artifact when an output dir is supplied.
 */

import crypto from 'crypto';
import { parseCode } from './parser';
import { detectAndRewriteStringArray } from './analyzers/stringarray';
import { foldConstants } from './analyzers/constfold';
import { analyzeObfuscation } from './analyzers/obfuscation';
import { analyzeEncoded } from './analyzers/encoded';
import { extractIocs } from './analyzers/iocs';
import type { Finding } from './types';
import type { Ioc } from './analyzers/iocs';

export type Verdict = 'clean' | 'suspicious' | 'malicious';

export interface TriageReport {
  file:        string;     // user-facing source name
  sha256:      string;     // hash of the analysed (expanded) source bytes
  bytes:       number;
  deobfuscated: boolean;   // true if string-array rewrite and/or folding changed the source
  stringArray: { detected: boolean; substitutions: number; attempted: number; wrappers: number; aliases: number } | null;
  folds:       number;
  findings:    Finding[];
  iocs:        Ioc[];
  score:       number;
  verdict:     Verdict;
  reasons:     string[];
  error?:      string;
}

// Indicator types that are inherently high-signal for "this is malicious".
const HIGH_SIGNAL_IOCS = new Set<Ioc['type']>([
  'suspicious-command', 'discord-webhook', 'telegram-bot-token', 'aws-key', 'private-key',
]);
const NETWORK_IOCS = new Set<Ioc['type']>(['url', 'domain', 'ipv4', 'ipv6']);

export function triageSource(code: string, filePath: string, displayName: string, fold = true): TriageReport {
  const sha256 = crypto.createHash('sha256').update(code).digest('hex');
  const report: TriageReport = {
    file: displayName, sha256, bytes: Buffer.byteLength(code),
    deobfuscated: false, stringArray: null, folds: 0,
    findings: [], iocs: [], score: 0, verdict: 'clean', reasons: [],
  };

  // ── 1. Deobfuscate: string-array rewrite then constant-fold ──────────────
  let working = code;
  const sa = detectAndRewriteStringArray(code, filePath);
  if (sa.detected && sa.rewritten) {
    working = sa.rewritten;
    report.stringArray = {
      detected: true, substitutions: sa.substitutions, attempted: sa.attempted,
      wrappers: sa.wrappers.length, aliases: sa.aliases.length,
    };
  }
  if (fold) {
    const f = foldConstants(working, filePath);
    working = f.code;
    report.folds = f.changes;
  }
  report.deobfuscated = (sa.detected && !!sa.rewritten) || report.folds > 0;

  // ── 2. Findings + IOCs over the deobfuscated form ────────────────────────
  try {
    const ast = parseCode(working, filePath);
    report.findings = [...analyzeObfuscation(ast, displayName), ...analyzeEncoded(ast, displayName)]
      .sort((a, b) => a.line - b.line);
    report.iocs = extractIocs(ast, displayName);
  } catch (e: any) {
    report.error = `analysis of deobfuscated form failed: ${e?.message ?? String(e)}`;
  }

  // ── 3. Score a coarse verdict ────────────────────────────────────────────
  scoreVerdict(report);
  return report;
}

function scoreVerdict(r: TriageReport): void {
  let score = 0;
  const reasons: string[] = [];

  if (r.stringArray?.detected) {
    score += 2;
    reasons.push(`string-array obfuscation (${r.stringArray.substitutions} substitutions)`);
  }

  const evalFindings = r.findings.filter(f => f.type === 'eval-usage' || f.type === 'dynamic-execution');
  if (evalFindings.length) {
    score += Math.min(3, evalFindings.length);
    reasons.push(`${evalFindings.length} dynamic-execution sink(s)`);
  }
  const obfHigh = r.findings.filter(f => f.type === 'obfuscation-pattern' && f.confidence === 'high').length;
  if (obfHigh) { score += Math.min(2, obfHigh); reasons.push(`${obfHigh} high-confidence obfuscation pattern(s)`); }

  const highIocs = r.iocs.filter(i => HIGH_SIGNAL_IOCS.has(i.type));
  for (const i of highIocs) { score += 4; reasons.push(`${i.type}`); }

  const netCount = r.iocs.filter(i => NETWORK_IOCS.has(i.type)).length;
  if (netCount) { score += Math.min(2, netCount); reasons.push(`${netCount} network indicator(s)`); }

  const viaB64 = r.iocs.filter(i => (i.context ?? '').includes('base64')).length;
  if (viaB64) { score += 2; reasons.push(`${viaB64} indicator(s) recovered from base64`); }

  r.score = score;
  r.verdict = score >= 6 ? 'malicious' : score >= 2 ? 'suspicious' : 'clean';
  r.reasons = [...new Set(reasons)];
}
