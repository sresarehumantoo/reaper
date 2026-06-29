/**
 * Shared helpers used across analyzers and reporters.
 */
import _traverse from '@babel/traverse';
import _generate from '@babel/generator';

// @babel/traverse and @babel/generator ship as CJS with the real function on
// `.default` under esModuleInterop. Normalise both so every module imports the
// callable form from here instead of repeating the interop dance.
export const traverse = (typeof _traverse === 'function'
  ? _traverse
  : (_traverse as any).default) as typeof _traverse;

export const generate = (typeof _generate === 'function'
  ? _generate
  : (_generate as any).default) as typeof _generate;

/** Shannon entropy (bits/symbol) of a string. High → likely encoded/encrypted. */
export function shannonEntropy(s: string): number {
  if (s.length === 0) return 0;
  const freq = new Map<string, number>();
  for (const c of s) freq.set(c, (freq.get(c) ?? 0) + 1);
  let h = 0;
  for (const count of freq.values()) {
    const p = count / s.length;
    h -= p * Math.log2(p);
  }
  return h;
}

/** Fraction of characters that are printable ASCII (incl. tab/newline). */
export function printableRatio(s: string): number {
  if (s.length === 0) return 0;
  let printable = 0;
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if ((c >= 32 && c < 127) || c === 9 || c === 10 || c === 13) printable++;
  }
  return printable / s.length;
}

export function truncate(s: string, n: number): string {
  return s.length <= n ? s : s.slice(0, n - 1) + '…';
}

/**
 * Defang a network indicator for safe inclusion in reports/tickets:
 * `http://evil.com/x` → `hxxp://evil[.]com/x`, `1.2.3.4` → `1[.]2[.]3[.]4`,
 * `a@b.com` → `a[@]b[.]com`. Idempotent-ish for already-defanged input.
 */
export function defang(s: string): string {
  return s
    .replace(/\bhttps?:\/\//gi, m => m.replace(/^http/i, 'hxxp').replace('://', '[://]'))
    .replace(/@/g, '[@]')
    .replace(/\./g, '[.]');
}
