/**
 * Indicator-of-Compromise extractor.
 *
 * Walks every string literal and template literal in the AST and pattern-
 * matches against the IOC families most useful for malware / web-threat triage.
 * Network indicators (URL, domain, IPv4/IPv6), chain indicators (EVM/BTC/XMR),
 * credential/secret indicators (AWS keys, JWTs, Telegram bot tokens, Discord
 * webhooks, PEM private keys), host indicators (Windows paths, registry keys),
 * and staging indicators (base64 blobs, high-entropy strings, suspicious
 * commands) all flow through one scanner.
 *
 * Base64 blobs that decode to mostly-printable text are decoded and the plain
 * text is re-scanned, so IOCs nested one base64 layer deep surface too. Each
 * derived indicator records the chain it came from in `context` (`via:base64`).
 *
 * Deduplicates by (type, value).
 *
 * Important: this runs against the AST it is given. The caller should feed it
 * the deobfuscated form when possible (see `--rewrite` / `triage`), otherwise
 * IOCs hidden behind a string-array decoder will not be visible here.
 */

import * as t from '@babel/types';
import type { File } from '@babel/types';
import { parse as parseDomain } from 'tldts';
import { traverse, shannonEntropy } from '../util';

export type IocType =
  | 'url'
  | 'domain'
  | 'ipv4'
  | 'ipv6'
  | 'evm-address'
  | 'evm-selector'
  | 'btc-address'
  | 'xmr-address'
  | 'base64'
  | 'high-entropy'
  | 'email'
  | 'telegram-bot-token'
  | 'discord-webhook'
  | 'aws-key'
  | 'jwt'
  | 'private-key'
  | 'windows-path'
  | 'registry-key'
  | 'suspicious-command';

export interface Ioc {
  type:   IocType;
  value:  string;
  line:   number;
  column: number;
  context?: string;     // "what kind of API was this passed to", or a derivation chain
}

// Non-global variants are used for membership tests; global ones for matchAll.
const URL_RE        = /\bhttps?:\/\/[^\s"'<>`)]+/gi;
// Label repetition is bounded ({1,10}) so the engine can't match a huge run of
// single-char labels and then backtrack it at every start position — the
// unbounded `(?:label\.)+` form is O(n²) on inputs like `a.`×N (real domains
// never approach 10 labels, and parseDomain reduces to the registrable domain
// anyway).
const DOMAIN_RE     = /\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.){1,10}(?:[a-z]{2,24})\b/gi;
const IPV4_RE       = /\b(?:25[0-5]|2[0-4]\d|[01]?\d\d?)(?:\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)){3}\b/g;
const IPV6_RE       = /\b(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{0,4}(?:::)?(?:[0-9a-fA-F]{1,4})?\b/g;
const EVM_ADDR_RE   = /\b0x[0-9a-fA-F]{40}\b/g;
// Every quantifier is bounded (RFC-realistic caps) so the engine can't scan an
// unbounded run at each start position: the old unbounded local part
// `[a-z0-9._%+-]+` re-scanned the whole no-`@` tail at every offset (O(n²) on
// `x@` + `a.`×N + `!`), and putting `.` inside a `+` in the domain overlapped
// the required `\.` + TLD. Dot-separated labels + fixed maxima keep it linear.
const EMAIL_RE      = /\b[a-z0-9._%+-]{1,64}@[a-z0-9-]{1,63}(?:\.[a-z0-9-]{1,63}){0,10}\.[a-z]{2,24}\b/gi;
const BASE64_RE     = /\b[A-Za-z0-9+/]{80,}={0,2}/g;
const TELEGRAM_RE   = /\b\d{8,10}:[A-Za-z0-9_-]{35}\b/g;
const DISCORD_WH_RE = /\bhttps?:\/\/(?:canary\.|ptb\.)?discord(?:app)?\.com\/api\/(?:v\d+\/)?webhooks\/\d+\/[A-Za-z0-9_-]+/gi;
const AWS_KEY_RE    = /\b(?:AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ABIA|ACCA)[A-Z0-9]{16}\b/g;
const JWT_RE        = /\beyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/g;
const PEM_RE        = /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----/g;
const BTC_BECH32_RE = /\bbc1[a-z0-9]{25,87}\b/g;
const BTC_LEGACY_RE = /\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b/g;
const XMR_RE        = /\b[48][0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b/g;
const WIN_PATH_RE   = /\b[A-Za-z]:\\(?:[^\\\/:*?"<>|\r\n]+\\)*[^\\\/:*?"<>|\r\n]+/g;
const REG_KEY_RE    = /\b(?:HKEY_(?:LOCAL_MACHINE|CURRENT_USER|CLASSES_ROOT|USERS|CURRENT_CONFIG)|HKLM|HKCU|HKCR|HKU)\\[^\r\n"']{3,}/g;

// Distinctive substrings of living-off-the-land / dropper command lines.
const COMMAND_SIGNATURES = [
  /Invoke-Expression\b/i, /\bIEX\b/, /-enc(?:odedcommand)?\s/i,
  /FromBase64String/i, /DownloadString/i, /Invoke-WebRequest/i, /\bcurl\s+-/i,
  /certutil\s+(?:-urlcache|-decode)/i, /bitsadmin\s+\/transfer/i,
  /reg\s+add\b/i, /schtasks\s+\/create/i, /\brundll32\b/i, /\bmshta\b/i,
  /wscript\.shell/i, /-WindowStyle\s+Hidden/i, /-nop\b/i,
];

// Common analyst-host noise (browsers, public-good infra) we treat as
// registrable domains to suppress. Matched against tldts' registrable domain.
const DOMAIN_DENYLIST = new Set([
  'w3.org', 'gmpg.org', 'wordpress.org',
  'fontawesome.com', 'jquery.com', 'jquery.org',
  'github.com', 'github.io', 'githubusercontent.com',
  'json-schema.org', 'schema.org', 'googleapis.com', 'gstatic.com',
]);

const MAX_DECODE_DEPTH = 2;

// Cap on a base64 blob we're willing to decode-and-rescan. The blob is still
// recorded as a `base64` IOC regardless; this only bounds the decode +
// recursive re-scan so a multi-MB blob can't blow up memory/CPU (decode →
// re-scan → decode again). 1 MiB of base64 → ~768 KiB of text, plenty for a
// nested URL/key/config; anything larger is almost always padding or binary.
const MAX_DECODE_BASE64_LEN = 1 << 20;

export function extractIocs(ast: File, filePath: string): Ioc[] {
  const found = new Map<string, Ioc>(); // key = type|value
  const classified = new Set<string>(); // exact values matched to a specific type

  function add(type: IocType, value: string, loc: t.SourceLocation | null | undefined, context?: string) {
    if (type !== 'high-entropy' && type !== 'base64') classified.add(value);
    const key = `${type}|${value}`;
    const existing = found.get(key);
    if (existing) {
      // Keep the original sighting but prefer a concrete context over none.
      if (!existing.context && context) existing.context = context;
      return;
    }
    found.set(key, {
      type, value,
      line:   loc?.start.line   ?? 0,
      column: loc?.start.column ?? 0,
      context,
    });
  }

  function scanString(value: string, loc: t.SourceLocation | null | undefined, context?: string, depth = 0) {
    if (typeof value !== 'string' || value.length === 0) return;

    // ── URLs (collect first so URL-substring noise is suppressed below) ────
    const urlHosts = new Set<string>();
    for (const m of value.matchAll(URL_RE)) {
      const url = m[0].replace(/[.,;:)\]>]+$/, '');
      add('url', url, loc, context);
      try { urlHosts.add(new URL(url).hostname.toLowerCase()); } catch { /* still useful as a string */ }
    }

    // ── Discord webhooks (a URL, but high-signal — promote to its own type) ─
    for (const m of value.matchAll(DISCORD_WH_RE)) add('discord-webhook', m[0], loc, context ?? 'exfil/c2');

    // ── Bare domains (skip URL hosts + denylisted registrable domains) ─────
    for (const m of value.matchAll(DOMAIN_RE)) {
      const d = m[0].toLowerCase();
      if (urlHosts.has(d)) continue;
      const parsed = parseDomain(d);
      const registrable = parsed.domain;
      if (!registrable || !parsed.isIcann) continue;          // not a real public domain
      if (DOMAIN_DENYLIST.has(registrable)) continue;
      if (urlHosts.has(registrable)) continue;
      add('domain', d, loc, context);
    }

    // ── IP addresses ───────────────────────────────────────────────────────
    for (const m of value.matchAll(IPV4_RE)) add('ipv4', m[0], loc, context);
    for (const m of value.matchAll(IPV6_RE)) {
      const v = m[0];
      if ((v.match(/:/g) ?? []).length >= 2 && /[0-9a-fA-F]/.test(v)) add('ipv6', v, loc, context);
    }

    // ── Blockchain ─────────────────────────────────────────────────────────
    for (const m of value.matchAll(EVM_ADDR_RE)) add('evm-address', m[0], loc, context);
    for (const m of value.matchAll(BTC_BECH32_RE)) add('btc-address', m[0], loc, context);
    for (const m of value.matchAll(XMR_RE))        add('xmr-address', m[0], loc, context);
    if (/^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$/.test(value)) add('btc-address', value, loc, context);

    // ── EVM function selector: only when the string IS exactly the selector ─
    if (/^0x[0-9a-fA-F]{8}$/.test(value)) add('evm-selector', value, loc, context);

    // ── Secrets / credentials ──────────────────────────────────────────────
    for (const m of value.matchAll(TELEGRAM_RE)) add('telegram-bot-token', m[0], loc, context ?? 'exfil/c2');
    for (const m of value.matchAll(AWS_KEY_RE))  add('aws-key', m[0], loc, context);
    for (const m of value.matchAll(JWT_RE))      add('jwt', m[0], loc, context);
    if (PEM_RE.test(value)) { PEM_RE.lastIndex = 0; add('private-key', value.slice(0, 64) + '…', loc, context); }

    // ── Host indicators ─────────────────────────────────────────────────────
    for (const m of value.matchAll(REG_KEY_RE))  add('registry-key', m[0], loc, context);
    for (const m of value.matchAll(WIN_PATH_RE)) {
      if (m[0].length >= 6) add('windows-path', m[0], loc, context);
    }

    // ── Email ────────────────────────────────────────────────────────────────
    for (const m of value.matchAll(EMAIL_RE)) add('email', m[0].toLowerCase(), loc, context);

    // ── Suspicious command lines ───────────────────────────────────────────
    if (value.length <= 4096 && COMMAND_SIGNATURES.some(re => re.test(value))) {
      add('suspicious-command', value.length > 200 ? value.slice(0, 199) + '…' : value, loc, context ?? 'loader');
    }

    // ── Base64 blobs → record, and decode-and-recurse one layer deeper ─────
    for (const m of value.matchAll(BASE64_RE)) {
      const blob = m[0];
      add('base64', blob, loc, context ? `${context} length=${blob.length}` : `length=${blob.length}`);
      if (depth < MAX_DECODE_DEPTH) {
        const decoded = tryDecodeBase64(blob);
        if (decoded) {
          const chain = context ? `${context}>base64` : 'via:base64';
          scanString(decoded, loc, chain, depth + 1);
        }
      }
    }

    // ── atob()/base64-decode arguments: decode regardless of length, since
    //    the call itself is the signal (short blobs hide URLs/keys too) ─────
    if (depth < MAX_DECODE_DEPTH && /^(?:arg-of:atob|arg-of:from)/.test(context ?? '') &&
        value.length >= 8 && /^[A-Za-z0-9+/]+={0,2}$/.test(value)) {
      const decoded = tryDecodeBase64(value);
      if (decoded && decoded !== value) scanString(decoded, loc, 'via:base64', depth + 1);
    }

    // ── High-entropy fallback (only at the top layer, to limit noise) ──────
    if (depth === 0 && value.length >= 32 && value.length <= 2048 && !/\s/.test(value)) {
      const e = shannonEntropy(value);
      if (e > 5.0) {
        const alreadyClassified = classified.has(value) ||
          /\bhttps?:\/\//i.test(value) || /^[A-Za-z0-9+/]{80,}={0,2}$/.test(value) || /\b0x[0-9a-fA-F]{40}\b/.test(value);
        if (!alreadyClassified) {
          add('high-entropy', value, loc, `length=${value.length} entropy=${e.toFixed(2)}`);
        }
      }
    }
  }

  traverse(ast, {
    StringLiteral(path) {
      scanString(path.node.value, path.node.loc, inferContext(path));
    },
    TemplateLiteral(path) {
      for (const q of path.node.quasis) scanString(q.value.cooked ?? '', q.loc);
    },
  });

  return [...found.values()].sort((a, b) =>
    a.type !== b.type ? a.type.localeCompare(b.type) : a.value.localeCompare(b.value)
  );
}

// Decode a base64 blob if it yields mostly-printable text (i.e. a nested
// payload/config worth re-scanning, not raw binary).
function tryDecodeBase64(blob: string): string | null {
  if (blob.length > MAX_DECODE_BASE64_LEN) return null;   // too big to decode+rescan safely
  if (blob.length % 4 !== 0 && !blob.endsWith('=')) {
    // tolerate unpadded — Buffer handles it, but skip obvious non-multiples
  }
  let decoded: string;
  try {
    decoded = Buffer.from(blob, 'base64').toString('utf-8');
  } catch { return null; }
  if (decoded.length < 4) return null;
  let printable = 0;
  for (let i = 0; i < decoded.length; i++) {
    const c = decoded.charCodeAt(i);
    if ((c >= 32 && c < 127) || c === 9 || c === 10 || c === 13) printable++;
  }
  return printable / decoded.length > 0.85 ? decoded : null;
}

// Hint about WHERE this string is used — property name, call it's an argument
// to, or the variable it initialises.
function inferContext(path: any): string | undefined {
  if (t.isObjectProperty(path.parent)) {
    const key = path.parent.key;
    if (t.isIdentifier(key)) return `prop:${key.name}`;
    if (t.isStringLiteral(key)) return `prop:${key.value}`;
  }
  if (t.isCallExpression(path.parent)) {
    const callee = path.parent.callee;
    if (t.isIdentifier(callee)) return `arg-of:${callee.name}`;
    if (t.isMemberExpression(callee) && t.isIdentifier(callee.property)) {
      return `arg-of:${callee.property.name}`;
    }
  }
  if (t.isVariableDeclarator(path.parent) && t.isIdentifier(path.parent.id)) {
    return `init:${path.parent.id.name}`;
  }
  return undefined;
}
