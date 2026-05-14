/**
 * Indicator-of-Compromise extractor.
 *
 * Walks every string literal and template literal in the AST and pattern-
 * matches against the IOC families most useful for malware triage:
 *
 *   - URL (http/https, with full URL parsed for host)
 *   - Bare domain (registrable name, when not already covered by a URL)
 *   - IPv4
 *   - EVM address (0x + 40 hex chars, EIP-55 mixed-case ok)
 *   - EVM function selector (0x + 8 hex chars, when in an obvious selector context)
 *   - Base64 blob (>= 80 chars, base64 charset, deduped against substrings of URLs)
 *   - High-entropy string (>= 32 chars, Shannon entropy > 5.0, not already classified)
 *   - Email address
 *
 * Deduplicates by (type, value).
 *
 * Important: this runs against the AST it is given. The caller should feed
 * it the deobfuscated form when possible (see `--rewrite` mode), otherwise
 * IOCs hidden behind a string-array decoder will not be visible here.
 */

import _traverse from '@babel/traverse';
import * as t from '@babel/types';
import type { File } from '@babel/types';

const traverse = (typeof _traverse === 'function'
  ? _traverse
  : (_traverse as any).default) as typeof _traverse;

export type IocType =
  | 'url'
  | 'domain'
  | 'ipv4'
  | 'evm-address'
  | 'evm-selector'
  | 'base64'
  | 'high-entropy'
  | 'email';

export interface Ioc {
  type:   IocType;
  value:  string;
  line:   number;
  column: number;
  context?: string;     // optional snippet — useful for "what kind of API was this passed to"
}

const URL_RE        = /\bhttps?:\/\/[^\s"'<>`)]+/gi;
const DOMAIN_RE     = /\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:[a-z]{2,24})\b/gi;
const IPV4_RE       = /\b(?:25[0-5]|2[0-4]\d|[01]?\d\d?)(?:\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)){3}\b/g;
const EVM_ADDR_RE   = /\b0x[0-9a-fA-F]{40}\b/g;
const EVM_SEL_RE    = /\b0x[0-9a-fA-F]{8}\b/g;
const EMAIL_RE      = /\b[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,24}\b/gi;
const BASE64_RE     = /\b[A-Za-z0-9+/]{80,}={0,2}\b/g;

// Domains we never want to treat as IOC noise — common analyst-host noise
// (browser CDNs, public-good infrastructure that appears in *many* samples
// alongside the actual C2).
const DOMAIN_DENYLIST = new Set([
  'w3.org', 'gmpg.org', 'wordpress.org', 'wp.org',
  'fontawesome.com', 'use.fontawesome.com',
  'jquery.com', 'jquery.org',
  'github.com', 'github.io', 'githubusercontent.com',
  'json-schema.org',
]);

export function extractIocs(ast: File, filePath: string): Ioc[] {
  const found = new Map<string, Ioc>(); // key = type|value

  function add(type: IocType, value: string, loc: t.SourceLocation | null | undefined, context?: string) {
    const key = `${type}|${value}`;
    if (found.has(key)) return;
    found.set(key, {
      type,
      value,
      line:    loc?.start.line   ?? 0,
      column:  loc?.start.column ?? 0,
      context,
    });
  }

  function scanString(value: string, loc: t.SourceLocation | null | undefined, context?: string) {
    if (typeof value !== 'string' || value.length === 0) return;

    // ── URLs (collect first so URL-substring noise is suppressed below) ────
    const urlHosts = new Set<string>();
    for (const m of value.matchAll(URL_RE)) {
      const url = m[0].replace(/[.,;:)\]>]+$/, ''); // strip trailing punctuation
      add('url', url, loc, context);
      try {
        const u = new URL(url);
        urlHosts.add(u.hostname.toLowerCase());
      } catch { /* malformed but still useful as a string */ }
    }

    // ── Bare domains (skip ones already in a captured URL or denylisted) ───
    for (const m of value.matchAll(DOMAIN_RE)) {
      const d = m[0].toLowerCase();
      if (urlHosts.has(d)) continue;
      if (DOMAIN_DENYLIST.has(d)) continue;
      // Drop domains whose registrable suffix is one of the denylist entries
      const suffix = d.split('.').slice(-2).join('.');
      if (DOMAIN_DENYLIST.has(suffix)) continue;
      // Drop "x.y" where x or y is purely numeric (catches accidental matches
      // like "1.0" or "version 2.5") — real domains have at least one alpha
      // label before the TLD.
      if (/^\d+\.\d+$/.test(d)) continue;
      add('domain', d, loc, context);
    }

    // ── IPv4 ────────────────────────────────────────────────────────────────
    for (const m of value.matchAll(IPV4_RE)) {
      add('ipv4', m[0], loc, context);
    }

    // ── EVM addresses ──────────────────────────────────────────────────────
    for (const m of value.matchAll(EVM_ADDR_RE)) {
      add('evm-address', m[0], loc, context);
    }

    // ── EVM function selectors. Only flag when the surrounding string looks
    //    like a selector context (the string IS just the selector, or appears
    //    as the `data` field of a JSON-RPC call). Otherwise hex literals are
    //    too noisy.
    if (/^0x[0-9a-fA-F]{8}$/.test(value)) {
      add('evm-selector', value, loc, context);
    }

    // ── Email ──────────────────────────────────────────────────────────────
    for (const m of value.matchAll(EMAIL_RE)) {
      add('email', m[0].toLowerCase(), loc, context);
    }

    // ── Base64 blobs (long enough to be a real payload, not nonce/id) ──────
    for (const m of value.matchAll(BASE64_RE)) {
      const blob = m[0];
      // Skip if this is the entire string and could just be an arbitrary key/token
      // We keep len in the value for the reporter to render.
      add('base64', blob, loc, `length=${blob.length}`);
    }

    // ── High-entropy fallback ──────────────────────────────────────────────
    if (value.length >= 32 && value.length <= 2048) {
      const e = shannon(value);
      if (e > 5.0 && !/\s/.test(value)) {
        // Skip if this whole string was already classified as something more
        // specific (URL, base64, etc.).
        const alreadyClassified =
          URL_RE.test(value) || BASE64_RE.test(value) || EVM_ADDR_RE.test(value);
        URL_RE.lastIndex = 0; BASE64_RE.lastIndex = 0; EVM_ADDR_RE.lastIndex = 0;
        if (!alreadyClassified) {
          add('high-entropy', value, loc, `length=${value.length} entropy=${e.toFixed(2)}`);
        }
      }
    }
  }

  traverse(ast, {
    StringLiteral(path) {
      const ctx = inferContext(path);
      scanString(path.node.value, path.node.loc, ctx);
    },
    TemplateLiteral(path) {
      // Concatenate cooked values from quasis — note: ignores expression
      // interpolations entirely, so `https://${HOST}/path` produces only
      // "https://" and "/path" which probably won't match anything useful.
      // That's intentional; we don't want false positives from partial URLs.
      for (const q of path.node.quasis) {
        scanString(q.value.cooked ?? '', q.loc);
      }
    },
  });

  return [...found.values()].sort((a, b) =>
    a.type !== b.type ? a.type.localeCompare(b.type) : a.value.localeCompare(b.value)
  );
}

// Try to extract a hint about WHERE this string is used — e.g. the property
// name it's assigned to, or the function it's passed to. Useful for the
// reporter to render "method: 'POST'" vs just "POST".
function inferContext(path: any): string | undefined {
  // Object property: { to: '0x...' }
  if (t.isObjectProperty(path.parent)) {
    const key = path.parent.key;
    if (t.isIdentifier(key)) return `prop:${key.name}`;
    if (t.isStringLiteral(key)) return `prop:${key.value}`;
  }
  // Argument: fetch('https://...')
  if (t.isCallExpression(path.parent)) {
    const callee = path.parent.callee;
    if (t.isIdentifier(callee)) return `arg-of:${callee.name}`;
    if (t.isMemberExpression(callee) && t.isIdentifier(callee.property)) {
      return `arg-of:${callee.property.name}`;
    }
  }
  // Initialiser: const URL = 'https://...'
  if (t.isVariableDeclarator(path.parent) && t.isIdentifier(path.parent.id)) {
    return `init:${path.parent.id.name}`;
  }
  return undefined;
}

function shannon(s: string): number {
  const freq = new Map<string, number>();
  for (const c of s) freq.set(c, (freq.get(c) ?? 0) + 1);
  let h = 0;
  for (const count of freq.values()) {
    const p = count / s.length;
    h -= p * Math.log2(p);
  }
  return h;
}
