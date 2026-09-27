/**
 * HTML ingester: extracts JS-bearing payloads out of a .html file into
 * named virtual sub-files so the rest of the pipeline can treat them as
 * normal JS inputs.
 *
 * Captures:
 *   - Inline <script>…</script> blocks (anything without an external src)
 *   - <script src="data:text/javascript;base64,…"> data URIs
 *   - <script src="data:text/javascript,…"> percent-encoded data URIs
 *   - <script src="javascript:…"> (rare but valid)
 *   - Inline event-handler attributes (onload="…", onerror="…") on any tag
 *
 * External <script src> and <iframe>/<frame> src URLs are returned as
 * references for IOC reporting; nothing is fetched. Non-JS data URIs
 * (text/css etc) are skipped.
 *
 * A hand-rolled forward scan on purpose: jsdom would pull in ~50 MB of deps,
 * and the obvious regexes (`<script\b[^>]*>[\s\S]*?<\/script>`,
 * `<!--[\s\S]*?-->`) rescan to EOF from every unterminated opener, which is
 * O(n²) on hostile input. Every loop here only moves its cursor forward.
 */

import { readSourceCapped } from './index';

export interface ExtractedScript {
  /** Virtual file path: "<original.html>#script-N" or "#data-uri-N" */
  virtualPath: string;
  /** Raw JS source */
  source: string;
  /** Where it came from inside the original file */
  origin: 'inline' | 'data-uri-base64' | 'data-uri-raw' | 'javascript-uri' | 'event-handler';
  /** Approximate line in the original .html where it appeared */
  line: number;
}

export interface HtmlReference {
  url:     string;
  line:    number;
  context: 'script-src' | 'iframe-src';
}

const REMOTE_URL_RE = /^(?:https?:)?\/\//i;

export function extractScriptsFromHtml(filePath: string): ExtractedScript[] {
  return scanHtml(filePath).scripts;
}

export function scanHtml(filePath: string): { scripts: ExtractedScript[]; references: HtmlReference[] } {
  const html  = stripComments(readSourceCapped(filePath));
  const lower = html.toLowerCase();
  const out: ExtractedScript[] = [];
  const references: HtmlReference[] = [];

  let inlineIdx  = 0;
  let dataIdx    = 0;
  let handlerIdx = 0;

  let line    = 1;
  let counted = 0;

  let i = 0;
  while ((i = html.indexOf('<', i)) !== -1) {
    const tag = readTag(html, i);
    if (tag === 'unterminated') break;
    if (!tag) { i++; continue; }

    for (; counted < i; counted++) if (html.charCodeAt(counted) === 10) line++;
    const attr = (name: string) => tag.attrs.find(a => a[0] === name)?.[1];

    for (const [name, value] of tag.attrs) {
      if (/^on[a-z]+$/.test(name) && value.trim()) {
        out.push({
          virtualPath: `${filePath}#handler-${handlerIdx++}.js`,
          source:      value,
          origin:      'event-handler',
          line,
        });
      }
    }

    if (tag.name === 'iframe' || tag.name === 'frame') {
      const src = attr('src') ?? '';
      if (REMOTE_URL_RE.test(src)) references.push({ url: src, line, context: 'iframe-src' });
    }

    if (tag.name !== 'script') { i = tag.end + 1; continue; }

    // Browsers run an unclosed <script> to EOF, so do the same.
    const close = lower.indexOf('</script', tag.end + 1);
    const body  = html.slice(tag.end + 1, close === -1 ? html.length : close);
    i = close === -1 ? html.length : close + 8;

    const src  = attr('src') ?? '';
    const type = attr('type') ?? '';

    // Skip data blocks like JSON, importmap, etc.
    if (type && !/javascript|ecmascript|module/i.test(type)) continue;

    if (src) {
      // ── data:text/javascript;base64,... ────────────────────────────────
      const b64Match = /^data:(?:text|application)\/(?:java|ecma)script[^,;]*;base64,(.*)$/i.exec(src);
      if (b64Match) {
        try {
          const decoded = Buffer.from(b64Match[1], 'base64').toString('utf-8');
          out.push({
            virtualPath: `${filePath}#data-uri-${dataIdx++}.js`,
            source:      decoded,
            origin:      'data-uri-base64',
            line,
          });
        } catch {
          // Malformed base64 — skip
        }
        continue;
      }

      // ── data:text/javascript,...  (percent-encoded) ────────────────────
      const rawMatch = /^data:(?:text|application)\/(?:java|ecma)script[^,]*,(.*)$/i.exec(src);
      if (rawMatch) {
        try {
          const decoded = decodeURIComponent(rawMatch[1]);
          out.push({
            virtualPath: `${filePath}#data-uri-${dataIdx++}.js`,
            source:      decoded,
            origin:      'data-uri-raw',
            line,
          });
        } catch { /* skip */ }
        continue;
      }

      // ── javascript:... ─────────────────────────────────────────────────
      const jsMatch = /^javascript:(.*)$/i.exec(src);
      if (jsMatch) {
        out.push({
          virtualPath: `${filePath}#javascript-uri-${dataIdx++}.js`,
          source:      jsMatch[1],
          origin:      'javascript-uri',
          line,
        });
        continue;
      }

      if (REMOTE_URL_RE.test(src)) references.push({ url: src, line, context: 'script-src' });
      continue;
    }

    // ── Inline <script>…</script> ────────────────────────────────────────
    if (!body.trim()) continue;

    out.push({
      virtualPath: `${filePath}#script-${inlineIdx++}.js`,
      source:      body,
      origin:      'inline',
      line,
    });
  }

  return { scripts: out, references };
}

// Blank HTML comments so a literal <script…> inside one doesn't fool the
// scanner. Newlines are kept so downstream line numbers stay accurate. An
// unclosed comment runs to EOF, as it does in a browser.
function stripComments(raw: string): string {
  let out = '';
  let pos = 0;
  let start: number;
  while ((start = raw.indexOf('<!--', pos)) !== -1) {
    const end = raw.indexOf('-->', start + 4);
    const stop = end === -1 ? raw.length : end + 3;
    out += raw.slice(pos, start) + raw.slice(start, stop).replace(/[^\n]+/g, m => ' '.repeat(m.length));
    pos = stop;
  }
  return out + raw.slice(pos);
}

interface Tag { name: string; attrs: [string, string][]; end: number }

// Parse the tag opening at `start`. Returns null if `<` doesn't begin a tag,
// or 'unterminated' if no closing `>` exists, in which case no later tag can
// close either and the caller stops.
function readTag(html: string, start: number): Tag | null | 'unterminated' {
  const nameMatch = /^<([a-zA-Z][a-zA-Z0-9-]*)/.exec(html.slice(start, start + 64));
  if (!nameMatch) return null;

  let j = start + nameMatch[0].length;
  let quote = 0;
  for (; j < html.length; j++) {
    const c = html.charCodeAt(j);
    if (quote) { if (c === quote) quote = 0; }
    else if (c === 34 || c === 39) quote = c;
    else if (c === 62) break;
  }
  if (j >= html.length) return 'unterminated';

  const attrs: [string, string][] = [];
  const attrText = html.slice(start + nameMatch[0].length, j);
  for (const m of attrText.matchAll(/([^\s"'=<>\/]+)(?:\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'=<>`]+)))?/g)) {
    attrs.push([m[1].toLowerCase(), decodeEntities(m[2] ?? m[3] ?? m[4] ?? '')]);
  }
  return { name: nameMatch[1].toLowerCase(), attrs, end: j };
}

const NAMED_ENTITIES: Record<string, string> = { amp: '&', lt: '<', gt: '>', quot: '"', apos: "'", nbsp: ' ' };

function decodeEntities(s: string): string {
  return s.replace(/&(?:#(\d{1,7})|#x([0-9a-f]{1,6})|([a-z]{2,6}));/gi, (m, dec, hex, name) => {
    if (dec || hex) {
      const cp = dec ? parseInt(dec, 10) : parseInt(hex, 16);
      return cp <= 0x10ffff ? String.fromCodePoint(cp) : m;
    }
    return NAMED_ENTITIES[name.toLowerCase()] ?? m;
  });
}

export function isHtmlPath(p: string): boolean {
  return /\.(html?|htm)$/i.test(p);
}
