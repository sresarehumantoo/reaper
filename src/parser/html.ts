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
 *
 * Does NOT fetch remote scripts (no network) and intentionally skips
 * non-JS data URIs (text/css etc).
 *
 * Regex-based on purpose: jsdom would pull in ~50 MB of deps and we only
 * need to find <script> tags in a flat scan. Edge cases (comments containing
 * </script>) are rare enough to ignore — and reaper falls back to "treat as
 * raw JS" if extraction yields nothing.
 */

import fs from 'fs';
import path from 'path';

export interface ExtractedScript {
  /** Virtual file path: "<original.html>#script-N" or "#data-uri-N" */
  virtualPath: string;
  /** Raw JS source */
  source: string;
  /** Where it came from inside the original file */
  origin: 'inline' | 'data-uri-base64' | 'data-uri-raw' | 'javascript-uri';
  /** Approximate line in the original .html where it appeared */
  line: number;
}

const SCRIPT_RE = /<script\b([^>]*)>([\s\S]*?)<\/script\s*>/gi;
const SRC_RE    = /\bsrc\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))/i;
const TYPE_RE   = /\btype\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))/i;

export function extractScriptsFromHtml(filePath: string): ExtractedScript[] {
  const raw  = fs.readFileSync(filePath, 'utf-8');
  // Strip HTML comments so literal <script…> inside a comment doesn't fool
  // the scanner. Replace each comment with a same-length run of spaces so
  // downstream line numbers stay accurate.
  const html = raw.replace(/<!--[\s\S]*?-->/g, m => ' '.repeat(m.length));
  const out: ExtractedScript[] = [];
  const base = path.basename(filePath);

  let inlineIdx = 0;
  let dataIdx   = 0;

  for (const m of html.matchAll(SCRIPT_RE)) {
    const attrs   = m[1] ?? '';
    const body    = m[2] ?? '';
    const tagPos  = m.index ?? 0;
    const line    = html.slice(0, tagPos).split('\n').length;

    const srcMatch = attrs.match(SRC_RE);
    const src      = srcMatch ? (srcMatch[1] ?? srcMatch[2] ?? srcMatch[3] ?? '') : '';

    const typeMatch = attrs.match(TYPE_RE);
    const type      = typeMatch ? (typeMatch[1] ?? typeMatch[2] ?? typeMatch[3] ?? '') : '';

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

      // External src — we don't fetch. Skip.
      continue;
    }

    // ── Inline <script>…</script> ────────────────────────────────────────
    const trimmed = body.trim();
    if (!trimmed) continue;

    out.push({
      virtualPath: `${filePath}#script-${inlineIdx++}.js`,
      source:      body,
      origin:      'inline',
      line,
    });
  }

  return out;
}

export function isHtmlPath(p: string): boolean {
  return /\.(html?|htm)$/i.test(p);
}
