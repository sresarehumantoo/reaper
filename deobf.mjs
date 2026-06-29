#!/usr/bin/env node
// One-off deobfuscator for the PropellerAds-style payload.
// Boots the string-array + decoder in a VM, then rewrites every wrapper call.

import fs from 'node:fs';
import vm from 'node:vm';
import { parse } from '@babel/parser';
import _traverse from '@babel/traverse';
import _generate from '@babel/generator';
import * as t from '@babel/types';

const traverse = _traverse.default || _traverse;
const generate = _generate.default || _generate;

const IN = '/home/owen/1285133f2f3d4bffd19ce5188f677353.js';
const OUT = '/home/owen/reaper_out/deobf.js';
const src = fs.readFileSync(IN, 'utf8');

const ARRAY_FN = 'pqkm2o2';     // returns the string table
const DECODER_FN = 'pqkm2o3';   // (idx, key) -> string

// 1. Boot the decoder in a VM by extracting the IIFE prelude.
// The whole file is `(function(){...})()`. We need the decoder + array + rotator,
// but NOT the rest. Slice: from `(function(){` through the rotator close.
// Rotator ends right before `,!(function(){var Ni=` (first big use).
const rotatorEnd = src.indexOf(',!(function(){');
if (rotatorEnd < 0) throw new Error('rotator boundary not found');
const prelude = src.slice(0, rotatorEnd);

// Also need the standalone string-array function defined far below.
const arrFnRe = new RegExp(`function ${ARRAY_FN}\\(\\)\\{var [^=]+=\\[[\\s\\S]*?\\];${ARRAY_FN}=function\\(\\)\\{return [^;]+;\\};return ${ARRAY_FN}\\(\\);\\}`);
const m = src.match(arrFnRe);
if (!m) throw new Error('string-array fn not matched');
const arrayFnSrc = m[0];

const bootSrc = `${prelude} );\n${arrayFnSrc}\nglobalThis.__decode = ${DECODER_FN};`;
// Note: `prelude` is "(function(){function pqkm2o3...(function(o,k){...}(pqkm2o2,0xdf895)"
// We need to close the outer IIFE call. Add ` })()` is tricky; instead wrap.
// Simpler: rewrap from scratch — reconstruct a tiny boot script.

const decoderFnRe = new RegExp(`function ${DECODER_FN}\\(o,k\\)\\{[^}]+\\}`);
const decoderSrc = src.match(decoderFnRe)[0];

// Rotator: `function(o,k){...}(pqkm2o2,0xdf895)` — match the inner IIFE call.
const rotIdx = src.indexOf(`(${ARRAY_FN},0x`);
if (rotIdx < 0) throw new Error('rotator call site not found');
const rStart = src.lastIndexOf('function(o,k){', rotIdx);
// End: position of `)` that closes `(pqkm2o2,0xNNN)`.
const rEnd = src.indexOf(')', rotIdx) + 1;
// Wrap in parens so it's a valid ExpressionStatement.
const rotatorSrc = '(' + src.slice(rStart, rEnd) + ')';
console.error('[boot] rotator len=', rotatorSrc.length);

const boot = `${decoderSrc}\n${arrayFnSrc}\n${rotatorSrc};\nglobalThis.__decode = ${DECODER_FN};`;
fs.writeFileSync('/tmp/boot.js', boot);
console.error('[boot] wrote /tmp/boot.js, len=', boot.length, 'last120=', JSON.stringify(boot.slice(-120)));
const ctx = vm.createContext({ globalThis: {} });
vm.runInContext(boot, ctx, { timeout: 5000 });
const decode = ctx.globalThis.__decode;
console.error('[boot] decoder ok, sample:', JSON.stringify(decode(0x1ec)), decode(0x393), decode(0x315));

// 2. Parse the full file, find every alias `var Xx = pqkm2o3;` and every call
//    `Xx(0xNNN)` — replace with the string literal.
const ast = parse(src, { sourceType: 'script', allowReturnOutsideFunction: true });

let replaced = 0;
let aliases = new Set([DECODER_FN]);

// Pass 1: collect alias variable names (any `var X = pqkm2o3` in any scope).
traverse(ast, {
  VariableDeclarator(path) {
    const { id, init } = path.node;
    if (!init || init.type !== 'Identifier') return;
    if (aliases.has(init.name) && id.type === 'Identifier') {
      aliases.add(id.name);
    }
  },
});
console.error('[pass1] aliases:', [...aliases].slice(0, 20).join(','), '...total=', aliases.size);

// Re-traverse until no new aliases appear (transitive: var A = pqkm2o3; var B = A;)
let grew = true;
while (grew) {
  grew = false;
  traverse(ast, {
    VariableDeclarator(path) {
      const { id, init } = path.node;
      if (!init || init.type !== 'Identifier') return;
      if (aliases.has(init.name) && id.type === 'Identifier' && !aliases.has(id.name)) {
        aliases.add(id.name);
        grew = true;
      }
    },
  });
}
console.error('[pass1+] transitive aliases:', aliases.size);

// Pass 2: rewrite every CallExpression where callee is an alias and arg is a NumericLiteral.
traverse(ast, {
  CallExpression(path) {
    const c = path.node.callee;
    if (c.type !== 'Identifier' || !aliases.has(c.name)) return;
    const args = path.node.arguments;
    if (args.length !== 1) return;
    const a = args[0];
    if (a.type !== 'NumericLiteral') return;
    let v;
    try { v = decode(a.value); } catch { return; }
    if (typeof v !== 'string') return;
    path.replaceWith(t.stringLiteral(v));
    replaced++;
  },
});
console.error('[pass2] replaced', replaced, 'wrapper calls');

const out = generate(ast, { compact: false, retainLines: false }).code;
fs.writeFileSync(OUT, out);
console.error('[done] wrote', OUT, 'bytes=', out.length);
