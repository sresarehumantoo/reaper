#!/usr/bin/env node
// fetch-evm-payload - read EtherHiding-style staged payloads out of EVM
// contract storage via a single eth_call. Safe by construction:
//   - eth_call is a READ. No gas, no signed tx, no funds at risk.
//   - The returned bytes are decoded and written to disk for inspection.
//     They are NEVER executed.
//
// Lives alongside examples/etherhiding/ because it is specific to that
// family. Move to scripts/ when a second blockchain-staged example exists.
//
// Usage:
//   ./examples/etherhiding/fetch-evm-payload.mjs <contract>
//     [--selector 0x6d4ce63c]                  (default: matches the EtherHiding loader)
//     [--rpc https://bsc-testnet-rpc.publicnode.com/]
//     [--block latest]                         (or a hex block number / tag)
//     [--out /tmp/stageN.js]                   (default: ./<contract>.bin / .js)
//     [--raw]                                  (skip base64 decode - write the ABI string verbatim)
//     [--json]                                 (machine-readable summary to stdout)
//
// Examples:
//   ./examples/etherhiding/fetch-evm-payload.mjs 0xA1decFB75C8C0CA28C10517ce56B710baf727d2e
//   ./examples/etherhiding/fetch-evm-payload.mjs 0x46790e2... --rpc https://eth.llamarpc.com/
//   ./examples/etherhiding/fetch-evm-payload.mjs 0xa1de... --selector 0x12345678 --raw --json

import fs from 'fs';
import path from 'path';

// ── Args ────────────────────────────────────────────────────────────────────
const argv = process.argv.slice(2);
let contract  = '';
let selector  = '0x6d4ce63c';
let rpc       = 'https://bsc-testnet-rpc.publicnode.com/';
let block     = 'latest';
let outPath   = '';
let raw       = false;
let jsonOut   = false;

for (let i = 0; i < argv.length; i++) {
  const a = argv[i];
  if (a === '--selector') { selector = argv[++i]; continue; }
  if (a === '--rpc')      { rpc      = argv[++i]; continue; }
  if (a === '--block')    { block    = argv[++i]; continue; }
  if (a === '--out')      { outPath  = argv[++i]; continue; }
  if (a === '--raw')      { raw      = true;      continue; }
  if (a === '--json')     { jsonOut  = true;      continue; }
  if (a === '-h' || a === '--help') {
    console.log(fs.readFileSync(import.meta.url.replace('file://', ''), 'utf8').split('\n').slice(1, 24).join('\n').replace(/^\/\/ ?/gm, ''));
    process.exit(0);
  }
  if (a.startsWith('-')) {
    console.error(`unknown flag: ${a}`); process.exit(2);
  }
  contract = a;
}

if (!/^0x[0-9a-fA-F]{40}$/.test(contract)) {
  console.error('usage: fetch-evm-payload <0x…40hex contract address> [--selector 0xNNNNNNNN] [--rpc URL] [--block latest|0xN] [--out PATH] [--raw] [--json]');
  process.exit(2);
}
if (!/^0x[0-9a-fA-F]{8}$/.test(selector)) {
  console.error(`bad selector: ${selector} (want 0x + 8 hex chars)`); process.exit(2);
}

// ── eth_call ────────────────────────────────────────────────────────────────
const reqBody = {
  jsonrpc: '2.0',
  id:      1,
  method:  'eth_call',
  params:  [{ to: contract, data: selector }, block],
};

if (!jsonOut) console.error(`→ POST ${rpc}  eth_call to=${contract} data=${selector} block=${block}`);

const resp = await fetch(rpc, {
  method:  'POST',
  headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
  body:    JSON.stringify(reqBody),
});
if (!resp.ok) {
  console.error(`rpc http ${resp.status}: ${await resp.text()}`); process.exit(1);
}
const rpcBody = await resp.json();
if (rpcBody.error) {
  console.error(`rpc error: ${JSON.stringify(rpcBody.error)}`); process.exit(1);
}
const hex = String(rpcBody.result || '').replace(/^0x/, '');
if (!hex || hex === '') {
  console.error(`empty result — contract has no data at selector ${selector} (or doesn't exist on this chain)`);
  process.exit(1);
}

// ── ABI-decode the leading string return ────────────────────────────────────
// Solidity ABI for a `function fn() external view returns (string)`:
//   [32 bytes: offset (always 0x20)] [32 bytes: byte length] [length bytes: data, right-padded to 32]
let abiString = null;
let abiOffset = null;
let abiLength = null;
if (hex.length >= 128) {
  abiOffset = parseInt(hex.slice(0, 64), 16);
  abiLength = parseInt(hex.slice(64, 128), 16);
  if (Number.isFinite(abiOffset) && Number.isFinite(abiLength) && abiLength > 0 &&
      hex.length >= 128 + abiLength * 2) {
    const buf = Buffer.from(hex.slice(128, 128 + abiLength * 2), 'hex');
    abiString = buf.toString('utf8');
  }
}

// ── Decide what to write ────────────────────────────────────────────────────
let mode = 'raw-hex';
let payload = Buffer.from(hex, 'hex');
let suffix = '.bin';

if (abiString !== null) {
  mode    = 'abi-string';
  payload = Buffer.from(abiString, 'utf8');
  suffix  = '.txt';

  if (!raw) {
    // Looks like base64? (tolerate trailing whitespace; long, base64-charset only)
    const trimmed = abiString.trim();
    if (trimmed.length > 16 && /^[A-Za-z0-9+/=\s]+$/.test(trimmed)) {
      try {
        const decoded = Buffer.from(trimmed, 'base64');
        // Heuristic: only treat as JS if decoded looks like printable ASCII
        const printable = decoded.toString('utf8');
        const printRatio = [...printable].filter(c => {
          const code = c.charCodeAt(0);
          return (code >= 32 && code < 127) || code === 9 || code === 10 || code === 13;
        }).length / Math.max(printable.length, 1);
        if (printRatio > 0.9) {
          mode    = 'abi-string→base64→utf8';
          payload = decoded;
          suffix  = '.js';
        }
      } catch { /* not valid base64; keep the raw abi string */ }
    }
  }
}

// ── Write to disk ───────────────────────────────────────────────────────────
const defaultName = `${contract.toLowerCase()}${suffix}`;
const dst = outPath || defaultName;
fs.writeFileSync(dst, payload);

// ── Report ──────────────────────────────────────────────────────────────────
const summary = {
  contract,
  selector,
  rpc,
  block,
  raw_hex_bytes:   hex.length / 2,
  abi_offset:      abiOffset,
  abi_length:      abiLength,
  decode_mode:     mode,
  output_bytes:    payload.length,
  output_path:     path.resolve(dst),
  preview_utf8:    payload.toString('utf8').slice(0, 200),
};

if (jsonOut) {
  console.log(JSON.stringify(summary, null, 2));
} else {
  console.error('');
  console.error(`  raw hex bytes : ${summary.raw_hex_bytes}`);
  console.error(`  abi offset    : ${summary.abi_offset}`);
  console.error(`  abi length    : ${summary.abi_length}`);
  console.error(`  decode mode   : ${summary.decode_mode}`);
  console.error(`  output        : ${summary.output_path} (${summary.output_bytes} B)`);
  console.error('');
  console.error(`  preview:`);
  console.error(summary.preview_utf8.split('\n').map(l => '    ' + l).join('\n'));
}
