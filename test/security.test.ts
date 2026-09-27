import { test } from 'node:test';
import { strict as assert } from 'node:assert';
import fs from 'fs';
import path from 'path';
import { withTempDir } from './helpers';

// Note: MAX_SOURCE_BYTES is read from REAPER_MAX_SOURCE_MB at module-eval time,
// so the parser module is imported dynamically *after* the env var is set.

test('readSourceCapped: rejects a file above the cap, accepts one below', async () => {
  process.env.REAPER_MAX_SOURCE_MB = '1';
  const { readSourceCapped } = await import('../src/parser/index');

  await withTempDir((dir) => {
    const big   = path.join(dir, 'big.js');
    const small = path.join(dir, 'small.js');
    fs.writeFileSync(big, 'a'.repeat(2 * 1024 * 1024));   // 2 MB > 1 MB cap
    fs.writeFileSync(small, 'const x = 1;');

    assert.throws(() => readSourceCapped(big), /over the 1 MB cap/);
    assert.equal(readSourceCapped(small), 'const x = 1;');
  });
});

test('detectAndRewriteStringArray: executes in an isolated worker and still rewrites', async () => {
  // Exercises the child-process boundary end-to-end on the committed sample:
  // if isolation broke boot/decode, substitutions would drop to 0.
  const { detectAndRewriteStringArray } = await import('../src/analyzers/stringarray');
  const { readExample } = await import('./helpers');
  const src = readExample('etherhiding/artifacts/stage1/payload.js');
  const r = detectAndRewriteStringArray(src, 'payload.js');
  assert.equal(r.detected, true);
  assert.equal(r.substitutions, 28);
  assert.equal(r.error, null);
});

test('docker shim: every Function-constructor route is logged and blocked', async () => {
  const { spawnSync } = await import('child_process');
  const { repoRoot } = await import('./helpers');
  await withTempDir(dir => {
    const probe = path.join(dir, 'probe.js');
    fs.writeFileSync(probe, `
      const routes = [
        () => Function('return 1')(),
        () => [].constructor.constructor('return 2')(),
        () => (async function () {}).constructor('return 3'),
        () => (function* () {}).constructor('yield 4'),
        () => (async function* () {}).constructor('yield 5'),
      ];
      let ran = 0;
      for (const r of routes) { try { r(); ran++; } catch {} }
      console.log('ran=' + ran);
      process.exit(0);
    `);
    const res = spawnSync(process.execPath, ['--require', path.join(repoRoot, 'docker/runner.js'), probe], {
      env: { PATH: process.env.PATH, REAPER_BLOCK_EVAL: '1', SANDBOX_TIMEOUT: '5000' },
      encoding: 'utf-8',
    });
    assert.match(res.stdout, /ran=0/);
    for (const body of ['return 1', 'return 2', 'return 3', 'yield 4', 'yield 5']) {
      assert.ok(res.stderr.includes(`"detail":"${body}"`), `not logged: ${body}`);
    }
  });
});
