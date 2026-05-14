import { test } from 'node:test';
import { strict as assert } from 'node:assert';
import { formatSarif } from '../src/reporter/sarif';
import type { ReaperResult } from '../src/types';

function makeResult(): ReaperResult {
  return {
    findings: [
      {
        type:       'eval-usage',
        file:       '/repo/src/malware.js',
        line:       12,
        column:     5,
        message:    'Direct eval() call',
        confidence: 'high',
      },
      {
        type:       'unused-import',
        file:       '/repo/src/lib.js',
        line:       3,
        column:     0,
        message:    "Unused import 'foo'",
        confidence: 'low',
      },
    ],
    filesScanned: 2,
    duration:     42,
  };
}

test('sarif: top-level shape is SARIF 2.1.0', () => {
  const doc = JSON.parse(formatSarif(makeResult(), '/repo'));
  assert.equal(doc.version, '2.1.0');
  assert.ok(Array.isArray(doc.runs));
  assert.equal(doc.runs.length, 1);
});

test('sarif: tool driver block is well-formed', () => {
  const doc = JSON.parse(formatSarif(makeResult(), '/repo'));
  const driver = doc.runs[0].tool.driver;
  assert.equal(driver.name, 'reaper');
  assert.ok(typeof driver.version === 'string');
  assert.match(driver.informationUri, /^https?:\/\//);
  assert.ok(Array.isArray(driver.rules));
  // Two distinct rule ids in our fixture: eval-usage and unused-import.
  const ids = driver.rules.map((r: any) => r.id).sort();
  assert.deepEqual(ids, ['eval-usage', 'unused-import']);
});

test('sarif: confidence is mapped to SARIF level', () => {
  const doc = JSON.parse(formatSarif(makeResult(), '/repo'));
  const byRule = Object.fromEntries(doc.runs[0].results.map((r: any) => [r.ruleId, r]));
  assert.equal(byRule['eval-usage'].level,    'error');     // high
  assert.equal(byRule['unused-import'].level, 'note');      // low
});

test('sarif: file uri is repo-relative and POSIX-style', () => {
  const doc = JSON.parse(formatSarif(makeResult(), '/repo'));
  const uri = doc.runs[0].results[0].locations[0].physicalLocation.artifactLocation.uri;
  assert.equal(uri, 'src/malware.js');
  assert.ok(!uri.includes('\\'));
  assert.ok(!uri.startsWith('/'));
});

test('sarif: column is 1-based per spec', () => {
  // Reaper internal column is 0-based; SARIF region.startColumn is 1-based.
  const doc = JSON.parse(formatSarif(makeResult(), '/repo'));
  const region = doc.runs[0].results[0].locations[0].physicalLocation.region;
  assert.equal(region.startLine,   12);
  assert.equal(region.startColumn, 6);     // reaper column 5 + 1
});

test('sarif: empty findings → valid empty results array', () => {
  const doc = JSON.parse(formatSarif({ findings: [], filesScanned: 0, duration: 0 }, '/repo'));
  assert.deepEqual(doc.runs[0].results, []);
  assert.deepEqual(doc.runs[0].tool.driver.rules, []);
});
