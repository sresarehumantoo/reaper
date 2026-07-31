/**
 * SARIF 2.1.0 output for reaper findings.
 *
 * SARIF is the open standard for static-analysis results; GitHub Code
 * Scanning consumes it natively, as do most enterprise SAST aggregators.
 *
 * Reference: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
 */

import path from 'path';
import type { Finding, FindingType, ReaperResult, Confidence } from '../types';

// Description per rule. Used to populate the `tool.driver.rules` block so
// downstream consumers can render hover-help and rule documentation links.
const RULE_DESCRIPTIONS: Record<FindingType, { short: string; full: string }> = {
  'unused-import':       { short: 'Unused import',        full: 'An import statement whose imported name is never referenced in the module.' },
  'unused-variable':     { short: 'Unused variable',      full: 'A declared variable that is never read.' },
  'unused-function':     { short: 'Unused function',      full: 'A declared function that is never called or referenced.' },
  'unused-export':       { short: 'Unused export',        full: 'An exported binding with no detectable importer.' },
  'unreachable':         { short: 'Unreachable code',     full: 'Code positioned after an unconditional return, throw, or break that can never execute.' },
  'dead-branch':         { short: 'Dead branch',          full: 'A branch whose condition is provably constant after fold; the unreachable side is dead.' },
  'eval-usage':          { short: 'Direct eval / Function constructor', full: 'A direct eval() call or new Function() — common malware payload execution vector.' },
  'dynamic-execution':   { short: 'Implicit eval',        full: 'setTimeout/setInterval invoked with a string body, which is implicitly eval-ed.' },
  'obfuscation-pattern': { short: 'Obfuscation pattern',  full: 'A pattern characteristic of obfuscated or hostile code (atob, fromCharCode, bracket access to dangerous identifiers, high-entropy strings, AAEncode, XOR decoders, etc).' },
};

const CONFIDENCE_TO_LEVEL: Record<Confidence, 'note' | 'warning' | 'error'> = {
  low:    'note',
  medium: 'warning',
  high:   'error',
};

export function formatSarif(result: ReaperResult, cwd: string, toolVersion = '0.1.0'): string {
  const allTypes = new Set<FindingType>(result.findings.map(f => f.type));

  const rules = [...allTypes].sort().map(id => ({
    id,
    name:             id,
    shortDescription: { text: RULE_DESCRIPTIONS[id]?.short ?? id },
    fullDescription:  { text: RULE_DESCRIPTIONS[id]?.full  ?? '' },
    defaultConfiguration: {
      level: 'warning',
    },
    helpUri: 'https://github.com/sresarehumantoo/reaper#what-it-does',
  }));

  const results = result.findings.map(f => buildResult(f, cwd));

  const doc = {
    version: '2.1.0',
    $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
    runs: [
      {
        tool: {
          driver: {
            name:           'reaper',
            version:        toolVersion,
            informationUri: 'https://github.com/sresarehumantoo/reaper',
            rules,
          },
        },
        results,
        invocations: [
          {
            executionSuccessful: true,
            workingDirectory:    { uri: 'file://' + cwd + '/' },
          },
        ],
      },
    ],
  };

  return JSON.stringify(doc, null, 2);
}

function buildResult(f: Finding, cwd: string) {
  // SARIF wants forward-slash URIs relative to the run's working directory
  // (when present). Use POSIX separator regardless of host.
  const uri = relPosix(cwd, f.file);

  const region: Record<string, number> = {
    startLine: Math.max(1, f.line || 1),
  };
  if (f.column >= 0) region.startColumn = f.column + 1;       // Babel col is 0-based; SARIF is 1-based (col 0 → 1)
  if (f.endLine && f.endLine > f.line) region.endLine = f.endLine;

  return {
    ruleId:  f.type,
    level:   CONFIDENCE_TO_LEVEL[f.confidence],
    message: { text: f.message },
    locations: [
      {
        physicalLocation: {
          artifactLocation: { uri },
          region,
        },
      },
    ],
    properties: { confidence: f.confidence },
  };
}

function relPosix(cwd: string, abs: string): string {
  const rel = path.relative(cwd, abs);
  // Normalise Windows-style backslashes — SARIF URIs are POSIX.
  return rel.split(path.sep).join('/');
}
