import { parseFile } from '../parser';
import { analyzeUnreachable } from './unreachable';
import { analyzeUnusedImports } from './imports';
import { analyzeUnusedReferences } from './references';
import { analyzeDeadBranches } from './branches';
import { analyzeObfuscation } from './obfuscation';
import type { Finding, AnalyzerOptions } from '../types';

export function analyzeFile(filePath: string, options: AnalyzerOptions): Finding[] {
  const ast = parseFile(filePath);
  const findings: Finding[] = [];

  if (options.unreachable)    findings.push(...analyzeUnreachable(ast, filePath));
  if (options.unusedImports)  findings.push(...analyzeUnusedImports(ast, filePath));
  if (options.unusedVars)     findings.push(...analyzeUnusedReferences(ast, filePath));
  if (options.deadBranches)   findings.push(...analyzeDeadBranches(ast, filePath));
  if (options.obfuscation)    findings.push(...analyzeObfuscation(ast, filePath));

  return findings.sort((a, b) => a.line - b.line);
}
