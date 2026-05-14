export type FindingType =
  | 'unreachable'
  | 'unused-import'
  | 'unused-variable'
  | 'unused-function'
  | 'unused-export'
  // Phase 2 — malware-focused
  | 'dead-branch'
  | 'eval-usage'
  | 'dynamic-execution'
  | 'obfuscation-pattern';

export type Confidence = 'high' | 'medium' | 'low';

export interface Finding {
  type: FindingType;
  file: string;
  line: number;
  column: number;
  endLine?: number;
  message: string;
  confidence: Confidence;
}

export interface AnalyzerOptions {
  unusedImports: boolean;
  unusedVars: boolean;
  unreachable: boolean;
  deadBranches: boolean;
  obfuscation: boolean;
}

export interface ReaperResult {
  findings: Finding[];
  filesScanned: number;
  duration: number;
}
