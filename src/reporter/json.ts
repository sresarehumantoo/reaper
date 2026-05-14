import type { ReaperResult } from '../types';

export function formatJson(result: ReaperResult): string {
  return JSON.stringify(result, null, 2);
}
