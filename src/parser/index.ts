import { parse } from '@babel/parser';
import type { File } from '@babel/types';
import fs from 'fs';

/**
 * Upper bound on a single source file reaper will read into memory. Untrusted
 * samples can be arbitrarily large (the file-bloat evasion where a payload is
 * padded to hundreds of MB is real), and both `readFileSync` and the Babel
 * parse that follows are O(size) in memory. Reading a multi-hundred-MB file
 * would OOM the analyzer before analysis even starts. Override with
 * REAPER_MAX_SOURCE_MB for the rare legitimately-huge input.
 */
export const MAX_SOURCE_BYTES = (() => {
  const mb = Number(process.env.REAPER_MAX_SOURCE_MB);
  return Number.isFinite(mb) && mb > 0 ? mb * 1024 * 1024 : 16 * 1024 * 1024;
})();

/** Read a source file, refusing inputs above MAX_SOURCE_BYTES. */
export function readSourceCapped(filePath: string): string {
  let size: number;
  try {
    size = fs.statSync(filePath).size;
  } catch (e: any) {
    throw new Error(`cannot stat ${filePath}: ${e.message}`);
  }
  if (size > MAX_SOURCE_BYTES) {
    const mb  = (size / 1048576).toFixed(1);
    const cap = Math.floor(MAX_SOURCE_BYTES / 1048576);
    throw new Error(
      `${filePath} is ${mb} MB, over the ${cap} MB cap — carve the real content ` +
      `out first, or raise REAPER_MAX_SOURCE_MB`);
  }
  return fs.readFileSync(filePath, 'utf-8');
}

export function parseFile(filePath: string): File {
  return parseCode(readSourceCapped(filePath), filePath);
}

export function parseCode(code: string, filePath: string): File {
  const isTS = /\.tsx?$/.test(filePath);
  const isJSX = /\.[jt]sx$/.test(filePath);

  return parse(code, {
    sourceType: 'module',
    strictMode: false,
    allowImportExportEverywhere: true,
    allowReturnOutsideFunction: true,
    plugins: [
      ...(isTS ? (['typescript'] as const) : (['flow'] as const)),
      ...(isJSX ? (['jsx'] as const) : []),
      'decorators-legacy',
      'classProperties',
      'classStaticBlock',
      'dynamicImport',
      'exportDefaultFrom',
      'nullishCoalescingOperator',
      'optionalChaining',
    ],
  });
}
