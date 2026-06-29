import { parse } from '@babel/parser';
import type { File } from '@babel/types';
import fs from 'fs';

/**
 * A parsed source unit. Carries the raw `code` alongside the `ast` so analyzers
 * that need the source representation (escape-density, katakana scans, byte
 * hashing) don't have to re-read the file, and so a multi-analyzer run parses
 * each input exactly once.
 */
export interface SourceUnit {
  path: string;
  code: string;
  ast: File;
}

export function parseFile(filePath: string): File {
  const code = fs.readFileSync(filePath, 'utf-8');
  return parseCode(code, filePath);
}

/** Read + parse a file once into a reusable {path, code, ast} unit. */
export function loadSource(filePath: string): SourceUnit {
  const code = fs.readFileSync(filePath, 'utf-8');
  return { path: filePath, code, ast: parseCode(code, filePath) };
}

/** Build a SourceUnit from in-memory source (e.g. a deobfuscated string). */
export function sourceFromString(code: string, filePath: string): SourceUnit {
  return { path: filePath, code, ast: parseCode(code, filePath) };
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
