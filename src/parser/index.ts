import { parse } from '@babel/parser';
import type { File } from '@babel/types';
import fs from 'fs';

export function parseFile(filePath: string): File {
  const code = fs.readFileSync(filePath, 'utf-8');
  return parseCode(code, filePath);
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
