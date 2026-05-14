import _traverse from '@babel/traverse';
import type * as t from '@babel/types';
import type { File } from '@babel/types';
import type { Finding } from '../types';

// CJS/ESM interop for @babel/traverse
const traverse = (typeof _traverse === 'function' ? _traverse : (_traverse as any).default) as typeof _traverse;

const TERMINATING = [
  'ReturnStatement',
  'ThrowStatement',
  'BreakStatement',
  'ContinueStatement',
] as const;

type TerminatingType = (typeof TERMINATING)[number];

function isTerminating(node: t.Node): node is t.Statement {
  return TERMINATING.includes(node.type as TerminatingType);
}

export function analyzeUnreachable(ast: File, filePath: string): Finding[] {
  const findings: Finding[] = [];

  traverse(ast, {
    BlockStatement(path) {
      const { body } = path.node;
      for (let i = 0; i < body.length - 1; i++) {
        const node = body[i];
        if (isTerminating(node)) {
          const deadStart = body[i + 1];
          const deadEnd = body[body.length - 1];
          const termType = node.type.replace('Statement', '').toLowerCase();

          findings.push({
            type: 'unreachable',
            file: filePath,
            line: deadStart.loc?.start.line ?? 0,
            column: deadStart.loc?.start.column ?? 0,
            endLine: deadEnd.loc?.end.line,
            message: `Unreachable code after ${termType} statement`,
            confidence: 'high',
          });
          break;
        }
      }
    },
  });

  return findings;
}
