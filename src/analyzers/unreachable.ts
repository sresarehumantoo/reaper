import { traverse } from '../util';
import type * as t from '@babel/types';
import type { File } from '@babel/types';
import type { Finding } from '../types';

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

  // Scan a statement list for code following an unconditional terminator.
  // Used for both block bodies and switch-case consequents (a Statement[],
  // not a BlockStatement — so it needs its own visitor).
  function scan(body: t.Statement[]): void {
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
  }

  traverse(ast, {
    BlockStatement(path) {
      scan(path.node.body);
    },
    SwitchCase(path) {
      // Skip the last statement being a nested block etc. — the flat scan on
      // the consequent list is enough to catch `case x: return; foo();`.
      scan(path.node.consequent);
    },
  });

  return findings;
}
