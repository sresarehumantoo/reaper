import { traverse } from '../util';
import * as t from '@babel/types';
import type { File } from '@babel/types';
import type { Finding } from '../types';

// ---------------------------------------------------------------------------
// Constant folding — evaluate expressions made entirely of literals
// ---------------------------------------------------------------------------

type KnownValue = { known: true; value: unknown } | { known: false };

function evaluate(node: t.Node): KnownValue {
  if (t.isBooleanLiteral(node)) return { known: true, value: node.value };
  if (t.isNumericLiteral(node)) return { known: true, value: node.value };
  if (t.isStringLiteral(node))  return { known: true, value: node.value };
  if (t.isNullLiteral(node))    return { known: true, value: null };
  if (t.isIdentifier(node) && node.name === 'undefined') return { known: true, value: undefined };

  if (t.isUnaryExpression(node) && node.operator === '!') {
    const arg = evaluate(node.argument);
    if (arg.known) return { known: true, value: !arg.value };
  }

  if (t.isUnaryExpression(node) && node.operator === 'void') {
    return { known: true, value: undefined };
  }

  if (t.isBinaryExpression(node)) {
    const l = evaluate(node.left);
    const r = evaluate(node.right);
    if (!l.known || !r.known) return { known: false };

    const lv = l.value as any;
    const rv = r.value as any;

    switch (node.operator) {
      case '===': return { known: true, value: lv === rv };
      case '!==': return { known: true, value: lv !== rv };
      case '==':  return { known: true, value: lv == rv };   // eslint-disable-line eqeqeq
      case '!=':  return { known: true, value: lv != rv };   // eslint-disable-line eqeqeq
      case '>':   return { known: true, value: lv > rv };
      case '<':   return { known: true, value: lv < rv };
      case '>=':  return { known: true, value: lv >= rv };
      case '<=':  return { known: true, value: lv <= rv };
      case '+':   return { known: true, value: lv + rv };
      case '-':   return { known: true, value: lv - rv };
      case '*':   return { known: true, value: lv * rv };
      case '|':   return { known: true, value: lv | rv };
      case '&':   return { known: true, value: lv & rv };
      case '^':   return { known: true, value: lv ^ rv };
    }
  }

  if (t.isLogicalExpression(node)) {
    const l = evaluate(node.left);
    if (node.operator === '&&' && l.known && !l.value) return { known: true, value: l.value };
    if (node.operator === '||' && l.known && l.value)  return { known: true, value: l.value };
    const r = evaluate(node.right);
    if (l.known && r.known) return r;
  }

  return { known: false };
}

// ---------------------------------------------------------------------------
// Analyzer
// ---------------------------------------------------------------------------

export function analyzeDeadBranches(ast: File, filePath: string): Finding[] {
  const findings: Finding[] = [];

  traverse(ast, {
    IfStatement(path) {
      const result = evaluate(path.node.test);
      if (!result.known) return;

      const isAlwaysTrue  = Boolean(result.value);
      const isAlwaysFalse = !isAlwaysTrue;
      const loc = path.node.test.loc;

      if (isAlwaysTrue && path.node.alternate) {
        // else branch is dead
        findings.push({
          type: 'dead-branch',
          file: filePath,
          line: path.node.alternate.loc?.start.line ?? loc?.start.line ?? 0,
          column: path.node.alternate.loc?.start.column ?? 0,
          endLine: path.node.alternate.loc?.end.line,
          message: `Dead else-branch — condition is always truthy: \`${condSource(path.node.test)}\``,
          confidence: 'high',
        });
      }

      if (isAlwaysFalse) {
        // then branch is dead
        findings.push({
          type: 'dead-branch',
          file: filePath,
          line: path.node.consequent.loc?.start.line ?? loc?.start.line ?? 0,
          column: path.node.consequent.loc?.start.column ?? 0,
          endLine: path.node.consequent.loc?.end.line,
          message: `Dead if-branch — condition is always falsy: \`${condSource(path.node.test)}\``,
          confidence: 'high',
        });
      }
    },

    ConditionalExpression(path) {
      const result = evaluate(path.node.test);
      if (!result.known) return;

      const dead = result.value ? path.node.alternate : path.node.consequent;
      findings.push({
        type: 'dead-branch',
        file: filePath,
        line: dead.loc?.start.line ?? 0,
        column: dead.loc?.start.column ?? 0,
        endLine: dead.loc?.end.line,
        message: `Dead ternary ${result.value ? 'else' : 'then'}-branch — condition is always ${result.value ? 'truthy' : 'falsy'}: \`${condSource(path.node.test)}\``,
        confidence: 'high',
      });
    },

    WhileStatement(path) {
      const result = evaluate(path.node.test);
      if (!result.known) return;
      if (!result.value) {
        findings.push({
          type: 'dead-branch',
          file: filePath,
          line: path.node.loc?.start.line ?? 0,
          column: path.node.loc?.start.column ?? 0,
          endLine: path.node.loc?.end.line,
          message: `Dead while-loop — condition is always falsy: \`${condSource(path.node.test)}\``,
          confidence: 'high',
        });
      }
    },
  });

  return findings;
}

function condSource(node: t.Node): string {
  // Best-effort reconstruction of simple literal conditions for the message
  if (t.isBooleanLiteral(node)) return String(node.value);
  if (t.isNumericLiteral(node)) return String(node.value);
  if (t.isStringLiteral(node))  return JSON.stringify(node.value);
  if (t.isNullLiteral(node))    return 'null';
  if (t.isIdentifier(node))     return node.name;
  if (t.isUnaryExpression(node)) return `${node.operator}${condSource(node.argument)}`;
  if (t.isBinaryExpression(node)) return `${condSource(node.left)} ${node.operator} ${condSource(node.right)}`;
  return '[expression]';
}
