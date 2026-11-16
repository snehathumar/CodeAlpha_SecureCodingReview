import { parse } from '@babel/parser';
import type { CodeFile, Finding, FindingStatus, SastRule } from '../types/audit';

interface AstNode {
  type: string;
  loc?: { start: { line: number; column: number } } | null;
  [key: string]: unknown;
}

function isAstNode(val: unknown): val is AstNode {
  return Boolean(val && typeof val === 'object' && typeof (val as { type?: unknown }).type === 'string');
}

function getMemberChain(node: unknown): string {
  if (!isAstNode(node)) return '';
  if (node.type === 'Identifier' && typeof node.name === 'string') return node.name;
  if (node.type === 'ThisExpression') return 'this';
  if (node.type === 'MemberExpression') {
    const obj = getMemberChain(node.object);
    const prop = isAstNode(node.property)
      ? typeof node.property.name === 'string'
        ? node.property.name
        : typeof node.property.value === 'string'
        ? node.property.value
        : ''
      : '';
    return obj && prop ? `${obj}.${prop}` : prop || obj;
  }
  return '';
}

function collectIdentifiers(node: unknown, out: Set<string> = new Set()): Set<string> {
  if (!node || typeof node !== 'object') return out;
  if (Array.isArray(node)) {
    for (const item of node) collectIdentifiers(item, out);
    return out;
  }
  if (!isAstNode(node)) return out;
  if (node.type === 'Identifier' && typeof node.name === 'string') {
    out.add(node.name);
    return out;
  }
  for (const [k, v] of Object.entries(node)) {
    if (k === 'loc' || k === 'start' || k === 'end' || k === 'extra') continue;
    collectIdentifiers(v, out);
  }
  return out;
}

function isDirectTaintedSource(node: unknown): string | null {
  if (!isAstNode(node)) return null;
  const chain = getMemberChain(node);
  if (
    /^(?:req|request)\.(?:body|query|params|headers|cookies)/i.test(chain) ||
    /^window\.location/i.test(chain) ||
    /^document\.(?:location|cookie|URL)/i.test(chain) ||
    /^process\.argv/i.test(chain)
  ) {
    return chain;
  }
  if (node.type === 'MemberExpression' || node.type === 'CallExpression' || node.type === 'TSAsExpression' || node.type === 'TSTypeAssertion') {
    if (node.type === 'CallExpression') {
      const calleeChain = getMemberChain(node.callee);
      if (/^(?:prompt|readline)$/i.test(calleeChain)) return `${calleeChain}()`;
      for (const arg of (node.arguments as unknown[]) ?? []) {
        const inner = isDirectTaintedSource(arg);
        if (inner) return inner;
      }
    }
    if (node.type === 'MemberExpression') {
      return isDirectTaintedSource(node.object);
    }
    if ('expression' in node) {
      return isDirectTaintedSource(node.expression);
    }
  }
  return null;
}

function findTaintInExpr(
  node: unknown,
  taintedVars: Map<string, string>
): { tainted: boolean; sourceLabel: string } {
  const direct = isDirectTaintedSource(node);
  if (direct) return { tainted: true, sourceLabel: direct };

  if (isAstNode(node)) {
    const ids = collectIdentifiers(node);
    for (const id of ids) {
      if (taintedVars.has(id)) {
        return { tainted: true, sourceLabel: `${id} (from ${taintedVars.get(id)})` };
      }
    }
    // Check nested member chains like req.query.id inside BinaryExpression or TemplateLiteral
    let nestedDirect: string | null = null;
    const scanNested = (cur: unknown) => {
      if (nestedDirect || !cur || typeof cur !== 'object') return;
      if (Array.isArray(cur)) {
        cur.forEach(scanNested);
        return;
      }
      if (!isAstNode(cur)) return;
      const d = isDirectTaintedSource(cur);
      if (d) {
        nestedDirect = d;
        return;
      }
      for (const [k, v] of Object.entries(cur)) {
        if (k === 'loc' || k === 'start' || k === 'end' || k === 'extra') continue;
        scanNested(v);
      }
    };
    scanNested(node);
    if (nestedDirect) return { tainted: true, sourceLabel: nestedDirect };
  }

  return { tainted: false, sourceLabel: '' };
}

function isDynamicSqlExpression(node: unknown, taintedVars: Map<string, string>): { dynamic: boolean; taintLabel: string } {
  if (!isAstNode(node)) return { dynamic: false, taintLabel: '' };
  const taint = findTaintInExpr(node, taintedVars);
  if (node.type === 'TemplateLiteral' && Array.isArray(node.expressions) && node.expressions.length > 0) {
    return { dynamic: true, taintLabel: taint.tainted ? taint.sourceLabel : 'Template Interpolation' };
  }
  if (node.type === 'BinaryExpression' && node.operator === '+') {
    return { dynamic: true, taintLabel: taint.tainted ? taint.sourceLabel : 'String Concatenation' };
  }
  if (node.type === 'Identifier' && taint.tainted) {
    return { dynamic: true, taintLabel: taint.sourceLabel };
  }
  return { dynamic: false, taintLabel: '' };
}

export function scanJsTsWithAst(
  file: CodeFile,
  rules: SastRule[],
  overrides?: Record<string, { status: FindingStatus; reviewerNotes: string; aiPatch?: Finding['aiPatch'] }>
): { parsed: boolean; findings: Finding[] } {
  if (file.language !== 'typescript' && file.language !== 'javascript') {
    return { parsed: false, findings: [] };
  }

  let ast: AstNode;
  try {
    ast = parse(file.content, {
      sourceType: 'unambiguous',
      plugins: ['typescript', 'jsx', 'decorators-legacy'],
      errorRecovery: false,
    }) as unknown as AstNode;
  } catch {
    return { parsed: false, findings: [] };
  }

  const ruleById = new Map(rules.filter((r) => r.enabled).map((r) => [r.id, r]));
  const lines = file.content.split(/\r?\n/);
  const taintedVars = new Map<string, string>();
  const findings: Finding[] = [];
  const emittedKeys = new Set<string>();

  const pushFinding = (ruleId: string, line: number, column: number, taintFlow: string) => {
    const rule = ruleById.get(ruleId);
    if (!rule || line < 1 || line > lines.length) return;
    const dedupKey = `${line}:${ruleId}`;
    if (emittedKeys.has(dedupKey)) return;
    emittedKeys.add(dedupKey);

    const findingId = `${file.path}:${line}:${rule.id}`;
    const override = overrides?.[findingId];
    findings.push({
      id: findingId,
      ruleId: rule.id,
      ruleName: rule.name,
      filePath: file.path,
      language: file.language,
      line,
      column: Math.max(1, column + 1),
      codeLine: lines[line - 1].trim(),
      contextBefore: lines.slice(Math.max(0, line - 3), line - 1),
      contextAfter: lines.slice(line, Math.min(lines.length, line + 2)),
      severity: rule.severity,
      cvssScore: rule.cvssScore,
      cweId: rule.cweId,
      owaspCategory: rule.owaspCategory,
      category: rule.category,
      description: rule.description,
      recommendation: rule.recommendation,
      remediationExample: rule.remediationExample,
      taintFlow,
      status: override?.status ?? 'open',
      source: 'sast',
      engine: 'AST',
      reviewerNotes: override?.reviewerNotes ?? '',
      ...(override?.aiPatch ? { aiPatch: override.aiPatch } : {}),
    });
  };

  const visit = (node: unknown) => {
    if (!node || typeof node !== 'object') return;
    if (Array.isArray(node)) {
      for (const item of node) visit(item);
      return;
    }
    if (!isAstNode(node)) return;

    // Track tainted variable declarations & assignments
    if (node.type === 'VariableDeclarator' && isAstNode(node.id) && typeof node.id.name === 'string' && node.init) {
      const taint = findTaintInExpr(node.init, taintedVars);
      if (taint.tainted) {
        taintedVars.set(node.id.name, taint.sourceLabel);
      }
    }

    if (node.type === 'AssignmentExpression') {
      const leftName = getMemberChain(node.left);
      if (leftName && /\.(?:innerHTML|outerHTML)$/i.test(leftName)) {
        const line = node.loc?.start.line ?? 1;
        const col = node.loc?.start.column ?? 0;
        const taint = findTaintInExpr(node.right, taintedVars);
        const taintFlow = taint.tainted
          ? `AST Taint (${taint.sourceLabel}) -> DOM XSS Sink (CWE-79)`
          : `AST DOM Assignment (${leftName}) -> XSS Sink (CWE-79)`;
        pushFinding('SAST-JS-005', line, col, taintFlow);
      } else if (isAstNode(node.left) && node.left.type === 'Identifier' && typeof node.left.name === 'string') {
        const taint = findTaintInExpr(node.right, taintedVars);
        if (taint.tainted) {
          taintedVars.set(node.left.name, taint.sourceLabel);
        }
      }
    }

    // JSX dangerouslySetInnerHTML={{ __html: ... }}
    if (node.type === 'JSXAttribute' && isAstNode(node.name) && node.name.name === 'dangerouslySetInnerHTML') {
      const line = node.loc?.start.line ?? 1;
      const col = node.loc?.start.column ?? 0;
      const taint = findTaintInExpr(node.value, taintedVars);
      pushFinding(
        'SAST-JS-005',
        line,
        col,
        taint.tainted
          ? `AST Taint (${taint.sourceLabel}) -> React dangerouslySetInnerHTML Sink (CWE-79)`
          : 'AST JSX Prop dangerouslySetInnerHTML -> XSS Sink (CWE-79)'
      );
    }

    // CallExpression sinks: SQL, child_process, eval, document.write
    if (node.type === 'CallExpression') {
      const calleeChain = getMemberChain(node.callee);
      const args = Array.isArray(node.arguments) ? node.arguments : [];
      const line = node.loc?.start.line ?? 1;
      const col = node.loc?.start.column ?? 0;

      // 1. SQL sinks
      if (/(?:^|\.)(?:query|execute|raw)$/i.test(calleeChain) && args.length > 0) {
        const sqlCheck = isDynamicSqlExpression(args[0], taintedVars);
        if (sqlCheck.dynamic) {
          pushFinding(
            'SAST-JS-001',
            line,
            col,
            `AST Taint (${sqlCheck.taintLabel}) -> SQL Sink ${calleeChain}() (CWE-89)`
          );
        }
      }

      // 2. child_process sinks (exec, execSync, spawn/execFile with shell: true)
      if (/^(?:child_process\.)?(?:exec|execSync)$/.test(calleeChain) && args.length > 0) {
        const arg0 = args[0];
        const taint = findTaintInExpr(arg0, taintedVars);
        const isDynamic =
          isAstNode(arg0) &&
          (arg0.type === 'TemplateLiteral' && Array.isArray(arg0.expressions) && arg0.expressions.length > 0 ||
            arg0.type === 'BinaryExpression' ||
            taint.tainted);
        if (isDynamic) {
          pushFinding(
            'SAST-JS-002',
            line,
            col,
            taint.tainted
              ? `AST Taint (${taint.sourceLabel}) -> Shell Sink ${calleeChain}() (CWE-78)`
              : `AST Dynamic Command -> Shell Sink ${calleeChain}() (CWE-78)`
          );
        }
      }

      if (/^(?:child_process\.)?(?:spawn|spawnSync|execFile|execFileSync)$/.test(calleeChain) && args.length > 1) {
        const hasShellTrue = args.some(
          (a) =>
            isAstNode(a) &&
            a.type === 'ObjectExpression' &&
            Array.isArray(a.properties) &&
            a.properties.some(
              (p) =>
                isAstNode(p) &&
                p.type === 'ObjectProperty' &&
                getMemberChain(p.key) === 'shell' &&
                isAstNode(p.value) &&
                p.value.type === 'BooleanLiteral' &&
                p.value.value === true
            )
        );
        if (hasShellTrue) {
          const taint = findTaintInExpr(args[0], taintedVars) || findTaintInExpr(args[1], taintedVars);
          pushFinding(
            'SAST-JS-002',
            line,
            col,
            taint.tainted
              ? `AST Taint (${taint.sourceLabel}) -> ${calleeChain}(shell: true) (CWE-78)`
              : `AST Shell Execution (${calleeChain} with shell: true) -> CWE-78`
          );
        }
      }

      // 3. eval(...)
      if (calleeChain === 'eval') {
        const taint = args[0] ? findTaintInExpr(args[0], taintedVars) : { tainted: false, sourceLabel: '' };
        pushFinding(
          'SAST-JS-009',
          line,
          col,
          taint.tainted
            ? `AST Taint (${taint.sourceLabel}) -> eval() Code Execution Sink (CWE-95)`
            : 'AST Direct eval() Call -> Code Injection Sink (CWE-95)'
        );
      }

      // 4. document.write(...)
      if (calleeChain === 'document.write' || calleeChain === 'document.writeln') {
        const taint = args[0] ? findTaintInExpr(args[0], taintedVars) : { tainted: false, sourceLabel: '' };
        pushFinding(
          'SAST-JS-005',
          line,
          col,
          taint.tainted
            ? `AST Taint (${taint.sourceLabel}) -> ${calleeChain}() XSS Sink (CWE-79)`
            : `AST ${calleeChain}() Call -> DOM XSS Sink (CWE-79)`
        );
      }
    }

    // new Function(...)
    if (node.type === 'NewExpression' && getMemberChain(node.callee) === 'Function') {
      const line = node.loc?.start.line ?? 1;
      const col = node.loc?.start.column ?? 0;
      const args = Array.isArray(node.arguments) ? node.arguments : [];
      const taintedArg = args.map((a) => findTaintInExpr(a, taintedVars)).find((t) => t.tainted);
      pushFinding(
        'SAST-JS-009',
        line,
        col,
        taintedArg
          ? `AST Taint (${taintedArg.sourceLabel}) -> new Function() Sink (CWE-95)`
          : 'AST new Function() Constructor -> Code Injection Sink (CWE-95)'
      );
    }

    for (const [k, v] of Object.entries(node)) {
      if (k === 'loc' || k === 'start' || k === 'end' || k === 'extra') continue;
      visit(v);
    }
  };

  visit(ast);
  return { parsed: true, findings };
}
