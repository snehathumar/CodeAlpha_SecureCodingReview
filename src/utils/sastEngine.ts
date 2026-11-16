import type {
  AuditMetrics,
  AuditTarget,
  CodeFile,
  DependencyVulnerability,
  Finding,
  FindingStatus,
  SastRule,
  Severity,
} from '../types/audit';
import { scanFileEntropySecrets } from './secretEntropy';
import { scanJsTsWithAst } from './jsAstAnalyzer';

const SEVERITY_WEIGHTS: Record<Severity, number> = {
  critical: 24,
  high: 14,
  medium: 6,
  low: 2,
};

function isCommentOnlyLine(line: string, language: CodeFile['language']): boolean {
  const trimmed = line.trim();
  if (!trimmed) return true;
  if (language === 'python') {
    return trimmed.startsWith('#');
  }
  if (language === 'php') {
    return trimmed.startsWith('#') || trimmed.startsWith('//') || trimmed.startsWith('/*') || trimmed.startsWith('*');
  }
  if (language === 'sql') {
    return trimmed.startsWith('--') || trimmed.startsWith('/*');
  }
  return trimmed.startsWith('//') || trimmed.startsWith('/*') || trimmed.startsWith('*');
}

function extractAssignedTaintedVar(line: string, taintedVars: Set<string>): string | null {
  const assignMatch = /^(?:const|let|var)?\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*(?::[^=]+)?=\s*(.+)$/.exec(line.trim());
  if (!assignMatch) return null;
  const [, varName, rhs] = assignMatch;
  const hasDirectSource = /(?:req\.(?:body|query|params|headers)|request\.(?:args|form|json|data|headers)|os\.environ|getenv)/i.test(rhs);
  const propagatesTaint = Array.from(taintedVars).some((tv) => new RegExp(`\\b${tv}\\b`).test(rhs));
  return hasDirectSource || propagatesTaint ? varName : null;
}

function inferTaintFlow(line: string, rule: SastRule, taintedVars: Set<string>): string {
  const trimmed = line.trim();
  if (/req\.(body|query|params|headers)|request\.(args|form|json|data|headers)/i.test(trimmed)) {
    return `HTTP Request Input -> ${rule.category} Sink (${rule.cweId})`;
  }
  const matchedVar = Array.from(taintedVars).find((tv) => new RegExp(`\\b${tv}\\b`).test(trimmed));
  if (matchedVar) {
    return `Tainted Variable (${matchedVar}) -> ${rule.category} Sink (${rule.cweId})`;
  }
  if (/os\.environ|getenv|process\.env/i.test(trimmed)) {
    return `Environment Config -> ${rule.category} Sink (${rule.cweId})`;
  }
  if (/cookie|token|jwt|session|raw_/i.test(trimmed)) {
    return `Untrusted Token/Payload -> ${rule.category} Sink (${rule.cweId})`;
  }
  return `Direct Source Literal / Variable -> ${rule.category} Sink (${rule.cweId})`;
}

export function compileRuleRegex(rule: SastRule): RegExp | null {
  try {
    const cleanFlags = rule.flags.replace(/g/g, '');
    return new RegExp(rule.patternSource, cleanFlags);
  } catch {
    return null;
  }
}

export function scanFile(
  file: CodeFile,
  rules: SastRule[],
  overrides?: Record<string, { status: FindingStatus; reviewerNotes: string; aiPatch?: Finding['aiPatch'] }>
): Finding[] {
  const lines = file.content.split(/\r?\n/);
  const activeRules = rules.filter(
    (rule) => rule.enabled && rule.languages.includes(file.language)
  );

  // 1. Run @babel/parser AST analysis for JavaScript / TypeScript files (falls back to regex if parse fails)
  const astResult =
    file.language === 'typescript' || file.language === 'javascript'
      ? scanJsTsWithAst(file, rules, overrides)
      : { parsed: false, findings: [] };

  const astCoveredKeys = new Set(
    astResult.findings.map((f) => `${f.line}:${f.cweId}`)
  );

  const regexFindings: Finding[] = [];
  const taintedVars = new Set<string>();

  for (let idx = 0; idx < lines.length; idx++) {
    const rawLine = lines[idx];
    if (isCommentOnlyLine(rawLine, file.language)) continue;

    const newTainted = extractAssignedTaintedVar(rawLine, taintedVars);
    if (newTainted) taintedVars.add(newTainted);

    for (const rule of activeRules) {
      const lineNumber = idx + 1;
      if (astCoveredKeys.has(`${lineNumber}:${rule.cweId}`)) continue;

      const regex = compileRuleRegex(rule);
      if (!regex) continue;
      const match = regex.exec(rawLine);
      if (!match) continue;

      const column = (match.index ?? 0) + 1;
      const findingId = `${file.path}:${lineNumber}:${rule.id}`;
      const override = overrides?.[findingId];

      regexFindings.push({
        id: findingId,
        ruleId: rule.id,
        ruleName: rule.name,
        filePath: file.path,
        language: file.language,
        line: lineNumber,
        column,
        codeLine: rawLine.trim(),
        contextBefore: lines.slice(Math.max(0, idx - 2), idx),
        contextAfter: lines.slice(idx + 1, Math.min(lines.length, idx + 3)),
        severity: rule.severity,
        cvssScore: rule.cvssScore,
        cweId: rule.cweId,
        owaspCategory: rule.owaspCategory,
        category: rule.category,
        description: rule.description,
        recommendation: rule.recommendation,
        remediationExample: rule.remediationExample,
        taintFlow: inferTaintFlow(rawLine, rule, taintedVars),
        status: override?.status ?? 'open',
        source: 'sast',
        engine: 'Regex',
        reviewerNotes: override?.reviewerNotes ?? '',
        ...(override?.aiPatch ? { aiPatch: override.aiPatch } : {}),
      });
    }
  }

  const secretRuleLines = new Set(
    [...astResult.findings, ...regexFindings]
      .filter((f) => f.cweId === 'CWE-798')
      .map((f) => f.line)
  );
  const entropyFindings = scanFileEntropySecrets(file, overrides, secretRuleLines);
  const merged = [...astResult.findings, ...regexFindings, ...entropyFindings];

  return merged.sort((a, b) => b.cvssScore - a.cvssScore || a.line - b.line);
}

export function scanTarget(
  target: AuditTarget,
  rules: SastRule[],
  overrides?: Record<string, { status: FindingStatus; reviewerNotes: string; aiPatch?: Finding['aiPatch'] }>
): Finding[] {
  const allFindings = target.files.flatMap((file) => scanFile(file, rules, overrides));
  return allFindings.sort((a, b) => b.cvssScore - a.cvssScore || a.filePath.localeCompare(b.filePath));
}

export function mergeAstFindings(
  baseFindings: Finding[],
  astFindings: Finding[],
  overrides?: Record<string, { status: FindingStatus; reviewerNotes: string; aiPatch?: Finding['aiPatch'] }>
): Finding[] {
  if (astFindings.length === 0) return baseFindings;
  const astKeys = new Set(astFindings.map((f) => `${f.filePath}:${f.line}:${f.cweId}`));
  const filteredBase = baseFindings.filter(
    (f) => f.engine === 'AST' || !astKeys.has(`${f.filePath}:${f.line}:${f.cweId}`)
  );
  const hydratedAst = astFindings.map((f) => {
    const ov = overrides?.[f.id];
    if (!ov) return f;
    return {
      ...f,
      status: ov.status,
      reviewerNotes: ov.reviewerNotes,
      ...(ov.aiPatch ? { aiPatch: ov.aiPatch } : {}),
    };
  });
  return [...hydratedAst, ...filteredBase].sort(
    (a, b) => b.cvssScore - a.cvssScore || a.filePath.localeCompare(b.filePath) || a.line - b.line
  );
}

export function computeSecurityMetrics(findings: Finding[]): AuditMetrics {
  const severityCounts: Record<Severity, number> = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
  };

  let openFindings = 0;
  let confirmedFindings = 0;
  let remediatedFindings = 0;
  let falsePositiveFindings = 0;
  let rawPenalty = 0;

  const owaspMap = new Map<string, { count: number; openCount: number }>();
  const cweMap = new Map<string, number>();

  for (const f of findings) {
    const isActive = f.status === 'open' || f.status === 'confirmed';

    if (f.status === 'open') openFindings++;
    else if (f.status === 'confirmed') confirmedFindings++;
    else if (f.status === 'remediated') remediatedFindings++;
    else if (f.status === 'false_positive') falsePositiveFindings++;

    if (isActive) {
      severityCounts[f.severity]++;
      rawPenalty += SEVERITY_WEIGHTS[f.severity];
    }

    const existingOwasp = owaspMap.get(f.owaspCategory) ?? { count: 0, openCount: 0 };
    existingOwasp.count += 1;
    if (isActive) existingOwasp.openCount += 1;
    owaspMap.set(f.owaspCategory, existingOwasp);

    if (isActive) {
      cweMap.set(f.cweId, (cweMap.get(f.cweId) ?? 0) + 1);
    }
  }

  const riskScore = Math.min(100, rawPenalty);
  let securityPostureGrade: AuditMetrics['securityPostureGrade'] = 'A';
  if (riskScore >= 75) securityPostureGrade = 'F';
  else if (riskScore >= 50) securityPostureGrade = 'D';
  else if (riskScore >= 25) securityPostureGrade = 'C';
  else if (riskScore >= 10) securityPostureGrade = 'B';

  const owaspBreakdown = Array.from(owaspMap.entries())
    .map(([category, stats]) => ({ category, ...stats }))
    .sort((a, b) => b.openCount - a.openCount || b.count - a.count);

  const topCwes = Array.from(cweMap.entries())
    .map(([cweId, count]) => ({ cweId, count }))
    .sort((a, b) => b.count - a.count);

  return {
    totalFindings: findings.length,
    openFindings,
    confirmedFindings,
    remediatedFindings,
    falsePositiveFindings,
    riskScore,
    securityPostureGrade,
    severityCounts,
    owaspBreakdown,
    topCwes,
  };
}

export function applyLinePatch(
  sourceCode: string,
  lineNumber: number,
  replacementSnippet: string
): string {
  const lines = sourceCode.split(/\r?\n/);
  if (lineNumber < 1 || lineNumber > lines.length) {
    return sourceCode;
  }
  const existingIndent = lines[lineNumber - 1].match(/^(\s*)/)?.[1] ?? '';
  const patchedLines = replacementSnippet
    .split(/\r?\n/)
    .map((line, index) => (index === 0 ? `${existingIndent}${line.trimStart()}` : `${existingIndent}${line}`));

  const updated = [
    ...lines.slice(0, lineNumber - 1),
    ...patchedLines,
    ...lines.slice(lineNumber),
  ];
  return updated.join('\n');
}

export function stripUndefined<T>(value: T): T {
  return JSON.parse(JSON.stringify(value)) as T;
}

export function generateMarkdownReport(
  target: AuditTarget,
  findings: Finding[],
  dependencyVulns: DependencyVulnerability[] = []
): string {
  const metrics = computeSecurityMetrics(findings);
  const dateStr = new Date().toISOString().split('T')[0];

  const lines: string[] = [
    `# Secure Coding Review Report: ${target.name}`,
    '',
    `**Audit Date:** ${dateStr}  `,
    `**Application Stack:** ${target.stack}  `,
    `**Security Posture Grade:** ${metrics.securityPostureGrade} (Residual Risk Index: ${metrics.riskScore}/100)  `,
    `**Findings Summary:** ${metrics.totalFindings} code findings (${metrics.openFindings + metrics.confirmedFindings} active, ${metrics.remediatedFindings} remediated, ${metrics.falsePositiveFindings} false positive) · ${dependencyVulns.length} dependency CVEs`,
    '',
    '## 1. Executive Summary',
    '',
    target.description,
    '',
    '| Severity | Active Count |',
    '| --- | ---: |',
    `| Critical | ${metrics.severityCounts.critical} |`,
    `| High | ${metrics.severityCounts.high} |`,
    `| Medium | ${metrics.severityCounts.medium} |`,
    `| Low | ${metrics.severityCounts.low} |`,
    '',
    '## 2. OWASP Top 10 Coverage',
    '',
    '| OWASP Category | Total Findings | Active Findings |',
    '| --- | ---: | ---: |',
    ...metrics.owaspBreakdown.map(
      (row) => `| ${row.category} | ${row.count} | ${row.openCount} |`
    ),
    '',
    '## 3. Detailed Security Findings & Remediation Steps',
    '',
  ];

  findings.forEach((f, idx) => {
    lines.push(`### ${idx + 1}. [${f.severity.toUpperCase()}] ${f.ruleName} (${f.cweId})`);
    lines.push('');
    lines.push(`- **Location:** \`${f.filePath}:${f.line}\``);
    lines.push(`- **Analysis Engine:** ${f.engine}`);
    lines.push(`- **Status:** ${f.status}`);
    lines.push(`- **CVSS 3.1 Score:** ${f.cvssScore.toFixed(1)}`);
    lines.push(`- **OWASP Category:** ${f.owaspCategory}`);
    lines.push(`- **Taint Flow:** ${f.taintFlow}`);
    lines.push('');
    lines.push(`**Risk Analysis:** ${f.description}`);
    lines.push('');
    lines.push('**Vulnerable Code:**');
    lines.push('```');
    lines.push(f.codeLine);
    lines.push('```');
    lines.push('');
    lines.push(`**Remediation Recommendation:** ${f.recommendation}`);
    lines.push('');
    lines.push('**Secure Implementation Pattern:**');
    lines.push('```');
    lines.push(f.aiPatch?.patchedSnippet ?? f.remediationExample.secure);
    lines.push('```');
    if (f.reviewerNotes.trim()) {
      lines.push('');
      lines.push(`**Auditor Notes:** ${f.reviewerNotes.trim()}`);
    }
    lines.push('');
  });

  if (dependencyVulns.length > 0) {
    lines.push('## 4. Supply-Chain Dependency Advisories (OSV.dev)');
    lines.push('');
    lines.push('| Package | Installed | Advisory | Severity | Fixed Version |');
    lines.push('| --- | --- | --- | --- | --- |');
    for (const dep of dependencyVulns) {
      lines.push(
        `| ${dep.packageName} (${dep.ecosystem}) | ${dep.installedVersion} | ${dep.advisoryId} | ${dep.severity.toUpperCase()} | ${dep.fixedVersion ?? 'Check advisory'} |`
      );
    }
    lines.push('');
  }

  return lines.join('\n');
}

export function generateSarifReport(target: AuditTarget, findings: Finding[]): Record<string, unknown> {
  const uniqueRules = new Map<string, Finding>();
  for (const f of findings) {
    if (!uniqueRules.has(f.ruleId)) uniqueRules.set(f.ruleId, f);
  }

  return {
    $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: 'Aegis Code Audit SAST',
            informationUri: 'https://owasp.org/Top10/',
            rules: Array.from(uniqueRules.values()).map((f) => ({
              id: f.ruleId,
              name: f.ruleName,
              shortDescription: { text: f.ruleName },
              fullDescription: { text: f.description },
              help: { text: f.recommendation },
              properties: {
                cwe: f.cweId,
                owasp: f.owaspCategory,
                'security-severity': String(f.cvssScore),
              },
            })),
          },
        },
        results: findings
          .filter((f) => f.status !== 'false_positive')
          .map((f) => ({
            ruleId: f.ruleId,
            level: f.severity === 'critical' || f.severity === 'high' ? 'error' : f.severity === 'medium' ? 'warning' : 'note',
            message: {
              text: `${f.description} Recommendation: ${f.recommendation}`,
            },
            locations: [
              {
                physicalLocation: {
                  artifactLocation: { uri: f.filePath },
                  region: {
                    startLine: f.line,
                    startColumn: f.column,
                  },
                },
              },
            ],
            properties: {
              status: f.status,
              engine: f.engine,
              taintFlow: f.taintFlow,
            },
          })),
      },
    ],
  };
}
