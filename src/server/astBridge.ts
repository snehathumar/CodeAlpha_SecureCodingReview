import { spawn } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import type { CodeFile, Finding } from '../types/audit.ts';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const PYTHON_AUDITOR_SCRIPT = path.resolve(__dirname, '../../server/python_ast_auditor.py');

interface PythonAstFindingRaw {
  ruleId: string;
  ruleName: string;
  category: string;
  owaspCategory: string;
  cweId: string;
  cvssScore: number;
  severity: Finding['severity'];
  line: number;
  column: number;
  codeLine: string;
  contextBefore: string[];
  contextAfter: string[];
  taintFlow: string;
  description: string;
  recommendation: string;
  remediationExample: {
    vulnerable: string;
    secure: string;
  };
}

interface PythonAstScriptOutput {
  ok: boolean;
  error?: string;
  findings: PythonAstFindingRaw[];
}

function runPythonAstProcess(source: string): Promise<{
  available: boolean;
  output?: PythonAstScriptOutput;
  reason?: string;
}> {
  return new Promise((resolve) => {
    let settled = false;
    const child = spawn('python3', [PYTHON_AUDITOR_SCRIPT], {
      stdio: ['pipe', 'pipe', 'pipe'],
    });

    let stdout = '';
    let stderr = '';
    const timer = setTimeout(() => {
      if (settled) return;
      settled = true;
      child.kill('SIGKILL');
      resolve({ available: false, reason: 'python3 AST process timed out' });
    }, 5000);

    child.stdout.on('data', (chunk: Buffer) => {
      stdout += chunk.toString('utf8');
    });
    child.stderr.on('data', (chunk: Buffer) => {
      stderr += chunk.toString('utf8');
    });

    child.on('error', (err: NodeJS.ErrnoException) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      const reason =
        err.code === 'ENOENT'
          ? 'python3 executable is not available in runtime'
          : err.message;
      resolve({ available: false, reason });
    });

    child.on('close', (code) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      if (code !== 0) {
        resolve({
          available: false,
          reason: stderr.trim() || `python3 exited with code ${code}`,
        });
        return;
      }
      try {
        const parsed = JSON.parse(stdout) as PythonAstScriptOutput;
        resolve({ available: true, output: parsed });
      } catch {
        resolve({ available: false, reason: 'Invalid JSON returned by python_ast_auditor.py' });
      }
    });

    child.stdin.write(source);
    child.stdin.end();
  });
}

export async function runPythonAstAuditOnFiles(
  files: CodeFile[],
  disabledRuleIds: string[] = []
): Promise<{
  pythonAstAvailable: boolean;
  fallbackNotice: string | null;
  findings: Finding[];
}> {
  const pythonFiles = files.filter((f) => f.language === 'python');
  if (pythonFiles.length === 0) {
    return { pythonAstAvailable: true, fallbackNotice: null, findings: [] };
  }

  const disabledSet = new Set(disabledRuleIds);
  const allFindings: Finding[] = [];
  let pythonAvailable = true;
  let fallbackReason: string | null = null;

  for (const file of pythonFiles) {
    const res = await runPythonAstProcess(file.content);
    if (!res.available) {
      pythonAvailable = false;
      fallbackReason = res.reason ?? 'python3 unavailable';
      break;
    }
    if (!res.output?.ok) {
      // Syntax error in a specific Python file falls back to regex for that file
      continue;
    }
    for (const raw of res.output.findings) {
      if (disabledSet.has(raw.ruleId)) continue;
      allFindings.push({
        id: `${file.path}:${raw.line}:${raw.ruleId}`,
        ruleId: raw.ruleId,
        ruleName: raw.ruleName,
        filePath: file.path,
        language: 'python',
        line: raw.line,
        column: raw.column,
        codeLine: raw.codeLine,
        contextBefore: raw.contextBefore,
        contextAfter: raw.contextAfter,
        severity: raw.severity,
        cvssScore: raw.cvssScore,
        cweId: raw.cweId,
        owaspCategory: raw.owaspCategory,
        category: raw.category,
        description: raw.description,
        recommendation: raw.recommendation,
        remediationExample: raw.remediationExample,
        taintFlow: raw.taintFlow,
        status: 'open',
        source: 'sast',
        engine: 'AST',
        reviewerNotes: '',
      });
    }
  }

  return {
    pythonAstAvailable: pythonAvailable,
    fallbackNotice: pythonAvailable
      ? null
      : `Python AST scanner unavailable (${fallbackReason}); falling back to Regex rules for .py files.`,
    findings: allFindings,
  };
}
