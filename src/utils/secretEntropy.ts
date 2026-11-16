import type { CodeFile, Finding, FindingStatus } from '../types/audit.ts';

export function calculateShannonEntropy(value: string): number {
  if (!value) return 0;
  const freq = new Map<string, number>();
  for (const ch of value) {
    freq.set(ch, (freq.get(ch) ?? 0) + 1);
  }
  let entropy = 0;
  const len = value.length;
  for (const count of freq.values()) {
    const p = count / len;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

function isLikelyBenignLiteral(literal: string): boolean {
  if (literal.length < 20) return true;
  if (/^https?:\/\//i.test(literal)) return true;
  if (/^(\/|\.\.?\/|[a-zA-Z]:\\)/.test(literal)) return true;
  if (/\s/.test(literal)) return true;
  if (/^[a-z0-9._-]+@[a-z0-9.-]+\.[a-z]{2,}$/i.test(literal)) return true;
  if (/^(?:[a-z-]+:)?[a-z0-9_-]+(?:-[a-z0-9_-]+){3,}$/i.test(literal)) return true;
  return false;
}

const KNOWN_PREFIX_RE = /^(?:ghp_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|glpat-[A-Za-z0-9_-]{18,}|xox[baprs]-[A-Za-z0-9-]{10,}|sk-[A-Za-z0-9]{20,}|AIza[0-9A-Za-z\-_]{20,}|AKIA[0-9A-Z]{16})$/;
const CREDENTIAL_CONTEXT_RE = /(?:secret|token|api_?key|passwd|password|private_?key|auth_?key|access_?key|bearer|signing_?key|credential)/i;
const PEM_KEY_RE = /-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/;

export function scanFileEntropySecrets(
  file: CodeFile,
  overrides?: Record<string, { status: FindingStatus; reviewerNotes: string; aiPatch?: Finding['aiPatch'] }>,
  existingFindingLines?: Set<number>
): Finding[] {
  if (file.language === 'json' || file.language === 'text') return [];

  const lines = file.content.split(/\r?\n/);
  const findings: Finding[] = [];

  for (let idx = 0; idx < lines.length; idx++) {
    const lineNumber = idx + 1;
    if (existingFindingLines?.has(lineNumber)) continue;

    const rawLine = lines[idx];
    const trimmed = rawLine.trim();
    if (!trimmed || trimmed.startsWith('//') || trimmed.startsWith('#')) continue;

    if (PEM_KEY_RE.test(trimmed)) {
      const findingId = `${file.path}:${lineNumber}:ENTROPY-PEM-001`;
      const override = overrides?.[findingId];
      findings.push({
        id: findingId,
        ruleId: 'ENTROPY-PEM-001',
        ruleName: 'Embedded Private Cryptographic Key Material',
        filePath: file.path,
        language: file.language,
        line: lineNumber,
        column: 1,
        codeLine: trimmed,
        contextBefore: lines.slice(Math.max(0, idx - 2), idx),
        contextAfter: lines.slice(idx + 1, Math.min(lines.length, idx + 3)),
        severity: 'critical',
        cvssScore: 9.4,
        cweId: 'CWE-798',
        owaspCategory: 'A07:2021 Identification and Authentication Failures',
        category: 'Secrets Management',
        description: 'PEM-encoded private key material is committed directly inside source code.',
        recommendation: 'Remove private keys from source control and mount them at runtime from Secret Manager or KMS.',
        remediationExample: {
          vulnerable: trimmed,
          secure: 'const PRIVATE_KEY = process.env.SERVICE_PRIVATE_KEY ?? "";',
        },
        taintFlow: 'Hardcoded Private Key Block -> Repository Exposure (CWE-798)',
        status: override?.status ?? 'open',
        source: 'entropy',
        reviewerNotes: override?.reviewerNotes ?? '',
        ...(override?.aiPatch ? { aiPatch: override.aiPatch } : {}),
      });
      continue;
    }

    const stringMatches = rawLine.matchAll(/["'`]([^"'`\r\n]{16,120})["'`]/g);
    for (const match of stringMatches) {
      const literal = match[1];
      if (!literal) continue;

      const isKnownToken = KNOWN_PREFIX_RE.test(literal);
      const entropy = calculateShannonEntropy(literal);
      const hasCredentialContext = CREDENTIAL_CONTEXT_RE.test(rawLine);

      if (isKnownToken || (hasCredentialContext && !isLikelyBenignLiteral(literal) && entropy >= 3.85)) {
        const findingId = `${file.path}:${lineNumber}:ENTROPY-SEC-001`;
        const override = overrides?.[findingId];
        findings.push({
          id: findingId,
          ruleId: 'ENTROPY-SEC-001',
          ruleName: `High-Entropy Secret Literal (${entropy.toFixed(2)} bits/char)`,
          filePath: file.path,
          language: file.language,
          line: lineNumber,
          column: (match.index ?? 0) + 1,
          codeLine: trimmed,
          contextBefore: lines.slice(Math.max(0, idx - 2), idx),
          contextAfter: lines.slice(idx + 1, Math.min(lines.length, idx + 3)),
          severity: isKnownToken ? 'critical' : 'high',
          cvssScore: isKnownToken ? 9.1 : 8.2,
          cweId: 'CWE-798',
          owaspCategory: 'A07:2021 Identification and Authentication Failures',
          category: 'Secrets Management',
          description: `Detected a high-entropy string literal (${entropy.toFixed(2)} bits/char) in credential context, indicating a hardcoded API key, signing secret, or password.`,
          recommendation: 'Revoke and rotate the credential immediately, then inject it via environment variables or Secret Manager.',
          remediationExample: {
            vulnerable: trimmed,
            secure: 'const secretValue = process.env.SECRET_VALUE ?? "";',
          },
          taintFlow: `High-Entropy Literal (${entropy.toFixed(2)} bits/char) -> Static Secret Exposure (CWE-798)`,
          status: override?.status ?? 'open',
          source: 'entropy',
          reviewerNotes: override?.reviewerNotes ?? '',
          ...(override?.aiPatch ? { aiPatch: override.aiPatch } : {}),
        });
        break;
      }
    }
  }

  return findings;
}
