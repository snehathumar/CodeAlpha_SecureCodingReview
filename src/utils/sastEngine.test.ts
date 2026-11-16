import test from 'node:test';
import assert from 'node:assert/strict';
import {
  applyLinePatch,
  computeSecurityMetrics,
  generateMarkdownReport,
  generateSarifReport,
  scanFile,
  scanTarget,
  stripUndefined,
} from './sastEngine';
import { DEFAULT_SAST_RULES } from './sastRules';
import { calculateShannonEntropy, scanFileEntropySecrets } from './secretEntropy';
import { extractDependenciesFromFiles } from './manifestParser';
import { parseGithubRepoSlug } from '../server/projectImporter';
import type { AuditTarget, SastRule } from '../types/audit';

const PYTHON_TEST_TARGET: AuditTarget = {
  id: 'py-test-service',
  name: 'Python Billing Service',
  stack: 'Python 3.12 · Flask',
  description: 'Test target for deterministic Python SAST scanning.',
  files: [
    {
      path: 'app.py',
      language: 'python',
      content: [
        'import hashlib, os, pickle, subprocess, jwt, requests',
        'JWT_SECRET = "hardcoded-test-signing-key-9911"',
        'def handler(email, filename, raw_cookie, token):',
        '    cursor.execute(f"SELECT * FROM users WHERE email = \'{email}\'")',
        '    subprocess.run(f"convert {filename} out.png", shell=True)',
        '    data = pickle.loads(raw_cookie)',
        '    digest = hashlib.md5(email.encode()).hexdigest()',
        '    claims = jwt.decode(token, options={"verify_signature": False})',
        '    requests.post("https://hooks.internal/cb", json=data, verify=False)',
        '    parsed = eval(email)',
        'app.run(host="0.0.0.0", port=5000, debug=True)',
      ].join('\n'),
    },
  ],
};

const TS_TEST_TARGET: AuditTarget = {
  id: 'ts-test-service',
  name: 'TypeScript Express API',
  stack: 'Node.js · Express',
  description: 'Test target for TypeScript SAST scanning and taint flow.',
  files: [
    {
      path: 'routes/orders.ts',
      language: 'typescript',
      content: [
        'app.use(cors({ origin: "*", credentials: true }));',
        'async function lookup(req, res, db, fs, path) {',
        '  await db.query(`SELECT * FROM orders WHERE id = ${req.params.id}`);',
        '  const out = execSync(`wkhtmltopdf ${req.query.url}`);',
        '  const filePath = path.join(BASE_DIR, req.query.file);',
        '  const data = fs.readFileSync(filePath);',
        '  previewEl.innerHTML = `<div>${req.body.note}</div>`;',
        '  Object.assign(settings, req.body);',
        '  res.send(out + data);',
        '}',
      ].join('\n'),
    },
  ],
};

const GO_TEST_TARGET: AuditTarget = {
  id: 'go-test-service',
  name: 'Go Auth Service',
  stack: 'Go 1.23',
  description: 'Test target for Go SAST scanning.',
  files: [
    {
      path: 'main.go',
      language: 'go',
      content: [
        'package main',
        'import ("fmt"; "math/rand"; "net/http"; "crypto/tls")',
        'const ADMIN_SECRET = "go-admin-static-token-value-7712"',
        'func check(db *sql.DB, username string) {',
        '  db.QueryRow(fmt.Sprintf("SELECT id FROM accounts WHERE user = \'%s\'", username))',
        '  token := fmt.Sprintf("%d", rand.Int63())',
        '  tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}',
        '  _, _ = token, tr',
        '}',
      ].join('\n'),
    },
  ],
};

test('scans Python code for SQLi, Command Injection, Pickle, Hardcoded Secret, Debug mode, and Python eval', () => {
  const findings = scanTarget(PYTHON_TEST_TARGET, DEFAULT_SAST_RULES);
  const cwes = new Set(findings.map((f) => f.cweId));

  assert.ok(cwes.has('CWE-89'), 'Must detect SQL Injection (CWE-89)');
  assert.ok(cwes.has('CWE-78'), 'Must detect Command Injection (CWE-78)');
  assert.ok(cwes.has('CWE-502'), 'Must detect Pickle Deserialization (CWE-502)');
  assert.ok(cwes.has('CWE-798'), 'Must detect Hardcoded Secret (CWE-798)');
  assert.ok(cwes.has('CWE-328'), 'Must detect Weak MD5 Hash (CWE-328)');
  assert.ok(cwes.has('CWE-295'), 'Must detect TLS verify=False (CWE-295)');
  assert.ok(cwes.has('CWE-347'), 'Must detect unverified JWT (CWE-347)');
  assert.ok(cwes.has('CWE-489'), 'Must detect Flask debug=True (CWE-489)');
  assert.ok(cwes.has('CWE-95'), 'Must detect Python eval() (CWE-95)');

  const pyEval = findings.find((f) => f.cweId === 'CWE-95');
  assert.equal(pyEval?.ruleId, 'SAST-PY-005');
  assert.ok(pyEval?.remediationExample.secure.includes('ast.literal_eval'));
});

test('scans TypeScript Express code for SQLi, Command Injection, Path Traversal, XSS, Prototype Pollution, CORS', () => {
  const findings = scanTarget(TS_TEST_TARGET, DEFAULT_SAST_RULES);
  const cwes = new Set(findings.map((f) => f.cweId));

  assert.ok(cwes.has('CWE-89'), 'Must detect TS template SQLi');
  assert.ok(cwes.has('CWE-78'), 'Must detect execSync Command Injection');
  assert.ok(cwes.has('CWE-22'), 'Must detect Path Traversal');
  assert.ok(cwes.has('CWE-79'), 'Must detect innerHTML XSS');
  assert.ok(cwes.has('CWE-1321'), 'Must detect Prototype Pollution');
  assert.ok(cwes.has('CWE-942'), 'Must detect Permissive CORS');

  const jsxXss = scanFile(
    {
      path: 'Card.tsx',
      language: 'typescript',
      content: 'const a = <div dangerouslySetInnerHTML={{ __html: userInput }} />;\nconst b = <input placeholder="e.g. dangerouslySetInnerHTML" />;\n',
    },
    DEFAULT_SAST_RULES
  );
  assert.equal(jsxXss.length, 1);
  assert.equal(jsxXss[0].line, 1);
});

test('scans Go code for SQLi, math/rand PRNG, TLS SkipVerify, and Hardcoded Secret', () => {
  const findings = scanTarget(GO_TEST_TARGET, DEFAULT_SAST_RULES);
  const cwes = new Set(findings.map((f) => f.cweId));

  assert.ok(cwes.has('CWE-89'), 'Must detect Go SQLi');
  assert.ok(cwes.has('CWE-338'), 'Must detect Go math/rand');
  assert.ok(cwes.has('CWE-295'), 'Must detect InsecureSkipVerify');
  assert.ok(cwes.has('CWE-798'), 'Must detect hardcoded ADMIN_SECRET');
});

test('ignores comment-only lines during static scanning', () => {
  const findings = scanFile(
    {
      path: 'clean.py',
      language: 'python',
      content: `# cursor.execute(f"SELECT * FROM users WHERE id = {uid}")\nprint("safe")\n`,
    },
    DEFAULT_SAST_RULES
  );
  assert.equal(findings.length, 0);
});

test('computeSecurityMetrics recalculates risk score and posture grade on triage', () => {
  const findings = scanTarget(PYTHON_TEST_TARGET, DEFAULT_SAST_RULES);
  const initialMetrics = computeSecurityMetrics(findings);
  assert.equal(initialMetrics.securityPostureGrade, 'F');
  assert.ok(initialMetrics.riskScore > 75);

  const remediatedAll = findings.map((f) => ({ ...f, status: 'remediated' as const }));
  const cleanMetrics = computeSecurityMetrics(remediatedAll);
  assert.equal(cleanMetrics.riskScore, 0);
  assert.equal(cleanMetrics.securityPostureGrade, 'A');
  assert.equal(cleanMetrics.remediatedFindings, findings.length);
});

test('supports custom SAST rules and live patch application', () => {
  const customRule: SastRule = {
    id: 'CUSTOM-001',
    name: 'Forbidden Debug Print',
    category: 'Information Exposure',
    owaspCategory: 'A05:2021 Security Misconfiguration',
    cweId: 'CWE-209',
    cvssScore: 4.3,
    severity: 'medium',
    languages: ['python'],
    patternSource: String.raw`print\s*\(\s*secret`,
    flags: '',
    description: 'Printing secret variables leaks credentials to logs.',
    recommendation: 'Remove print statements referencing secrets.',
    remediationExample: {
      vulnerable: 'print(secret_token)',
      secure: 'logger.info("Token rotated")',
    },
    enabled: true,
    isCustom: true,
  };

  const code = 'def run():\n    print(secret_token)\n';
  const findings = scanFile({ path: 'debug.py', language: 'python', content: code }, [customRule]);
  assert.equal(findings.length, 1);
  assert.equal(findings[0].line, 2);

  const patched = applyLinePatch(code, 2, 'logger.info("Token rotated")');
  assert.equal(patched, 'def run():\n    logger.info("Token rotated")\n');
});

test('generates valid Markdown and SARIF 2.1.0 audit reports and strips undefined fields', () => {
  const findings = scanTarget(GO_TEST_TARGET, DEFAULT_SAST_RULES);

  const md = generateMarkdownReport(GO_TEST_TARGET, findings);
  assert.ok(md.includes('# Secure Coding Review Report: Go Auth Service'));
  assert.ok(md.includes('CWE-89'));

  const sarif = generateSarifReport(GO_TEST_TARGET, findings) as { version: string; runs: Array<{ results: unknown[] }> };
  assert.equal(sarif.version, '2.1.0');
  assert.ok(sarif.runs[0].results.length > 0);

  const cleaned = stripUndefined({ a: 1, b: undefined, nested: { c: undefined, d: 'ok' } }) as Record<string, unknown>;
  assert.equal('b' in cleaned, false);
  assert.deepEqual(cleaned.nested, { d: 'ok' });
});

test('detects high-entropy secret tokens and avoids RegExp.exec false positives', () => {
  const highEntropy = calculateShannonEntropy('x9K2mPq8ZrT4wL7vN1bC6yF3hJ5dG0sA');
  assert.ok(highEntropy > 4.2);

  const findings = scanFileEntropySecrets({
    path: 'config.ts',
    language: 'typescript',
    content: 'const serviceToken = "x9K2mPq8ZrT4wL7vN1bC6yF3hJ5dG0sA";\n',
  });
  assert.equal(findings.length, 1);
  assert.equal(findings[0].cweId, 'CWE-798');

  const regexExecFindings = scanFile(
    {
      path: 'parser.ts',
      language: 'typescript',
      content: 'const m = /hello/.exec("hello world");\n',
    },
    DEFAULT_SAST_RULES
  );
  assert.equal(regexExecFindings.length, 0);
});

test('extracts npm, PyPI, and Go dependencies from manifests and parses GitHub slugs', () => {
  const deps = extractDependenciesFromFiles([
    {
      path: 'package.json',
      language: 'json',
      content: JSON.stringify({
        dependencies: { express: '^4.21.2', lodash: '4.17.20' },
      }),
    },
    {
      path: 'requirements.txt',
      language: 'text',
      content: 'flask==2.0.1\nrequests>=2.31.0\n# comment\n',
    },
    {
      path: 'go.mod',
      language: 'text',
      content: 'module example.com/app\nrequire (\n\tgithub.com/gin-gonic/gin v1.9.1\n)\n',
    },
  ]);

  assert.equal(deps.length, 5);
  assert.deepEqual(deps[0], {
    name: 'express',
    version: '4.21.2',
    ecosystem: 'npm',
    manifestPath: 'package.json',
  });
  assert.deepEqual(deps[2], {
    name: 'flask',
    version: '2.0.1',
    ecosystem: 'PyPI',
    manifestPath: 'requirements.txt',
  });
  assert.deepEqual(deps[4], {
    name: 'github.com/gin-gonic/gin',
    version: '1.9.1',
    ecosystem: 'Go',
    manifestPath: 'go.mod',
  });

  assert.deepEqual(parseGithubRepoSlug('https://github.com/pallets/flask'), {
    owner: 'pallets',
    repo: 'flask',
  });
  assert.deepEqual(parseGithubRepoSlug('expressjs/express'), {
    owner: 'expressjs',
    repo: 'express',
  });
  assert.equal(parseGithubRepoSlug('https://evil.example.com/a/b'), null);
});
