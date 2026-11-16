import 'dotenv/config';
import express from 'express';
import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  generateFindingRemediation,
  runDeepSecurityReview,
} from './src/server/geminiService.ts';
import { scanDependenciesWithOsv } from './src/server/osvService.ts';
import { runPythonAstAuditOnFiles } from './src/server/astBridge.ts';
import {
  importGithubRepository,
  loadLocalWorkspaceProject,
} from './src/server/projectImporter.ts';
import type { CodeFile, PersistedAuditState } from './src/types/audit.ts';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const DATA_DIR = path.join(__dirname, 'data');
const STATE_FILE = path.join(DATA_DIR, 'audit-state.json');

const DEFAULT_PERSISTED_STATE: PersistedAuditState = {
  targetId: 'local-workspace',
  findingOverrides: {},
  customRules: [],
  disabledRuleIds: [],
  dependencyVulnsByTarget: {},
  dependencyStatusByTarget: {},
  deepReviews: {},
  updatedAt: new Date().toISOString(),
};

function stripUndefined<T>(value: T): T {
  return JSON.parse(JSON.stringify(value)) as T;
}

async function readAuditState(): Promise<PersistedAuditState> {
  try {
    const raw = await fs.readFile(STATE_FILE, 'utf8');
    const parsed = JSON.parse(raw) as Partial<PersistedAuditState>;
    return {
      targetId: typeof parsed.targetId === 'string' ? parsed.targetId : 'local-workspace',
      findingOverrides:
        parsed.findingOverrides && typeof parsed.findingOverrides === 'object'
          ? parsed.findingOverrides
          : {},
      remediatedArchive:
        parsed.remediatedArchive && typeof parsed.remediatedArchive === 'object'
          ? parsed.remediatedArchive
          : {},
      targetFileOverrides:
        parsed.targetFileOverrides && typeof parsed.targetFileOverrides === 'object'
          ? parsed.targetFileOverrides
          : {},
      customRules: Array.isArray(parsed.customRules) ? parsed.customRules : [],
      disabledRuleIds: Array.isArray(parsed.disabledRuleIds) ? parsed.disabledRuleIds : [],
      ...(parsed.customTarget ? { customTarget: parsed.customTarget } : {}),
      ...(Array.isArray(parsed.importedTargets) ? { importedTargets: parsed.importedTargets } : {}),
      dependencyVulnsByTarget:
        parsed.dependencyVulnsByTarget && typeof parsed.dependencyVulnsByTarget === 'object'
          ? parsed.dependencyVulnsByTarget
          : {},
      dependencyStatusByTarget:
        parsed.dependencyStatusByTarget && typeof parsed.dependencyStatusByTarget === 'object'
          ? parsed.dependencyStatusByTarget
          : {},
      deepReviews:
        parsed.deepReviews && typeof parsed.deepReviews === 'object' ? parsed.deepReviews : {},
      updatedAt: typeof parsed.updatedAt === 'string' ? parsed.updatedAt : new Date().toISOString(),
    };
  } catch {
    return DEFAULT_PERSISTED_STATE;
  }
}

async function writeAuditState(nextState: PersistedAuditState): Promise<PersistedAuditState> {
  await fs.mkdir(DATA_DIR, { recursive: true });
  const sanitized = stripUndefined({
    ...nextState,
    updatedAt: new Date().toISOString(),
  });
  await fs.writeFile(STATE_FILE, JSON.stringify(sanitized, null, 2), 'utf8');
  return sanitized;
}

const app = express();

// Top-Level Request Deserialization (mounted before all route handlers)
app.use(express.json({ limit: '4mb' }));

app.get('/api/health', (_req, res) => {
  res.json({
    status: 'ok',
    geminiConfigured: Boolean(
      process.env.GEMINI_API_KEY && process.env.GEMINI_API_KEY !== 'MY_GEMINI_API_KEY'
    ),
  });
});

app.get('/api/state', async (_req, res) => {
  try {
    const state = await readAuditState();
    res.json(state);
  } catch {
    res.status(500).json({ error: 'Failed to load persisted audit workspace state.' });
  }
});

app.put('/api/state', async (req, res) => {
  try {
    const body = req.body && typeof req.body === 'object' ? req.body : {};
    const targetId = typeof body.targetId === 'string' && body.targetId.trim()
      ? body.targetId.trim().slice(0, 80)
      : 'local-workspace';

    const findingOverrides =
      body.findingOverrides && typeof body.findingOverrides === 'object' && !Array.isArray(body.findingOverrides)
        ? body.findingOverrides
        : {};

    const remediatedArchive =
      body.remediatedArchive && typeof body.remediatedArchive === 'object' && !Array.isArray(body.remediatedArchive)
        ? body.remediatedArchive
        : {};

    const targetFileOverrides =
      body.targetFileOverrides && typeof body.targetFileOverrides === 'object' && !Array.isArray(body.targetFileOverrides)
        ? body.targetFileOverrides
        : {};

    const customRules = Array.isArray(body.customRules) ? body.customRules.slice(0, 50) : [];
    const disabledRuleIds = Array.isArray(body.disabledRuleIds)
      ? body.disabledRuleIds.filter((id: unknown): id is string => typeof id === 'string').slice(0, 100)
      : [];

    const deepReviews =
      body.deepReviews && typeof body.deepReviews === 'object' && !Array.isArray(body.deepReviews)
        ? body.deepReviews
        : {};

    const dependencyVulnsByTarget =
      body.dependencyVulnsByTarget &&
      typeof body.dependencyVulnsByTarget === 'object' &&
      !Array.isArray(body.dependencyVulnsByTarget)
        ? body.dependencyVulnsByTarget
        : {};

    const dependencyStatusByTarget =
      body.dependencyStatusByTarget &&
      typeof body.dependencyStatusByTarget === 'object' &&
      !Array.isArray(body.dependencyStatusByTarget)
        ? body.dependencyStatusByTarget
        : {};

    const customTarget =
      body.customTarget && typeof body.customTarget === 'object' && Array.isArray(body.customTarget.files)
        ? body.customTarget
        : undefined;

    const importedTargets = Array.isArray(body.importedTargets)
      ? body.importedTargets.slice(0, 10)
      : undefined;

    const saved = await writeAuditState({
      targetId,
      findingOverrides,
      remediatedArchive,
      targetFileOverrides,
      customRules,
      disabledRuleIds,
      ...(customTarget ? { customTarget } : {}),
      ...(importedTargets ? { importedTargets } : {}),
      dependencyVulnsByTarget,
      dependencyStatusByTarget,
      deepReviews,
      updatedAt: new Date().toISOString(),
    });

    res.json(saved);
  } catch {
    res.status(500).json({ error: 'Failed to save audit workspace state.' });
  }
});

app.post('/api/audit/github', async (req, res) => {
  try {
    const body = req.body && typeof req.body === 'object' ? req.body : {};
    const repoUrl = typeof body.repoUrl === 'string' ? body.repoUrl.trim() : '';
    if (!repoUrl) {
      res.status(400).json({ error: 'Enter a GitHub repository slug (owner/repo) or URL.' });
      return;
    }

    const target = await importGithubRepository(repoUrl);
    const [depScan, astScan] = await Promise.all([
      scanDependenciesWithOsv(target.files),
      runPythonAstAuditOnFiles(target.files),
    ]);
    res.json({ target, depScan, astScan });
  } catch (err) {
    const message = err instanceof Error ? err.message : 'GitHub repository import failed.';
    res.status(400).json({ error: message });
  }
});

app.post('/api/audit/workspace', async (_req, res) => {
  try {
    const target = await loadLocalWorkspaceProject(__dirname);
    const [depScan, astScan] = await Promise.all([
      scanDependenciesWithOsv(target.files),
      runPythonAstAuditOnFiles(target.files),
    ]);
    res.json({ target, depScan, astScan });
  } catch (err) {
    const message = err instanceof Error ? err.message : 'Failed to scan local workspace.';
    res.status(500).json({ error: message });
  }
});

app.post('/api/audit/ast', async (req, res) => {
  try {
    const body = req.body && typeof req.body === 'object' ? req.body : {};
    const files = Array.isArray(body.files) ? (body.files as CodeFile[]) : [];
    const disabledRuleIds = Array.isArray(body.disabledRuleIds)
      ? body.disabledRuleIds.filter((id: unknown): id is string => typeof id === 'string')
      : [];
    const astScan = await runPythonAstAuditOnFiles(files, disabledRuleIds);
    res.json(astScan);
  } catch (err) {
    const message = err instanceof Error ? err.message : 'Python AST analysis failed.';
    res.status(500).json({ error: message });
  }
});

app.post('/api/audit/dependencies', async (req, res) => {
  try {
    const body = req.body && typeof req.body === 'object' ? req.body : {};
    const files = Array.isArray(body.files) ? (body.files as CodeFile[]) : [];
    const depScan = await scanDependenciesWithOsv(files);
    res.json(depScan);
  } catch (err) {
    const message = err instanceof Error ? err.message : 'Dependency CVE scan failed.';
    res.status(500).json({ error: message });
  }
});

app.post('/api/audit/deep-review', async (req, res) => {
  try {
    const body = req.body && typeof req.body === 'object' ? req.body : {};
    const targetName = typeof body.targetName === 'string' ? body.targetName.trim().slice(0, 120) : '';
    const stack = typeof body.stack === 'string' ? body.stack.trim().slice(0, 120) : 'Application';
    const files = Array.isArray(body.files) ? body.files : [];
    const existingFindings = Array.isArray(body.existingFindings) ? body.existingFindings : [];

    if (!targetName || files.length === 0) {
      res.status(400).json({ error: 'Target application name and at least one source file are required.' });
      return;
    }

    const sanitizedFiles = files
      .filter(
        (f: unknown): f is { path: string; language: string; content: string } =>
          Boolean(f && typeof f === 'object' && typeof (f as { content?: unknown }).content === 'string')
      )
      .map((f: { path?: unknown; language?: unknown; content: string }) => ({
        path: typeof f.path === 'string' ? f.path : 'untitled',
        language: typeof f.language === 'string' ? f.language : 'typescript',
        content: f.content,
      }));

    if (sanitizedFiles.length === 0) {
      res.status(400).json({ error: 'No valid source code files provided for deep review.' });
      return;
    }

    const result = await runDeepSecurityReview({
      targetName,
      stack,
      files: sanitizedFiles,
      existingFindings,
    });

    res.json(result);
  } catch (err) {
    const message = err instanceof Error ? err.message : 'Deep security review failed.';
    const status = message.includes('GEMINI_API_KEY') ? 503 : 500;
    res.status(status).json({ error: message });
  }
});

app.post('/api/audit/remediate', async (req, res) => {
  try {
    const body = req.body && typeof req.body === 'object' ? req.body : {};
    const ruleName = typeof body.ruleName === 'string' ? body.ruleName.trim() : '';
    const cweId = typeof body.cweId === 'string' ? body.cweId.trim() : '';
    const language = typeof body.language === 'string' ? body.language.trim() : '';
    const filePath = typeof body.filePath === 'string' ? body.filePath.trim() : '';
    const line = typeof body.line === 'number' ? body.line : 1;
    const codeLine = typeof body.codeLine === 'string' ? body.codeLine : '';
    const surroundingContext =
      typeof body.surroundingContext === 'string' ? body.surroundingContext : codeLine;

    if (!ruleName || !codeLine) {
      res.status(400).json({ error: 'Finding details and vulnerable code line are required.' });
      return;
    }

    const patch = await generateFindingRemediation({
      ruleName,
      cweId,
      language,
      filePath,
      line,
      codeLine,
      surroundingContext,
    });

    res.json(patch);
  } catch (err) {
    const message = err instanceof Error ? err.message : 'Automated patch generation failed.';
    const status = message.includes('GEMINI_API_KEY') ? 503 : 500;
    res.status(status).json({ error: message });
  }
});

async function startServer() {
  const port = Number(process.env.PORT) || 3000;

  if (process.env.NODE_ENV !== 'production') {
    const { createServer: createViteServer } = await import('vite');
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(__dirname, 'dist');
    app.use(express.static(distPath));
    app.get('*', (_req, res) => {
      res.sendFile(path.join(distPath, 'index.html'));
    });
  }

  app.listen(port, '0.0.0.0', () => {
    console.log(`Aegis Code Audit listening on http://localhost:${port}`);
  });
}

startServer().catch((err) => {
  console.error('Failed to start server:', err);
  process.exit(1);
});
