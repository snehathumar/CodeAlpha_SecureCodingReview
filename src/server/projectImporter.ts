import fs from 'node:fs/promises';
import path from 'node:path';
import type { AuditTarget, CodeFile, Language } from '../types/audit.ts';

const ALLOWED_EXTENSIONS = new Map<string, Language>([
  ['.py', 'python'],
  ['.ts', 'typescript'],
  ['.tsx', 'typescript'],
  ['.js', 'javascript'],
  ['.jsx', 'javascript'],
  ['.go', 'go'],
  ['.sql', 'sql'],
]);

const SKIP_DIRS = new Set([
  'node_modules',
  '.git',
  'dist',
  'build',
  '.next',
  '__pycache__',
  '.venv',
  'venv',
  '.playwright-cli',
  'data',
]);

export function inferFileLanguage(filePath: string): Language | null {
  const base = path.basename(filePath).toLowerCase();
  if (base === 'package.json') return 'json';
  if (base === 'requirements.txt' || base === 'go.mod') return 'text';
  const ext = path.extname(base);
  return ALLOWED_EXTENSIONS.get(ext) ?? null;
}

export function parseGithubRepoSlug(rawInput: string): { owner: string; repo: string } | null {
  const trimmed = rawInput.trim().replace(/\.git$/i, '').replace(/\/+$/, '');
  const urlMatch = /^https?:\/\/github\.com\/([A-Za-z0-9_.-]+)\/([A-Za-z0-9_.-]+)(?:\/.*)?$/i.exec(trimmed);
  if (urlMatch) {
    return { owner: urlMatch[1], repo: urlMatch[2] };
  }
  const slugMatch = /^([A-Za-z0-9_.-]+)\/([A-Za-z0-9_.-]+)$/.exec(trimmed);
  if (slugMatch) {
    return { owner: slugMatch[1], repo: slugMatch[2] };
  }
  return null;
}

export async function importGithubRepository(rawInput: string): Promise<AuditTarget> {
  const parsed = parseGithubRepoSlug(rawInput);
  if (!parsed) {
    throw new Error('Enter a valid GitHub repository as "owner/repo" or "https://github.com/owner/repo".');
  }

  const { owner, repo } = parsed;
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 12000);

  try {
    const headers: Record<string, string> = {
      Accept: 'application/vnd.github+json',
      'User-Agent': 'aegis-code-audit',
    };

    const metaRes = await fetch(`https://api.github.com/repos/${owner}/${repo}`, {
      headers,
      signal: controller.signal,
    });
    if (!metaRes.ok) {
      if (metaRes.status === 404) {
        throw new Error(`Public repository "${owner}/${repo}" was not found on GitHub.`);
      }
      throw new Error(`GitHub API error (${metaRes.status}) while reading repository metadata.`);
    }

    const meta = (await metaRes.json()) as {
      full_name?: string;
      description?: string;
      language?: string;
      default_branch?: string;
    };
    const branch = meta.default_branch || 'main';

    const treeRes = await fetch(
      `https://api.github.com/repos/${owner}/${repo}/git/trees/${encodeURIComponent(branch)}?recursive=1`,
      { headers, signal: controller.signal }
    );
    if (!treeRes.ok) {
      throw new Error(`Unable to read repository file tree (HTTP ${treeRes.status}).`);
    }

    const treeData = (await treeRes.json()) as {
      tree?: Array<{ path?: string; type?: string; size?: number }>;
    };

    const candidates = (treeData.tree ?? [])
      .filter((entry) => {
        if (entry.type !== 'blob' || !entry.path) return false;
        if ((entry.size ?? 0) > 120_000) return false;
        const segments = entry.path.split('/');
        if (segments.some((seg) => SKIP_DIRS.has(seg))) return false;
        if (entry.path.endsWith('.min.js') || entry.path.endsWith('.d.ts')) return false;
        return inferFileLanguage(entry.path) !== null;
      })
      .sort((a, b) => {
        const aIsManifest = /package\.json$|requirements\.txt$|go\.mod$/i.test(a.path ?? '') ? 0 : 1;
        const bIsManifest = /package\.json$|requirements\.txt$|go\.mod$/i.test(b.path ?? '') ? 0 : 1;
        if (aIsManifest !== bIsManifest) return aIsManifest - bIsManifest;
        return (a.path ?? '').length - (b.path ?? '').length;
      })
      .slice(0, 20);

    if (candidates.length === 0) {
      throw new Error(`No supported source or manifest files (.py, .ts, .js, .go, .sql, package.json, requirements.txt, go.mod) found in ${owner}/${repo}.`);
    }

    const files: CodeFile[] = [];
    await Promise.all(
      candidates.map(async (item) => {
        const filePath = item.path!;
        const language = inferFileLanguage(filePath);
        if (!language) return;
        const encodedPath = filePath
          .split('/')
          .map((seg) => encodeURIComponent(seg))
          .join('/');
        const rawRes = await fetch(
          `https://raw.githubusercontent.com/${owner}/${repo}/${encodeURIComponent(branch)}/${encodedPath}`,
          { headers: { 'User-Agent': 'aegis-code-audit' }, signal: controller.signal }
        );
        if (rawRes.ok) {
          const content = await rawRes.text();
          files.push({
            path: filePath,
            language,
            content: content.slice(0, 60000),
          });
        }
      })
    );

    files.sort((a, b) => a.path.localeCompare(b.path));

    return {
      id: `gh-${owner.toLowerCase()}-${repo.toLowerCase()}`.replace(/[^a-z0-9-]/g, '-'),
      name: meta.full_name || `${owner}/${repo}`,
      stack: `GitHub (${branch}) · ${meta.language || 'Multi-Language'}`,
      description:
        meta.description?.trim() ||
        `Live security audit of public GitHub repository ${owner}/${repo} (${files.length} source and manifest files).`,
      files,
      sourceKind: 'github',
      sourceUrl: `https://github.com/${owner}/${repo}`,
    };
  } finally {
    clearTimeout(timeout);
  }
}

export async function loadLocalWorkspaceProject(workspaceRoot: string): Promise<AuditTarget> {
  const canonicalRoot = path.resolve(workspaceRoot);
  const collected: CodeFile[] = [];

  async function walk(currentDir: string) {
    if (collected.length >= 28) return;
    const entries = await fs.readdir(currentDir, { withFileTypes: true });
    for (const entry of entries) {
      if (collected.length >= 28) break;
      if (SKIP_DIRS.has(entry.name)) continue;

      const absPath = path.resolve(currentDir, entry.name);
      if (!absPath.startsWith(canonicalRoot + path.sep) && absPath !== canonicalRoot) {
        continue;
      }

      if (entry.isDirectory()) {
        await walk(absPath);
      } else if (entry.isFile()) {
        const relPath = path.relative(canonicalRoot, absPath).split(path.sep).join('/');
        if (
          relPath.endsWith('.test.ts') ||
          relPath === 'package-lock.json' ||
          relPath === 'src/data/sampleApps.ts' ||
          relPath === 'src/utils/sastRules.ts'
        ) {
          continue;
        }
        const lang = inferFileLanguage(relPath);
        if (!lang) continue;

        const stat = await fs.stat(absPath);
        if (stat.size > 120_000) continue;

        const content = await fs.readFile(absPath, 'utf8');
        collected.push({
          path: relPath,
          language: lang,
          content: content.slice(0, 60000),
        });
      }
    }
  }

  await walk(canonicalRoot);
  collected.sort((a, b) => a.path.localeCompare(b.path));

  return {
    id: 'local-workspace',
    name: 'Live Workspace Codebase',
    stack: 'TypeScript · React · Express · Node.js',
    description: `Self-audit of the live application workspace (${collected.length} files including server.ts, src/, and package.json).`,
    files: collected,
    sourceKind: 'workspace',
  };
}
