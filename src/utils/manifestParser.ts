import type { CodeFile } from '../types/audit.ts';

export interface ParsedDependency {
  name: string;
  version: string;
  ecosystem: 'npm' | 'PyPI' | 'Go';
  manifestPath: string;
}

function cleanNpmVersion(rawRange: string): string | null {
  const trimmed = rawRange.trim();
  if (!trimmed || trimmed.startsWith('workspace:') || trimmed.startsWith('file:') || trimmed.startsWith('git+')) {
    return null;
  }
  const match = /(\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?)/.exec(trimmed);
  return match ? match[1] : null;
}

export function extractDependenciesFromFiles(files: CodeFile[]): ParsedDependency[] {
  const deps: ParsedDependency[] = [];
  const seen = new Set<string>();

  for (const file of files) {
    const baseName = file.path.split('/').pop()?.toLowerCase() ?? '';

    if (baseName === 'package.json') {
      try {
        const parsed = JSON.parse(file.content) as {
          dependencies?: Record<string, unknown>;
          devDependencies?: Record<string, unknown>;
        };
        const merged = {
          ...(parsed.dependencies ?? {}),
          ...(parsed.devDependencies ?? {}),
        };
        for (const [name, rawVer] of Object.entries(merged)) {
          if (typeof rawVer !== 'string') continue;
          const version = cleanNpmVersion(rawVer);
          if (!version) continue;
          const key = `npm:${name}@${version}`;
          if (seen.has(key)) continue;
          seen.add(key);
          deps.push({
            name,
            version,
            ecosystem: 'npm',
            manifestPath: file.path,
          });
        }
      } catch {
        // Ignore malformed package.json
      }
    }

    if (baseName === 'requirements.txt') {
      const lines = file.content.split(/\r?\n/);
      for (const line of lines) {
        const trimmed = line.split('#')[0].trim();
        if (!trimmed || trimmed.startsWith('-')) continue;
        const match = /^([A-Za-z0-9_.-]+)\s*(?:==|>=|~=)\s*([0-9][0-9A-Za-z._-]*)/.exec(trimmed);
        if (!match) continue;
        const [, name, version] = match;
        const key = `PyPI:${name}@${version}`;
        if (seen.has(key)) continue;
        seen.add(key);
        deps.push({
          name,
          version,
          ecosystem: 'PyPI',
          manifestPath: file.path,
        });
      }
    }

    if (baseName === 'go.mod') {
      const lines = file.content.split(/\r?\n/);
      let inRequireBlock = false;
      for (const line of lines) {
        const trimmed = line.split('//')[0].trim();
        if (!trimmed) continue;
        if (/^require\s*\($/.test(trimmed)) {
          inRequireBlock = true;
          continue;
        }
        if (inRequireBlock && trimmed === ')') {
          inRequireBlock = false;
          continue;
        }
        const match = inRequireBlock
          ? /^([^\s]+)\s+v([0-9][^\s]*)/.exec(trimmed)
          : /^require\s+([^\s]+)\s+v([0-9][^\s]*)/.exec(trimmed);
        if (!match) continue;
        const [, name, version] = match;
        const key = `Go:${name}@${version}`;
        if (seen.has(key)) continue;
        seen.add(key);
        deps.push({
          name,
          version,
          ecosystem: 'Go',
          manifestPath: file.path,
        });
      }
    }
  }

  return deps.slice(0, 60);
}
