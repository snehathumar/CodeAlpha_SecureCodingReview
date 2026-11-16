import type { CodeFile, DependencyVulnerability, Severity } from '../types/audit.ts';
import { extractDependenciesFromFiles } from '../utils/manifestParser.ts';

interface OsvBatchQuery {
  package: { name: string; ecosystem: 'npm' | 'PyPI' | 'Go' };
  version: string;
}

interface OsvAffectedRangeEvent {
  introduced?: string;
  fixed?: string;
}

interface OsvVulnerability {
  id: string;
  summary?: string;
  details?: string;
  aliases?: string[];
  severity?: Array<{ type: string; score: string }>;
  database_specific?: { severity?: string };
  affected?: Array<{
    ranges?: Array<{ events?: OsvAffectedRangeEvent[] }>;
  }>;
  references?: Array<{ url?: string }>;
}

function mapOsvSeverity(vuln: OsvVulnerability): { severity: Severity; cvssScore: number } {
  const dbSev = vuln.database_specific?.severity?.toUpperCase() ?? '';
  if (dbSev === 'CRITICAL') return { severity: 'critical', cvssScore: 9.4 };
  if (dbSev === 'HIGH') return { severity: 'high', cvssScore: 7.8 };
  if (dbSev === 'MODERATE' || dbSev === 'MEDIUM') return { severity: 'medium', cvssScore: 5.5 };
  if (dbSev === 'LOW') return { severity: 'low', cvssScore: 3.1 };
  return { severity: 'high', cvssScore: 7.5 };
}

function extractFixedVersion(vuln: OsvVulnerability): string | null {
  for (const aff of vuln.affected ?? []) {
    for (const range of aff.ranges ?? []) {
      for (const ev of range.events ?? []) {
        if (ev.fixed) return ev.fixed;
      }
    }
  }
  return null;
}

export async function scanDependenciesWithOsv(files: CodeFile[]): Promise<{
  vulnerabilities: DependencyVulnerability[];
  checkedCount: number;
  statusMessage: string;
}> {
  const deps = extractDependenciesFromFiles(files);
  if (deps.length === 0) {
    return {
      vulnerabilities: [],
      checkedCount: 0,
      statusMessage: 'No package.json, requirements.txt, or go.mod manifests found in project.',
    };
  }

  const queries: OsvBatchQuery[] = deps.map((d) => ({
    package: { name: d.name, ecosystem: d.ecosystem },
    version: d.version,
  }));

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 7000);

  try {
    const batchRes = await fetch('https://api.osv.dev/v1/querybatch', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ queries }),
      signal: controller.signal,
    });

    if (!batchRes.ok) {
      throw new Error(`OSV API returned HTTP ${batchRes.status}`);
    }

    const batchData = (await batchRes.json()) as {
      results?: Array<{ vulns?: Array<{ id: string }> }>;
    };

    const hits: Array<{ depIndex: number; vulnId: string }> = [];
    (batchData.results ?? []).forEach((resItem, idx) => {
      for (const v of resItem.vulns ?? []) {
        if (v.id && hits.length < 25) {
          hits.push({ depIndex: idx, vulnId: v.id });
        }
      }
    });

    const uniqueIds = Array.from(new Set(hits.map((h) => h.vulnId)));
    const detailMap = new Map<string, OsvVulnerability>();

    await Promise.all(
      uniqueIds.slice(0, 15).map(async (vulnId) => {
        try {
          const detailRes = await fetch(`https://api.osv.dev/v1/vulns/${encodeURIComponent(vulnId)}`, {
            signal: controller.signal,
          });
          if (detailRes.ok) {
            const detail = (await detailRes.json()) as OsvVulnerability;
            detailMap.set(vulnId, detail);
          }
        } catch {
          // Non-fatal individual detail fetch failure
        }
      })
    );

    const vulnerabilities: DependencyVulnerability[] = hits.map((hit) => {
      const dep = deps[hit.depIndex];
      const detail = detailMap.get(hit.vulnId);
      const { severity, cvssScore } = detail
        ? mapOsvSeverity(detail)
        : { severity: 'high' as Severity, cvssScore: 7.5 };
      const cveAlias = detail?.aliases?.find((a) => a.startsWith('CVE-'));

      return {
        id: `${dep.ecosystem}:${dep.name}@${dep.version}:${hit.vulnId}`,
        advisoryId: cveAlias ? `${cveAlias} (${hit.vulnId})` : hit.vulnId,
        packageName: dep.name,
        installedVersion: dep.version,
        ecosystem: dep.ecosystem,
        severity,
        cvssScore,
        summary: detail?.summary || detail?.details?.slice(0, 220) || 'Known vulnerability reported in OSV database.',
        fixedVersion: detail ? extractFixedVersion(detail) : null,
        referenceUrl: detail?.references?.[0]?.url ?? `https://osv.dev/vulnerability/${hit.vulnId}`,
        manifestPath: dep.manifestPath,
      };
    });

    return {
      vulnerabilities: vulnerabilities.sort((a, b) => b.cvssScore - a.cvssScore),
      checkedCount: deps.length,
      statusMessage: `Checked ${deps.length} dependencies against OSV.dev (${vulnerabilities.length} advisories found).`,
    };
  } catch (err) {
    return {
      vulnerabilities: [],
      checkedCount: deps.length,
      statusMessage:
        err instanceof Error
          ? `OSV.dev live lookup unavailable (${err.message}); manifest parsed (${deps.length} packages).`
          : 'OSV.dev live lookup unavailable.',
    };
  } finally {
    clearTimeout(timeout);
  }
}
