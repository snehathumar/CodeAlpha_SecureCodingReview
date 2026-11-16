import React, { useMemo, useState } from 'react';
import { Check, Copy, Download, FileJson } from 'lucide-react';
import type {
  AuditMetrics,
  AuditTarget,
  DeepReviewResult,
  DependencyVulnerability,
  Finding,
} from '../types/audit';
import { generateMarkdownReport, generateSarifReport } from '../utils/sastEngine';

interface AuditReportViewProps {
  target: AuditTarget;
  findings: Finding[];
  dependencyVulns: DependencyVulnerability[];
  metrics: AuditMetrics;
  deepReview: DeepReviewResult | null;
}

export const AuditReportView: React.FC<AuditReportViewProps> = ({
  target,
  findings,
  dependencyVulns,
  metrics,
  deepReview,
}) => {
  const [copied, setCopied] = useState(false);

  const markdownReport = useMemo(
    () => generateMarkdownReport(target, findings, dependencyVulns),
    [target, findings, dependencyVulns]
  );

  const downloadFile = (content: string, filename: string, mimeType: string) => {
    const blob = new Blob([content], { type: mimeType });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = filename;
    document.body.appendChild(link);
    link.click();
    link.remove();
    URL.revokeObjectURL(url);
  };

  const handleDownloadMarkdown = () => {
    downloadFile(markdownReport, `${target.id}-security-audit-report.md`, 'text/markdown;charset=utf-8');
  };

  const handleDownloadSarif = () => {
    const sarif = generateSarifReport(target, findings);
    downloadFile(
      JSON.stringify(sarif, null, 2),
      `${target.id}-results.sarif.json`,
      'application/sarif+json;charset=utf-8'
    );
  };

  const handleCopyMarkdown = async () => {
    try {
      await navigator.clipboard.writeText(markdownReport);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      // Clipboard API may be unavailable in restricted contexts
    }
  };

  return (
    <div className="space-y-6">
      {/* Executive Header & Export Controls */}
      <section className="bg-white border border-slate-200 rounded-lg p-6 flex flex-wrap items-center justify-between gap-4">
        <div>
          <div className="text-xs font-medium text-slate-500">
            Secure Coding Review Deliverable · {target.stack}
          </div>
          <h2 className="mt-1 font-display text-xl font-bold text-slate-900">
            {target.name} — Security Audit Report
          </h2>
          <p className="mt-1 text-sm text-slate-600 max-w-2xl">{target.description}</p>
        </div>

        <div className="flex flex-wrap items-center gap-2 shrink-0">
          <button
            type="button"
            onClick={handleCopyMarkdown}
            className="inline-flex items-center gap-1.5 px-3 py-2 text-xs font-medium text-slate-700 bg-white border border-slate-300 hover:bg-slate-50 rounded-md transition-colors whitespace-nowrap shrink-0"
          >
            {copied ? <Check className="w-3.5 h-3.5 text-emerald-600" /> : <Copy className="w-3.5 h-3.5" />}
            <span>{copied ? 'Copied Markdown' : 'Copy Markdown'}</span>
          </button>

          <button
            type="button"
            onClick={handleDownloadSarif}
            className="inline-flex items-center gap-1.5 px-3 py-2 text-xs font-medium text-slate-700 bg-white border border-slate-300 hover:bg-slate-50 rounded-md transition-colors whitespace-nowrap shrink-0"
          >
            <FileJson className="w-3.5 h-3.5" />
            <span>Export SARIF 2.1.0</span>
          </button>

          <button
            type="button"
            onClick={handleDownloadMarkdown}
            className="inline-flex items-center gap-1.5 px-4 py-2 text-xs font-semibold text-white bg-slate-900 hover:bg-slate-800 rounded-md transition-colors whitespace-nowrap shrink-0"
          >
            <Download className="w-3.5 h-3.5" />
            <span>Download Report (.md)</span>
          </button>
        </div>
      </section>

      {/* OWASP Top 10 Breakdown + Top CWEs */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        <section className="lg:col-span-8 bg-white border border-slate-200 rounded-lg overflow-hidden">
          <div className="px-5 py-4 border-b border-slate-200">
            <h3 className="font-display text-sm font-semibold text-slate-900">
              OWASP Top 10 Coverage Matrix
            </h3>
          </div>
          {metrics.owaspBreakdown.length === 0 ? (
            <div className="p-6 text-xs text-slate-500">No findings recorded for this application.</div>
          ) : (
            <table className="w-full text-left border-collapse">
              <thead>
                <tr className="border-b border-slate-200 bg-slate-50 text-xs font-medium text-slate-600">
                  <th className="px-5 py-2.5">OWASP Category</th>
                  <th className="px-5 py-2.5 text-right">Total</th>
                  <th className="px-5 py-2.5 text-right">Active</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100 text-sm">
                {metrics.owaspBreakdown.map((row) => (
                  <tr key={row.category} className="hover:bg-slate-50/70">
                    <td className="px-5 py-2.5 text-slate-800">{row.category}</td>
                    <td className="px-5 py-2.5 text-right font-mono tabular-nums text-slate-600">
                      {row.count}
                    </td>
                    <td className="px-5 py-2.5 text-right font-mono tabular-nums font-semibold text-slate-900">
                      {row.openCount}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </section>

        <section className="lg:col-span-4 bg-white border border-slate-200 rounded-lg p-5 space-y-3">
          <h3 className="font-display text-sm font-semibold text-slate-900">
            Active CWE Hotspots
          </h3>
          {metrics.topCwes.length === 0 ? (
            <p className="text-xs text-emerald-700">All identified findings are resolved.</p>
          ) : (
            <div className="divide-y divide-slate-100">
              {metrics.topCwes.map((cwe) => (
                <div key={cwe.cweId} className="py-2 flex items-center justify-between text-sm">
                  <span className="font-mono text-slate-800">{cwe.cweId}</span>
                  <span className="font-mono tabular-nums text-slate-600">
                    {cwe.count} {cwe.count === 1 ? 'finding' : 'findings'}
                  </span>
                </div>
              ))}
            </div>
          )}

          {deepReview && (
            <div className="pt-3 border-t border-slate-200 space-y-1.5">
              <div className="text-xs font-medium text-slate-500">Architectural Posture</div>
              <p className="text-xs text-slate-700 leading-relaxed">{deepReview.architecturePosture}</p>
            </div>
          )}
        </section>
      </div>

      {/* Documented Findings Table */}
      <section className="bg-white border border-slate-200 rounded-lg overflow-hidden">
        <div className="px-5 py-4 border-b border-slate-200">
          <h3 className="font-display text-sm font-semibold text-slate-900">
            Documented Findings & Remediation Plan
          </h3>
        </div>
        {findings.length === 0 ? (
          <div className="px-5 py-4 text-xs text-slate-500">
            No static code vulnerabilities detected in {target.name}.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse">
              <thead>
                <tr className="border-b border-slate-200 bg-slate-50 text-xs font-medium text-slate-600">
                  <th className="px-4 py-2.5">Rule & Location</th>
                  <th className="px-4 py-2.5">CWE</th>
                  <th className="px-4 py-2.5">Severity</th>
                  <th className="px-4 py-2.5 text-right">CVSS</th>
                  <th className="px-4 py-2.5">Status</th>
                  <th className="px-4 py-2.5">Remediation Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100 text-xs">
                {findings.map((f) => (
                  <tr key={f.id} className="hover:bg-slate-50/70 align-top">
                    <td className="px-4 py-3">
                      <div className="font-medium text-slate-900">{f.ruleName}</div>
                      <div className="font-mono text-slate-500">
                        {f.filePath}:{f.line}
                      </div>
                    </td>
                    <td className="px-4 py-3 font-mono text-slate-700 whitespace-nowrap">{f.cweId}</td>
                    <td className="px-4 py-3 capitalize font-medium text-slate-800 whitespace-nowrap">
                      {f.severity}
                    </td>
                    <td className="px-4 py-3 text-right font-mono tabular-nums text-slate-700">
                      {f.cvssScore.toFixed(1)}
                    </td>
                    <td className="px-4 py-3 capitalize text-slate-700 whitespace-nowrap">
                      {f.status.replace('_', ' ')}
                    </td>
                    <td className="px-4 py-3 text-slate-600 max-w-md">{f.recommendation}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>

      {/* Supply-Chain Dependency Advisories Table */}
      <section className="bg-white border border-slate-200 rounded-lg overflow-hidden">
        <div className="px-5 py-4 border-b border-slate-200 flex items-center justify-between gap-4">
          <h3 className="font-display text-sm font-semibold text-slate-900">
            Supply-Chain Dependency Advisories (OSV.dev)
          </h3>
          <span className="text-xs font-mono tabular-nums text-slate-500">
            {dependencyVulns.length} {dependencyVulns.length === 1 ? 'advisory' : 'advisories'}
          </span>
        </div>
        {dependencyVulns.length === 0 ? (
          <div className="px-5 py-4 text-xs text-slate-500">
            No vulnerable dependency versions recorded for this target. Import a repository with
            package.json, requirements.txt, or go.mod or run Re-scan Manifests in the Code Auditor tab.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse">
              <thead>
                <tr className="border-b border-slate-200 bg-slate-50 text-xs font-medium text-slate-600">
                  <th className="px-4 py-2.5">Package & Version</th>
                  <th className="px-4 py-2.5">Advisory</th>
                  <th className="px-4 py-2.5">Severity</th>
                  <th className="px-4 py-2.5">Fixed Version</th>
                  <th className="px-4 py-2.5">Summary</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100 text-xs">
                {dependencyVulns.map((v) => (
                  <tr key={v.id} className="hover:bg-slate-50/70 align-top">
                    <td className="px-4 py-3 whitespace-nowrap">
                      <div className="font-mono font-semibold text-slate-900">
                        {v.packageName}@{v.installedVersion}
                      </div>
                      <div className="text-slate-500">
                        {v.ecosystem} · {v.manifestPath}
                      </div>
                    </td>
                    <td className="px-4 py-3 font-mono text-slate-800 whitespace-nowrap">
                      {v.advisoryId}
                    </td>
                    <td className="px-4 py-3 capitalize font-medium text-slate-800 whitespace-nowrap">
                      {v.severity}
                    </td>
                    <td className="px-4 py-3 font-mono text-emerald-700 whitespace-nowrap">
                      {v.fixedVersion || 'See advisory'}
                    </td>
                    <td className="px-4 py-3 text-slate-600 max-w-md">{v.summary}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </div>
  );
};
