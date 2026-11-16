import React, { useEffect, useMemo, useRef, useState } from 'react';
import {
  AlertTriangle,
  Check,
  Code2,
  Download,
  ExternalLink,
  FileUp,
  FolderUp,
  GitBranch,
  HardDrive,
  Package,
  Search,
  Sparkles,
  Wrench,
} from 'lucide-react';
import type {
  AuditMetrics,
  AuditTarget,
  CodeFile,
  DeepReviewResult,
  DependencyVulnerability,
  Finding,
  FindingStatus,
  Language,
} from '../types/audit';

interface CodeAuditorViewProps {
  target: AuditTarget;
  targets: AuditTarget[];
  onSelectTarget: (id: string) => void;
  activeFilePath: string;
  onSelectFile: (path: string) => void;
  onUpdateFileContent: (path: string, content: string, language?: Language) => void;
  onUploadFile: (fileName: string, language: Language, content: string) => void;
  onImportGithubRepo: (repoUrl: string) => Promise<void>;
  importingGithub: boolean;
  onImportLocalFolder: (projectName: string, files: CodeFile[]) => Promise<void>;
  onAuditLiveWorkspace: () => Promise<void>;
  auditingWorkspace: boolean;
  findings: Finding[];
  dependencyVulns: DependencyVulnerability[];
  dependencyScanStatus: string | null;
  scanningDependencies: boolean;
  onScanDependencies: () => Promise<void>;
  selectedFindingId: string | null;
  onSelectFinding: (findingId: string) => void;
  metrics: AuditMetrics;
  onUpdateFindingTriage: (
    findingId: string,
    status: FindingStatus,
    reviewerNotes: string
  ) => Promise<void>;
  onApplyRemediationPatch: (finding: Finding, patchedLine: string) => Promise<void>;
  onGenerateAiPatch: (finding: Finding) => Promise<void>;
  generatingPatchForId: string | null;
  deepReview: DeepReviewResult | null;
  onRunDeepReview: () => Promise<void>;
  runningDeepReview: boolean;
  activeRuleCount: number;
}

const SEVERITY_TEXT_CLASS: Record<Finding['severity'], string> = {
  critical: 'text-red-700 font-semibold',
  high: 'text-orange-700 font-semibold',
  medium: 'text-amber-700 font-semibold',
  low: 'text-slate-600 font-medium',
};

const SEVERITY_LABEL: Record<Finding['severity'], string> = {
  critical: 'Critical',
  high: 'High',
  medium: 'Medium',
  low: 'Low',
};

const STATUS_LABEL: Record<FindingStatus, string> = {
  open: 'Open',
  confirmed: 'Confirmed',
  remediated: 'Remediated',
  false_positive: 'False Positive',
};

const SKIP_FOLDER_SEGMENTS = new Set([
  'node_modules',
  '.git',
  'dist',
  'build',
  '.next',
  '__pycache__',
  '.venv',
  'venv',
]);

function inferLanguageFromFilename(name: string): Language | null {
  const lower = name.toLowerCase();
  const base = lower.split('/').pop() ?? lower;
  if (base === 'package.json') return 'json';
  if (base === 'requirements.txt' || base === 'go.mod') return 'text';
  if (lower.endsWith('.py')) return 'python';
  if (lower.endsWith('.go')) return 'go';
  if (lower.endsWith('.sql')) return 'sql';
  if (lower.endsWith('.js') || lower.endsWith('.jsx')) return 'javascript';
  if (lower.endsWith('.ts') || lower.endsWith('.tsx')) return 'typescript';
  return null;
}

export const CodeAuditorView: React.FC<CodeAuditorViewProps> = ({
  target,
  targets,
  onSelectTarget,
  activeFilePath,
  onSelectFile,
  onUpdateFileContent,
  onUploadFile,
  onImportGithubRepo,
  importingGithub,
  onImportLocalFolder,
  onAuditLiveWorkspace,
  auditingWorkspace,
  findings,
  dependencyVulns,
  dependencyScanStatus,
  scanningDependencies,
  onScanDependencies,
  selectedFindingId,
  onSelectFinding,
  metrics,
  onUpdateFindingTriage,
  onApplyRemediationPatch,
  onGenerateAiPatch,
  generatingPatchForId,
  deepReview,
  onRunDeepReview,
  runningDeepReview,
  activeRuleCount,
}) => {
  const [severityFilter, setSeverityFilter] = useState<'all' | 'critical' | 'high' | 'medium' | 'remediated'>('all');
  const [queueTab, setQueueTab] = useState<'code' | 'dependencies'>('code');
  const [searchQuery, setSearchQuery] = useState('');
  const [isEditingSource, setIsEditingSource] = useState(false);
  const [draftNotes, setDraftNotes] = useState<string | null>(null);
  const [draftStatus, setDraftStatus] = useState<FindingStatus | null>(null);
  const [savingTriage, setSavingTriage] = useState(false);
  const [githubInput, setGithubInput] = useState('');

  const activeFile = useMemo(
    () => target.files.find((f) => f.path === activeFilePath) ?? target.files[0],
    [target.files, activeFilePath]
  );

  const filteredFindings = useMemo(() => {
    const q = searchQuery.trim().toLowerCase();
    return findings.filter((f) => {
      if (severityFilter === 'remediated') {
        if (f.status !== 'remediated') return false;
      } else if (severityFilter !== 'all') {
        if (f.severity !== severityFilter || f.status === 'remediated' || f.status === 'false_positive') {
          return false;
        }
      }

      if (!q) return true;
      return (
        f.ruleName.toLowerCase().includes(q) ||
        f.cweId.toLowerCase().includes(q) ||
        f.filePath.toLowerCase().includes(q) ||
        f.owaspCategory.toLowerCase().includes(q)
      );
    });
  }, [findings, severityFilter, searchQuery]);

  const selectedFinding = useMemo(() => {
    return (
      findings.find((f) => f.id === selectedFindingId) ??
      filteredFindings[0] ??
      findings[0] ??
      null
    );
  }, [findings, filteredFindings, selectedFindingId]);

  const currentFileFindingsByLine = useMemo(() => {
    const map = new Map<number, Finding[]>();
    if (!activeFile) return map;
    for (const f of findings) {
      if (f.filePath === activeFile.path) {
        const list = map.get(f.line) ?? [];
        list.push(f);
        map.set(f.line, list);
      }
    }
    return map;
  }, [findings, activeFile]);

  const currentNotesValue =
    draftNotes !== null ? draftNotes : selectedFinding?.reviewerNotes ?? '';
  const currentStatusValue =
    draftStatus !== null ? draftStatus : selectedFinding?.status ?? 'open';

  const handleFindingSelect = (finding: Finding) => {
    onSelectFinding(finding.id);
    if (finding.filePath !== activeFile?.path) {
      onSelectFile(finding.filePath);
    }
    setDraftNotes(null);
    setDraftStatus(null);
  };

  const handleFileInput = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    const text = await file.text();
    const lang = inferLanguageFromFilename(file.name) ?? 'typescript';
    onUploadFile(file.name, lang, text.slice(0, 60000));
    e.target.value = '';
  };

  const handleFolderInput = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const fileList = e.target.files;
    if (!fileList || fileList.length === 0) return;

    const collected: CodeFile[] = [];
    let folderName = 'Local Project';

    for (let i = 0; i < fileList.length && collected.length < 25; i++) {
      const f = fileList[i];
      const rel = (f as File & { webkitRelativePath?: string }).webkitRelativePath || f.name;
      const parts = rel.split('/');
      if (i === 0 && parts.length > 1) {
        folderName = parts[0];
      }
      if (parts.some((seg) => SKIP_FOLDER_SEGMENTS.has(seg))) continue;
      if (f.size > 120_000) continue;

      const lang = inferLanguageFromFilename(rel);
      if (!lang) continue;

      const content = await f.text();
      const displayPath = parts.length > 1 ? parts.slice(1).join('/') : rel;
      collected.push({
        path: displayPath,
        language: lang,
        content: content.slice(0, 60000),
      });
    }

    e.target.value = '';
    if (collected.length > 0) {
      await onImportLocalFolder(folderName, collected);
    }
  };

  const handleGithubSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!githubInput.trim()) return;
    await onImportGithubRepo(githubInput.trim());
    setGithubInput('');
  };

  const handleSaveTriage = async () => {
    if (!selectedFinding) return;
    setSavingTriage(true);
    try {
      await onUpdateFindingTriage(selectedFinding.id, currentStatusValue, currentNotesValue);
      setDraftNotes(null);
      setDraftStatus(null);
    } finally {
      setSavingTriage(false);
    }
  };

  const handleDownloadActiveFile = () => {
    if (!activeFile) return;
    const blob = new Blob([activeFile.content], { type: 'text/plain;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = activeFile.path.split('/').pop() || 'source.txt';
    document.body.appendChild(link);
    link.click();
    link.remove();
    URL.revokeObjectURL(url);
  };

  const sourceLines = activeFile ? activeFile.content.split(/\r?\n/) : [];
  const lineRefs = useRef<Map<number, HTMLTableRowElement>>(new Map());

  useEffect(() => {
    if (!selectedFinding || selectedFinding.filePath !== activeFile?.path) return;
    const rowEl = lineRefs.current.get(selectedFinding.line);
    if (rowEl && typeof rowEl.scrollIntoView === 'function') {
      rowEl.scrollIntoView({ block: 'nearest', behavior: 'smooth' });
    }
  }, [selectedFinding?.id, selectedFinding?.line, selectedFinding?.filePath, activeFile?.path]);

  return (
    <div className="space-y-6">
      {/* Real Project Ingestion Bar: GitHub Repo, Local Folder, or Live Workspace */}
      <section
        aria-label="Import real project for audit"
        className="bg-white border border-slate-200 rounded-lg px-4 py-3 flex flex-wrap items-center justify-between gap-3"
      >
        <form onSubmit={handleGithubSubmit} className="flex flex-1 min-w-[260px] items-center gap-2">
          <div className="relative flex-1 max-w-md">
            <GitBranch className="w-3.5 h-3.5 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2 pointer-events-none" />
            <label htmlFor="github-repo-input" className="sr-only">
              GitHub public repository URL or owner/repo
            </label>
            <input
              id="github-repo-input"
              type="text"
              value={githubInput}
              onChange={(e) => setGithubInput(e.target.value)}
              placeholder="Audit real GitHub repo (e.g. pallets/flask or owner/repo)"
              className="w-full pl-8 pr-3 py-1.5 text-xs bg-slate-50 border border-slate-300 rounded-md text-slate-900 placeholder:text-slate-400 focus:outline-none focus:border-blue-500"
            />
          </div>
          <button
            type="submit"
            disabled={importingGithub || !githubInput.trim()}
            className="px-3 py-1.5 text-xs font-semibold text-white bg-blue-600 hover:bg-blue-700 rounded-md transition-colors whitespace-nowrap shrink-0 disabled:opacity-50"
          >
            {importingGithub ? 'Importing...' : 'Audit GitHub Repo'}
          </button>
        </form>

        <div className="flex flex-wrap items-center gap-2 shrink-0">
          <label className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-md border border-slate-300 bg-white text-slate-700 hover:bg-slate-50 cursor-pointer whitespace-nowrap shrink-0">
            <FolderUp className="w-3.5 h-3.5" />
            <span>Upload Project Folder</span>
            <input
              type="file"
              multiple
              {...({ webkitdirectory: '', directory: '' } as Record<string, string>)}
              onChange={handleFolderInput}
              className="sr-only"
            />
          </label>

          <button
            type="button"
            onClick={() => void onAuditLiveWorkspace()}
            disabled={auditingWorkspace}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-md border border-slate-300 bg-white text-slate-800 hover:bg-slate-50 transition-colors whitespace-nowrap shrink-0 disabled:opacity-50"
          >
            <HardDrive className="w-3.5 h-3.5" />
            <span>{auditingWorkspace ? 'Scanning...' : 'Audit Live Workspace'}</span>
          </button>
        </div>
      </section>

      {/* 4-column Summary Metrics Strip */}
      <section
        aria-label="Security posture metrics"
        className="grid grid-cols-2 xl:grid-cols-4 bg-white border border-slate-200 rounded-lg divide-y xl:divide-y-0 xl:divide-x divide-slate-200"
      >
        <div className="p-4">
          <div className="text-xs font-medium text-slate-500">Security Posture</div>
          <div className="mt-1 flex flex-wrap items-baseline gap-x-2.5 gap-y-0.5">
            <span className="font-display text-xl sm:text-2xl font-bold text-slate-900 tabular-nums whitespace-nowrap">
              Grade {metrics.securityPostureGrade}
            </span>
            <span className="text-xs text-slate-500 tabular-nums whitespace-nowrap">
              Risk {metrics.riskScore}/100
            </span>
          </div>
        </div>

        <div className="p-4">
          <div className="text-xs font-medium text-slate-500">Active Vulnerabilities</div>
          <div className="mt-1 flex flex-wrap items-baseline gap-x-2.5 gap-y-0.5">
            <span className="font-display text-xl sm:text-2xl font-bold text-slate-900 tabular-nums whitespace-nowrap">
              {metrics.openFindings + metrics.confirmedFindings}
            </span>
            <span className="text-xs text-red-700 tabular-nums whitespace-nowrap">
              {metrics.severityCounts.critical} critical · {metrics.severityCounts.high} high
            </span>
          </div>
        </div>

        <div className="p-4">
          <div className="text-xs font-medium text-slate-500">Supply-Chain CVEs</div>
          <div className="mt-1 flex flex-wrap items-baseline gap-x-2.5 gap-y-0.5">
            <span className="font-display text-xl sm:text-2xl font-bold text-slate-900 tabular-nums whitespace-nowrap">
              {dependencyVulns.length}
            </span>
            <span className="text-xs text-slate-500 tabular-nums whitespace-nowrap">
              {metrics.remediatedFindings} code issues fixed
            </span>
          </div>
        </div>

        <div className="p-4">
          <div className="text-xs font-medium text-slate-500">Audit Scope</div>
          <div className="mt-1 flex flex-wrap items-baseline gap-x-2.5 gap-y-0.5">
            <span className="font-display text-xl sm:text-2xl font-bold text-slate-900 tabular-nums whitespace-nowrap">
              {target.files.length} {target.files.length === 1 ? 'file' : 'files'}
            </span>
            <span className="text-xs text-slate-500 tabular-nums whitespace-nowrap">
              {activeRuleCount} SAST rules + entropy
            </span>
          </div>
        </div>
      </section>

      {/* Mobile target selector + File & Tool Controls */}
      <div className="flex flex-wrap items-center justify-between gap-3 bg-white border border-slate-200 rounded-lg px-4 py-3">
        <div className="flex flex-wrap items-center gap-2 min-w-0 flex-1">
          <label htmlFor="mobile-target-select" className="sr-only">
            Select target application
          </label>
          <select
            id="mobile-target-select"
            value={target.id}
            onChange={(e) => onSelectTarget(e.target.value)}
            className="lg:hidden px-2.5 py-1.5 text-xs font-medium bg-slate-50 border border-slate-300 rounded-md text-slate-900"
          >
            {targets.map((t) => (
              <option key={t.id} value={t.id}>
                {t.name}
              </option>
            ))}
          </select>

          <div className="flex items-center gap-1 overflow-x-auto max-w-full" role="tablist" aria-label="Source files">
            {target.files.map((file) => {
              const isSelected = file.path === activeFile?.path;
              const fileIssueCount = findings.filter(
                (f) => f.filePath === file.path && f.status !== 'remediated' && f.status !== 'false_positive'
              ).length;
              return (
                <button
                  key={file.path}
                  type="button"
                  role="tab"
                  aria-selected={isSelected}
                  onClick={() => onSelectFile(file.path)}
                  className={`px-3 py-1.5 text-xs font-mono rounded-md transition-colors whitespace-nowrap shrink-0 ${
                    isSelected
                      ? 'bg-slate-900 text-white'
                      : 'bg-slate-100 text-slate-700 hover:bg-slate-200'
                  }`}
                >
                  {file.path}
                  {fileIssueCount > 0 ? ` (${fileIssueCount})` : ''}
                </button>
              );
            })}
          </div>
        </div>

        <div className="flex items-center gap-2 shrink-0">
          {activeFile && (
            <select
              aria-label="Source file language"
              value={activeFile.language}
              onChange={(e) =>
                onUpdateFileContent(activeFile.path, activeFile.content, e.target.value as Language)
              }
              className="px-2.5 py-1.5 text-xs font-medium bg-white border border-slate-300 rounded-md text-slate-700"
            >
              <option value="python">Python</option>
              <option value="typescript">TypeScript</option>
              <option value="javascript">JavaScript</option>
              <option value="go">Go</option>
              <option value="sql">SQL</option>
              <option value="json">JSON</option>
              <option value="text">Text</option>
            </select>
          )}

          <button
            type="button"
            onClick={() => setIsEditingSource((v) => !v)}
            className={`inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-md border transition-colors whitespace-nowrap shrink-0 ${
              isEditingSource
                ? 'bg-blue-50 border-blue-300 text-blue-700'
                : 'bg-white border-slate-300 text-slate-700 hover:bg-slate-50'
            }`}
          >
            <Code2 className="w-3.5 h-3.5" />
            <span>{isEditingSource ? 'Inspect Mode' : 'Edit Code'}</span>
          </button>

          <label className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-md border border-slate-300 bg-white text-slate-700 hover:bg-slate-50 cursor-pointer whitespace-nowrap shrink-0">
            <FileUp className="w-3.5 h-3.5" />
            <span>Upload File</span>
            <input
              type="file"
              accept=".py,.ts,.tsx,.js,.jsx,.go,.sql,.json,.txt,.mod"
              onChange={handleFileInput}
              className="sr-only"
            />
          </label>

          {activeFile && (
            <button
              type="button"
              onClick={handleDownloadActiveFile}
              title="Download current or patched source file"
              className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-md border border-slate-300 bg-white text-slate-700 hover:bg-slate-50 transition-colors whitespace-nowrap shrink-0"
            >
              <Download className="w-3.5 h-3.5" />
              <span>Export File</span>
            </button>
          )}
        </div>
      </div>

      {/* Main Split Workbench */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
        {/* Left: Code Viewer + Findings / Supply-Chain Queue */}
        <div className="lg:col-span-7 space-y-6 min-w-0">
          {/* Code Inspector / Editor */}
          <div className="bg-slate-900 rounded-lg border border-slate-800 overflow-hidden">
            <div className="px-4 py-2.5 bg-slate-950/70 border-b border-slate-800 flex items-center justify-between gap-4">
              <div className="text-xs font-mono text-slate-300 truncate">
                {activeFile?.path ?? 'No file selected'} · {activeFile?.language} ·{' '}
                {sourceLines.length} lines
              </div>
              <div className="text-xs text-slate-400 whitespace-nowrap shrink-0">
                Click highlighted lines to inspect
              </div>
            </div>

            {isEditingSource && activeFile ? (
              <div className="p-3">
                <label htmlFor="source-code-editor" className="sr-only">
                  Source code editor
                </label>
                <textarea
                  id="source-code-editor"
                  value={activeFile.content}
                  onChange={(e) => onUpdateFileContent(activeFile.path, e.target.value)}
                  spellCheck={false}
                  rows={16}
                  className="w-full bg-slate-950 text-slate-100 font-mono text-xs leading-6 p-3 rounded border border-slate-700 focus:outline-none focus:border-blue-500 resize-y"
                />
              </div>
            ) : (
              <div className="overflow-x-auto max-h-[380px] overflow-y-auto py-2">
                <table className="w-full border-collapse font-mono text-xs leading-6">
                  <tbody>
                    {sourceLines.map((lineText, idx) => {
                      const lineNum = idx + 1;
                      const lineFindings = currentFileFindingsByLine.get(lineNum) ?? [];
                      const activeFindings = lineFindings.filter(
                        (f) => f.status !== 'remediated' && f.status !== 'false_positive'
                      );
                      const isSelectedLine =
                        selectedFinding?.filePath === activeFile?.path &&
                        selectedFinding?.line === lineNum;
                      const hasActiveIssue = activeFindings.length > 0;

                      return (
                        <tr
                          key={lineNum}
                          ref={(el) => {
                            if (el) lineRefs.current.set(lineNum, el);
                            else lineRefs.current.delete(lineNum);
                          }}
                          onClick={() => {
                            if (lineFindings.length > 0) {
                              handleFindingSelect(lineFindings[0]);
                            }
                          }}
                          className={`${
                            lineFindings.length > 0 ? 'cursor-pointer' : ''
                          } ${
                            isSelectedLine
                              ? 'bg-red-950/75'
                              : hasActiveIssue
                              ? 'bg-red-950/35 hover:bg-red-950/55'
                              : 'hover:bg-slate-800/40'
                          }`}
                        >
                          <td className="select-none text-right pr-2.5 pl-4 text-slate-500 w-12 tabular-nums align-top">
                            {lineNum}
                          </td>
                          <td className="select-none w-6 pr-2 text-center align-top">
                            {hasActiveIssue ? (
                              <span
                                title={activeFindings.map((f) => f.cweId).join(', ')}
                                className="inline-block text-red-400 font-bold"
                              >
                                !
                              </span>
                            ) : lineFindings.length > 0 ? (
                              <span className="inline-block text-emerald-400">✓</span>
                            ) : null}
                          </td>
                          <td className="pl-1 pr-4 text-slate-100 whitespace-pre align-top">
                            {lineText || ' '}
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            )}
          </div>

          {/* Code Findings & Supply-Chain CVE Queue */}
          <div className="bg-white border border-slate-200 rounded-lg overflow-hidden">
            <div className="px-4 py-2.5 border-b border-slate-200 bg-slate-50/70 flex flex-wrap items-center justify-between gap-2">
              <div className="flex items-center gap-1 p-1 bg-slate-200/70 rounded-md">
                <button
                  type="button"
                  onClick={() => setQueueTab('code')}
                  className={`px-2.5 py-1 text-xs font-medium rounded transition-colors whitespace-nowrap ${
                    queueTab === 'code' ? 'bg-white text-slate-900 shadow-xs' : 'text-slate-600'
                  }`}
                >
                  Code Findings ({findings.length})
                </button>
                <button
                  type="button"
                  onClick={() => setQueueTab('dependencies')}
                  className={`inline-flex items-center gap-1.5 px-2.5 py-1 text-xs font-medium rounded transition-colors whitespace-nowrap ${
                    queueTab === 'dependencies' ? 'bg-white text-slate-900 shadow-xs' : 'text-slate-600'
                  }`}
                >
                  <Package className="w-3.5 h-3.5" />
                  <span>Supply-Chain CVEs ({dependencyVulns.length})</span>
                </button>
              </div>

              {queueTab === 'dependencies' && (
                <button
                  type="button"
                  onClick={() => void onScanDependencies()}
                  disabled={scanningDependencies}
                  className="px-2.5 py-1 text-xs font-medium text-blue-700 bg-blue-50 hover:bg-blue-100 rounded transition-colors whitespace-nowrap disabled:opacity-50"
                >
                  {scanningDependencies ? 'Querying OSV.dev...' : 'Re-scan Manifests'}
                </button>
              )}
            </div>

            {queueTab === 'code' ? (
              <>
                <div className="px-4 py-3 border-b border-slate-200 flex flex-wrap items-center justify-between gap-3">
                  <div
                    className="flex items-center gap-1 p-1 bg-slate-100 rounded-md overflow-x-auto"
                    role="group"
                    aria-label="Filter findings by severity"
                  >
                    {(
                      [
                        { key: 'all', label: 'All' },
                        { key: 'critical', label: 'Critical' },
                        { key: 'high', label: 'High' },
                        { key: 'medium', label: 'Medium' },
                        { key: 'remediated', label: 'Remediated' },
                      ] as const
                    ).map((tab) => (
                      <button
                        key={tab.key}
                        type="button"
                        onClick={() => setSeverityFilter(tab.key)}
                        className={`px-2.5 py-1 text-xs font-medium rounded transition-colors whitespace-nowrap shrink-0 ${
                          severityFilter === tab.key
                            ? 'bg-white text-slate-900 shadow-xs'
                            : 'text-slate-600 hover:text-slate-900'
                        }`}
                      >
                        {tab.label}
                      </button>
                    ))}
                  </div>

                  <div className="relative flex-1 min-w-[180px] max-w-xs">
                    <Search className="w-3.5 h-3.5 text-slate-400 absolute left-2.5 top-1/2 -translate-y-1/2 pointer-events-none" />
                    <label htmlFor="findings-search" className="sr-only">
                      Search findings
                    </label>
                    <input
                      id="findings-search"
                      type="text"
                      value={searchQuery}
                      onChange={(e) => setSearchQuery(e.target.value)}
                      placeholder="Filter by CWE, rule, file..."
                      className="w-full pl-8 pr-3 py-1.5 text-xs bg-slate-50 border border-slate-200 rounded-md text-slate-900 placeholder:text-slate-400 focus:outline-none focus:border-blue-500"
                    />
                  </div>
                </div>

                {filteredFindings.length === 0 ? (
                  <div className="p-8 text-center">
                    <p className="text-sm font-medium text-slate-800">
                      No matching code vulnerabilities in this view
                    </p>
                    <p className="mt-1 text-xs text-slate-500">
                      Switch severity tabs, clear your search query, or check Supply-Chain CVEs.
                    </p>
                  </div>
                ) : (
                  <div className="divide-y divide-slate-100 max-h-[360px] overflow-y-auto">
                    {filteredFindings.map((finding) => {
                      const isSelected = selectedFinding?.id === finding.id;
                      return (
                        <button
                          key={finding.id}
                          type="button"
                          onClick={() => handleFindingSelect(finding)}
                          className={`w-full text-left px-4 py-3 transition-colors flex items-start justify-between gap-4 ${
                            isSelected ? 'bg-blue-50/70' : 'hover:bg-slate-50'
                          }`}
                        >
                          <div className="min-w-0">
                            <div className="text-sm font-medium text-slate-900 truncate">
                              {finding.ruleName}
                            </div>
                            <div className="mt-0.5 flex flex-wrap items-center gap-x-2 text-xs text-slate-500 font-mono tabular-nums">
                              <span className={SEVERITY_TEXT_CLASS[finding.severity]}>
                                {SEVERITY_LABEL[finding.severity]}
                              </span>
                              <span aria-hidden="true">·</span>
                              <span>{finding.cweId}</span>
                              <span aria-hidden="true">·</span>
                              <span>CVSS {finding.cvssScore.toFixed(1)}</span>
                              <span aria-hidden="true">·</span>
                              <span className="truncate">
                                {finding.filePath}:{finding.line}
                              </span>
                            </div>
                          </div>
                          <span
                            className={`text-xs font-medium whitespace-nowrap shrink-0 ${
                              finding.status === 'remediated'
                                ? 'text-emerald-700'
                                : finding.status === 'confirmed'
                                ? 'text-blue-700'
                                : finding.status === 'false_positive'
                                ? 'text-slate-400'
                                : 'text-slate-700'
                            }`}
                          >
                            {STATUS_LABEL[finding.status]}
                          </span>
                        </button>
                      );
                    })}
                  </div>
                )}
              </>
            ) : (
              <div className="divide-y divide-slate-100 max-h-[420px] overflow-y-auto">
                {dependencyScanStatus && (
                  <div className="px-4 py-2 text-xs text-slate-600 bg-slate-50">
                    {dependencyScanStatus}
                  </div>
                )}
                {dependencyVulns.length === 0 ? (
                  <div className="p-8 text-center">
                    <p className="text-sm font-medium text-slate-800">
                      No known dependency CVEs detected
                    </p>
                    <p className="mt-1 text-xs text-slate-500">
                      Projects with package.json, requirements.txt, or go.mod are queried live against OSV.dev.
                    </p>
                  </div>
                ) : (
                  dependencyVulns.map((vuln) => (
                    <div key={vuln.id} className="px-4 py-3 space-y-1">
                      <div className="flex items-start justify-between gap-3">
                        <div className="text-sm font-semibold text-slate-900">
                          {vuln.packageName}@{vuln.installedVersion}
                        </div>
                        <span className={`text-xs font-mono ${SEVERITY_TEXT_CLASS[vuln.severity]}`}>
                          {SEVERITY_LABEL[vuln.severity]} · CVSS {vuln.cvssScore.toFixed(1)}
                        </span>
                      </div>
                      <div className="text-xs font-mono text-slate-500">
                        {vuln.advisoryId} · {vuln.ecosystem} · {vuln.manifestPath}
                      </div>
                      <p className="text-xs text-slate-700 leading-relaxed">{vuln.summary}</p>
                      <div className="flex items-center justify-between gap-2 pt-1 text-xs">
                        <span className="font-medium text-emerald-700">
                          {vuln.fixedVersion
                            ? `Upgrade to >= ${vuln.fixedVersion}`
                            : 'Review upstream advisory'}
                        </span>
                        {vuln.referenceUrl && (
                          <a
                            href={vuln.referenceUrl}
                            target="_blank"
                            rel="noreferrer"
                            className="inline-flex items-center gap-1 text-blue-600 hover:underline"
                          >
                            <span>Advisory</span>
                            <ExternalLink className="w-3 h-3" />
                          </a>
                        )}
                      </div>
                    </div>
                  ))
                )}
              </div>
            )}
          </div>
        </div>

        {/* Right: Finding Detail, Remediation Diff & Deep Semantic Review */}
        <div className="lg:col-span-5 space-y-6 min-w-0">
          {selectedFinding ? (
            <section
              aria-label="Selected vulnerability details"
              className="bg-white border border-slate-200 rounded-lg p-5 space-y-4"
            >
              <div>
                <div className="flex flex-wrap items-center gap-2 text-xs text-slate-500 font-mono tabular-nums">
                  <span className={SEVERITY_TEXT_CLASS[selectedFinding.severity]}>
                    {SEVERITY_LABEL[selectedFinding.severity]}
                  </span>
                  <span aria-hidden="true">·</span>
                  <span>{selectedFinding.cweId}</span>
                  <span aria-hidden="true">·</span>
                  <span>CVSS {selectedFinding.cvssScore.toFixed(1)}</span>
                  <span aria-hidden="true">·</span>
                  <span>{selectedFinding.ruleId}</span>
                </div>
                <h2 className="mt-1.5 font-display text-lg font-semibold text-slate-900">
                  {selectedFinding.ruleName}
                </h2>
                <p className="mt-0.5 text-xs text-slate-500">
                  {selectedFinding.owaspCategory} · {selectedFinding.filePath}:{selectedFinding.line}
                </p>
              </div>

              <div className="pt-3 border-t border-slate-100 space-y-2">
                <div className="text-xs font-medium text-slate-500">Taint Trace</div>
                <div className="font-mono text-xs bg-slate-50 border border-slate-200 rounded px-3 py-2 text-slate-800">
                  {selectedFinding.taintFlow}
                </div>
              </div>

              <div className="space-y-1.5">
                <div className="text-xs font-medium text-slate-500">Vulnerability Analysis</div>
                <p className="text-sm text-slate-700 leading-relaxed">
                  {selectedFinding.description}
                </p>
              </div>

              <div className="space-y-1.5">
                <div className="text-xs font-medium text-slate-500">Secure Coding Guidance</div>
                <p className="text-sm text-slate-700 leading-relaxed">
                  {selectedFinding.recommendation}
                </p>
              </div>

              {/* Remediation Diff Preview */}
              <div className="space-y-2 pt-2 border-t border-slate-100">
                <div className="flex items-center justify-between gap-2">
                  <span className="text-xs font-medium text-slate-500">
                    {selectedFinding.aiPatch ? 'Context-Aware Patch Diff' : 'Remediation Pattern'}
                  </span>
                  <button
                    type="button"
                    onClick={() => onGenerateAiPatch(selectedFinding)}
                    disabled={generatingPatchForId === selectedFinding.id}
                    className="inline-flex items-center gap-1.5 px-2.5 py-1 text-xs font-medium text-blue-700 bg-blue-50 hover:bg-blue-100 rounded transition-colors whitespace-nowrap shrink-0 disabled:opacity-50"
                  >
                    <Sparkles className="w-3.5 h-3.5" />
                    <span>
                      {generatingPatchForId === selectedFinding.id
                        ? 'Generating Patch...'
                        : 'Generate Context Patch'}
                    </span>
                  </button>
                </div>

                <div className="rounded-md overflow-hidden border border-slate-200 font-mono text-xs">
                  <div className="bg-red-50 text-red-900 px-3 py-2 border-b border-red-100 overflow-x-auto whitespace-pre">
                    - {selectedFinding.codeLine}
                  </div>
                  <div className="bg-emerald-50 text-emerald-900 px-3 py-2 overflow-x-auto whitespace-pre">
                    + {selectedFinding.aiPatch?.patchedSnippet ?? selectedFinding.remediationExample.secure}
                  </div>
                </div>

                {selectedFinding.aiPatch?.explanation && (
                  <p className="text-xs text-slate-600 leading-relaxed">
                    {selectedFinding.aiPatch.explanation}
                  </p>
                )}

                {selectedFinding.status !== 'remediated' && (
                  <button
                    type="button"
                    onClick={() =>
                      onApplyRemediationPatch(
                        selectedFinding,
                        selectedFinding.aiPatch?.patchedSnippet ??
                          selectedFinding.remediationExample.secure
                      )
                    }
                    className="w-full inline-flex items-center justify-center gap-2 px-4 py-2 text-xs font-semibold text-white bg-emerald-700 hover:bg-emerald-800 rounded-md transition-colors whitespace-nowrap"
                  >
                    <Wrench className="w-3.5 h-3.5" />
                    <span>Apply Patch to Source File</span>
                  </button>
                )}
              </div>

              {/* Manual Review Triage & Notes */}
              <div className="pt-3 border-t border-slate-200 space-y-3">
                <div className="grid grid-cols-2 gap-3">
                  <div>
                    <label
                      htmlFor="finding-status-select"
                      className="block text-xs font-medium text-slate-600 mb-1"
                    >
                      Audit Status
                    </label>
                    <select
                      id="finding-status-select"
                      value={currentStatusValue}
                      onChange={(e) => setDraftStatus(e.target.value as FindingStatus)}
                      className="w-full px-2.5 py-1.5 text-xs bg-white border border-slate-300 rounded-md text-slate-900"
                    >
                      <option value="open">Open</option>
                      <option value="confirmed">Confirmed</option>
                      <option value="remediated">Remediated</option>
                      <option value="false_positive">False Positive</option>
                    </select>
                  </div>
                  <div className="flex items-end">
                    <button
                      type="button"
                      onClick={handleSaveTriage}
                      disabled={savingTriage}
                      className="w-full inline-flex items-center justify-center gap-1.5 px-3 py-1.5 text-xs font-medium text-white bg-slate-900 hover:bg-slate-800 rounded-md transition-colors whitespace-nowrap disabled:opacity-50"
                    >
                      <Check className="w-3.5 h-3.5" />
                      <span>{savingTriage ? 'Saving...' : 'Save Triage'}</span>
                    </button>
                  </div>
                </div>

                <div>
                  <label
                    htmlFor="reviewer-notes-input"
                    className="block text-xs font-medium text-slate-600 mb-1"
                  >
                    Auditor Verification Notes
                  </label>
                  <textarea
                    id="reviewer-notes-input"
                    rows={2}
                    value={currentNotesValue}
                    onChange={(e) => setDraftNotes(e.target.value)}
                    placeholder="Document manual verification evidence, exploitability, or ticket reference..."
                    className="w-full px-3 py-2 text-xs bg-slate-50 border border-slate-200 rounded-md text-slate-900 placeholder:text-slate-400 focus:outline-none focus:border-blue-500"
                  />
                </div>
              </div>
            </section>
          ) : (
            <div className="bg-white border border-slate-200 rounded-lg p-6 text-center">
              <p className="text-sm font-medium text-slate-900">
                No static findings detected in {target.name}
              </p>
              <p className="mt-1 text-xs text-slate-500">
                Run a Deep Semantic Review below to inspect business logic, authorization boundaries, and multi-function flows.
              </p>
            </div>
          )}

          {/* Deep Semantic Architecture Review */}
          <section
            aria-label="Deep semantic security review"
            className="bg-white border border-slate-200 rounded-lg p-5 space-y-4"
          >
            <div className="flex items-center justify-between gap-3">
              <div>
                <h3 className="font-display text-sm font-semibold text-slate-900">
                  Deep Semantic Review
                </h3>
                <p className="text-xs text-slate-500">
                  Business-logic, auth boundary, and multi-file taint inspection
                </p>
              </div>
              <button
                type="button"
                onClick={onRunDeepReview}
                disabled={runningDeepReview}
                className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-white bg-blue-600 hover:bg-blue-700 rounded-md transition-colors whitespace-nowrap shrink-0 disabled:opacity-50"
              >
                <AlertTriangle className="w-3.5 h-3.5" />
                <span>{runningDeepReview ? 'Auditing...' : 'Analyze Architecture'}</span>
              </button>
            </div>

            {deepReview ? (
              <div className="space-y-4 pt-3 border-t border-slate-100">
                <p className="text-sm text-slate-700 leading-relaxed">{deepReview.summary}</p>
                <div className="text-xs text-slate-500">
                  Model: {deepReview.modelUsed} · Generated{' '}
                  {new Date(deepReview.generatedAt).toLocaleTimeString()}
                </div>

                {deepReview.semanticFindings.length > 0 && (
                  <div className="space-y-3">
                    <div className="text-xs font-medium text-slate-500">
                      Additional Semantic Findings ({deepReview.semanticFindings.length})
                    </div>
                    <div className="divide-y divide-slate-100 border border-slate-200 rounded-md">
                      {deepReview.semanticFindings.map((sf, idx) => (
                        <div key={idx} className="p-3 space-y-1.5">
                          <div className="flex items-baseline justify-between gap-2">
                            <span className="text-sm font-medium text-slate-900">{sf.title}</span>
                            <span className={`text-xs font-mono ${SEVERITY_TEXT_CLASS[sf.severity]}`}>
                              {SEVERITY_LABEL[sf.severity]} · {sf.cweId}
                            </span>
                          </div>
                          <p className="text-xs text-slate-600">{sf.attackScenario}</p>
                          <p className="text-xs text-slate-700 font-medium">
                            Fix: {sf.remediationSteps}
                          </p>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {deepReview.prioritizedRoadmap.length > 0 && (
                  <div className="space-y-1.5">
                    <div className="text-xs font-medium text-slate-500">Remediation Roadmap</div>
                    <ol className="list-decimal list-inside space-y-1 text-xs text-slate-700">
                      {deepReview.prioritizedRoadmap.map((step, i) => (
                        <li key={i}>{step}</li>
                      ))}
                    </ol>
                  </div>
                )}
              </div>
            ) : (
              <p className="text-xs text-slate-500 pt-2 border-t border-slate-100">
                Deterministic SAST + entropy analysis runs automatically on every edit. Click &ldquo;Analyze Architecture&rdquo; to inspect cross-file trust boundaries and logic flaws.
              </p>
            )}
          </section>
        </div>
      </div>
    </div>
  );
};
