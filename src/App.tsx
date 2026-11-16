import React, { useCallback, useEffect, useMemo, useState } from 'react';
import { RefreshCw, RotateCcw, ShieldAlert } from 'lucide-react';
import { DEFAULT_SAST_RULES } from './utils/sastRules';
import {
  applyLinePatch,
  computeSecurityMetrics,
  mergeAstFindings,
  scanTarget,
  stripUndefined,
} from './utils/sastEngine';
import type {
  AuditTarget,
  CodeFile,
  DeepReviewResult,
  DependencyVulnerability,
  Finding,
  FindingStatus,
  Language,
  PersistedAuditState,
  SastRule,
} from './types/audit';
import { SidebarNav, type WorkspaceTab } from './components/SidebarNav';
import { CodeAuditorView } from './components/CodeAuditorView';
import { RulesEngineView } from './components/RulesEngineView';
import { AuditReportView } from './components/AuditReportView';

const DEFAULT_CUSTOM_TARGET: AuditTarget = {
  id: 'custom-snippet',
  name: 'Custom Audit Workspace',
  stack: 'Custom Source Upload / Paste',
  sourceKind: 'custom',
  description:
    'User-supplied application source or manifest files for real-time SAST, entropy, and CVE auditing.',
  isCustom: true,
  files: [
    {
      path: 'handler.ts',
      language: 'typescript',
      content: `// Paste your source file or click "Upload File" / "Upload Project Folder" above to run a live audit.\n`,
    },
  ],
};

export default function App() {
  const [activeTab, setActiveTab] = useState<WorkspaceTab>('auditor');
  const [targets, setTargets] = useState<AuditTarget[]>([]);
  const [selectedTargetId, setSelectedTargetId] = useState<string>('local-workspace');
  const [activeFilePath, setActiveFilePath] = useState<string>('server.ts');
  const [selectedFindingId, setSelectedFindingId] = useState<string | null>(null);
  const [hydratingWorkspace, setHydratingWorkspace] = useState(true);

  const [findingOverrides, setFindingOverrides] = useState<
    Record<string, { status: FindingStatus; reviewerNotes: string; aiPatch?: Finding['aiPatch'] }>
  >({});
  const [remediatedArchive, setRemediatedArchive] = useState<Record<string, Finding>>({});
  const [targetFileOverrides, setTargetFileOverrides] = useState<Record<string, Record<string, string>>>({});
  const [customRules, setCustomRules] = useState<SastRule[]>([]);
  const [disabledRuleIds, setDisabledRuleIds] = useState<string[]>([]);
  const [deepReviews, setDeepReviews] = useState<Record<string, DeepReviewResult>>({});

  const [generatingPatchForId, setGeneratingPatchForId] = useState<string | null>(null);
  const [runningDeepReview, setRunningDeepReview] = useState(false);
  const [importingGithub, setImportingGithub] = useState(false);
  const [auditingWorkspace, setAuditingWorkspace] = useState(false);
  const [scanningDependencies, setScanningDependencies] = useState(false);
  const [dependencyVulnsByTarget, setDependencyVulnsByTarget] = useState<
    Record<string, DependencyVulnerability[]>
  >({});
  const [dependencyStatusByTarget, setDependencyStatusByTarget] = useState<
    Record<string, string>
  >({});
  const [pythonAstFindingsByTarget, setPythonAstFindingsByTarget] = useState<
    Record<string, Finding[]>
  >({});
  const [astFallbackNotice, setAstFallbackNotice] = useState<string | null>(null);
  const [scanPulseCount, setScanPulseCount] = useState(0);

  const [persistError, setPersistError] = useState<string | null>(null);
  const [pendingStateToRetry, setPendingStateToRetry] = useState<PersistedAuditState | null>(null);
  const [actionNotice, setActionNotice] = useState<string | null>(null);

  const persistWorkspace = useCallback(
    async (nextState: PersistedAuditState) => {
      const cleaned = stripUndefined(nextState);
      setPersistError(null);
      setPendingStateToRetry(null);
      try {
        const res = await fetch('/api/state', {
          method: 'PUT',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(cleaned),
        });
        if (!res.ok) {
          throw new Error(`Persistence error (${res.status})`);
        }
      } catch (err) {
        setPendingStateToRetry(cleaned);
        setPersistError(
          err instanceof Error
            ? `Unable to save audit state to server: ${err.message}`
            : 'Unable to save audit state to server.'
        );
      }
    },
    []
  );

  // Hydrate persisted state from server on mount; if empty, auto-audit the live workspace codebase
  useEffect(() => {
    let cancelled = false;
    async function loadState() {
      try {
        const res = await fetch('/api/state');
        const data = res.ok ? ((await res.json()) as PersistedAuditState) : null;
        if (cancelled) return;

        const fileOverrides =
          data?.targetFileOverrides && typeof data.targetFileOverrides === 'object'
            ? data.targetFileOverrides
            : {};
        setTargetFileOverrides(fileOverrides);

        const imported = Array.isArray(data?.importedTargets) ? data.importedTargets : [];
        let baseTargets = [
          ...imported,
          ...(data?.customTarget ? [data.customTarget] : []),
        ].map((t) => {
          const perFile = fileOverrides[t.id];
          if (!perFile) return t;
          return {
            ...t,
            files: t.files.map((f) =>
              typeof perFile[f.path] === 'string' ? { ...f, content: perFile[f.path] } : f
            ),
          };
        });

        let depVulns =
          data?.dependencyVulnsByTarget && typeof data.dependencyVulnsByTarget === 'object'
            ? data.dependencyVulnsByTarget
            : {};
        let depStatus =
          data?.dependencyStatusByTarget && typeof data.dependencyStatusByTarget === 'object'
            ? data.dependencyStatusByTarget
            : {};

        if (baseTargets.length === 0) {
          const wsRes = await fetch('/api/audit/workspace', { method: 'POST' });
          if (wsRes.ok && !cancelled) {
            const wsData = (await wsRes.json()) as {
              target: AuditTarget;
              depScan?: { vulnerabilities: DependencyVulnerability[]; statusMessage: string };
            };
            baseTargets = [wsData.target];
            if (wsData.depScan) {
              depVulns = { ...depVulns, [wsData.target.id]: wsData.depScan.vulnerabilities };
              depStatus = { ...depStatus, [wsData.target.id]: wsData.depScan.statusMessage };
            }
          } else {
            baseTargets = [DEFAULT_CUSTOM_TARGET];
          }
        }

        if (cancelled) return;

        setTargets(baseTargets);
        setDependencyVulnsByTarget(depVulns);
        setDependencyStatusByTarget(depStatus);

        const initialId =
          data?.targetId && baseTargets.some((t) => t.id === data.targetId)
            ? data.targetId
            : baseTargets[0].id;
        setSelectedTargetId(initialId);
        const initialTarget = baseTargets.find((t) => t.id === initialId) ?? baseTargets[0];
        if (initialTarget?.files[0]) {
          setActiveFilePath(initialTarget.files[0].path);
        }

        if (data?.findingOverrides) setFindingOverrides(data.findingOverrides);
        if (data?.remediatedArchive) setRemediatedArchive(data.remediatedArchive);
        if (Array.isArray(data?.customRules)) setCustomRules(data.customRules);
        if (Array.isArray(data?.disabledRuleIds)) setDisabledRuleIds(data.disabledRuleIds);
        if (data?.deepReviews) setDeepReviews(data.deepReviews);
      } catch {
        if (!cancelled) {
          setTargets([DEFAULT_CUSTOM_TARGET]);
          setSelectedTargetId(DEFAULT_CUSTOM_TARGET.id);
          setActiveFilePath(DEFAULT_CUSTOM_TARGET.files[0].path);
        }
      } finally {
        if (!cancelled) setHydratingWorkspace(false);
      }
    }
    loadState();
    return () => {
      cancelled = true;
    };
  }, []);

  const buildCurrentState = useCallback(
    (overrides?: Partial<PersistedAuditState>, overrideTargets?: AuditTarget[]): PersistedAuditState => {
      const sourceTargets = overrideTargets ?? targets;
      const customTarget = sourceTargets.find((t) => t.isCustom);
      const importedTargets = sourceTargets.filter((t) => !t.isCustom);
      return {
        targetId: overrides?.targetId ?? selectedTargetId,
        findingOverrides: overrides?.findingOverrides ?? findingOverrides,
        remediatedArchive: overrides?.remediatedArchive ?? remediatedArchive,
        targetFileOverrides: overrides?.targetFileOverrides ?? targetFileOverrides,
        customRules: overrides?.customRules ?? customRules,
        disabledRuleIds: overrides?.disabledRuleIds ?? disabledRuleIds,
        ...(overrides?.customTarget !== undefined
          ? overrides.customTarget
            ? { customTarget: overrides.customTarget }
            : {}
          : customTarget
          ? { customTarget }
          : {}),
        importedTargets: overrides?.importedTargets ?? importedTargets,
        dependencyVulnsByTarget: overrides?.dependencyVulnsByTarget ?? dependencyVulnsByTarget,
        dependencyStatusByTarget: overrides?.dependencyStatusByTarget ?? dependencyStatusByTarget,
        deepReviews: overrides?.deepReviews ?? deepReviews,
        updatedAt: new Date().toISOString(),
      };
    },
    [
      targets,
      selectedTargetId,
      findingOverrides,
      remediatedArchive,
      targetFileOverrides,
      customRules,
      disabledRuleIds,
      dependencyVulnsByTarget,
      dependencyStatusByTarget,
      deepReviews,
    ]
  );

  const allRules = useMemo(() => {
    const merged = [...DEFAULT_SAST_RULES, ...customRules];
    return merged.map((r) => ({
      ...r,
      enabled: !disabledRuleIds.includes(r.id),
    }));
  }, [customRules, disabledRuleIds]);

  const currentTarget = useMemo(
    () => targets.find((t) => t.id === selectedTargetId) ?? targets[0] ?? DEFAULT_CUSTOM_TARGET,
    [targets, selectedTargetId]
  );

  // Trigger server-side Python AST analysis whenever the current target contains Python source files
  useEffect(() => {
    const hasPython = currentTarget.files.some((f) => f.language === 'python');
    if (!hasPython) {
      setAstFallbackNotice(null);
      return;
    }

    let cancelled = false;
    async function runPyAst() {
      try {
        const res = await fetch('/api/audit/ast', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            files: currentTarget.files.filter((f) => f.language === 'python'),
            disabledRuleIds,
          }),
        });
        if (!res.ok || cancelled) return;
        const data = (await res.json()) as {
          pythonAstAvailable: boolean;
          fallbackNotice: string | null;
          findings: Finding[];
        };
        if (cancelled) return;
        setAstFallbackNotice(data.pythonAstAvailable ? null : data.fallbackNotice);
        setPythonAstFindingsByTarget((prev) => ({
          ...prev,
          [currentTarget.id]: data.findings,
        }));
      } catch {
        // Non-blocking fallback to regex rules
      }
    }
    void runPyAst();
    return () => {
      cancelled = true;
    };
  }, [currentTarget, disabledRuleIds, scanPulseCount]);

  const findings = useMemo(() => {
    const baseFindings = scanTarget(currentTarget, allRules, findingOverrides);
    const pyAstFindings = pythonAstFindingsByTarget[currentTarget.id] ?? [];
    const liveFindings = mergeAstFindings(baseFindings, pyAstFindings, findingOverrides);
    const liveIds = new Set(liveFindings.map((f) => f.id));
    const archivedForTarget = Object.values(remediatedArchive).filter(
      (archived) =>
        !liveIds.has(archived.id) &&
        currentTarget.files.some((f) => f.path === archived.filePath)
    );
    return [...liveFindings, ...archivedForTarget];
  }, [
    currentTarget,
    allRules,
    findingOverrides,
    pythonAstFindingsByTarget,
    remediatedArchive,
    scanPulseCount,
  ]);

  const metrics = useMemo(() => computeSecurityMetrics(findings), [findings]);

  const handleSelectTarget = (targetId: string) => {
    setSelectedTargetId(targetId);
    const next = targets.find((t) => t.id === targetId);
    if (next?.files[0]) {
      setActiveFilePath(next.files[0].path);
    }
    setSelectedFindingId(null);
    void persistWorkspace(buildCurrentState({ targetId }));
  };

  const handleCreateCustomTarget = () => {
    const existingCustom = targets.find((t) => t.isCustom);
    const customTarget = existingCustom ?? DEFAULT_CUSTOM_TARGET;
    const nextTargets = existingCustom ? targets : [...targets, customTarget];
    if (!existingCustom) {
      setTargets(nextTargets);
    }
    setSelectedTargetId(customTarget.id);
    setActiveFilePath(customTarget.files[0].path);
    setActiveTab('auditor');
    setSelectedFindingId(null);
    void persistWorkspace(
      buildCurrentState({ targetId: customTarget.id, customTarget }, nextTargets)
    );
  };

  const handleUpdateFileContent = (path: string, content: string, language?: Language) => {
    const updatedTargets = targets.map((t) => {
      if (t.id !== currentTarget.id) return t;
      return {
        ...t,
        files: t.files.map((f) =>
          f.path === path
            ? { ...f, content, ...(language ? { language } : {}) }
            : f
        ),
      };
    });
    setTargets(updatedTargets);
    const nextFileOverrides = {
      ...targetFileOverrides,
      [currentTarget.id]: {
        ...(targetFileOverrides[currentTarget.id] ?? {}),
        [path]: content,
      },
    };
    setTargetFileOverrides(nextFileOverrides);
    const updatedCustom = updatedTargets.find((t) => t.isCustom);
    void persistWorkspace(
      buildCurrentState(
        {
          targetFileOverrides: nextFileOverrides,
          ...(updatedCustom && currentTarget.isCustom ? { customTarget: updatedCustom } : {}),
        },
        updatedTargets
      )
    );
  };

  const handleUploadFile = async (fileName: string, language: Language, content: string) => {
    const cleanName = fileName.replace(/[^a-zA-Z0-9._/-]/g, '_').slice(0, 80);
    const updatedTargets = targets.map((t) => {
      if (t.id !== currentTarget.id) return t;
      const exists = t.files.some((f) => f.path === cleanName);
      return {
        ...t,
        files: exists
          ? t.files.map((f) => (f.path === cleanName ? { ...f, language, content } : f))
          : [...t.files, { path: cleanName, language, content }],
      };
    });
    setTargets(updatedTargets);
    setActiveFilePath(cleanName);
    setSelectedFindingId(null);

    let nextDepVulns = dependencyVulnsByTarget;
    let nextDepStatus = dependencyStatusByTarget;

    if (/^(?:package\.json|requirements\.txt|go\.mod)$/i.test(cleanName.split('/').pop() ?? '')) {
      const targetFiles = updatedTargets.find((t) => t.id === currentTarget.id)?.files ?? [];
      try {
        const res = await fetch('/api/audit/dependencies', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ files: targetFiles }),
        });
        if (res.ok) {
          const depData = await res.json();
          nextDepVulns = { ...dependencyVulnsByTarget, [currentTarget.id]: depData.vulnerabilities };
          nextDepStatus = { ...dependencyStatusByTarget, [currentTarget.id]: depData.statusMessage };
          setDependencyVulnsByTarget(nextDepVulns);
          setDependencyStatusByTarget(nextDepStatus);
        }
      } catch {
        // Non-blocking manifest scan
      }
    }

    setActionNotice(`Loaded ${cleanName} (${language}) and executed live static scan.`);
    const updatedCustom = updatedTargets.find((t) => t.isCustom);
    void persistWorkspace(
      buildCurrentState(
        {
          ...(updatedCustom && currentTarget.isCustom ? { customTarget: updatedCustom } : {}),
          dependencyVulnsByTarget: nextDepVulns,
          dependencyStatusByTarget: nextDepStatus,
        },
        updatedTargets
      )
    );
  };

  const handleUpdateFindingTriage = async (
    findingId: string,
    status: FindingStatus,
    reviewerNotes: string
  ) => {
    const existing = findingOverrides[findingId];
    const nextOverrides = {
      ...findingOverrides,
      [findingId]: {
        status,
        reviewerNotes,
        ...(existing?.aiPatch ? { aiPatch: existing.aiPatch } : {}),
      },
    };
    setFindingOverrides(nextOverrides);
    await persistWorkspace(buildCurrentState({ findingOverrides: nextOverrides }));
    setActionNotice(`Saved triage status (${status.replace('_', ' ')}) for ${findingId}.`);
  };

  const handleApplyRemediationPatch = async (finding: Finding, patchedLine: string) => {
    const targetFile = currentTarget.files.find((f) => f.path === finding.filePath);
    if (!targetFile) return;

    const patchedCode = applyLinePatch(targetFile.content, finding.line, patchedLine);
    const nextTargets = targets.map((t) => {
      if (t.id !== currentTarget.id) return t;
      return {
        ...t,
        files: t.files.map((f) =>
          f.path === finding.filePath ? { ...f, content: patchedCode } : f
        ),
      };
    });
    setTargets(nextTargets);

    const nextOverrides = {
      ...findingOverrides,
      [finding.id]: {
        status: 'remediated' as FindingStatus,
        reviewerNotes:
          findingOverrides[finding.id]?.reviewerNotes ||
          `Patched line ${finding.line} via remediation workflow.`,
        ...(finding.aiPatch ? { aiPatch: finding.aiPatch } : {}),
      },
    };
    setFindingOverrides(nextOverrides);

    const nextArchive = {
      ...remediatedArchive,
      [finding.id]: {
        ...finding,
        status: 'remediated' as FindingStatus,
        reviewerNotes: nextOverrides[finding.id].reviewerNotes,
      },
    };
    setRemediatedArchive(nextArchive);

    const nextFileOverrides = {
      ...targetFileOverrides,
      [currentTarget.id]: {
        ...(targetFileOverrides[currentTarget.id] ?? {}),
        [finding.filePath]: patchedCode,
      },
    };
    setTargetFileOverrides(nextFileOverrides);

    const updatedCustom = nextTargets.find((t) => t.isCustom);
    await persistWorkspace(
      buildCurrentState(
        {
          findingOverrides: nextOverrides,
          remediatedArchive: nextArchive,
          targetFileOverrides: nextFileOverrides,
          ...(updatedCustom ? { customTarget: updatedCustom } : {}),
        },
        nextTargets
      )
    );
    setActionNotice(`Applied secure patch to ${finding.filePath}:${finding.line}.`);
  };

  const handleGenerateAiPatch = async (finding: Finding) => {
    setGeneratingPatchForId(finding.id);
    setPersistError(null);
    try {
      const surroundingContext = [
        ...finding.contextBefore,
        finding.codeLine,
        ...finding.contextAfter,
      ].join('\n');

      const res = await fetch('/api/audit/remediate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          ruleName: finding.ruleName,
          cweId: finding.cweId,
          language: finding.language,
          filePath: finding.filePath,
          line: finding.line,
          codeLine: finding.codeLine,
          surroundingContext,
        }),
      });
      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.error || 'Failed to generate remediation patch.');
      }

      const aiPatch: Finding['aiPatch'] = {
        patchedSnippet: data.patchedSnippet,
        explanation: data.explanation,
        confidence: data.confidence,
      };

      const existing = findingOverrides[finding.id];
      const nextOverrides = {
        ...findingOverrides,
        [finding.id]: {
          status: existing?.status ?? finding.status,
          reviewerNotes: existing?.reviewerNotes ?? finding.reviewerNotes,
          aiPatch,
        },
      };
      setFindingOverrides(nextOverrides);
      await persistWorkspace(buildCurrentState({ findingOverrides: nextOverrides }));
    } catch (err) {
      setPersistError(
        err instanceof Error
          ? err.message
          : 'Unable to generate context-aware patch.'
      );
    } finally {
      setGeneratingPatchForId(null);
    }
  };

  const handleRunDeepReview = async () => {
    setRunningDeepReview(true);
    setPersistError(null);
    try {
      const res = await fetch('/api/audit/deep-review', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          targetName: currentTarget.name,
          stack: currentTarget.stack,
          files: currentTarget.files,
          existingFindings: findings.map((f) => ({
            ruleId: f.ruleId,
            ruleName: f.ruleName,
            filePath: f.filePath,
            line: f.line,
            cweId: f.cweId,
            severity: f.severity,
          })),
        }),
      });
      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.error || 'Deep semantic review failed.');
      }

      const nextReviews = {
        ...deepReviews,
        [currentTarget.id]: data as DeepReviewResult,
      };
      setDeepReviews(nextReviews);
      await persistWorkspace(buildCurrentState({ deepReviews: nextReviews }));
      setActionNotice(`Completed architectural deep review for ${currentTarget.name}.`);
    } catch (err) {
      setPersistError(
        err instanceof Error ? err.message : 'Unable to complete deep semantic review.'
      );
    } finally {
      setRunningDeepReview(false);
    }
  };

  const handleToggleRule = (ruleId: string) => {
    const nextDisabled = disabledRuleIds.includes(ruleId)
      ? disabledRuleIds.filter((id) => id !== ruleId)
      : [...disabledRuleIds, ruleId];
    setDisabledRuleIds(nextDisabled);
    void persistWorkspace(buildCurrentState({ disabledRuleIds: nextDisabled }));
  };

  const handleAddCustomRule = (rule: SastRule) => {
    const nextCustom = [...customRules, rule];
    setCustomRules(nextCustom);
    void persistWorkspace(buildCurrentState({ customRules: nextCustom }));
    setActionNotice(`Added custom SAST rule ${rule.id} (${rule.name}).`);
  };

  const handleDeleteCustomRule = (ruleId: string) => {
    const nextCustom = customRules.filter((r) => r.id !== ruleId);
    setCustomRules(nextCustom);
    void persistWorkspace(buildCurrentState({ customRules: nextCustom }));
  };

  const upsertAndSelectImportedTarget = async (
    newTarget: AuditTarget,
    depScan?: { vulnerabilities: DependencyVulnerability[]; statusMessage: string }
  ) => {
    const filtered = targets.filter((t) => t.id !== newTarget.id);
    const nextTargets = [newTarget, ...filtered];
    setTargets(nextTargets);
    setSelectedTargetId(newTarget.id);
    if (newTarget.files[0]) {
      setActiveFilePath(newTarget.files[0].path);
    }
    setSelectedFindingId(null);
    setActiveTab('auditor');

    const nextDepVulns = depScan
      ? { ...dependencyVulnsByTarget, [newTarget.id]: depScan.vulnerabilities }
      : dependencyVulnsByTarget;
    const nextDepStatus = depScan
      ? { ...dependencyStatusByTarget, [newTarget.id]: depScan.statusMessage }
      : dependencyStatusByTarget;

    if (depScan) {
      setDependencyVulnsByTarget(nextDepVulns);
      setDependencyStatusByTarget(nextDepStatus);
    }

    await persistWorkspace(
      buildCurrentState(
        {
          targetId: newTarget.id,
          dependencyVulnsByTarget: nextDepVulns,
          dependencyStatusByTarget: nextDepStatus,
        },
        nextTargets
      )
    );
  };

  const handleImportGithubRepo = async (repoUrl: string) => {
    setImportingGithub(true);
    setPersistError(null);
    try {
      const res = await fetch('/api/audit/github', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ repoUrl }),
      });
      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.error || 'Failed to import GitHub repository.');
      }
      await upsertAndSelectImportedTarget(data.target, data.depScan);
      setActionNotice(
        `Imported ${data.target.name} (${data.target.files.length} files). ${data.depScan?.statusMessage ?? ''}`
      );
    } catch (err) {
      setPersistError(err instanceof Error ? err.message : 'GitHub repository import failed.');
    } finally {
      setImportingGithub(false);
    }
  };

  const handleAuditLiveWorkspace = async () => {
    setAuditingWorkspace(true);
    setPersistError(null);
    try {
      const res = await fetch('/api/audit/workspace', { method: 'POST' });
      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.error || 'Failed to scan live workspace.');
      }
      await upsertAndSelectImportedTarget(data.target, data.depScan);
      setActionNotice(
        `Loaded Live Workspace Codebase (${data.target.files.length} files). ${data.depScan?.statusMessage ?? ''}`
      );
    } catch (err) {
      setPersistError(err instanceof Error ? err.message : 'Live workspace scan failed.');
    } finally {
      setAuditingWorkspace(false);
    }
  };

  const handleImportLocalFolder = async (projectName: string, files: CodeFile[]) => {
    setScanningDependencies(true);
    setPersistError(null);
    try {
      const id = `folder-${projectName.toLowerCase().replace(/[^a-z0-9]+/g, '-')}`;
      const newTarget: AuditTarget = {
        id,
        name: projectName,
        stack: `Local Folder · ${files.length} files`,
        description: `Uploaded local project directory (${files.length} source and manifest files).`,
        files,
        sourceKind: 'folder',
      };
      const res = await fetch('/api/audit/dependencies', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ files }),
      });
      const depScan = res.ok ? await res.json() : undefined;
      await upsertAndSelectImportedTarget(newTarget, depScan);
      setActionNotice(
        `Loaded folder "${projectName}" (${files.length} files). ${depScan?.statusMessage ?? ''}`
      );
    } catch (err) {
      setPersistError(err instanceof Error ? err.message : 'Failed to import local folder.');
    } finally {
      setScanningDependencies(false);
    }
  };

  const handleScanDependencies = async () => {
    setScanningDependencies(true);
    setPersistError(null);
    try {
      const res = await fetch('/api/audit/dependencies', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ files: currentTarget.files }),
      });
      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.error || 'Dependency CVE scan failed.');
      }
      const nextDepVulns = {
        ...dependencyVulnsByTarget,
        [currentTarget.id]: data.vulnerabilities,
      };
      const nextDepStatus = {
        ...dependencyStatusByTarget,
        [currentTarget.id]: data.statusMessage,
      };
      setDependencyVulnsByTarget(nextDepVulns);
      setDependencyStatusByTarget(nextDepStatus);
      await persistWorkspace(
        buildCurrentState({
          dependencyVulnsByTarget: nextDepVulns,
          dependencyStatusByTarget: nextDepStatus,
        })
      );
    } catch (err) {
      setPersistError(err instanceof Error ? err.message : 'Dependency CVE scan failed.');
    } finally {
      setScanningDependencies(false);
    }
  };

  const handleDeleteImportedTarget = (targetId: string) => {
    const remaining = targets.filter((t) => t.id !== targetId);
    const nextTargets = remaining.length > 0 ? remaining : [DEFAULT_CUSTOM_TARGET];
    setTargets(nextTargets);
    const nextSelected = selectedTargetId === targetId ? nextTargets[0].id : selectedTargetId;
    setSelectedTargetId(nextSelected);
    const nextTarget = nextTargets.find((t) => t.id === nextSelected);
    if (nextTarget?.files[0]) {
      setActiveFilePath(nextTarget.files[0].path);
    }
    void persistWorkspace(buildCurrentState({ targetId: nextSelected }, nextTargets));
  };

  const handleRunStaticScan = () => {
    setScanPulseCount((c) => c + 1);
    setActionNotice(
      `Static scan completed on ${currentTarget.name}: ${findings.filter((f) => f.status !== 'remediated' && f.status !== 'false_positive').length} active code findings and ${(dependencyVulnsByTarget[currentTarget.id] ?? []).length} dependency CVEs.`
    );
  };

  const tabHeading: Record<WorkspaceTab, string> = {
    auditor: 'Code Auditor',
    rules: 'Rules Engine',
    report: 'Audit Report',
  };

  return (
    <div className="min-h-screen flex flex-col lg:flex-row bg-slate-50 text-slate-900">
      <SidebarNav
        activeTab={activeTab}
        onSelectTab={setActiveTab}
        targets={targets}
        selectedTargetId={currentTarget.id}
        onSelectTarget={handleSelectTarget}
        onCreateCustomTarget={handleCreateCustomTarget}
        onDeleteImportedTarget={handleDeleteImportedTarget}
        metrics={metrics}
      />

      <div className="flex-1 flex flex-col min-w-0">
        {/* Top Bar Contract: Breadcrumb on Left, Single Primary Action on Right */}
        <header className="bg-white border-b border-slate-200 px-6 py-3.5 flex items-center justify-between gap-8">
          <div className="min-w-0 flex items-center gap-2 text-sm">
            <span className="text-slate-500 whitespace-nowrap shrink-0">
              {tabHeading[activeTab]}
            </span>
            <span className="text-slate-300" aria-hidden="true">
              /
            </span>
            <h1 className="font-display font-semibold text-slate-900 truncate">
              {hydratingWorkspace ? 'Loading Live Workspace...' : currentTarget.name}
            </h1>
          </div>

          <button
            type="button"
            onClick={handleRunStaticScan}
            className="inline-flex items-center gap-2 px-4 py-2 text-xs font-semibold text-white bg-slate-900 hover:bg-slate-800 rounded-md transition-colors whitespace-nowrap shrink-0"
          >
            <RefreshCw className="w-3.5 h-3.5" />
            <span>Run Static Scan</span>
          </button>
        </header>

        <main className="flex-1 p-6 max-w-[1360px] w-full mx-auto space-y-5">
          {persistError && (
            <div
              role="alert"
              className="bg-red-50 border border-red-200 rounded-lg px-4 py-3 flex flex-wrap items-center justify-between gap-3"
            >
              <div className="flex items-center gap-2.5 text-xs text-red-900">
                <ShieldAlert className="w-4 h-4 text-red-700 shrink-0" />
                <span>{persistError}</span>
              </div>
              <div className="flex items-center gap-2">
                {pendingStateToRetry && (
                  <button
                    type="button"
                    onClick={() => void persistWorkspace(pendingStateToRetry)}
                    className="inline-flex items-center gap-1.5 px-3 py-1 text-xs font-medium text-red-900 bg-white border border-red-300 hover:bg-red-100 rounded transition-colors whitespace-nowrap"
                  >
                    <RotateCcw className="w-3 h-3" />
                    <span>Retry Save</span>
                  </button>
                )}
                <button
                  type="button"
                  onClick={() => setPersistError(null)}
                  className="text-xs font-medium text-red-700 hover:text-red-900 px-2 py-1"
                >
                  Dismiss
                </button>
              </div>
            </div>
          )}

          {actionNotice && (
            <div
              role="status"
              className="bg-blue-50/70 border border-blue-200 rounded-lg px-4 py-2.5 flex items-center justify-between gap-3 text-xs text-blue-900"
            >
              <span>{actionNotice}</span>
              <button
                type="button"
                onClick={() => setActionNotice(null)}
                className="font-medium text-blue-700 hover:text-blue-900 whitespace-nowrap"
              >
                Dismiss
              </button>
            </div>
          )}

          {activeTab === 'auditor' && (
            <CodeAuditorView
              target={currentTarget}
              targets={targets}
              onSelectTarget={handleSelectTarget}
              activeFilePath={activeFilePath}
              onSelectFile={setActiveFilePath}
              onUpdateFileContent={handleUpdateFileContent}
              onUploadFile={handleUploadFile}
              onImportGithubRepo={handleImportGithubRepo}
              importingGithub={importingGithub}
              onImportLocalFolder={handleImportLocalFolder}
              onAuditLiveWorkspace={handleAuditLiveWorkspace}
              auditingWorkspace={auditingWorkspace}
              findings={findings}
              dependencyVulns={dependencyVulnsByTarget[currentTarget.id] ?? []}
              dependencyScanStatus={dependencyStatusByTarget[currentTarget.id] ?? null}
              scanningDependencies={scanningDependencies}
              onScanDependencies={handleScanDependencies}
              selectedFindingId={selectedFindingId}
              onSelectFinding={setSelectedFindingId}
              metrics={metrics}
              onUpdateFindingTriage={handleUpdateFindingTriage}
              onApplyRemediationPatch={handleApplyRemediationPatch}
              onGenerateAiPatch={handleGenerateAiPatch}
              generatingPatchForId={generatingPatchForId}
              deepReview={deepReviews[currentTarget.id] ?? null}
              onRunDeepReview={handleRunDeepReview}
              runningDeepReview={runningDeepReview}
              activeRuleCount={allRules.filter((r) => r.enabled).length}
              astFallbackNotice={astFallbackNotice}
            />
          )}

          {activeTab === 'rules' && (
            <RulesEngineView
              rules={allRules}
              onToggleRule={handleToggleRule}
              onAddCustomRule={handleAddCustomRule}
              onDeleteCustomRule={handleDeleteCustomRule}
            />
          )}

          {activeTab === 'report' && (
            <AuditReportView
              target={currentTarget}
              findings={findings}
              dependencyVulns={dependencyVulnsByTarget[currentTarget.id] ?? []}
              metrics={metrics}
              deepReview={deepReviews[currentTarget.id] ?? null}
            />
          )}
        </main>
      </div>
    </div>
  );
}
