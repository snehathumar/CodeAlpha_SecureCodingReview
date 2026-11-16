import React from 'react';
import { FileCode2, ShieldCheck, SlidersHorizontal, FileText, Plus } from 'lucide-react';
import type { AuditMetrics, AuditTarget } from '../types/audit';

export type WorkspaceTab = 'auditor' | 'rules' | 'report';

interface SidebarNavProps {
  activeTab: WorkspaceTab;
  onSelectTab: (tab: WorkspaceTab) => void;
  targets: AuditTarget[];
  selectedTargetId: string;
  onSelectTarget: (targetId: string) => void;
  onCreateCustomTarget: () => void;
  onDeleteImportedTarget: (targetId: string) => void;
  metrics: AuditMetrics;
}

const GRADE_STYLE: Record<AuditMetrics['securityPostureGrade'], string> = {
  A: 'text-emerald-700',
  B: 'text-emerald-700',
  C: 'text-amber-700',
  D: 'text-orange-700',
  F: 'text-red-700',
};

export const SidebarNav: React.FC<SidebarNavProps> = ({
  activeTab,
  onSelectTab,
  targets,
  selectedTargetId,
  onSelectTarget,
  onCreateCustomTarget,
  onDeleteImportedTarget,
  metrics,
}) => {
  const navItems: Array<{ id: WorkspaceTab; label: string; icon: React.ReactNode }> = [
    { id: 'auditor', label: 'Code Auditor', icon: <FileCode2 className="w-4 h-4 shrink-0" /> },
    { id: 'rules', label: 'Rules Engine', icon: <SlidersHorizontal className="w-4 h-4 shrink-0" /> },
    { id: 'report', label: 'Audit Report', icon: <FileText className="w-4 h-4 shrink-0" /> },
  ];

  return (
    <aside className="w-full lg:w-[248px] shrink-0 bg-white border-b lg:border-b-0 lg:border-r border-slate-200 flex flex-col justify-between">
      <div>
        <div className="px-4 lg:px-5 py-3 lg:py-4 border-b border-slate-200 flex items-center justify-between gap-2.5">
          <div className="flex items-center gap-2.5">
            <ShieldCheck className="w-5 h-5 text-blue-600 shrink-0" />
            <span className="font-display font-bold text-base tracking-tight text-slate-900 whitespace-nowrap">
              Aegis Code Audit
            </span>
          </div>
          <button
            type="button"
            onClick={onCreateCustomTarget}
            className="lg:hidden inline-flex items-center gap-1 text-xs font-medium text-blue-600 hover:text-blue-700 whitespace-nowrap shrink-0 px-2 py-1 rounded border border-blue-200 bg-blue-50/60"
          >
            <Plus className="w-3.5 h-3.5" />
            <span>Custom</span>
          </button>
        </div>

        <nav aria-label="Workspace navigation" className="px-3 py-2 lg:p-3 border-b border-slate-200">
          <p className="hidden lg:block px-2.5 pb-1.5 text-xs font-medium text-slate-500">Workbench</p>
          <div className="flex lg:flex-col gap-1 overflow-x-auto">
            {navItems.map((item) => {
              const isActive = activeTab === item.id;
              return (
                <button
                  key={item.id}
                  type="button"
                  onClick={() => onSelectTab(item.id)}
                  className={`flex items-center gap-2 px-2.5 lg:px-3 py-1.5 lg:py-2 rounded-md text-xs lg:text-sm font-medium transition-colors whitespace-nowrap shrink-0 text-left ${
                    isActive
                      ? 'bg-slate-900 text-white'
                      : 'text-slate-700 hover:bg-slate-100 hover:text-slate-900'
                  }`}
                >
                  {item.icon}
                  <span>{item.label}</span>
                </button>
              );
            })}
          </div>
        </nav>

        <div className="p-3 hidden lg:block">
          <div className="flex items-center justify-between px-2.5 pb-2">
            <p className="text-xs font-medium text-slate-500">Projects</p>
            <button
              type="button"
              onClick={onCreateCustomTarget}
              className="inline-flex items-center gap-1 text-xs font-medium text-blue-600 hover:text-blue-700 whitespace-nowrap shrink-0 focus-visible:outline-2 focus-visible:outline-blue-600 rounded px-1 py-0.5"
              aria-label="New custom audit snippet"
            >
              <Plus className="w-3.5 h-3.5" />
              <span>Custom</span>
            </button>
          </div>
          <div className="space-y-1 max-h-[380px] overflow-y-auto">
            {targets.map((target) => {
              const selected = target.id === selectedTargetId;
              const isRemovable = Boolean(target.sourceKind && target.sourceKind !== 'sample');
              return (
                <div key={target.id} className="group flex items-center gap-1">
                  <button
                    type="button"
                    onClick={() => {
                      onSelectTarget(target.id);
                      onSelectTab('auditor');
                    }}
                    className={`flex-1 min-w-0 text-left px-3 py-2 rounded-md transition-colors border ${
                      selected
                        ? 'bg-blue-50/70 border-blue-200 text-slate-900'
                        : 'border-transparent text-slate-700 hover:bg-slate-50'
                    }`}
                  >
                    <div className="text-sm font-medium truncate">{target.name}</div>
                    <div className="text-xs text-slate-500 truncate">{target.stack}</div>
                  </button>
                  {isRemovable && (
                    <button
                      type="button"
                      onClick={() => onDeleteImportedTarget(target.id)}
                      aria-label={`Remove ${target.name}`}
                      className="px-1.5 py-1 text-xs text-slate-400 hover:text-red-600 rounded transition-colors shrink-0"
                    >
                      ×
                    </button>
                  )}
                </div>
              );
            })}
          </div>
        </div>
      </div>

      <div className="hidden lg:block p-4 border-t border-slate-200 bg-slate-50/60">
        <div className="flex items-baseline justify-between mb-2">
          <span className="text-xs font-medium text-slate-500">Posture Grade</span>
          <span className={`font-display text-xl font-bold tabular-nums ${GRADE_STYLE[metrics.securityPostureGrade]}`}>
            {metrics.securityPostureGrade}
          </span>
        </div>
        <div className="w-full h-1.5 bg-slate-200 rounded-full overflow-hidden mb-3">
          <div
            className={`h-full transition-all duration-200 ${
              metrics.riskScore >= 50
                ? 'bg-red-600'
                : metrics.riskScore >= 25
                ? 'bg-amber-500'
                : 'bg-emerald-600'
            }`}
            style={{ width: `${Math.max(4, metrics.riskScore)}%` }}
          />
        </div>
        <div className="flex items-center justify-between text-xs text-slate-600 tabular-nums">
          <span>Risk Index: {metrics.riskScore}/100</span>
          <span>
            {metrics.openFindings + metrics.confirmedFindings} open · {metrics.remediatedFindings} fixed
          </span>
        </div>
      </div>
    </aside>
  );
};
