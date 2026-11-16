export type Language = 'python' | 'typescript' | 'javascript' | 'go' | 'sql' | 'json' | 'text';

export type Severity = 'critical' | 'high' | 'medium' | 'low';

export type FindingStatus = 'open' | 'confirmed' | 'remediated' | 'false_positive';

export interface DependencyVulnerability {
  id: string;
  advisoryId: string;
  packageName: string;
  installedVersion: string;
  ecosystem: 'npm' | 'PyPI' | 'Go';
  severity: Severity;
  cvssScore: number;
  summary: string;
  fixedVersion: string | null;
  referenceUrl: string | null;
  manifestPath: string;
}

export interface SastRule {
  id: string;
  name: string;
  category: string;
  owaspCategory: string;
  cweId: string;
  cvssScore: number;
  severity: Severity;
  languages: Language[];
  patternSource: string;
  flags: string;
  description: string;
  recommendation: string;
  remediationExample: {
    vulnerable: string;
    secure: string;
  };
  enabled: boolean;
  isCustom?: boolean;
}

export interface Finding {
  id: string;
  ruleId: string;
  ruleName: string;
  filePath: string;
  language: Language;
  line: number;
  column: number;
  codeLine: string;
  contextBefore: string[];
  contextAfter: string[];
  severity: Severity;
  cvssScore: number;
  cweId: string;
  owaspCategory: string;
  category: string;
  description: string;
  recommendation: string;
  remediationExample: {
    vulnerable: string;
    secure: string;
  };
  taintFlow: string;
  status: FindingStatus;
  source: 'sast' | 'ai-semantic' | 'entropy';
  reviewerNotes: string;
  aiPatch?: {
    patchedSnippet: string;
    explanation: string;
    confidence: string;
  };
}

export interface CodeFile {
  path: string;
  language: Language;
  content: string;
}

export interface AuditTarget {
  id: string;
  name: string;
  stack: string;
  description: string;
  files: CodeFile[];
  isCustom?: boolean;
  sourceKind?: 'sample' | 'github' | 'folder' | 'workspace' | 'custom';
  sourceUrl?: string;
}

export interface SemanticFinding {
  title: string;
  severity: Severity;
  cweId: string;
  owaspCategory: string;
  affectedLocation: string;
  attackScenario: string;
  remediationSteps: string;
  secureCodeSnippet: string;
}

export interface DeepReviewResult {
  summary: string;
  architecturePosture: string;
  semanticFindings: SemanticFinding[];
  prioritizedRoadmap: string[];
  modelUsed: string;
  generatedAt: string;
}

export interface AuditMetrics {
  totalFindings: number;
  openFindings: number;
  confirmedFindings: number;
  remediatedFindings: number;
  falsePositiveFindings: number;
  riskScore: number;
  securityPostureGrade: 'A' | 'B' | 'C' | 'D' | 'F';
  severityCounts: Record<Severity, number>;
  owaspBreakdown: Array<{ category: string; count: number; openCount: number }>;
  topCwes: Array<{ cweId: string; count: number }>;
}

export interface PersistedAuditState {
  targetId: string;
  findingOverrides: Record<string, { status: FindingStatus; reviewerNotes: string; aiPatch?: Finding['aiPatch'] }>;
  remediatedArchive?: Record<string, Finding>;
  targetFileOverrides?: Record<string, Record<string, string>>;
  customRules: SastRule[];
  disabledRuleIds: string[];
  customTarget?: AuditTarget;
  importedTargets?: AuditTarget[];
  dependencyVulnsByTarget?: Record<string, DependencyVulnerability[]>;
  dependencyStatusByTarget?: Record<string, string>;
  deepReviews: Record<string, DeepReviewResult>;
  updatedAt: string;
}
