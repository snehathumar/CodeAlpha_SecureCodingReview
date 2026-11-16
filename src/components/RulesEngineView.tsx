import React, { useMemo, useState } from 'react';
import { Plus, Trash2, Play } from 'lucide-react';
import type { Language, SastRule, Severity } from '../types/audit';

interface RulesEngineViewProps {
  rules: SastRule[];
  onToggleRule: (ruleId: string) => void;
  onAddCustomRule: (rule: SastRule) => void;
  onDeleteCustomRule: (ruleId: string) => void;
}

const ALL_LANGUAGES: Language[] = ['python', 'typescript', 'javascript', 'go', 'sql'];

export const RulesEngineView: React.FC<RulesEngineViewProps> = ({
  rules,
  onToggleRule,
  onAddCustomRule,
  onDeleteCustomRule,
}) => {
  const [langFilter, setLangFilter] = useState<'all' | Language>('all');
  const [ruleName, setRuleName] = useState('');
  const [cweId, setCweId] = useState('CWE-20');
  const [owaspCategory, setOwaspCategory] = useState('A03:2021 Injection');
  const [severity, setSeverity] = useState<Severity>('high');
  const [selectedLangs, setSelectedLangs] = useState<Language[]>(['python', 'typescript']);
  const [patternSource, setPatternSource] = useState('');
  const [description, setDescription] = useState('');
  const [recommendation, setRecommendation] = useState('');
  const [secureExample, setSecureExample] = useState('');
  const [testInput, setTestInput] = useState('');
  const [formError, setFormError] = useState<string | null>(null);

  const visibleRules = useMemo(() => {
    if (langFilter === 'all') return rules;
    return rules.filter((r) => r.languages.includes(langFilter));
  }, [rules, langFilter]);

  const patternTestResult = useMemo(() => {
    if (!patternSource.trim() || !testInput) return null;
    try {
      const re = new RegExp(patternSource, 'i');
      const match = re.exec(testInput);
      return match ? { matched: true, token: match[0] } : { matched: false, token: '' };
    } catch (err) {
      return {
        matched: false,
        error: err instanceof Error ? err.message : 'Invalid regular expression',
      };
    }
  }, [patternSource, testInput]);

  const toggleFormLanguage = (lang: Language) => {
    setSelectedLangs((prev) =>
      prev.includes(lang) ? prev.filter((l) => l !== lang) : [...prev, lang]
    );
  };

  const handleCreateRule = (e: React.FormEvent) => {
    e.preventDefault();
    setFormError(null);

    if (!ruleName.trim() || !patternSource.trim() || !description.trim()) {
      setFormError('Rule name, regex pattern, and description are required.');
      return;
    }
    if (selectedLangs.length === 0) {
      setFormError('Select at least one target language.');
      return;
    }
    try {
      new RegExp(patternSource);
    } catch {
      setFormError('Regex pattern is invalid and cannot be compiled.');
      return;
    }

    const cvssBySeverity: Record<Severity, number> = {
      critical: 9.2,
      high: 7.8,
      medium: 5.5,
      low: 3.1,
    };

    const customRule: SastRule = {
      id: `CUSTOM-${String(rules.filter((r) => r.isCustom).length + 1).padStart(3, '0')}`,
      name: ruleName.trim(),
      category: 'Custom Policy',
      owaspCategory,
      cweId: cweId.trim() || 'CWE-20',
      cvssScore: cvssBySeverity[severity],
      severity,
      languages: selectedLangs,
      patternSource: patternSource.trim(),
      flags: 'i',
      description: description.trim(),
      recommendation: recommendation.trim() || 'Sanitize and validate untrusted inputs before use.',
      remediationExample: {
        vulnerable: testInput.trim() || patternSource.trim(),
        secure: secureExample.trim() || '// Replace with validated safe alternative',
      },
      enabled: true,
      isCustom: true,
    };

    onAddCustomRule(customRule);
    setRuleName('');
    setPatternSource('');
    setDescription('');
    setRecommendation('');
    setSecureExample('');
    setTestInput('');
  };

  return (
    <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
      {/* Left: Rule Catalog */}
      <section className="lg:col-span-7 bg-white border border-slate-200 rounded-lg overflow-hidden">
        <div className="px-5 py-4 border-b border-slate-200 flex flex-wrap items-center justify-between gap-3">
          <div>
            <h2 className="font-display text-base font-semibold text-slate-900">
              SAST Detection Rules ({rules.filter((r) => r.enabled).length}/{rules.length} enabled)
            </h2>
            <p className="text-xs text-slate-500">
              Toggle OWASP Top 10 and CWE signatures applied during live source scanning
            </p>
          </div>
          <div className="flex items-center gap-1 p-1 bg-slate-100 rounded-md overflow-x-auto">
            {(['all', ...ALL_LANGUAGES] as const).map((lang) => (
              <button
                key={lang}
                type="button"
                onClick={() => setLangFilter(lang)}
                className={`px-2.5 py-1 text-xs font-medium rounded capitalize transition-colors whitespace-nowrap shrink-0 ${
                  langFilter === lang
                    ? 'bg-white text-slate-900 shadow-xs'
                    : 'text-slate-600 hover:text-slate-900'
                }`}
              >
                {lang}
              </button>
            ))}
          </div>
        </div>

        <div className="divide-y divide-slate-100 max-h-[680px] overflow-y-auto">
          {visibleRules.map((rule) => (
            <div key={rule.id} className="px-5 py-4 flex items-start justify-between gap-4">
              <div className="min-w-0 space-y-1">
                <div className="flex flex-wrap items-center gap-2 text-xs font-mono text-slate-500">
                  <span className="font-semibold text-slate-800">{rule.id}</span>
                  <span aria-hidden="true">·</span>
                  <span>{rule.cweId}</span>
                  <span aria-hidden="true">·</span>
                  <span className="capitalize">{rule.severity}</span>
                  <span aria-hidden="true">·</span>
                  <span>{rule.languages.join(', ')}</span>
                </div>
                <div className="text-sm font-semibold text-slate-900">{rule.name}</div>
                <p className="text-xs text-slate-600 leading-relaxed">{rule.description}</p>
                <div className="font-mono text-[11px] text-slate-500 bg-slate-50 border border-slate-200 rounded px-2 py-1 truncate">
                  /{rule.patternSource}/{rule.flags}
                </div>
              </div>

              <div className="flex items-center gap-2 shrink-0">
                {rule.isCustom && (
                  <button
                    type="button"
                    onClick={() => onDeleteCustomRule(rule.id)}
                    aria-label={`Delete custom rule ${rule.name}`}
                    className="p-1.5 text-slate-400 hover:text-red-600 rounded transition-colors"
                  >
                    <Trash2 className="w-4 h-4" />
                  </button>
                )}
                <button
                  type="button"
                  role="switch"
                  aria-checked={rule.enabled}
                  aria-label={`Toggle ${rule.name}`}
                  onClick={() => onToggleRule(rule.id)}
                  className={`px-3 py-1.5 text-xs font-medium rounded-md border transition-colors whitespace-nowrap shrink-0 ${
                    rule.enabled
                      ? 'bg-slate-900 text-white border-slate-900'
                      : 'bg-white text-slate-600 border-slate-300 hover:bg-slate-50'
                  }`}
                >
                  {rule.enabled ? 'Enabled' : 'Disabled'}
                </button>
              </div>
            </div>
          ))}
        </div>
      </section>

      {/* Right: Custom Rule Authoring & Regex Test Bench */}
      <section className="lg:col-span-5 bg-white border border-slate-200 rounded-lg p-5 space-y-4">
        <div>
          <h2 className="font-display text-base font-semibold text-slate-900">
            Author Custom SAST Rule
          </h2>
          <p className="text-xs text-slate-500">
            Add organization-specific security policies and verify matching before deployment
          </p>
        </div>

        <form onSubmit={handleCreateRule} className="space-y-3.5">
          <div>
            <label htmlFor="rule-name" className="block text-xs font-medium text-slate-700 mb-1">
              Rule Name
            </label>
            <input
              id="rule-name"
              type="text"
              value={ruleName}
              onChange={(e) => setRuleName(e.target.value)}
              placeholder="e.g. Unsafe Raw SQL Query Builder"
              className="w-full px-3 py-2 text-xs bg-white border border-slate-300 rounded-md text-slate-900 focus:outline-none focus:border-blue-500"
            />
          </div>

          <div className="grid grid-cols-2 gap-3">
            <div>
              <label htmlFor="rule-cwe" className="block text-xs font-medium text-slate-700 mb-1">
                CWE Identifier
              </label>
              <input
                id="rule-cwe"
                type="text"
                value={cweId}
                onChange={(e) => setCweId(e.target.value)}
                className="w-full px-3 py-2 text-xs font-mono bg-white border border-slate-300 rounded-md text-slate-900"
              />
            </div>
            <div>
              <label htmlFor="rule-severity" className="block text-xs font-medium text-slate-700 mb-1">
                Severity
              </label>
              <select
                id="rule-severity"
                value={severity}
                onChange={(e) => setSeverity(e.target.value as Severity)}
                className="w-full px-3 py-2 text-xs bg-white border border-slate-300 rounded-md text-slate-900"
              >
                <option value="critical">Critical</option>
                <option value="high">High</option>
                <option value="medium">Medium</option>
                <option value="low">Low</option>
              </select>
            </div>
          </div>

          <div>
            <label htmlFor="rule-owasp" className="block text-xs font-medium text-slate-700 mb-1">
              OWASP Top 10 Category
            </label>
            <select
              id="rule-owasp"
              value={owaspCategory}
              onChange={(e) => setOwaspCategory(e.target.value)}
              className="w-full px-3 py-2 text-xs bg-white border border-slate-300 rounded-md text-slate-900"
            >
              <option value="A01:2021 Broken Access Control">A01:2021 Broken Access Control</option>
              <option value="A02:2021 Cryptographic Failures">A02:2021 Cryptographic Failures</option>
              <option value="A03:2021 Injection">A03:2021 Injection</option>
              <option value="A05:2021 Security Misconfiguration">A05:2021 Security Misconfiguration</option>
              <option value="A07:2021 Identification and Authentication Failures">
                A07:2021 Identification and Authentication Failures
              </option>
              <option value="A08:2021 Software and Data Integrity Failures">
                A08:2021 Software and Data Integrity Failures
              </option>
              <option value="A10:2021 Server-Side Request Forgery">
                A10:2021 Server-Side Request Forgery
              </option>
            </select>
          </div>

          <div>
            <span className="block text-xs font-medium text-slate-700 mb-1.5">
              Target Languages
            </span>
            <div className="flex flex-wrap gap-2">
              {ALL_LANGUAGES.map((lang) => {
                const checked = selectedLangs.includes(lang);
                return (
                  <button
                    key={lang}
                    type="button"
                    onClick={() => toggleFormLanguage(lang)}
                    className={`px-2.5 py-1 text-xs font-medium rounded border capitalize transition-colors ${
                      checked
                        ? 'bg-blue-50 border-blue-300 text-blue-800'
                        : 'bg-white border-slate-300 text-slate-600'
                    }`}
                  >
                    {lang}
                  </button>
                );
              })}
            </div>
          </div>

          <div>
            <label htmlFor="rule-pattern" className="block text-xs font-medium text-slate-700 mb-1">
              Detection Pattern (JavaScript RegExp)
            </label>
            <input
              id="rule-pattern"
              type="text"
              value={patternSource}
              onChange={(e) => setPatternSource(e.target.value)}
              placeholder="e.g. dangerouslySetInnerHTML|document\.write\("
              className="w-full px-3 py-2 text-xs font-mono bg-white border border-slate-300 rounded-md text-slate-900"
            />
          </div>

          <div>
            <label htmlFor="rule-test-input" className="block text-xs font-medium text-slate-700 mb-1">
              Live Test Line
            </label>
            <div className="flex items-center gap-2">
              <input
                id="rule-test-input"
                type="text"
                value={testInput}
                onChange={(e) => setTestInput(e.target.value)}
                placeholder="Paste a sample line to verify rule matching"
                className="flex-1 px-3 py-2 text-xs font-mono bg-slate-50 border border-slate-200 rounded-md text-slate-900"
              />
              <Play className="w-4 h-4 text-slate-400 shrink-0" />
            </div>
            {patternTestResult && (
              <p
                className={`mt-1 text-xs ${
                  'error' in patternTestResult && patternTestResult.error
                    ? 'text-red-700'
                    : patternTestResult.matched
                    ? 'text-emerald-700'
                    : 'text-slate-500'
                }`}
              >
                {'error' in patternTestResult && patternTestResult.error
                  ? `Regex Error: ${patternTestResult.error}`
                  : patternTestResult.matched
                  ? `Matched token: "${patternTestResult.token}"`
                  : 'No match on sample line'}
              </p>
            )}
          </div>

          <div>
            <label htmlFor="rule-description" className="block text-xs font-medium text-slate-700 mb-1">
              Security Risk Description
            </label>
            <textarea
              id="rule-description"
              rows={2}
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              placeholder="Explain why this pattern introduces risk..."
              className="w-full px-3 py-2 text-xs bg-white border border-slate-300 rounded-md text-slate-900"
            />
          </div>

          <div>
            <label htmlFor="rule-recommendation" className="block text-xs font-medium text-slate-700 mb-1">
              Remediation Recommendation
            </label>
            <input
              id="rule-recommendation"
              type="text"
              value={recommendation}
              onChange={(e) => setRecommendation(e.target.value)}
              placeholder="Recommended secure coding alternative..."
              className="w-full px-3 py-2 text-xs bg-white border border-slate-300 rounded-md text-slate-900"
            />
          </div>

          <div>
            <label htmlFor="rule-secure-example" className="block text-xs font-medium text-slate-700 mb-1">
              Secure Code Example
            </label>
            <input
              id="rule-secure-example"
              type="text"
              value={secureExample}
              onChange={(e) => setSecureExample(e.target.value)}
              placeholder="e.g. element.textContent = sanitizedValue;"
              className="w-full px-3 py-2 text-xs font-mono bg-white border border-slate-300 rounded-md text-slate-900"
            />
          </div>

          {formError && (
            <div role="alert" className="p-2.5 text-xs text-red-800 bg-red-50 border border-red-200 rounded-md">
              {formError}
            </div>
          )}

          <button
            type="submit"
            className="w-full inline-flex items-center justify-center gap-2 px-4 py-2 text-xs font-semibold text-white bg-slate-900 hover:bg-slate-800 rounded-md transition-colors whitespace-nowrap"
          >
            <Plus className="w-3.5 h-3.5" />
            <span>Add Rule to Engine</span>
          </button>
        </form>
      </section>
    </div>
  );
};
