import { useState } from 'react';
import {
  Rocket, Target, Shield, Zap, AlertTriangle,
  Wrench, Play, RefreshCw, X, CheckCircle, Plus
} from 'lucide-react';
import { ToolValidator } from './ToolValidator';
import { csrfFetch } from '@/services/api';

interface LaunchMissionModalProps {
  onClose: () => void;
  onLaunch: () => void;
}

const templates = [
  { id: 'account-takeover', name: 'Account Takeover Hunt', goal: 'Account Takeover', icon: Target, color: 'text-red-400', description: 'Authentication bypass, session hijacking, credential abuse', estimatedDuration: '30-60 min', stealthLevel: 'stealth', type: 'exploit' as const },
  { id: 'api-security', name: 'API Security Audit', goal: 'IDOR', icon: Shield, color: 'text-blue-400', description: 'REST/GraphQL testing for authorization and data exposure', estimatedDuration: '45-90 min', stealthLevel: 'stealth', type: 'vuln_scan' as const },
  { id: 'xss-deep-dive', name: 'XSS Deep Dive', goal: 'XSS', icon: Zap, color: 'text-yellow-400', description: 'DOM-based, Stored, Reflected XSS across all inputs', estimatedDuration: '60-120 min', stealthLevel: 'stealth', type: 'vuln_scan' as const },
  { id: 'sql-injection', name: 'SQL Injection Sweep', goal: 'SQL Injection', icon: AlertTriangle, color: 'text-purple-400', description: 'Database exploitation with error-based and blind techniques', estimatedDuration: '60-90 min', stealthLevel: 'ultrastealth', type: 'exploit' as const },
  { id: 'rce-hunter', name: 'RCE Hunter', goal: 'RCE', icon: Rocket, color: 'text-orange-400', description: 'File uploads, deserialization, command injection', estimatedDuration: '45-90 min', stealthLevel: 'stealth', type: 'exploit' as const },
  { id: 'custom', name: 'Custom Mission', goal: 'Custom', icon: Wrench, color: 'text-gray-400', description: 'Define your own hunt parameters', estimatedDuration: 'Variable', stealthLevel: 'auto', type: 'custom' as const },
];

const goalOptions = [
  'Account Takeover', 'Payment Manipulation', 'PII Exposure', 'RCE',
  'SSRF', 'SQL Injection', 'XSS', 'IDOR', 'Auth Bypass', 'Custom',
];

const stealthOptions = ['aggressive', 'stealth', 'ultrastealth', 'auto'];

const stepLabels = ['Template', 'Configure', 'Validate'];

export function LaunchMissionModal({ onClose, onLaunch }: LaunchMissionModalProps) {
  const [step, setStep] = useState<'template' | 'config' | 'validate'>('template');
  const [selectedTemplate, setSelectedTemplate] = useState<typeof templates[0] | null>(null);
  const [target, setTarget] = useState('');
  const [goal, setGoal] = useState('');
  const [stealthLevel, setStealthLevel] = useState('auto');
  const [scopeInput, setScopeInput] = useState('');
  const [additionalScope, setAdditionalScope] = useState<string[]>([]);
  const [toolsReady, setToolsReady] = useState(false);
  const [launching, setLaunching] = useState(false);

  const stepIndex = step === 'template' ? 0 : step === 'config' ? 1 : 2;

  const handleTemplateSelect = (tmpl: typeof templates[0]) => {
    setSelectedTemplate(tmpl);
    setGoal(tmpl.goal);
    setStealthLevel(tmpl.stealthLevel);
    setStep('config');
  };

  const addScope = () => {
    const trimmed = scopeInput.trim();
    if (trimmed && !additionalScope.includes(trimmed)) {
      setAdditionalScope(prev => [...prev, trimmed]);
      setScopeInput('');
    }
  };

  const removeScope = (item: string) => {
    setAdditionalScope(prev => prev.filter(s => s !== item));
  };

  const handleLaunch = async () => {
    if (!selectedTemplate || !target) return;
    setLaunching(true);
    try {
      const createRes = await fetch('/api/missions', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          name: selectedTemplate.name + ' - ' + target,
          target,
          type: selectedTemplate.type,
          priority: 'high',
          goal,
          stealthLevel,
          scope: { inScope: [target, ...additionalScope], outOfScope: [] },
        }),
      });
      const createData = await createRes.json();
      if (createData.success && createData.mission) {
        await csrfFetch(`/api/missions/${createData.mission.id}/launch`, { method: 'POST' });
        onLaunch();
        onClose();
      }
    } catch (err) {
      console.error('Launch failed:', err);
    } finally {
      setLaunching(false);
    }
  };

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/60"
      data-testid="launch-mission-modal"
    >
      <div className="w-full max-w-3xl bg-[#1e1e1e] border border-[#3d3d3d] rounded-lg shadow-2xl flex flex-col max-h-[90vh]">
        <div className="flex items-center justify-between px-6 py-4 border-b border-[#2d2d2d]">
          <div className="flex items-center gap-2">
            <Rocket className="w-5 h-5 text-cyan-400" />
            <h2 className="text-base font-bold text-gray-100" data-testid="text-modal-title">Launch Mission</h2>
          </div>
          <button
            onClick={onClose}
            className="p-1.5 text-gray-400 hover:text-gray-200 hover:bg-[#2d2d2d] rounded transition-colors"
            data-testid="button-close-modal"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        <div className="flex items-center justify-center gap-0 py-4 px-6" data-testid="step-indicator">
          {stepLabels.map((label, i) => (
            <div key={label} className="flex items-center">
              {i > 0 && (
                <div className={`w-16 h-0.5 ${i <= stepIndex ? 'bg-cyan-400' : 'bg-[#3d3d3d]'}`} />
              )}
              <div className="flex flex-col items-center gap-1">
                <div
                  className={`w-8 h-8 rounded-full flex items-center justify-center text-xs font-bold ${
                    i < stepIndex
                      ? 'bg-green-500 text-white'
                      : i === stepIndex
                        ? 'bg-cyan-500 text-white'
                        : 'bg-[#3d3d3d] text-gray-500'
                  }`}
                  data-testid={`step-circle-${i + 1}`}
                >
                  {i < stepIndex ? <CheckCircle className="w-4 h-4" /> : i + 1}
                </div>
                <span className={`text-[10px] ${i === stepIndex ? 'text-cyan-400' : 'text-gray-500'}`}>
                  {label}
                </span>
              </div>
            </div>
          ))}
        </div>

        <div className="flex-1 overflow-auto px-6 pb-6">
          {step === 'template' && (
            <div className="grid grid-cols-2 gap-3" data-testid="template-grid">
              {templates.map((tmpl) => {
                const Icon = tmpl.icon;
                return (
                  <div
                    key={tmpl.id}
                    onClick={() => handleTemplateSelect(tmpl)}
                    className="bg-[#252526] border border-[#2d2d2d] rounded-lg p-4 cursor-pointer hover:border-cyan-400/50 hover:bg-[#2a2a2a] transition-all"
                    data-testid={`template-card-${tmpl.id}`}
                  >
                    <div className="flex items-center gap-3 mb-2">
                      <Icon className={`w-5 h-5 ${tmpl.color}`} />
                      <h3 className="text-sm font-semibold text-gray-100">{tmpl.name}</h3>
                    </div>
                    <p className="text-xs text-gray-400 mb-3">{tmpl.description}</p>
                    <div className="flex items-center justify-between">
                      <span className="text-[10px] text-gray-500">{tmpl.estimatedDuration}</span>
                      <span className="text-[10px] px-2 py-0.5 rounded bg-[#3d3d3d] text-gray-400">
                        {tmpl.stealthLevel}
                      </span>
                    </div>
                  </div>
                );
              })}
            </div>
          )}

          {step === 'config' && (
            <div className="space-y-4" data-testid="config-form">
              <div>
                <div className="text-xs text-gray-400 mb-1.5">Target Domain <span className="text-red-400">*</span></div>
                <input
                  type="text"
                  value={target}
                  onChange={(e) => setTarget(e.target.value)}
                  placeholder="e.g. example.com"
                  className="w-full px-3 py-2 text-sm bg-[#252526] border border-[#3d3d3d] rounded text-gray-200 placeholder-gray-600 focus:outline-none focus:border-cyan-400/50"
                  data-testid="input-target"
                />
              </div>

              <div>
                <div className="text-xs text-gray-400 mb-1.5">Hunt Goal</div>
                <select
                  value={goal}
                  onChange={(e) => setGoal(e.target.value)}
                  className="w-full px-3 py-2 text-sm bg-[#252526] border border-[#3d3d3d] rounded text-gray-200 focus:outline-none focus:border-cyan-400/50"
                  data-testid="select-goal"
                >
                  {goalOptions.map((g) => (
                    <option key={g} value={g}>{g}</option>
                  ))}
                </select>
              </div>

              <div>
                <div className="text-xs text-gray-400 mb-1.5">Stealth Level</div>
                <select
                  value={stealthLevel}
                  onChange={(e) => setStealthLevel(e.target.value)}
                  className="w-full px-3 py-2 text-sm bg-[#252526] border border-[#3d3d3d] rounded text-gray-200 focus:outline-none focus:border-cyan-400/50"
                  data-testid="select-stealth"
                >
                  {stealthOptions.map((s) => (
                    <option key={s} value={s}>{s}</option>
                  ))}
                </select>
              </div>

              <div>
                <div className="text-xs text-gray-400 mb-1.5">Additional Scope</div>
                <div className="flex gap-2">
                  <input
                    type="text"
                    value={scopeInput}
                    onChange={(e) => setScopeInput(e.target.value)}
                    onKeyDown={(e) => e.key === 'Enter' && addScope()}
                    placeholder="e.g. api.example.com"
                    className="flex-1 px-3 py-2 text-sm bg-[#252526] border border-[#3d3d3d] rounded text-gray-200 placeholder-gray-600 focus:outline-none focus:border-cyan-400/50"
                    data-testid="input-scope"
                  />
                  <button
                    onClick={addScope}
                    className="px-3 py-2 text-sm bg-[#3d3d3d] text-gray-300 rounded hover:bg-[#4d4d4d] transition-colors"
                    data-testid="button-add-scope"
                  >
                    <Plus className="w-4 h-4" />
                  </button>
                </div>
                {additionalScope.length > 0 && (
                  <div className="flex flex-wrap gap-2 mt-2" data-testid="scope-tags">
                    {additionalScope.map((s) => (
                      <span
                        key={s}
                        className="inline-flex items-center gap-1 px-2 py-1 text-xs bg-[#252526] border border-[#3d3d3d] rounded text-gray-300"
                        data-testid={`scope-tag-${s}`}
                      >
                        {s}
                        <button
                          onClick={() => removeScope(s)}
                          className="text-gray-500 hover:text-red-400 transition-colors"
                          data-testid={`button-remove-scope-${s}`}
                        >
                          <X className="w-3 h-3" />
                        </button>
                      </span>
                    ))}
                  </div>
                )}
              </div>

              <div className="flex items-center justify-between pt-2">
                <button
                  onClick={() => setStep('template')}
                  className="px-4 py-2 text-sm text-gray-400 hover:text-gray-200 hover:bg-[#2d2d2d] rounded transition-colors"
                  data-testid="button-back-to-template"
                >
                  Back
                </button>
                <button
                  onClick={() => setStep('validate')}
                  disabled={!target.trim()}
                  className="flex items-center gap-2 px-4 py-2 text-sm bg-cyan-500/20 border border-cyan-400/30 text-cyan-400 rounded hover:bg-cyan-500/30 transition-colors disabled:opacity-40 disabled:cursor-not-allowed"
                  data-testid="button-next-validate"
                >
                  Next: Validate Tools
                  <RefreshCw className="w-3.5 h-3.5" />
                </button>
              </div>
            </div>
          )}

          {step === 'validate' && (
            <div className="space-y-4" data-testid="validate-step">
              <ToolValidator
                huntGoal={goal}
                onValidationComplete={(ready) => setToolsReady(ready)}
              />

              <div className="flex items-center justify-between pt-2">
                <button
                  onClick={() => setStep('config')}
                  className="px-4 py-2 text-sm text-gray-400 hover:text-gray-200 hover:bg-[#2d2d2d] rounded transition-colors"
                  data-testid="button-back-to-config"
                >
                  Back
                </button>
                <button
                  onClick={handleLaunch}
                  disabled={launching || !toolsReady}
                  className="flex items-center gap-2 px-5 py-2 text-sm bg-green-500/20 border border-green-400/30 text-green-400 rounded hover:bg-green-500/30 transition-colors disabled:opacity-40 disabled:cursor-not-allowed"
                  data-testid="button-launch-mission"
                >
                  {launching ? (
                    <>
                      <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                      Launching...
                    </>
                  ) : (
                    <>
                      <Play className="w-3.5 h-3.5" />
                      Launch Mission
                    </>
                  )}
                </button>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
