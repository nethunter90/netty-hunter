import { useState } from 'react';
import { Card } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Input } from '@/components/ui/input';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import {
  Brain, TrendingUp, Shield, Clock, Loader2, AlertTriangle,
  Target, DollarSign, Copy, GitBranch, Zap, BarChart3
} from 'lucide-react';
import { cn } from '@/lib/utils';
import { csrfFetch } from '@/services/api';

interface ConditionalBranch {
  condition: string;
  conditionProbability: number;
  updatedProbability: number;
  updatedEvScore: number;
  suggestedAction: string;
}

interface PredictionNode {
  technique: string;
  baseProbability: number;
  conditionalBranches: ConditionalBranch[];
  expectedTimeMinutes: number;
  expectedSeverity: string;
  expectedPayout: number;
  evScore: number;
}

interface StrategyResult {
  rankedStrategies: PredictionNode[];
  optimalPath: string[];
  totalExpectedValue: number;
  confidence: number;
  reasoning: string;
}

interface PayoutEstimate {
  median: number;
  p75: number;
  p95: number;
  confidence: number;
  sampleSize?: number;
}

interface FramingResult {
  vulnType: string;
  lowValueFraming: string;
  highValueFraming: string;
  payoutMultiplier: number;
  escalationChain: string[];
}

interface DuplicatePrediction {
  vulnType: string;
  targetArea: string;
  duplicateProbability: number;
  reasoning: string;
  factors: Record<string, number>;
  recommendation: 'proceed' | 'caution' | 'avoid';
}

interface TriagePrediction {
  programId: string;
  estimatedDays: number;
  confidence: number;
  factors: Record<string, number>;
}

const VULN_TYPES = ['sqli', 'xss', 'ssrf', 'idor', 'rce', 'auth-bypass', 'path-traversal', 'ssti', 'xxe', 'open-redirect'];
const SEVERITIES = ['critical', 'high', 'medium', 'low'];
const HUNT_GOALS = ['find-vulns', 'recon-only', 'specific-vuln', 'full-audit', 'api-testing', 'auth-testing', 'injection-hunting', 'misconfig-hunting'];
const ERROR_VERBOSITIES = ['verbose', 'standard', 'suppressed'];
const API_STYLES = ['rest', 'graphql', 'soap', 'grpc', 'mixed'];

function evColor(ev: number) {
  if (ev > 500) return 'text-emerald-400';
  if (ev > 0) return 'text-yellow-400';
  return 'text-red-400';
}

function evBadgeColor(ev: number) {
  if (ev > 500) return 'bg-emerald-500/20 text-emerald-400 border-emerald-500/30';
  if (ev > 0) return 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30';
  return 'bg-red-500/20 text-red-400 border-red-500/30';
}

function recBadgeColor(rec: string) {
  if (rec === 'proceed') return 'bg-emerald-500/20 text-emerald-400 border-emerald-500/30';
  if (rec === 'caution') return 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30';
  return 'bg-red-500/20 text-red-400 border-red-500/30';
}

export function StrategyAdvisor() {
  const [wafPresent, setWafPresent] = useState(false);
  const [wafType, setWafType] = useState('');
  const [errorVerbosity, setErrorVerbosity] = useState('standard');
  const [apiStyle, setApiStyle] = useState('rest');
  const [authMechanisms, setAuthMechanisms] = useState('');
  const [industry, setIndustry] = useState('');
  const [huntGoal, setHuntGoal] = useState('find-vulns');
  const [strategyLoading, setStrategyLoading] = useState(false);
  const [strategyResult, setStrategyResult] = useState<StrategyResult | null>(null);
  const [strategyError, setStrategyError] = useState('');

  const [payProgram, setPayProgram] = useState('');
  const [payVulnType, setPayVulnType] = useState('xss');
  const [paySeverity, setPaySeverity] = useState('');
  const [payLoading, setPayLoading] = useState(false);
  const [payResult, setPayResult] = useState<PayoutEstimate | null>(null);
  const [payError, setPayError] = useState('');

  const [frameVulnType, setFrameVulnType] = useState('xss');
  const [frameSeverity, setFrameSeverity] = useState('high');
  const [frameBusinessImpact, setFrameBusinessImpact] = useState('');
  const [frameAffectedUsers, setFrameAffectedUsers] = useState('');
  const [frameDataAtRisk, setFrameDataAtRisk] = useState('');
  const [frameLoading, setFrameLoading] = useState(false);
  const [frameResult, setFrameResult] = useState<FramingResult[] | null>(null);
  const [frameError, setFrameError] = useState('');

  const [dupProgram, setDupProgram] = useState('');
  const [dupVulnType, setDupVulnType] = useState('xss');
  const [dupArea, setDupArea] = useState('');
  const [dupLoading, setDupLoading] = useState(false);
  const [dupResult, setDupResult] = useState<DuplicatePrediction | null>(null);
  const [dupError, setDupError] = useState('');

  const [triageProgram, setTriageProgram] = useState('');
  const [triageSeverity, setTriageSeverity] = useState('high');
  const [triageLoading, setTriageLoading] = useState(false);
  const [triageResult, setTriageResult] = useState<TriagePrediction | null>(null);
  const [triageError, setTriageError] = useState('');

  const [quickBrief, setQuickBrief] = useState<any[]>([]);
  const [briefLoading, setBriefLoading] = useState(false);
  const [briefTarget, setBriefTarget] = useState('');

  const fetchQuickBrief = async () => {
    if (!briefTarget.trim()) return;
    setBriefLoading(true);
    try {
      const res = await fetch(`/api/intelligence/unified/quick?programId=default&target=${encodeURIComponent(briefTarget)}`);
      const data = await res.json();
      if (data.success) setQuickBrief(data.data || []);
    } catch (err) {
      console.error('Failed to fetch intelligence brief:', err);
    } finally {
      setBriefLoading(false);
    }
  };

  const predictStrategy = async () => {
    setStrategyLoading(true);
    setStrategyError('');
    setStrategyResult(null);
    try {
      const featureVector = {
        techStack: {
          language: null,
          framework: null,
          server: null,
          database: null,
          cdn: null,
          jsLibraries: [],
        },
        defenseProfile: {
          wafType: wafPresent ? (wafType || 'unknown') : null,
          wafStrictness: 'moderate' as const,
          rateLimiting: { detected: false, threshold: null, resetWindow: null },
          errorVerbosity: errorVerbosity as 'verbose' | 'standard' | 'suppressed',
          cspPolicy: { present: false, strictness: 'none' as const, reportOnly: false },
          securityHeaders: { hsts: false, xFrameOptions: false, xContentType: false, referrerPolicy: null },
          cookieFlags: { httpOnly: false, secure: false, sameSite: null },
          authMechanisms: authMechanisms ? authMechanisms.split(',').map(s => s.trim()).filter(Boolean) : [],
          apiStyle: apiStyle as 'rest' | 'graphql' | 'soap' | 'grpc' | 'mixed',
        },
        industry: industry || 'general',
        huntGoal: huntGoal,
        campaignState: {
          tasksCompleted: 0,
          findingsSoFar: 0,
          timeElapsedMinutes: 0,
          techniquesAttempted: [],
          blockedTechniques: [],
        },
      };
      const res = await csrfFetch('/api/intelligence/predict', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ featureVector }),
      });
      const data = await res.json();
      if (!res.ok || !data.success) throw new Error(data.error || 'Prediction failed');
      setStrategyResult(data.data);
    } catch (err: any) {
      setStrategyError(err.message || 'Failed to predict strategy');
    } finally {
      setStrategyLoading(false);
    }
  };

  const estimatePayout = async () => {
    if (!payProgram.trim() || !payVulnType) return;
    setPayLoading(true);
    setPayError('');
    setPayResult(null);
    try {
      const params = new URLSearchParams({ program: payProgram, vulnType: payVulnType });
      if (paySeverity) params.set('severity', paySeverity);
      const res = await fetch(`/api/intelligence/payout/estimate?${params}`);
      const data = await res.json();
      if (!res.ok || !data.success) throw new Error(data.error || 'Estimate failed');
      setPayResult(data.data);
    } catch (err: any) {
      setPayError(err.message || 'Failed to estimate payout');
    } finally {
      setPayLoading(false);
    }
  };

  const getFraming = async () => {
    if (!frameVulnType) return;
    setFrameLoading(true);
    setFrameError('');
    setFrameResult(null);
    try {
      const context: Record<string, any> = {};
      if (frameSeverity) context.severity = frameSeverity;
      if (frameBusinessImpact) context.businessImpact = frameBusinessImpact;
      if (frameAffectedUsers) context.affectedUsers = Number(frameAffectedUsers);
      if (frameDataAtRisk) context.dataAtRisk = frameDataAtRisk;
      const params = new URLSearchParams({ vulnType: frameVulnType });
      if (Object.keys(context).length > 0) params.set('context', JSON.stringify(context));
      const res = await fetch(`/api/intelligence/payout/framing?${params}`);
      const data = await res.json();
      if (!res.ok || !data.success) throw new Error(data.error || 'Framing failed');
      setFrameResult(data.data);
    } catch (err: any) {
      setFrameError(err.message || 'Failed to get framing suggestions');
    } finally {
      setFrameLoading(false);
    }
  };

  const predictDuplicate = async () => {
    if (!dupProgram.trim() || !dupVulnType || !dupArea.trim()) return;
    setDupLoading(true);
    setDupError('');
    setDupResult(null);
    try {
      const params = new URLSearchParams({ program: dupProgram, vulnType: dupVulnType, area: dupArea });
      const res = await fetch(`/api/intelligence/duplicates/predict?${params}`);
      const data = await res.json();
      if (!res.ok || !data.success) throw new Error(data.error || 'Prediction failed');
      setDupResult(data.data);
    } catch (err: any) {
      setDupError(err.message || 'Failed to predict duplicate risk');
    } finally {
      setDupLoading(false);
    }
  };

  const predictTriage = async () => {
    if (!triageProgram.trim() || !triageSeverity) return;
    setTriageLoading(true);
    setTriageError('');
    setTriageResult(null);
    try {
      const params = new URLSearchParams({ program: triageProgram, severity: triageSeverity });
      const res = await fetch(`/api/intelligence/triage/predict?${params}`);
      const data = await res.json();
      if (!res.ok || !data.success) throw new Error(data.error || 'Prediction failed');
      setTriageResult(data.data);
    } catch (err: any) {
      setTriageError(err.message || 'Failed to predict triage time');
    } finally {
      setTriageLoading(false);
    }
  };

  const maxPayout = payResult ? Math.max(payResult.median, payResult.p75, payResult.p95, 1) : 1;

  return (
    <div className="h-full flex flex-col bg-[#1e1e1e] text-gray-300 overflow-auto" data-testid="strategy-advisor-panel">
      <div className="px-4 py-3 border-b border-[#3d3d3d] shrink-0">
        <div className="flex items-center gap-3">
          <Brain className="w-6 h-6 text-purple-400" />
          <h1 className="text-xl font-bold text-gray-100" data-testid="text-strategy-advisor-title">Strategy Advisor</h1>
        </div>
        <p className="text-xs text-gray-500 mt-1">AI-powered strategy prediction, payout optimization, duplicate avoidance & triage</p>
      </div>

      <div className="flex-1 overflow-auto p-4 space-y-6">
        {/* Pre-Hunt Intelligence Briefing */}
        <Card className="bg-gray-900/50 border-emerald-500/30 p-4" data-testid="pre-hunt-briefing">
          <div className="flex items-center gap-2 mb-4">
            <Brain className="w-5 h-5 text-emerald-400" />
            <h2 className="text-lg font-semibold text-gray-200">Pre-Hunt Intelligence Briefing</h2>
          </div>

          <div className="flex gap-2 mb-4">
            <Input
              value={briefTarget}
              onChange={e => setBriefTarget(e.target.value)}
              placeholder="Enter target (e.g. example.com)"
              className="bg-[#1e1e1e] border-[#3d3d3d] text-gray-200 text-sm h-9 flex-1"
              data-testid="input-brief-target"
              onKeyDown={e => e.key === 'Enter' && fetchQuickBrief()}
            />
            <Button
              onClick={fetchQuickBrief}
              disabled={briefLoading || !briefTarget.trim()}
              className="bg-emerald-600 hover:bg-emerald-700 text-white"
              data-testid="button-get-briefing"
            >
              {briefLoading ? <Loader2 className="w-4 h-4 animate-spin mr-2" /> : <Brain className="w-4 h-4 mr-2" />}
              Get Briefing
            </Button>
          </div>

          {quickBrief.length > 0 && (
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3" data-testid="brief-results-grid">
              {quickBrief.slice(0, 5).map((item: any, i: number) => (
                <Card
                  key={i}
                  className={cn(
                    'bg-[#1e1e1e] border-[#3d3d3d] p-3 relative',
                    i === 0 && 'border-emerald-500/50'
                  )}
                  data-testid={`card-brief-technique-${i}`}
                >
                  {i === 0 && (
                    <Badge
                      variant="outline"
                      className="absolute -top-2 right-2 bg-emerald-500/20 text-emerald-400 border-emerald-500/30 text-[10px]"
                      data-testid="badge-recommended"
                    >
                      Recommended
                    </Badge>
                  )}
                  <p className="text-sm font-semibold text-gray-200 mb-2" data-testid={`text-brief-technique-name-${i}`}>
                    {item.technique || item.name || `Technique ${i + 1}`}
                  </p>
                  <p className={cn('text-xl font-bold mb-2', evColor(item.evScore || item.ev || 0))} data-testid={`text-brief-ev-${i}`}>
                    EV: ${(item.evScore || item.ev || 0).toFixed(0)}
                  </p>
                  <div className="flex flex-wrap gap-1.5 mb-2">
                    <Badge variant="outline" className="bg-cyan-500/20 text-cyan-400 border-cyan-500/30 text-[10px]" data-testid={`badge-brief-success-${i}`}>
                      Success: {Math.round((item.successProbability || item.baseProbability || 0) * 100)}%
                    </Badge>
                    <Badge variant="outline" className="bg-orange-500/20 text-orange-400 border-orange-500/30 text-[10px]" data-testid={`badge-brief-duplicate-${i}`}>
                      Dup Risk: {Math.round((item.duplicateRisk || item.duplicateProbability || 0) * 100)}%
                    </Badge>
                  </div>
                  <p className="text-emerald-400 text-sm font-medium" data-testid={`text-brief-payout-${i}`}>
                    <DollarSign className="w-3 h-3 inline" />
                    {item.expectedPayout || item.payout || 0}
                  </p>
                </Card>
              ))}
            </div>
          )}

          {quickBrief.length === 0 && !briefLoading && (
            <p className="text-xs text-gray-500 text-center" data-testid="text-brief-empty">
              Enter a target to get a quick intelligence briefing before hunting
            </p>
          )}
        </Card>

        {/* Section 1: Strategy Predictor */}
        <Card className="bg-[#252526] border-[#3d3d3d] p-4" data-testid="section-strategy-predictor">
          <div className="flex items-center gap-2 mb-4">
            <Target className="w-5 h-5 text-cyan-400" />
            <h2 className="text-lg font-semibold text-gray-200">Strategy Predictor</h2>
          </div>

          <div className="grid grid-cols-2 gap-3 mb-4">
            <div className="space-y-1">
              <label className="text-xs text-gray-400">WAF Present</label>
              <Button
                variant="outline"
                size="sm"
                className={cn(
                  'w-full border-[#3d3d3d] text-sm',
                  wafPresent ? 'bg-cyan-500/20 text-cyan-400 border-cyan-500/30' : 'bg-[#1e1e1e] text-gray-400'
                )}
                onClick={() => setWafPresent(!wafPresent)}
                data-testid="button-waf-toggle"
              >
                {wafPresent ? 'WAF Active' : 'No WAF'}
              </Button>
            </div>
            <div className="space-y-1">
              <label className="text-xs text-gray-400">WAF Type</label>
              <Input
                value={wafType}
                onChange={e => setWafType(e.target.value)}
                placeholder="e.g. Cloudflare"
                disabled={!wafPresent}
                className="bg-[#1e1e1e] border-[#3d3d3d] text-gray-200 text-sm h-9"
                data-testid="input-waf-type"
              />
            </div>
            <div className="space-y-1">
              <label className="text-xs text-gray-400">Error Verbosity</label>
              <Select value={errorVerbosity} onValueChange={setErrorVerbosity}>
                <SelectTrigger className="bg-[#1e1e1e] border-[#3d3d3d] text-gray-200 text-sm h-9" data-testid="select-error-verbosity">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent className="bg-[#252526] border-[#3d3d3d]">
                  {ERROR_VERBOSITIES.map(v => (
                    <SelectItem key={v} value={v} className="text-gray-200">{v}</SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div className="space-y-1">
              <label className="text-xs text-gray-400">API Style</label>
              <Select value={apiStyle} onValueChange={setApiStyle}>
                <SelectTrigger className="bg-[#1e1e1e] border-[#3d3d3d] text-gray-200 text-sm h-9" data-testid="select-api-style">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent className="bg-[#252526] border-[#3d3d3d]">
                  {API_STYLES.map(s => (
                    <SelectItem key={s} value={s} className="text-gray-200">{s}</SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div className="space-y-1">
              <label className="text-xs text-gray-400">Auth Mechanisms (comma separated)</label>
              <Input
                value={authMechanisms}
                onChange={e => setAuthMechanisms(e.target.value)}
                placeholder="jwt, oauth2, api-key"
                className="bg-[#1e1e1e] border-[#3d3d3d] text-gray-200 text-sm h-9"
                data-testid="input-auth-mechanisms"
              />
            </div>
            <div className="space-y-1">
              <label className="text-xs text-gray-400">Industry</label>
              <Input
                value={industry}
                onChange={e => setIndustry(e.target.value)}
                placeholder="e.g. fintech, healthcare"
                className="bg-[#1e1e1e] border-[#3d3d3d] text-gray-200 text-sm h-9"
                data-testid="input-industry"
              />
            </div>
            <div className="col-span-2 space-y-1">
              <label className="text-xs text-gray-400">Hunt Goal</label>
              <Select value={huntGoal} onValueChange={setHuntGoal}>
                <SelectTrigger className="bg-[#1e1e1e] border-[#3d3d3d] text-gray-200 text-sm h-9" data-testid="select-hunt-goal">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent className="bg-[#252526] border-[#3d3d3d]">
                  {HUNT_GOALS.map(g => (
                    <SelectItem key={g} value={g} className="text-gray-200">{g}</SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
          </div>

          <Button
            onClick={predictStrategy}
            disabled={strategyLoading}
            className="w-full bg-cyan-600 hover:bg-cyan-700 text-white"
            data-testid="button-predict-strategy"
          >
            {strategyLoading ? <Loader2 className="w-4 h-4 animate-spin mr-2" /> : <Zap className="w-4 h-4 mr-2" />}
            Predict Optimal Strategy
          </Button>

          {strategyError && (
            <div className="mt-3 flex items-center gap-2 text-red-400 text-xs" data-testid="text-strategy-error">
              <AlertTriangle className="w-4 h-4" /> {strategyError}
            </div>
          )}

          {strategyResult && (
            <div className="mt-4 space-y-3" data-testid="strategy-results">
              <div className="flex items-center justify-between bg-[#1e1e1e] border border-[#3d3d3d] rounded p-3">
                <div>
                  <span className="text-xs text-gray-500">Confidence</span>
                  <p className="text-lg font-bold text-cyan-400" data-testid="text-strategy-confidence">
                    {Math.round((strategyResult.confidence || 0) * 100)}%
                  </p>
                </div>
                <div className="text-right">
                  <span className="text-xs text-gray-500">Total EV</span>
                  <p className={cn('text-lg font-bold', evColor(strategyResult.totalExpectedValue || 0))} data-testid="text-strategy-total-ev">
                    ${(strategyResult.totalExpectedValue || 0).toFixed(0)}
                  </p>
                </div>
              </div>

              {strategyResult.optimalPath && strategyResult.optimalPath.length > 0 && (
                <div className="bg-[#1e1e1e] border border-[#3d3d3d] rounded p-3">
                  <span className="text-xs text-gray-500">Optimal Path</span>
                  <div className="flex flex-wrap gap-1.5 mt-1" data-testid="strategy-optimal-path">
                    {strategyResult.optimalPath.map((step, i) => (
                      <Badge key={i} variant="outline" className="bg-purple-500/20 text-purple-400 border-purple-500/30 text-xs">
                        {i + 1}. {step}
                      </Badge>
                    ))}
                  </div>
                </div>
              )}

              {strategyResult.rankedStrategies?.map((s, i) => (
                <Card key={i} className="bg-[#1e1e1e] border-[#3d3d3d] p-3" data-testid={`card-strategy-${i}`}>
                  <div className="flex items-center justify-between mb-2">
                    <span className="text-sm font-semibold text-gray-200">{s.technique}</span>
                    <Badge variant="outline" className={cn('text-xs', evBadgeColor(s.evScore))}>
                      EV: ${s.evScore.toFixed(0)}
                    </Badge>
                  </div>
                  <div className="mb-2">
                    <div className="flex justify-between text-xs text-gray-500 mb-0.5">
                      <span>Base Probability</span>
                      <span>{Math.round(s.baseProbability * 100)}%</span>
                    </div>
                    <div className="w-full h-1.5 bg-[#3d3d3d] rounded-full">
                      <div
                        className="h-full bg-cyan-500 rounded-full transition-all"
                        style={{ width: `${Math.round(s.baseProbability * 100)}%` }}
                      />
                    </div>
                  </div>
                  <div className="grid grid-cols-3 gap-2 text-xs">
                    <div>
                      <span className="text-gray-500">Payout</span>
                      <p className="text-emerald-400 font-medium" data-testid={`text-payout-${i}`}>${s.expectedPayout}</p>
                    </div>
                    <div>
                      <span className="text-gray-500">Time</span>
                      <p className="text-orange-400 font-medium">{s.expectedTimeMinutes}m</p>
                    </div>
                    <div>
                      <span className="text-gray-500">Severity</span>
                      <p className="text-purple-400 font-medium capitalize">{s.expectedSeverity}</p>
                    </div>
                  </div>
                  {s.conditionalBranches && s.conditionalBranches.length > 0 && (
                    <div className="mt-2 pl-3 border-l border-[#3d3d3d] space-y-1.5">
                      {s.conditionalBranches.map((b, bi) => (
                        <div key={bi} className="text-xs" data-testid={`branch-${i}-${bi}`}>
                          <div className="flex items-center gap-1.5">
                            <GitBranch className="w-3 h-3 text-gray-500" />
                            <span className="text-gray-400">{b.condition}</span>
                            <Badge variant="outline" className={cn('text-[10px] px-1', evBadgeColor(b.updatedEvScore))}>
                              EV: ${b.updatedEvScore.toFixed(0)}
                            </Badge>
                          </div>
                          <p className="text-gray-500 ml-4.5 mt-0.5">{b.suggestedAction}</p>
                        </div>
                      ))}
                    </div>
                  )}
                </Card>
              ))}
            </div>
          )}

          {!strategyResult && !strategyLoading && !strategyError && (
            <p className="text-xs text-gray-500 text-center mt-3" data-testid="text-strategy-empty">
              Configure target parameters and predict optimal hunting strategy
            </p>
          )}
        </Card>

        {/* Section 2: Payout Optimizer */}
        <Card className="bg-[#252526] border-[#3d3d3d] p-4" data-testid="section-payout-optimizer">
          <div className="flex items-center gap-2 mb-4">
            <DollarSign className="w-5 h-5 text-emerald-400" />
            <h2 className="text-lg font-semibold text-gray-200">Payout Optimizer</h2>
          </div>

          <div className="space-y-3 mb-4">
            <div className="grid grid-cols-3 gap-3">
              <div className="space-y-1">
                <label className="text-xs text-gray-400">Program ID</label>
                <Input
                  value={payProgram}
                  onChange={e => setPayProgram(e.target.value)}
                  placeholder="program-id"
                  className="bg-[#1e1e1e] border-[#3d3d3d] text-gray-200 text-sm h-9"
                  data-testid="input-pay-program"
                />
              </div>
              <div className="space-y-1">
                <label className="text-xs text-gray-400">Vuln Type</label>
                <Select value={payVulnType} onValueChange={setPayVulnType}>
                  <SelectTrigger className="bg-[#1e1e1e] border-[#3d3d3d] text-gray-200 text-sm h-9" data-testid="select-pay-vuln-type">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent className="bg-[#252526] border-[#3d3d3d]">
                    {VULN_TYPES.map(v => (
                      <SelectItem key={v} value={v} className="text-gray-200">{v}</SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
              <div className="space-y-1">
                <label className="text-xs text-gray-400">Severity (optional)</label>
                <Select value={paySeverity} onValueChange={setPaySeverity}>
                  <SelectTrigger className="bg-[#1e1e1e] border-[#3d3d3d] text-gray-200 text-sm h-9" data-testid="select-pay-severity">
                    <SelectValue placeholder="Any" />
                  </SelectTrigger>
                  <SelectContent className="bg-[#252526] border-[#3d3d3d]">
                    <SelectItem value="any" className="text-gray-200">Any</SelectItem>
                    {SEVERITIES.map(s => (
                      <SelectItem key={s} value={s} className="text-gray-200">{s}</SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
            </div>
            <Button
              onClick={estimatePayout}
              disabled={payLoading || !payProgram.trim()}
              className="w-full bg-emerald-600 hover:bg-emerald-700 text-white"
              data-testid="button-estimate-payout"
            >
              {payLoading ? <Loader2 className="w-4 h-4 animate-spin mr-2" /> : <TrendingUp className="w-4 h-4 mr-2" />}
              Estimate Payout
            </Button>
          </div>

          {payError && (
            <div className="mb-3 flex items-center gap-2 text-red-400 text-xs" data-testid="text-pay-error">
              <AlertTriangle className="w-4 h-4" /> {payError}
            </div>
          )}

          {payResult && (
            <div className="mb-4 bg-[#1e1e1e] border border-[#3d3d3d] rounded p-3 space-y-2" data-testid="payout-results">
              <div className="flex items-center justify-between mb-1">
                <span className="text-xs text-gray-500">Confidence</span>
                <Badge variant="outline" className={cn('text-xs', payResult.confidence > 0.7 ? 'bg-emerald-500/20 text-emerald-400 border-emerald-500/30' : payResult.confidence > 0.4 ? 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30' : 'bg-red-500/20 text-red-400 border-red-500/30')} data-testid="badge-pay-confidence">
                  {Math.round(payResult.confidence * 100)}%
                </Badge>
              </div>
              {[
                { label: 'Median', value: payResult.median, color: 'bg-emerald-500' },
                { label: 'P75', value: payResult.p75, color: 'bg-cyan-500' },
                { label: 'P95', value: payResult.p95, color: 'bg-purple-500' },
              ].map(({ label, value, color }) => (
                <div key={label}>
                  <div className="flex justify-between text-xs mb-0.5">
                    <span className="text-gray-400">{label}</span>
                    <span className="text-gray-200 font-medium" data-testid={`text-pay-${label.toLowerCase()}`}>${value}</span>
                  </div>
                  <div className="w-full h-2 bg-[#3d3d3d] rounded-full">
                    <div className={cn('h-full rounded-full transition-all', color)} style={{ width: `${Math.min((value / maxPayout) * 100, 100)}%` }} />
                  </div>
                </div>
              ))}
            </div>
          )}

          {!payResult && !payLoading && !payError && (
            <p className="text-xs text-gray-500 text-center mb-4" data-testid="text-pay-empty">
              Enter a program ID and vuln type to estimate payout ranges
            </p>
          )}

          <div className="border-t border-[#3d3d3d] pt-4">
            <div className="flex items-center gap-2 mb-3">
              <Copy className="w-4 h-4 text-orange-400" />
              <h3 className="text-sm font-semibold text-gray-200">Impact Framing</h3>
            </div>
            <div className="grid grid-cols-2 gap-3 mb-3">
              <div className="space-y-1">
                <label className="text-xs text-gray-400">Vuln Type</label>
                <Select value={frameVulnType} onValueChange={setFrameVulnType}>
                  <SelectTrigger className="bg-[#1e1e1e] border-[#3d3d3d] text-gray-200 text-sm h-9" data-testid="select-frame-vuln-type">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent className="bg-[#252526] border-[#3d3d3d]">
                    {VULN_TYPES.map(v => (
                      <SelectItem key={v} value={v} className="text-gray-200">{v}</SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
              <div className="space-y-1">
                <label className="text-xs text-gray-400">Severity</label>
                <Select value={frameSeverity} onValueChange={setFrameSeverity}>
                  <SelectTrigger className="bg-[#1e1e1e] border-[#3d3d3d] text-gray-200 text-sm h-9" data-testid="select-frame-severity">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent className="bg-[#252526] border-[#3d3d3d]">
                    {SEVERITIES.map(s => (
                      <SelectItem key={s} value={s} className="text-gray-200">{s}</SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
              <div className="space-y-1">
                <label className="text-xs text-gray-400">Business Impact</label>
                <Input
                  value={frameBusinessImpact}
                  onChange={e => setFrameBusinessImpact(e.target.value)}
                  placeholder="e.g. data breach, account takeover"
                  className="bg-[#1e1e1e] border-[#3d3d3d] text-gray-200 text-sm h-9"
                  data-testid="input-frame-business-impact"
                />
              </div>
              <div className="space-y-1">
                <label className="text-xs text-gray-400">Affected Users</label>
                <Input
                  type="number"
                  value={frameAffectedUsers}
                  onChange={e => setFrameAffectedUsers(e.target.value)}
                  placeholder="e.g. 10000"
                  className="bg-[#1e1e1e] border-[#3d3d3d] text-gray-200 text-sm h-9"
                  data-testid="input-frame-affected-users"
                />
              </div>
              <div className="col-span-2 space-y-1">
                <label className="text-xs text-gray-400">Data at Risk</label>
                <Input
                  value={frameDataAtRisk}
                  onChange={e => setFrameDataAtRisk(e.target.value)}
                  placeholder="e.g. PII, credit cards, medical records"
                  className="bg-[#1e1e1e] border-[#3d3d3d] text-gray-200 text-sm h-9"
                  data-testid="input-frame-data-at-risk"
                />
              </div>
            </div>
            <Button
              onClick={getFraming}
              disabled={frameLoading}
              className="w-full bg-orange-600 hover:bg-orange-700 text-white"
              data-testid="button-get-framing"
            >
              {frameLoading ? <Loader2 className="w-4 h-4 animate-spin mr-2" /> : <BarChart3 className="w-4 h-4 mr-2" />}
              Get Framing Suggestions
            </Button>

            {frameError && (
              <div className="mt-3 flex items-center gap-2 text-red-400 text-xs" data-testid="text-frame-error">
                <AlertTriangle className="w-4 h-4" /> {frameError}
              </div>
            )}

            {frameResult && frameResult.length > 0 && (
              <div className="mt-3 space-y-2" data-testid="framing-results">
                {frameResult.map((f, i) => (
                  <Card key={i} className="bg-[#1e1e1e] border-[#3d3d3d] p-3" data-testid={`card-framing-${i}`}>
                    <div className="flex items-center justify-between mb-2">
                      <span className="text-sm font-medium text-gray-200 capitalize">{f.vulnType}</span>
                      <Badge variant="outline" className="bg-orange-500/20 text-orange-400 border-orange-500/30 text-xs">
                        {f.payoutMultiplier}x multiplier
                      </Badge>
                    </div>
                    <div className="space-y-1.5 text-xs">
                      <div>
                        <span className="text-gray-500">Low-value framing:</span>
                        <p className="text-red-400 mt-0.5">{f.lowValueFraming}</p>
                      </div>
                      <div>
                        <span className="text-gray-500">High-value framing:</span>
                        <p className="text-emerald-400 mt-0.5">{f.highValueFraming}</p>
                      </div>
                      {f.escalationChain && f.escalationChain.length > 0 && (
                        <div>
                          <span className="text-gray-500">Escalation chain:</span>
                          <div className="flex flex-wrap gap-1 mt-0.5">
                            {f.escalationChain.map((step, si) => (
                              <Badge key={si} variant="outline" className="bg-purple-500/10 text-purple-400 border-purple-500/20 text-[10px]">
                                {step}
                              </Badge>
                            ))}
                          </div>
                        </div>
                      )}
                    </div>
                  </Card>
                ))}
              </div>
            )}

            {!frameResult && !frameLoading && !frameError && (
              <p className="text-xs text-gray-500 text-center mt-3" data-testid="text-frame-empty">
                Get suggestions for framing vulnerability impact to maximize payouts
              </p>
            )}
          </div>
        </Card>

        {/* Section 3: Duplicate Risk Checker */}
        <Card className="bg-[#252526] border-[#3d3d3d] p-4" data-testid="section-duplicate-risk">
          <div className="flex items-center gap-2 mb-4">
            <Shield className="w-5 h-5 text-orange-400" />
            <h2 className="text-lg font-semibold text-gray-200">Duplicate Risk Checker</h2>
          </div>

          <div className="grid grid-cols-3 gap-3 mb-4">
            <div className="space-y-1">
              <label className="text-xs text-gray-400">Program</label>
              <Input
                value={dupProgram}
                onChange={e => setDupProgram(e.target.value)}
                placeholder="program-id"
                className="bg-[#1e1e1e] border-[#3d3d3d] text-gray-200 text-sm h-9"
                data-testid="input-dup-program"
              />
            </div>
            <div className="space-y-1">
              <label className="text-xs text-gray-400">Vuln Type</label>
              <Select value={dupVulnType} onValueChange={setDupVulnType}>
                <SelectTrigger className="bg-[#1e1e1e] border-[#3d3d3d] text-gray-200 text-sm h-9" data-testid="select-dup-vuln-type">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent className="bg-[#252526] border-[#3d3d3d]">
                  {VULN_TYPES.map(v => (
                    <SelectItem key={v} value={v} className="text-gray-200">{v}</SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div className="space-y-1">
              <label className="text-xs text-gray-400">Target Area</label>
              <Input
                value={dupArea}
                onChange={e => setDupArea(e.target.value)}
                placeholder="e.g. /api/users"
                className="bg-[#1e1e1e] border-[#3d3d3d] text-gray-200 text-sm h-9"
                data-testid="input-dup-area"
              />
            </div>
          </div>

          <Button
            onClick={predictDuplicate}
            disabled={dupLoading || !dupProgram.trim() || !dupArea.trim()}
            className="w-full bg-orange-600 hover:bg-orange-700 text-white"
            data-testid="button-predict-duplicate"
          >
            {dupLoading ? <Loader2 className="w-4 h-4 animate-spin mr-2" /> : <Shield className="w-4 h-4 mr-2" />}
            Check Duplicate Risk
          </Button>

          {dupError && (
            <div className="mt-3 flex items-center gap-2 text-red-400 text-xs" data-testid="text-dup-error">
              <AlertTriangle className="w-4 h-4" /> {dupError}
            </div>
          )}

          {dupResult && (
            <div className="mt-4 space-y-3" data-testid="duplicate-results">
              <div className="flex items-center justify-between bg-[#1e1e1e] border border-[#3d3d3d] rounded p-4">
                <div className="text-center flex-1">
                  <p className={cn(
                    'text-4xl font-bold',
                    dupResult.duplicateProbability > 0.7 ? 'text-red-400' : dupResult.duplicateProbability > 0.4 ? 'text-yellow-400' : 'text-emerald-400'
                  )} data-testid="text-dup-probability">
                    {Math.round(dupResult.duplicateProbability * 100)}%
                  </p>
                  <span className="text-xs text-gray-500">Duplicate Probability</span>
                </div>
                <Badge variant="outline" className={cn('text-sm px-3 py-1', recBadgeColor(dupResult.recommendation))} data-testid="badge-dup-recommendation">
                  {dupResult.recommendation.toUpperCase()}
                </Badge>
              </div>

              {dupResult.factors && Object.keys(dupResult.factors).length > 0 && (
                <div className="bg-[#1e1e1e] border border-[#3d3d3d] rounded p-3 space-y-2">
                  <span className="text-xs text-gray-500 font-medium">Factor Breakdown</span>
                  {['programAge', 'vulnCommonality', 'targetExposure', 'reportVolume', 'scopeFreshness', 'hunterActivity'].map(factor => {
                    const val = dupResult.factors[factor] ?? 0;
                    return (
                      <div key={factor}>
                        <div className="flex justify-between text-xs mb-0.5">
                          <span className="text-gray-400">{factor.replace(/([A-Z])/g, ' $1').trim()}</span>
                          <span className="text-gray-300">{typeof val === 'number' ? val.toFixed(2) : val}</span>
                        </div>
                        <div className="w-full h-1.5 bg-[#3d3d3d] rounded-full">
                          <div
                            className={cn('h-full rounded-full transition-all', val > 0.7 ? 'bg-red-500' : val > 0.4 ? 'bg-yellow-500' : 'bg-emerald-500')}
                            style={{ width: `${Math.min(Math.abs(val) * 100, 100)}%` }}
                          />
                        </div>
                      </div>
                    );
                  })}
                </div>
              )}

              {dupResult.reasoning && (
                <div className="bg-[#1e1e1e] border border-[#3d3d3d] rounded p-3">
                  <span className="text-xs text-gray-500">Reasoning</span>
                  <p className="text-xs text-gray-300 mt-1" data-testid="text-dup-reasoning">{dupResult.reasoning}</p>
                </div>
              )}
            </div>
          )}

          {!dupResult && !dupLoading && !dupError && (
            <p className="text-xs text-gray-500 text-center mt-3" data-testid="text-dup-empty">
              Check if a vulnerability type has already been reported for a program area
            </p>
          )}
        </Card>

        {/* Section 4: Triage Timer */}
        <Card className="bg-[#252526] border-[#3d3d3d] p-4" data-testid="section-triage-timer">
          <div className="flex items-center gap-2 mb-4">
            <Clock className="w-5 h-5 text-purple-400" />
            <h2 className="text-lg font-semibold text-gray-200">Triage Timer</h2>
          </div>

          <div className="grid grid-cols-2 gap-3 mb-4">
            <div className="space-y-1">
              <label className="text-xs text-gray-400">Program</label>
              <Input
                value={triageProgram}
                onChange={e => setTriageProgram(e.target.value)}
                placeholder="program-id"
                className="bg-[#1e1e1e] border-[#3d3d3d] text-gray-200 text-sm h-9"
                data-testid="input-triage-program"
              />
            </div>
            <div className="space-y-1">
              <label className="text-xs text-gray-400">Severity</label>
              <Select value={triageSeverity} onValueChange={setTriageSeverity}>
                <SelectTrigger className="bg-[#1e1e1e] border-[#3d3d3d] text-gray-200 text-sm h-9" data-testid="select-triage-severity">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent className="bg-[#252526] border-[#3d3d3d]">
                  {SEVERITIES.map(s => (
                    <SelectItem key={s} value={s} className="text-gray-200">{s}</SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
          </div>

          <Button
            onClick={predictTriage}
            disabled={triageLoading || !triageProgram.trim()}
            className="w-full bg-purple-600 hover:bg-purple-700 text-white"
            data-testid="button-predict-triage"
          >
            {triageLoading ? <Loader2 className="w-4 h-4 animate-spin mr-2" /> : <Clock className="w-4 h-4 mr-2" />}
            Predict Triage Time
          </Button>

          {triageError && (
            <div className="mt-3 flex items-center gap-2 text-red-400 text-xs" data-testid="text-triage-error">
              <AlertTriangle className="w-4 h-4" /> {triageError}
            </div>
          )}

          {triageResult && (
            <div className="mt-4 space-y-3" data-testid="triage-results">
              <div className="flex items-center justify-between bg-[#1e1e1e] border border-[#3d3d3d] rounded p-4">
                <div className="text-center flex-1">
                  <p className="text-4xl font-bold text-purple-400" data-testid="text-triage-days">
                    {triageResult.estimatedDays}
                  </p>
                  <span className="text-xs text-gray-500">Estimated Days</span>
                </div>
                <div className="text-center flex-1">
                  <p className="text-2xl font-bold text-cyan-400" data-testid="text-triage-confidence">
                    {Math.round(triageResult.confidence * 100)}%
                  </p>
                  <span className="text-xs text-gray-500">Confidence</span>
                </div>
              </div>

              {triageResult.factors && Object.keys(triageResult.factors).length > 0 && (
                <div className="bg-[#1e1e1e] border border-[#3d3d3d] rounded p-3 space-y-2">
                  <span className="text-xs text-gray-500 font-medium">Factor Breakdown</span>
                  {Object.entries(triageResult.factors).map(([key, val]) => (
                    <div key={key}>
                      <div className="flex justify-between text-xs mb-0.5">
                        <span className="text-gray-400">{key.replace(/([A-Z])/g, ' $1').replace(/_/g, ' ').trim()}</span>
                        <span className="text-gray-300">{typeof val === 'number' ? val.toFixed(2) : val}</span>
                      </div>
                      <div className="w-full h-1.5 bg-[#3d3d3d] rounded-full">
                        <div
                          className="h-full bg-purple-500 rounded-full transition-all"
                          style={{ width: `${Math.min(Math.abs(Number(val)) * 100, 100)}%` }}
                        />
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}

          {!triageResult && !triageLoading && !triageError && (
            <p className="text-xs text-gray-500 text-center mt-3" data-testid="text-triage-empty">
              Predict how long triage will take for a given program and severity
            </p>
          )}
        </Card>
      </div>
    </div>
  );
}
