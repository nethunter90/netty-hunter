import { useState, useEffect, useCallback } from 'react';
import { csrfFetch } from '@/services/api';
import { Card } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import {
  Network, BookOpen, ChevronRight, Loader2, RefreshCw,
  Zap, ArrowRight, Clock, Target, BarChart3, Shield,
  Play, ChevronDown, ChevronUp, Sparkles, Layers,
  GitBranch, AlertCircle, CheckCircle2
} from 'lucide-react';
import { cn } from '@/lib/utils';

type TabView = 'synergy' | 'playbooks';

interface SynergyPair {
  toolA: string;
  toolB: string;
  score: number;
  sampleSize: number;
  context: string;
}

interface SynergyChain {
  tools: string[];
  combinedScore: number;
  sampleSize: number;
}

interface SynergyData {
  pairs: SynergyPair[];
  topChains: SynergyChain[];
  lastUpdated: string;
}

interface PlaybookStep {
  order: number;
  tool: string;
  phase: string;
  defaultParams: Record<string, unknown>;
  inputMapping: Record<string, string>;
  requiredOutputFields: string[];
  gateCondition: string | null;
}

interface PlaybookStats {
  timesUsed: number;
  successRate: number;
  avgFindingsPerRun: number;
  avgDurationMinutes: number;
  lastUsed: string | null;
}

interface PlaybookSummary {
  id: string;
  name: string;
  description: string;
  stepCount: number;
  successRate: number;
  timesExecuted: number;
  avgTimeMinutes: number;
  lastUsed: string;
}

interface PlaybookDetail {
  id: string;
  name: string;
  steps: PlaybookStep[];
  applicableWhen: {
    techStack: Record<string, unknown>;
    defenseProfile: Record<string, unknown>;
    huntGoal: string[];
  };
  stats: PlaybookStats;
}

const PHASE_COLORS: Record<string, string> = {
  recon: 'bg-cyan-500/20 text-cyan-400 border-cyan-500/30',
  enumeration: 'bg-purple-500/20 text-purple-400 border-purple-500/30',
  exploitation: 'bg-orange-500/20 text-orange-400 border-orange-500/30',
  'post-exploit': 'bg-red-500/20 text-red-400 border-red-500/30',
};

function getSynergyColor(score: number): string {
  if (score >= 2.0) return 'text-emerald-400';
  if (score >= 1.5) return 'text-cyan-400';
  if (score >= 1.0) return 'text-yellow-400';
  return 'text-gray-500';
}

function getSuccessRateColor(rate: number): string {
  if (rate >= 0.8) return 'bg-emerald-500';
  if (rate >= 0.6) return 'bg-cyan-500';
  if (rate >= 0.4) return 'bg-yellow-500';
  if (rate >= 0.2) return 'bg-orange-500';
  return 'bg-red-500';
}

function getSuccessRateBarBg(rate: number): string {
  if (rate >= 0.8) return 'bg-emerald-500/20';
  if (rate >= 0.6) return 'bg-cyan-500/20';
  if (rate >= 0.4) return 'bg-yellow-500/20';
  if (rate >= 0.2) return 'bg-orange-500/20';
  return 'bg-red-500/20';
}

export function PlaybookLibrary() {
  const [tab, setTab] = useState<TabView>('synergy');

  const [synergyData, setSynergyData] = useState<SynergyData | null>(null);
  const [synergyLoading, setSynergyLoading] = useState(false);
  const [synergyError, setSynergyError] = useState('');

  const [playbooks, setPlaybooks] = useState<PlaybookSummary[]>([]);
  const [playbooksLoading, setPlaybooksLoading] = useState(false);
  const [playbooksError, setPlaybooksError] = useState('');

  const [selectedPlaybook, setSelectedPlaybook] = useState<PlaybookDetail | null>(null);
  const [detailLoading, setDetailLoading] = useState(false);
  const [expandedPlaybookId, setExpandedPlaybookId] = useState<string | null>(null);

  const [generating, setGenerating] = useState(false);
  const [generateError, setGenerateError] = useState('');
  const [generateSuccess, setGenerateSuccess] = useState('');

  const fetchSynergyData = useCallback(async () => {
    setSynergyLoading(true);
    setSynergyError('');
    try {
      const res = await csrfFetch('/api/intelligence/synergy/analyze', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ toolRecords: [] }),
      });
      const data = await res.json();
      if (data.success) {
        setSynergyData(data.data);
      } else {
        setSynergyError(data.error || 'Failed to fetch synergy data');
      }
    } catch (err) {
      setSynergyError('Failed to connect to synergy API');
    } finally {
      setSynergyLoading(false);
    }
  }, []);

  const fetchPlaybooks = useCallback(async () => {
    setPlaybooksLoading(true);
    setPlaybooksError('');
    try {
      const res = await fetch('/api/intelligence/playbooks');
      const data = await res.json();
      if (data.success) {
        setPlaybooks(data.data || []);
      } else {
        setPlaybooksError(data.error || 'Failed to fetch playbooks');
      }
    } catch (err) {
      setPlaybooksError('Failed to connect to playbooks API');
    } finally {
      setPlaybooksLoading(false);
    }
  }, []);

  const fetchPlaybookDetail = useCallback(async (id: string) => {
    if (expandedPlaybookId === id) {
      setExpandedPlaybookId(null);
      setSelectedPlaybook(null);
      return;
    }
    setDetailLoading(true);
    setExpandedPlaybookId(id);
    try {
      const res = await fetch(`/api/intelligence/playbooks/${id}`);
      const data = await res.json();
      if (data.success) {
        setSelectedPlaybook(data.data);
      } else {
        setSelectedPlaybook(null);
      }
    } catch {
      setSelectedPlaybook(null);
    } finally {
      setDetailLoading(false);
    }
  }, [expandedPlaybookId]);

  const generatePlaybook = useCallback(async () => {
    setGenerating(true);
    setGenerateError('');
    setGenerateSuccess('');
    const sampleRecords = [
      {
        id: 'rec-sample-1',
        campaignId: 'camp-demo',
        tool: 'subfinder',
        phase: 'recon',
        timestamp: new Date().toISOString(),
        input: { params: { domain: '{{target}}' }, sourceRecordId: null, consumedFields: [] },
        output: { rawResultHash: 'abc123', structuredFields: { subdomains: [], count: 0 }, findingCount: 0, severity: null },
        effectiveness: { producedActionableOutput: true, ledToFinding: false, timeToResult: 30 },
      },
      {
        id: 'rec-sample-2',
        campaignId: 'camp-demo',
        tool: 'httpx',
        phase: 'enumeration',
        timestamp: new Date().toISOString(),
        input: { params: { list: '{{subdomains}}' }, sourceRecordId: 'rec-sample-1', consumedFields: ['subdomains'] },
        output: { rawResultHash: 'def456', structuredFields: { liveHosts: [], statusCodes: {} }, findingCount: 0, severity: null },
        effectiveness: { producedActionableOutput: true, ledToFinding: false, timeToResult: 45 },
      },
      {
        id: 'rec-sample-3',
        campaignId: 'camp-demo',
        tool: 'nuclei',
        phase: 'exploitation',
        timestamp: new Date().toISOString(),
        input: { params: { targets: '{{liveHosts}}', templates: 'cves/' }, sourceRecordId: 'rec-sample-2', consumedFields: ['liveHosts'] },
        output: { rawResultHash: 'ghi789', structuredFields: { vulnerabilities: [], criticalCount: 0 }, findingCount: 2, severity: 'high' },
        effectiveness: { producedActionableOutput: true, ledToFinding: true, timeToResult: 120 },
      },
    ];

    try {
      const res = await csrfFetch('/api/intelligence/playbooks/generate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ toolRecords: sampleRecords }),
      });
      const data = await res.json();
      if (data.success) {
        setGenerateSuccess(`Playbook generated: ${data.data?.name || data.data?.id || 'success'}`);
        await fetchPlaybooks();
      } else {
        setGenerateError(data.error || 'Failed to generate playbook');
      }
    } catch {
      setGenerateError('Failed to connect to generate API');
    } finally {
      setGenerating(false);
    }
  }, [fetchPlaybooks]);

  useEffect(() => {
    if (tab === 'synergy') {
      fetchSynergyData();
    } else {
      fetchPlaybooks();
    }
  }, [tab, fetchSynergyData, fetchPlaybooks]);

  const tabs: { id: TabView; label: string; icon: typeof Network }[] = [
    { id: 'synergy', label: 'Synergy Map', icon: Network },
    { id: 'playbooks', label: 'Playbook Library', icon: BookOpen },
  ];

  return (
    <div className="h-full flex flex-col bg-[#1e1e1e] text-gray-300" data-testid="playbook-library-panel">
      <div className="px-4 py-3 border-b border-[#3d3d3d] shrink-0">
        <div className="flex items-center gap-3">
          <Layers className="w-6 h-6 text-purple-400" />
          <h1 className="text-xl font-bold text-gray-100" data-testid="text-panel-title">Playbook Library</h1>
        </div>
        <p className="text-xs text-gray-500 mt-1">Tool synergy analysis & automated hunting playbooks</p>
      </div>

      <div className="flex border-b border-[#3d3d3d] shrink-0">
        {tabs.map(t => {
          const Icon = t.icon;
          return (
            <button
              key={t.id}
              onClick={() => setTab(t.id)}
              data-testid={`tab-${t.id}`}
              className={cn(
                'px-4 py-2 text-xs font-medium transition-colors relative flex items-center gap-1.5',
                tab === t.id ? 'text-white bg-[#2d2d2d]' : 'text-gray-500 hover:text-gray-300'
              )}
            >
              <Icon className="w-3.5 h-3.5" />
              {t.label}
              {tab === t.id && <div className="absolute bottom-0 left-0 right-0 h-0.5 bg-purple-400" />}
            </button>
          );
        })}
      </div>

      <div className="flex-1 overflow-y-auto p-4">
        {tab === 'synergy' && (
          <div className="space-y-4">
            <div className="flex items-center justify-between">
              <h2 className="text-sm font-semibold text-gray-200 flex items-center gap-2">
                <Zap className="w-4 h-4 text-cyan-400" />
                Tool Synergy Pairs
              </h2>
              <Button
                size="sm"
                variant="outline"
                onClick={fetchSynergyData}
                disabled={synergyLoading}
                className="bg-[#252526] border-[#3d3d3d] text-gray-300 hover:bg-[#2d2d2d] h-7 text-xs"
                data-testid="button-refresh-synergy"
              >
                {synergyLoading ? <Loader2 className="w-3 h-3 animate-spin" /> : <RefreshCw className="w-3 h-3" />}
                <span className="ml-1">Refresh</span>
              </Button>
            </div>

            {synergyLoading && (
              <div className="flex items-center justify-center py-12" data-testid="synergy-loading">
                <Loader2 className="w-6 h-6 animate-spin text-purple-400" />
                <span className="ml-2 text-sm text-gray-400">Analyzing tool synergies...</span>
              </div>
            )}

            {synergyError && (
              <Card className="bg-[#252526] border-[#3d3d3d] p-4" data-testid="synergy-error">
                <div className="flex items-center gap-2 text-red-400">
                  <AlertCircle className="w-4 h-4" />
                  <span className="text-sm">{synergyError}</span>
                </div>
              </Card>
            )}

            {!synergyLoading && !synergyError && synergyData && (
              <>
                {synergyData.pairs.length === 0 ? (
                  <Card className="bg-[#252526] border-[#3d3d3d] p-6" data-testid="synergy-empty">
                    <div className="text-center">
                      <Network className="w-8 h-8 text-gray-600 mx-auto mb-2" />
                      <p className="text-sm text-gray-400">No synergy data available yet.</p>
                      <p className="text-xs text-gray-500 mt-1">Record tool executions to build synergy scores.</p>
                    </div>
                  </Card>
                ) : (
                  <div className="space-y-3">
                    {synergyData.pairs.slice(0, 10).map((pair, idx) => (
                      <Card
                        key={`${pair.toolA}-${pair.toolB}-${idx}`}
                        className="bg-[#252526] border-[#3d3d3d] p-3"
                        data-testid={`card-synergy-pair-${idx}`}
                      >
                        <div className="flex items-center justify-between">
                          <div className="flex items-center gap-2 flex-1">
                            <div className="bg-cyan-500/10 border border-cyan-500/30 rounded px-2 py-1">
                              <span className="text-xs font-mono text-cyan-400" data-testid={`text-tool-a-${idx}`}>{pair.toolA}</span>
                            </div>
                            <ArrowRight className="w-4 h-4 text-gray-500 shrink-0" />
                            <div className="bg-purple-500/10 border border-purple-500/30 rounded px-2 py-1">
                              <span className="text-xs font-mono text-purple-400" data-testid={`text-tool-b-${idx}`}>{pair.toolB}</span>
                            </div>
                          </div>
                          <div className="flex items-center gap-3 ml-3">
                            <div className="text-right">
                              <div className={cn('text-sm font-bold', getSynergyColor(pair.score))} data-testid={`text-synergy-score-${idx}`}>
                                {pair.score.toFixed(2)}x
                              </div>
                              <div className="text-[10px] text-gray-500">synergy</div>
                            </div>
                            <div className="text-right">
                              <div className="text-xs text-gray-300" data-testid={`text-sample-size-${idx}`}>{pair.sampleSize}</div>
                              <div className="text-[10px] text-gray-500">samples</div>
                            </div>
                          </div>
                        </div>
                        {pair.context && pair.context !== 'global' && (
                          <div className="mt-2">
                            <Badge variant="outline" className="text-[10px] bg-[#1e1e1e] border-[#3d3d3d] text-gray-400">
                              {pair.context}
                            </Badge>
                          </div>
                        )}
                        {pair.score > 1.0 && (
                          <div className="mt-2 flex items-center gap-1">
                            <CheckCircle2 className="w-3 h-3 text-emerald-400" />
                            <span className="text-[10px] text-emerald-400">
                              {((pair.score - 1) * 100).toFixed(0)}% finding rate improvement
                            </span>
                          </div>
                        )}
                      </Card>
                    ))}
                  </div>
                )}

                {synergyData.topChains.length > 0 && (
                  <div className="mt-6 space-y-3">
                    <h3 className="text-sm font-semibold text-gray-200 flex items-center gap-2">
                      <GitBranch className="w-4 h-4 text-emerald-400" />
                      Top Tool Chains
                    </h3>
                    {synergyData.topChains.slice(0, 5).map((chain, idx) => (
                      <Card
                        key={idx}
                        className="bg-[#252526] border-[#3d3d3d] p-3"
                        data-testid={`card-tool-chain-${idx}`}
                      >
                        <div className="flex items-center gap-1 flex-wrap">
                          {chain.tools.map((tool, tIdx) => (
                            <div key={tIdx} className="flex items-center gap-1">
                              <span className="text-xs font-mono text-gray-200 bg-[#1e1e1e] border border-[#3d3d3d] rounded px-2 py-0.5">
                                {tool}
                              </span>
                              {tIdx < chain.tools.length - 1 && (
                                <ChevronRight className="w-3 h-3 text-gray-600" />
                              )}
                            </div>
                          ))}
                          <div className="ml-auto flex items-center gap-2">
                            <span className={cn('text-xs font-bold', getSynergyColor(chain.combinedScore))}>
                              {chain.combinedScore.toFixed(2)}x
                            </span>
                            <span className="text-[10px] text-gray-500">({chain.sampleSize} samples)</span>
                          </div>
                        </div>
                      </Card>
                    ))}
                  </div>
                )}
              </>
            )}
          </div>
        )}

        {tab === 'playbooks' && (
          <div className="space-y-4">
            <div className="flex items-center justify-between">
              <h2 className="text-sm font-semibold text-gray-200 flex items-center gap-2">
                <BookOpen className="w-4 h-4 text-purple-400" />
                Playbooks
                {playbooks.length > 0 && (
                  <Badge variant="outline" className="text-[10px] bg-[#1e1e1e] border-[#3d3d3d] text-gray-400">
                    {playbooks.length}
                  </Badge>
                )}
              </h2>
              <div className="flex items-center gap-2">
                <Button
                  size="sm"
                  variant="outline"
                  onClick={generatePlaybook}
                  disabled={generating}
                  className="bg-purple-500/10 border-purple-500/30 text-purple-400 hover:bg-purple-500/20 h-7 text-xs"
                  data-testid="button-generate-playbook"
                >
                  {generating ? <Loader2 className="w-3 h-3 animate-spin" /> : <Sparkles className="w-3 h-3" />}
                  <span className="ml-1">Generate from sample data</span>
                </Button>
                <Button
                  size="sm"
                  variant="outline"
                  onClick={fetchPlaybooks}
                  disabled={playbooksLoading}
                  className="bg-[#252526] border-[#3d3d3d] text-gray-300 hover:bg-[#2d2d2d] h-7 text-xs"
                  data-testid="button-refresh-playbooks"
                >
                  {playbooksLoading ? <Loader2 className="w-3 h-3 animate-spin" /> : <RefreshCw className="w-3 h-3" />}
                </Button>
              </div>
            </div>

            {generateSuccess && (
              <Card className="bg-emerald-500/10 border-emerald-500/30 p-3" data-testid="generate-success">
                <div className="flex items-center gap-2 text-emerald-400">
                  <CheckCircle2 className="w-4 h-4" />
                  <span className="text-sm">{generateSuccess}</span>
                </div>
              </Card>
            )}

            {generateError && (
              <Card className="bg-red-500/10 border-red-500/30 p-3" data-testid="generate-error">
                <div className="flex items-center gap-2 text-red-400">
                  <AlertCircle className="w-4 h-4" />
                  <span className="text-sm">{generateError}</span>
                </div>
              </Card>
            )}

            {playbooksLoading && (
              <div className="flex items-center justify-center py-12" data-testid="playbooks-loading">
                <Loader2 className="w-6 h-6 animate-spin text-purple-400" />
                <span className="ml-2 text-sm text-gray-400">Loading playbooks...</span>
              </div>
            )}

            {playbooksError && (
              <Card className="bg-[#252526] border-[#3d3d3d] p-4" data-testid="playbooks-error">
                <div className="flex items-center gap-2 text-red-400">
                  <AlertCircle className="w-4 h-4" />
                  <span className="text-sm">{playbooksError}</span>
                </div>
              </Card>
            )}

            {!playbooksLoading && !playbooksError && playbooks.length === 0 && (
              <Card className="bg-[#252526] border-[#3d3d3d] p-6" data-testid="playbooks-empty">
                <div className="text-center">
                  <BookOpen className="w-8 h-8 text-gray-600 mx-auto mb-2" />
                  <p className="text-sm text-gray-400">No playbooks available yet.</p>
                  <p className="text-xs text-gray-500 mt-1">Generate one from sample data or complete tool campaigns.</p>
                </div>
              </Card>
            )}

            {!playbooksLoading && playbooks.length > 0 && (
              <div className="space-y-3">
                {playbooks.map((pb) => (
                  <div key={pb.id}>
                    <Card
                      className={cn(
                        'bg-[#252526] border-[#3d3d3d] p-3 cursor-pointer hover:border-purple-500/30 transition-colors',
                        expandedPlaybookId === pb.id && 'border-purple-500/50'
                      )}
                      onClick={() => fetchPlaybookDetail(pb.id)}
                      data-testid={`card-playbook-${pb.id}`}
                    >
                      <div className="flex items-center justify-between mb-2">
                        <div className="flex items-center gap-2">
                          <Play className="w-3.5 h-3.5 text-purple-400" />
                          <span className="text-sm font-semibold text-gray-200" data-testid={`text-playbook-name-${pb.id}`}>
                            {pb.name}
                          </span>
                        </div>
                        <button data-testid={`button-expand-playbook-${pb.id}`} className="text-gray-500">
                          {expandedPlaybookId === pb.id ? (
                            <ChevronUp className="w-4 h-4" />
                          ) : (
                            <ChevronDown className="w-4 h-4" />
                          )}
                        </button>
                      </div>

                      {pb.description && (
                        <div className="mb-2 flex items-center gap-1 flex-wrap">
                          {pb.description.split(' → ').map((step, sIdx, arr) => (
                            <div key={sIdx} className="flex items-center gap-1">
                              <span className="text-[10px] font-mono text-cyan-400 bg-cyan-500/10 border border-cyan-500/20 rounded px-1.5 py-0.5">
                                {step.replace(/\s*\(\d+ steps?\)\s*$/, '')}
                              </span>
                              {sIdx < arr.length - 1 && (
                                <ArrowRight className="w-3 h-3 text-gray-600" />
                              )}
                            </div>
                          ))}
                        </div>
                      )}

                      <div className="flex items-center gap-4 text-[10px] text-gray-400">
                        <div className="flex items-center gap-1" data-testid={`text-times-used-${pb.id}`}>
                          <BarChart3 className="w-3 h-3" />
                          {pb.timesExecuted} runs
                        </div>
                        <div className="flex items-center gap-1" data-testid={`text-success-rate-${pb.id}`}>
                          <Target className="w-3 h-3" />
                          {(pb.successRate * 100).toFixed(0)}% success
                        </div>
                        <div className="flex items-center gap-1" data-testid={`text-avg-time-${pb.id}`}>
                          <Clock className="w-3 h-3" />
                          {pb.avgTimeMinutes.toFixed(0)}m avg
                        </div>
                        <div className="flex items-center gap-1">
                          <Layers className="w-3 h-3" />
                          {pb.stepCount} steps
                        </div>
                      </div>

                      <div className="mt-2">
                        <div className={cn('h-1.5 rounded-full w-full', getSuccessRateBarBg(pb.successRate))}>
                          <div
                            className={cn('h-full rounded-full transition-all', getSuccessRateColor(pb.successRate))}
                            style={{ width: `${Math.max(pb.successRate * 100, 2)}%` }}
                            data-testid={`progress-success-${pb.id}`}
                          />
                        </div>
                      </div>
                    </Card>

                    {expandedPlaybookId === pb.id && (
                      <Card className="bg-[#1e1e1e] border-[#3d3d3d] border-t-0 rounded-t-none p-4 space-y-4" data-testid={`detail-playbook-${pb.id}`}>
                        {detailLoading ? (
                          <div className="flex items-center justify-center py-6" data-testid="detail-loading">
                            <Loader2 className="w-5 h-5 animate-spin text-purple-400" />
                            <span className="ml-2 text-sm text-gray-400">Loading details...</span>
                          </div>
                        ) : selectedPlaybook ? (
                          <>
                            <div>
                              <h4 className="text-xs font-semibold text-gray-300 mb-2 flex items-center gap-1">
                                <GitBranch className="w-3 h-3 text-purple-400" />
                                Pipeline Steps
                              </h4>
                              <div className="space-y-2">
                                {selectedPlaybook.steps.map((step) => (
                                  <div
                                    key={step.order}
                                    className="bg-[#252526] border border-[#3d3d3d] rounded p-3"
                                    data-testid={`step-${step.order}`}
                                  >
                                    <div className="flex items-center gap-2 mb-1">
                                      <span className="text-[10px] text-gray-500 font-mono w-5">#{step.order}</span>
                                      <span className="text-xs font-bold text-gray-200">{step.tool}</span>
                                      <Badge
                                        variant="outline"
                                        className={cn('text-[10px]', PHASE_COLORS[step.phase] || 'bg-gray-500/20 text-gray-400 border-gray-500/30')}
                                      >
                                        {step.phase}
                                      </Badge>
                                      {step.gateCondition && (
                                        <Badge variant="outline" className="text-[10px] bg-orange-500/10 border-orange-500/30 text-orange-400">
                                          gate: {step.gateCondition}
                                        </Badge>
                                      )}
                                    </div>

                                    {Object.keys(step.defaultParams).length > 0 && (
                                      <div className="mt-1.5">
                                        <span className="text-[10px] text-gray-500">Default Params:</span>
                                        <div className="flex flex-wrap gap-1 mt-0.5">
                                          {Object.entries(step.defaultParams).map(([key, value]) => (
                                            <code key={key} className="text-[10px] text-cyan-300 bg-[#1e1e1e] border border-[#3d3d3d] rounded px-1.5 py-0.5">
                                              {key}={String(value)}
                                            </code>
                                          ))}
                                        </div>
                                      </div>
                                    )}

                                    {Object.keys(step.inputMapping).length > 0 && (
                                      <div className="mt-1.5">
                                        <span className="text-[10px] text-gray-500">Input Mapping:</span>
                                        <div className="flex flex-wrap gap-1 mt-0.5">
                                          {Object.entries(step.inputMapping).map(([from, to]) => (
                                            <code key={from} className="text-[10px] text-purple-300 bg-purple-500/10 border border-purple-500/20 rounded px-1.5 py-0.5">
                                              {from} → {to}
                                            </code>
                                          ))}
                                        </div>
                                      </div>
                                    )}

                                    {step.requiredOutputFields.length > 0 && (
                                      <div className="mt-1.5">
                                        <span className="text-[10px] text-gray-500">Output Fields:</span>
                                        <div className="flex flex-wrap gap-1 mt-0.5">
                                          {step.requiredOutputFields.map((field) => (
                                            <code key={field} className="text-[10px] text-emerald-300 bg-emerald-500/10 border border-emerald-500/20 rounded px-1.5 py-0.5">
                                              {field}
                                            </code>
                                          ))}
                                        </div>
                                      </div>
                                    )}
                                  </div>
                                ))}
                              </div>
                            </div>

                            {selectedPlaybook.applicableWhen && (
                              <div>
                                <h4 className="text-xs font-semibold text-gray-300 mb-2 flex items-center gap-1">
                                  <Shield className="w-3 h-3 text-cyan-400" />
                                  Applicable Conditions
                                </h4>
                                <div className="flex flex-wrap gap-1.5">
                                  {selectedPlaybook.applicableWhen.huntGoal.map((goal) => (
                                    <Badge key={goal} variant="outline" className="text-[10px] bg-emerald-500/10 border-emerald-500/30 text-emerald-400">
                                      {goal}
                                    </Badge>
                                  ))}
                                  {Object.entries(selectedPlaybook.applicableWhen.techStack)
                                    .filter(([, v]) => v)
                                    .map(([key, value]) => (
                                      <Badge key={key} variant="outline" className="text-[10px] bg-cyan-500/10 border-cyan-500/30 text-cyan-400">
                                        {key}: {String(value)}
                                      </Badge>
                                    ))}
                                  {Object.entries(selectedPlaybook.applicableWhen.defenseProfile)
                                    .filter(([, v]) => v !== undefined && v !== null)
                                    .map(([key, value]) => (
                                      <Badge key={key} variant="outline" className="text-[10px] bg-orange-500/10 border-orange-500/30 text-orange-400">
                                        {key}: {String(value)}
                                      </Badge>
                                    ))}
                                  {selectedPlaybook.applicableWhen.huntGoal.length === 0 &&
                                    Object.keys(selectedPlaybook.applicableWhen.techStack).length === 0 &&
                                    Object.keys(selectedPlaybook.applicableWhen.defenseProfile).length === 0 && (
                                      <span className="text-[10px] text-gray-500">No specific conditions</span>
                                    )}
                                </div>
                              </div>
                            )}

                            <div>
                              <h4 className="text-xs font-semibold text-gray-300 mb-2 flex items-center gap-1">
                                <BarChart3 className="w-3 h-3 text-orange-400" />
                                Statistics
                              </h4>
                              <div className="grid grid-cols-2 gap-2">
                                <div className="bg-[#252526] border border-[#3d3d3d] rounded p-2">
                                  <div className="text-[10px] text-gray-500">Times Used</div>
                                  <div className="text-sm font-bold text-gray-200" data-testid={`detail-times-used-${pb.id}`}>
                                    {selectedPlaybook.stats.timesUsed}
                                  </div>
                                </div>
                                <div className="bg-[#252526] border border-[#3d3d3d] rounded p-2">
                                  <div className="text-[10px] text-gray-500">Success Rate</div>
                                  <div className="text-sm font-bold text-gray-200" data-testid={`detail-success-rate-${pb.id}`}>
                                    {(selectedPlaybook.stats.successRate * 100).toFixed(0)}%
                                  </div>
                                </div>
                                <div className="bg-[#252526] border border-[#3d3d3d] rounded p-2">
                                  <div className="text-[10px] text-gray-500">Avg Findings</div>
                                  <div className="text-sm font-bold text-gray-200" data-testid={`detail-avg-findings-${pb.id}`}>
                                    {selectedPlaybook.stats.avgFindingsPerRun.toFixed(1)}
                                  </div>
                                </div>
                                <div className="bg-[#252526] border border-[#3d3d3d] rounded p-2">
                                  <div className="text-[10px] text-gray-500">Avg Duration</div>
                                  <div className="text-sm font-bold text-gray-200" data-testid={`detail-avg-duration-${pb.id}`}>
                                    {selectedPlaybook.stats.avgDurationMinutes.toFixed(0)}m
                                  </div>
                                </div>
                              </div>
                            </div>
                          </>
                        ) : (
                          <div className="text-center py-4 text-sm text-gray-500">
                            Failed to load playbook details
                          </div>
                        )}
                      </Card>
                    )}
                  </div>
                ))}
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
