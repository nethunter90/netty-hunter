import { useState, useEffect } from 'react';
import { Card } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { ScrollArea } from '@/components/ui/scroll-area';
import { Input } from '@/components/ui/input';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import {
  Brain, Play, Search, FlaskConical, FileCheck, Upload,
  Copy, CheckCircle2, Loader2, AlertTriangle, RefreshCw,
  Target, Shield, Zap, BarChart3, Plus, Trash2, Clock,
  Download, Globe, Power, Crosshair, BookOpen, Lightbulb,
  DollarSign, TrendingUp
} from 'lucide-react';
import { cn } from '@/lib/utils';
import { csrfFetch } from '@/services/api';
import { CampaignIntelligence } from './CampaignIntelligence';
import { PlaybookLibrary } from './PlaybookLibrary';
import { StrategyAdvisor } from './StrategyAdvisor';

type TabView = 'dashboard' | 'scope' | 'payload' | 'report-coach' | 'submissions' | 'campaigns' | 'playbooks' | 'strategy';

interface AgentStatus {
  name: string;
  status: 'idle' | 'active' | 'error';
  totalRuns: number;
  successRate: number;
}

interface ScopeResult {
  targets?: { name: string; priority: string }[];
  attackSurface?: Record<string, number>;
  subdomains?: string[];
  recommendations?: string[];
}

interface PayloadResult {
  base?: string[];
  encoded?: string[];
  wafEvasion?: string[];
}

interface ReportCoachResult {
  scores?: Record<string, number>;
  suggestions?: string[];
  missingElements?: string[];
  acceptanceChance?: number;
}

interface SubmissionResult {
  optimizedReport?: string;
  platformFormatting?: string;
  preview?: string;
}

const STATUS_COLORS: Record<string, string> = {
  active: 'bg-green-500/20 text-green-400 border-green-500/30',
  idle: 'bg-gray-500/20 text-gray-400 border-gray-500/30',
  error: 'bg-red-500/20 text-red-400 border-red-500/30',
};

export function BountyIntelligence() {
  const [tab, setTab] = useState<TabView>('dashboard');

  const [agents, setAgents] = useState<AgentStatus[]>([]);
  const [pipelineTarget, setPipelineTarget] = useState('');
  const [pipelineLoading, setPipelineLoading] = useState(false);
  const [dashboardLoading, setDashboardLoading] = useState(false);

  const [scopeTarget, setScopeTarget] = useState('');
  const [scopeLoading, setScopeLoading] = useState(false);
  const [scopeResult, setScopeResult] = useState<ScopeResult | null>(null);
  const [scopeError, setScopeError] = useState('');

  const [payloadCategory, setPayloadCategory] = useState('xss');
  const [wafType, setWafType] = useState('');
  const [payloadLoading, setPayloadLoading] = useState(false);
  const [payloadResult, setPayloadResult] = useState<PayloadResult | null>(null);
  const [payloadError, setPayloadError] = useState('');
  const [copiedPayload, setCopiedPayload] = useState<string | null>(null);

  const [reportTitle, setReportTitle] = useState('');
  const [reportSeverity, setReportSeverity] = useState('medium');
  const [reportContent, setReportContent] = useState('');
  const [reportLoading, setReportLoading] = useState(false);
  const [reportResult, setReportResult] = useState<ReportCoachResult | null>(null);
  const [reportError, setReportError] = useState('');

  const [subTitle, setSubTitle] = useState('');
  const [subDescription, setSubDescription] = useState('');
  const [subSeverity, setSubSeverity] = useState('medium');
  const [subVulnType, setSubVulnType] = useState('');
  const [subSteps, setSubSteps] = useState('');
  const [subImpact, setSubImpact] = useState('');
  const [subPoc, setSubPoc] = useState('');
  const [subEndpoint, setSubEndpoint] = useState('');
  const [subPlatform, setSubPlatform] = useState('HackerOne');
  const [subLoading, setSubLoading] = useState(false);
  const [subResult, setSubResult] = useState<SubmissionResult | null>(null);
  const [subError, setSubError] = useState('');
  const [subCopied, setSubCopied] = useState(false);

  const [programs, setPrograms] = useState<any[]>([]);
  const [fetcherStatus, setFetcherStatus] = useState<any>(null);
  const [addProgramName, setAddProgramName] = useState('');
  const [addProgramPlatform, setAddProgramPlatform] = useState('hackerone');
  const [addProgramUrl, setAddProgramUrl] = useState('');
  const [addProgramHandle, setAddProgramHandle] = useState('');
  const [addingProgram, setAddingProgram] = useState(false);
  const [fetchingAll, setFetchingAll] = useState(false);
  const [fetchingProgram, setFetchingProgram] = useState<string | null>(null);
  const [showAddForm, setShowAddForm] = useState(false);
  const [recentChanges, setRecentChanges] = useState<any[]>([]);

  const [unifiedRecs, setUnifiedRecs] = useState<any[]>([]);
  const [unifiedTarget, setUnifiedTarget] = useState('');
  const [unifiedLoading, setUnifiedLoading] = useState(false);

  useEffect(() => {
    fetchAgentStatus();
    fetchPrograms();
    fetchFetcherStatus();
    const interval = setInterval(fetchAgentStatus, 15000);
    return () => clearInterval(interval);
  }, []);

  const fetchAgentStatus = async () => {
    setDashboardLoading(true);
    try {
      const res = await fetch('/api/bounty-intelligence/status');
      const data = await res.json();
      setAgents(data.data || data.agents || []);
    } catch (err) {
      console.error('Failed to fetch agent status:', err);
    } finally {
      setDashboardLoading(false);
    }
  };

  const runPipeline = async () => {
    if (!pipelineTarget.trim()) return;
    setPipelineLoading(true);
    try {
      await csrfFetch('/api/bounty-intelligence/pipeline/run', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target: pipelineTarget }),
      });
      await fetchAgentStatus();
    } catch (err) {
      console.error('Pipeline run failed:', err);
    } finally {
      setPipelineLoading(false);
    }
  };

  const fetchPrograms = async () => {
    try {
      const res = await fetch('/api/bounty-intelligence/programs');
      const data = await res.json();
      if (data.success) setPrograms(data.data || []);
    } catch (err) {
      console.error('Failed to fetch programs:', err);
    }
  };

  const fetchFetcherStatus = async () => {
    try {
      const res = await fetch('/api/bounty-intelligence/programs/status');
      const data = await res.json();
      if (data.success) setFetcherStatus(data.data);
    } catch (err) {
      console.error('Failed to fetch fetcher status:', err);
    }
  };

  const fetchRecentChanges = async () => {
    try {
      const res = await fetch('/api/bounty-intelligence/programs/changes/recent');
      const data = await res.json();
      if (data.success) setRecentChanges(data.data || []);
    } catch (err) {
      console.error('Failed to fetch changes:', err);
    }
  };

  const fetchUnifiedRecommendations = async () => {
    if (!unifiedTarget.trim()) return;
    setUnifiedLoading(true);
    try {
      const res = await fetch(`/api/intelligence/unified/quick?programId=default&target=${encodeURIComponent(unifiedTarget)}`);
      const data = await res.json();
      if (data.success) setUnifiedRecs(data.data || []);
    } catch (err) {
      console.error('Failed to fetch unified recommendations:', err);
    } finally {
      setUnifiedLoading(false);
    }
  };

  const addProgram = async () => {
    if (!addProgramName.trim() || !addProgramUrl.trim()) return;
    setAddingProgram(true);
    try {
      const res = await csrfFetch('/api/bounty-intelligence/programs/add', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          name: addProgramName,
          platform: addProgramPlatform,
          url: addProgramUrl,
          handle: addProgramHandle || undefined,
        }),
      });
      const data = await res.json();
      if (data.success) {
        setAddProgramName('');
        setAddProgramUrl('');
        setAddProgramHandle('');
        setShowAddForm(false);
        await fetchPrograms();
        await fetchFetcherStatus();
      }
    } catch (err) {
      console.error('Failed to add program:', err);
    } finally {
      setAddingProgram(false);
    }
  };

  const removeProgram = async (id: string) => {
    try {
      await csrfFetch(`/api/bounty-intelligence/programs/${id}`, { method: 'DELETE' });
      await fetchPrograms();
      await fetchFetcherStatus();
    } catch (err) {
      console.error('Failed to remove program:', err);
    }
  };

  const fetchSingleProgram = async (id: string) => {
    setFetchingProgram(id);
    try {
      await csrfFetch(`/api/bounty-intelligence/programs/${id}/fetch`, { method: 'POST' });
      await fetchPrograms();
      await fetchFetcherStatus();
      await fetchRecentChanges();
    } catch (err) {
      console.error('Failed to fetch program:', err);
    } finally {
      setFetchingProgram(null);
    }
  };

  const fetchAllPrograms = async () => {
    setFetchingAll(true);
    try {
      await csrfFetch('/api/bounty-intelligence/programs/fetch-all', { method: 'POST' });
      await fetchPrograms();
      await fetchFetcherStatus();
      await fetchRecentChanges();
    } catch (err) {
      console.error('Failed to fetch all programs:', err);
    } finally {
      setFetchingAll(false);
    }
  };

  const toggleAutoFetch = async (enabled: boolean) => {
    try {
      await csrfFetch('/api/bounty-intelligence/programs/auto-fetch', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ enabled }),
      });
      await fetchFetcherStatus();
    } catch (err) {
      console.error('Failed to toggle auto-fetch:', err);
    }
  };

  const formatTime = (ts: number | null) => {
    if (!ts) return 'Never';
    const d = new Date(ts);
    const now = Date.now();
    const diff = now - ts;
    if (diff < 60000) return 'Just now';
    if (diff < 3600000) return `${Math.floor(diff / 60000)}m ago`;
    if (diff < 86400000) return `${Math.floor(diff / 3600000)}h ago`;
    return d.toLocaleDateString();
  };

  const analyzeScope = async () => {
    if (!scopeTarget.trim()) return;
    setScopeLoading(true);
    setScopeError('');
    setScopeResult(null);
    try {
      const res = await csrfFetch('/api/bounty-intelligence/scope/analyze', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target: scopeTarget }),
      });
      const data = await res.json();
      setScopeResult(data);
    } catch (err) {
      setScopeError('Failed to analyze scope');
    } finally {
      setScopeLoading(false);
    }
  };

  const generatePayloads = async () => {
    setPayloadLoading(true);
    setPayloadError('');
    setPayloadResult(null);
    try {
      const res = await csrfFetch('/api/bounty-intelligence/payload/mutate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ category: payloadCategory, wafType: wafType || undefined }),
      });
      const data = await res.json();
      setPayloadResult(data);
    } catch (err) {
      setPayloadError('Failed to generate payloads');
    } finally {
      setPayloadLoading(false);
    }
  };

  const copyPayload = (payload: string) => {
    navigator.clipboard.writeText(payload);
    setCopiedPayload(payload);
    setTimeout(() => setCopiedPayload(null), 2000);
  };

  const analyzeReport = async () => {
    if (!reportContent.trim()) return;
    setReportLoading(true);
    setReportError('');
    setReportResult(null);
    try {
      const res = await csrfFetch('/api/bounty-intelligence/report/coach', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ title: reportTitle, severity: reportSeverity, content: reportContent }),
      });
      const data = await res.json();
      setReportResult(data);
    } catch (err) {
      setReportError('Failed to analyze report');
    } finally {
      setReportLoading(false);
    }
  };

  const optimizeSubmission = async () => {
    if (!subTitle.trim() || !subDescription.trim()) return;
    setSubLoading(true);
    setSubError('');
    setSubResult(null);
    try {
      const res = await csrfFetch('/api/bounty-intelligence/submission/optimize', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          title: subTitle,
          description: subDescription,
          severity: subSeverity,
          vulnerabilityType: subVulnType,
          stepsToReproduce: subSteps,
          impact: subImpact,
          proofOfConcept: subPoc,
          affectedEndpoint: subEndpoint,
          platform: subPlatform,
        }),
      });
      const data = await res.json();
      setSubResult(data);
    } catch (err) {
      setSubError('Failed to optimize submission');
    } finally {
      setSubLoading(false);
    }
  };

  const copySubmission = () => {
    const text = subResult?.optimizedReport || subResult?.preview || '';
    if (text) {
      navigator.clipboard.writeText(text);
      setSubCopied(true);
      setTimeout(() => setSubCopied(false), 2000);
    }
  };

  const tabs: { id: TabView; label: string; icon: any }[] = [
    { id: 'dashboard', label: 'Dashboard', icon: BarChart3 },
    { id: 'scope', label: 'Scope Analysis', icon: Target },
    { id: 'payload', label: 'Payload Lab', icon: FlaskConical },
    { id: 'report-coach', label: 'Report Coach', icon: FileCheck },
    { id: 'submissions', label: 'Submissions', icon: Upload },
    { id: 'campaigns', label: 'Campaigns', icon: Crosshair },
    { id: 'playbooks', label: 'Playbooks', icon: BookOpen },
    { id: 'strategy', label: 'Strategy', icon: Lightbulb },
  ];

  const getPriorityColor = (priority: string) => {
    switch (priority) {
      case 'critical': return 'bg-red-500/20 text-red-400 border-red-500/30';
      case 'high': return 'bg-orange-500/20 text-orange-400 border-orange-500/30';
      case 'medium': return 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30';
      case 'low': return 'bg-green-500/20 text-green-400 border-green-500/30';
      default: return 'bg-gray-500/20 text-gray-400 border-gray-500/30';
    }
  };

  const renderPayloadGroup = (title: string, payloads: string[] | undefined, testIdPrefix: string) => {
    if (!payloads || payloads.length === 0) return null;
    return (
      <div className="space-y-1.5">
        <h4 className="text-xs font-semibold text-gray-300">{title}</h4>
        {payloads.map((p, i) => (
          <div
            key={i}
            className="flex items-center gap-2 bg-[#1e1e1e] border border-[#3d3d3d] rounded px-3 py-2"
            data-testid={`${testIdPrefix}-${i}`}
          >
            <code className="text-xs text-cyan-300 flex-1 font-mono break-all">{p}</code>
            <button
              onClick={() => copyPayload(p)}
              className="shrink-0 text-gray-400 hover:text-white transition-colors"
              data-testid={`button-copy-${testIdPrefix}-${i}`}
            >
              {copiedPayload === p ? <CheckCircle2 className="w-3.5 h-3.5 text-green-400" /> : <Copy className="w-3.5 h-3.5" />}
            </button>
          </div>
        ))}
      </div>
    );
  };

  return (
    <div className="h-full flex flex-col bg-[#1e1e1e] text-gray-300" data-testid="bounty-intelligence-panel">
      <div className="px-4 py-3 border-b border-[#3d3d3d] shrink-0">
        <div className="flex items-center gap-3">
          <Brain className="w-6 h-6 text-cyan-400" />
          <h1 className="text-xl font-bold text-gray-100">Bug Bounty Intelligence</h1>
        </div>
        <p className="text-xs text-gray-500 mt-1">AI-powered bounty hunting pipeline</p>
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
                'px-3 py-2 text-xs font-medium transition-colors relative flex items-center gap-1.5',
                tab === t.id ? 'text-white bg-[#2d2d2d]' : 'text-gray-500 hover:text-gray-300'
              )}
            >
              <Icon className="w-3.5 h-3.5" />
              {t.label}
              {tab === t.id && <div className="absolute bottom-0 left-0 right-0 h-0.5 bg-cyan-400" />}
            </button>
          );
        })}
      </div>

      <ScrollArea className="flex-1">
        <div className="p-4">
          {tab === 'dashboard' && (
            <div className="space-y-4">
              <Card className="bg-[#252526] border-[#3d3d3d] p-4">
                <div className="flex items-center gap-2 mb-3">
                  <Zap className="w-4 h-4 text-purple-400" />
                  <span className="text-sm font-semibold text-gray-200">Run Full Pipeline</span>
                </div>
                <div className="flex gap-2">
                  <Input
                    value={pipelineTarget}
                    onChange={(e) => setPipelineTarget(e.target.value)}
                    placeholder="Enter target domain (e.g., example.com)"
                    className="bg-[#1e1e1e] border-[#3d3d3d] text-gray-200 h-9 flex-1"
                    data-testid="input-pipeline-target"
                  />
                  <Button
                    onClick={runPipeline}
                    disabled={pipelineLoading || !pipelineTarget.trim()}
                    className="bg-purple-600 hover:bg-purple-700 text-white"
                    data-testid="button-run-pipeline"
                  >
                    {pipelineLoading ? <Loader2 className="w-4 h-4 animate-spin" /> : <Play className="w-4 h-4" />}
                    <span className="ml-1">Run Pipeline</span>
                  </Button>
                </div>
              </Card>

              <div className="flex items-center justify-between">
                <h3 className="text-sm font-semibold text-gray-200">Agent Status</h3>
                <button
                  onClick={fetchAgentStatus}
                  className="text-gray-400 hover:text-white transition-colors"
                  data-testid="button-refresh-status"
                >
                  <RefreshCw className={cn("w-4 h-4", dashboardLoading && "animate-spin")} />
                </button>
              </div>

              {dashboardLoading && agents.length === 0 ? (
                <div className="flex items-center justify-center py-8">
                  <Loader2 className="w-6 h-6 animate-spin text-cyan-400" />
                </div>
              ) : agents.length === 0 ? (
                <div className="text-center py-8 text-gray-500 text-xs">
                  No agent data available. Run the pipeline to initialize agents.
                </div>
              ) : (
                <div className="grid grid-cols-2 gap-3">
                  {agents.map((agent, i) => (
                    <Card
                      key={i}
                      className="bg-[#252526] border-[#3d3d3d] p-3"
                      data-testid={`card-agent-${i}`}
                    >
                      <div className="flex items-center justify-between mb-2">
                        <span className="text-xs font-medium text-gray-200 truncate">{agent.name}</span>
                        <Badge className={cn('text-[10px]', STATUS_COLORS[agent.status] || STATUS_COLORS.idle)}>
                          {agent.status}
                        </Badge>
                      </div>
                      <div className="flex items-center gap-4 text-[10px] text-gray-500">
                        <span>Runs: <span className="text-gray-300" data-testid={`text-runs-${i}`}>{agent.totalRuns}</span></span>
                        <span>Success: <span className="text-cyan-400" data-testid={`text-success-${i}`}>{agent.successRate}%</span></span>
                      </div>
                    </Card>
                  ))}
                </div>
              )}

              <Card className="bg-[#252526] border-[#3d3d3d] p-4 mt-4">
                <div className="flex items-center justify-between mb-3">
                  <div className="flex items-center gap-2">
                    <Globe className="w-4 h-4 text-emerald-400" />
                    <span className="text-sm font-semibold text-gray-200">Program Tracker</span>
                    {fetcherStatus && (
                      <Badge className="text-[10px] bg-emerald-500/20 text-emerald-400 border-emerald-500/30">
                        {fetcherStatus.enabledPrograms || 0} tracked
                      </Badge>
                    )}
                  </div>
                  <div className="flex items-center gap-2">
                    <button
                      onClick={() => toggleAutoFetch(!fetcherStatus?.autoFetchEnabled)}
                      className={cn(
                        'flex items-center gap-1 text-[10px] px-2 py-1 rounded transition-colors',
                        fetcherStatus?.autoFetchEnabled
                          ? 'bg-emerald-500/20 text-emerald-400'
                          : 'bg-gray-500/20 text-gray-400'
                      )}
                      data-testid="button-toggle-autofetch"
                    >
                      <Power className="w-3 h-3" />
                      Auto {fetcherStatus?.autoFetchEnabled ? 'ON' : 'OFF'}
                    </button>
                    <Button
                      onClick={fetchAllPrograms}
                      disabled={fetchingAll || programs.length === 0}
                      size="sm"
                      className="bg-emerald-600 hover:bg-emerald-700 text-white h-7 text-xs"
                      data-testid="button-fetch-all-programs"
                    >
                      {fetchingAll ? <Loader2 className="w-3 h-3 animate-spin" /> : <Download className="w-3 h-3" />}
                      <span className="ml-1">Fetch All</span>
                    </Button>
                    <Button
                      onClick={() => setShowAddForm(!showAddForm)}
                      size="sm"
                      variant="outline"
                      className="bg-[#1e1e1e] border-[#3d3d3d] text-gray-300 hover:bg-[#333] h-7 text-xs"
                      data-testid="button-show-add-program"
                    >
                      <Plus className="w-3 h-3" />
                    </Button>
                  </div>
                </div>

                {fetcherStatus && (
                  <div className="grid grid-cols-3 gap-2 mb-3">
                    <div className="bg-[#1e1e1e] border border-[#3d3d3d] rounded p-2 text-center">
                      <div className="text-sm font-bold text-emerald-400">{fetcherStatus.totalPrograms}</div>
                      <div className="text-[10px] text-gray-500">Programs</div>
                    </div>
                    <div className="bg-[#1e1e1e] border border-[#3d3d3d] rounded p-2 text-center">
                      <div className="text-sm font-bold text-cyan-400">{formatTime(fetcherStatus.lastAutoFetch)}</div>
                      <div className="text-[10px] text-gray-500">Last Fetch</div>
                    </div>
                    <div className="bg-[#1e1e1e] border border-[#3d3d3d] rounded p-2 text-center">
                      <div className="text-sm font-bold text-purple-400">{formatTime(fetcherStatus.nextAutoFetch)}</div>
                      <div className="text-[10px] text-gray-500">Next Fetch</div>
                    </div>
                  </div>
                )}

                {showAddForm && (
                  <div className="bg-[#1e1e1e] border border-[#3d3d3d] rounded p-3 mb-3 space-y-2">
                    <div className="grid grid-cols-2 gap-2">
                      <Input
                        value={addProgramName}
                        onChange={(e) => setAddProgramName(e.target.value)}
                        placeholder="Program name"
                        className="bg-[#252526] border-[#3d3d3d] text-gray-200 h-8 text-xs"
                        data-testid="input-add-program-name"
                      />
                      <Select value={addProgramPlatform} onValueChange={setAddProgramPlatform}>
                        <SelectTrigger className="bg-[#252526] border-[#3d3d3d] text-gray-200 h-8 text-xs" data-testid="select-add-platform">
                          <SelectValue />
                        </SelectTrigger>
                        <SelectContent className="bg-[#252526] border-[#3d3d3d]">
                          <SelectItem value="hackerone">HackerOne</SelectItem>
                          <SelectItem value="bugcrowd">Bugcrowd</SelectItem>
                          <SelectItem value="intigriti">Intigriti</SelectItem>
                          <SelectItem value="synack">Synack</SelectItem>
                          <SelectItem value="yeswehack">YesWeHack</SelectItem>
                          <SelectItem value="custom">Custom</SelectItem>
                        </SelectContent>
                      </Select>
                    </div>
                    <div className="grid grid-cols-2 gap-2">
                      <Input
                        value={addProgramUrl}
                        onChange={(e) => setAddProgramUrl(e.target.value)}
                        placeholder="Program URL"
                        className="bg-[#252526] border-[#3d3d3d] text-gray-200 h-8 text-xs"
                        data-testid="input-add-program-url"
                      />
                      <Input
                        value={addProgramHandle}
                        onChange={(e) => setAddProgramHandle(e.target.value)}
                        placeholder="Handle (optional)"
                        className="bg-[#252526] border-[#3d3d3d] text-gray-200 h-8 text-xs"
                        data-testid="input-add-program-handle"
                      />
                    </div>
                    <div className="flex justify-end gap-2">
                      <Button
                        onClick={() => setShowAddForm(false)}
                        size="sm"
                        variant="outline"
                        className="bg-[#252526] border-[#3d3d3d] text-gray-300 h-7 text-xs"
                        data-testid="button-cancel-add-program"
                      >
                        Cancel
                      </Button>
                      <Button
                        onClick={addProgram}
                        disabled={addingProgram || !addProgramName.trim() || !addProgramUrl.trim()}
                        size="sm"
                        className="bg-emerald-600 hover:bg-emerald-700 text-white h-7 text-xs"
                        data-testid="button-confirm-add-program"
                      >
                        {addingProgram ? <Loader2 className="w-3 h-3 animate-spin mr-1" /> : <Plus className="w-3 h-3 mr-1" />}
                        Add Program
                      </Button>
                    </div>
                  </div>
                )}

                {programs.length === 0 ? (
                  <div className="text-center py-4 text-gray-500 text-xs">
                    No programs tracked. Add a bug bounty program to start auto-fetching scope and rules.
                  </div>
                ) : (
                  <div className="space-y-2">
                    {programs.map((prog) => (
                      <div
                        key={prog.id}
                        className="bg-[#1e1e1e] border border-[#3d3d3d] rounded px-3 py-2 flex items-center justify-between"
                        data-testid={`card-program-${prog.id}`}
                      >
                        <div className="flex-1 min-w-0">
                          <div className="flex items-center gap-2">
                            <span className="text-xs font-medium text-gray-200 truncate">{prog.name}</span>
                            <Badge className="text-[9px] bg-[#252526] text-gray-400 border-[#3d3d3d]">{prog.platform}</Badge>
                          </div>
                          <div className="text-[10px] text-gray-500 truncate mt-0.5">{prog.url}</div>
                        </div>
                        <div className="flex items-center gap-1 ml-2 shrink-0">
                          <button
                            onClick={() => fetchSingleProgram(prog.id)}
                            disabled={fetchingProgram === prog.id}
                            className="p-1 text-gray-400 hover:text-cyan-400 transition-colors"
                            data-testid={`button-fetch-program-${prog.id}`}
                          >
                            {fetchingProgram === prog.id ? (
                              <Loader2 className="w-3.5 h-3.5 animate-spin" />
                            ) : (
                              <Download className="w-3.5 h-3.5" />
                            )}
                          </button>
                          <button
                            onClick={() => removeProgram(prog.id)}
                            className="p-1 text-gray-400 hover:text-red-400 transition-colors"
                            data-testid={`button-remove-program-${prog.id}`}
                          >
                            <Trash2 className="w-3.5 h-3.5" />
                          </button>
                        </div>
                      </div>
                    ))}
                  </div>
                )}

                {recentChanges.length > 0 && (
                  <div className="mt-3 border-t border-[#3d3d3d] pt-3">
                    <div className="flex items-center gap-1 mb-2">
                      <Clock className="w-3 h-3 text-orange-400" />
                      <span className="text-[10px] font-semibold text-gray-300">Recent Changes</span>
                    </div>
                    <div className="space-y-1">
                      {recentChanges.slice(0, 5).map((change, i) => (
                        <div key={i} className="text-[10px] text-gray-400 bg-[#1e1e1e] rounded px-2 py-1" data-testid={`text-change-${i}`}>
                          <span className="text-orange-400">{change.field}</span>: {change.description}
                          <span className="text-gray-600 ml-1">{formatTime(change.timestamp)}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </Card>

              <Card className="bg-gray-900/50 border-gray-700/50 p-4 mt-4" data-testid="unified-recommendations-card">
                <div className="flex items-center gap-2 mb-3">
                  <TrendingUp className="w-4 h-4 text-green-400" />
                  <span className="text-sm font-semibold text-gray-200">EV-Ranked Strategy Recommendations</span>
                </div>
                <div className="flex gap-2 mb-4">
                  <Input
                    value={unifiedTarget}
                    onChange={(e) => setUnifiedTarget(e.target.value)}
                    placeholder="Enter target domain/URL (e.g., example.com)"
                    className="bg-[#1e1e1e] border-[#3d3d3d] text-gray-200 h-9 flex-1"
                    data-testid="input-unified-target"
                  />
                  <Button
                    onClick={fetchUnifiedRecommendations}
                    disabled={unifiedLoading || !unifiedTarget.trim()}
                    className="bg-green-600 hover:bg-green-700 text-white"
                    data-testid="button-fetch-recommendations"
                  >
                    {unifiedLoading ? <Loader2 className="w-4 h-4 animate-spin" /> : <Search className="w-4 h-4" />}
                    <span className="ml-1">Analyze</span>
                  </Button>
                </div>

                {unifiedLoading && (
                  <div className="flex items-center justify-center py-6">
                    <Loader2 className="w-5 h-5 animate-spin text-green-400" />
                  </div>
                )}

                {!unifiedLoading && unifiedRecs.length === 0 && (
                  <div className="text-center py-6 text-gray-500 text-xs">
                    Enter a target and click Analyze to get EV-ranked strategy recommendations.
                  </div>
                )}

                {!unifiedLoading && unifiedRecs.length > 0 && (
                  <div className="space-y-2">
                    {unifiedRecs.map((rec, idx) => (
                      <div
                        key={idx}
                        className="bg-[#1e1e1e] border border-gray-700/50 rounded-lg p-3 space-y-2"
                        data-testid={`recommendation-${rec.technique || rec.name || idx}`}
                      >
                        <div className="flex items-center justify-between">
                          <div className="flex items-center gap-2">
                            <Badge className="text-[10px] bg-cyan-500/20 text-cyan-400 border-cyan-500/30">
                              {rec.technique || rec.name || 'Unknown'}
                            </Badge>
                            <span className="text-[10px] text-gray-500 font-mono">#{idx + 1}</span>
                          </div>
                          <div className="flex items-center gap-1">
                            <TrendingUp className="w-3 h-3 text-green-400" />
                            <span className="text-xs font-bold text-green-400" data-testid={`text-ev-${idx}`}>
                              ${typeof rec.adjustedEV === 'number' ? rec.adjustedEV.toFixed(2) : (rec.ev || '0.00')}
                            </span>
                          </div>
                        </div>

                        <div className="grid grid-cols-3 gap-3">
                          <div className="flex items-center gap-1.5">
                            <DollarSign className="w-3 h-3 text-yellow-400" />
                            <div>
                              <div className="text-[9px] text-gray-500">Expected Payout</div>
                              <div className="text-xs font-semibold text-yellow-400" data-testid={`text-payout-${idx}`}>
                                ${rec.expectedPayout || rec.payout || 0}
                              </div>
                            </div>
                          </div>

                          <div className="flex items-center gap-1.5">
                            <Target className="w-3 h-3 text-green-400" />
                            <div className="flex-1">
                              <div className="text-[9px] text-gray-500">Success Prob.</div>
                              <div className="flex items-center gap-1">
                                <div className="flex-1 h-1.5 bg-gray-800 rounded-full overflow-hidden">
                                  <div
                                    className="h-full bg-green-500 rounded-full"
                                    style={{ width: `${(rec.successProbability || rec.probability || 0) * 100}%` }}
                                  />
                                </div>
                                <span className="text-[10px] text-green-400" data-testid={`text-probability-${idx}`}>
                                  {((rec.successProbability || rec.probability || 0) * 100).toFixed(0)}%
                                </span>
                              </div>
                            </div>
                          </div>

                          <div className="flex items-center gap-1.5">
                            <Shield className="w-3 h-3 text-amber-400" />
                            <div>
                              <div className="text-[9px] text-gray-500">Duplicate Risk</div>
                              <span
                                className={cn(
                                  'text-xs font-semibold',
                                  (rec.duplicateRisk || 0) > 0.5 ? 'text-red-400' : 'text-amber-400'
                                )}
                                data-testid={`text-duplicate-risk-${idx}`}
                              >
                                {((rec.duplicateRisk || 0) * 100).toFixed(0)}%
                              </span>
                            </div>
                          </div>
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </Card>
            </div>
          )}

          {tab === 'scope' && (
            <div className="space-y-4">
              <Card className="bg-[#252526] border-[#3d3d3d] p-4">
                <div className="flex items-center gap-2 mb-3">
                  <Target className="w-4 h-4 text-cyan-400" />
                  <span className="text-sm font-semibold text-gray-200">Scope Analysis</span>
                </div>
                <div className="flex gap-2">
                  <Input
                    value={scopeTarget}
                    onChange={(e) => setScopeTarget(e.target.value)}
                    placeholder="Enter target domain"
                    className="bg-[#1e1e1e] border-[#3d3d3d] text-gray-200 h-9 flex-1"
                    data-testid="input-scope-target"
                  />
                  <Button
                    onClick={analyzeScope}
                    disabled={scopeLoading || !scopeTarget.trim()}
                    className="bg-cyan-600 hover:bg-cyan-700 text-white"
                    data-testid="button-analyze-scope"
                  >
                    {scopeLoading ? <Loader2 className="w-4 h-4 animate-spin" /> : <Search className="w-4 h-4" />}
                    <span className="ml-1">Analyze</span>
                  </Button>
                </div>
              </Card>

              {scopeError && (
                <div className="flex items-center gap-2 text-red-400 text-xs bg-red-500/10 border border-red-500/20 rounded p-3" data-testid="text-scope-error">
                  <AlertTriangle className="w-4 h-4" />
                  {scopeError}
                </div>
              )}

              {scopeResult && (
                <div className="space-y-4">
                  {scopeResult.targets && scopeResult.targets.length > 0 && (
                    <Card className="bg-[#252526] border-[#3d3d3d] p-4">
                      <h4 className="text-xs font-semibold text-gray-200 mb-3">Prioritized Targets</h4>
                      <div className="space-y-2">
                        {scopeResult.targets.map((t, i) => (
                          <div key={i} className="flex items-center justify-between bg-[#1e1e1e] border border-[#3d3d3d] rounded px-3 py-2" data-testid={`card-target-${i}`}>
                            <span className="text-xs text-gray-300">{t.name}</span>
                            <Badge className={cn('text-[10px]', getPriorityColor(t.priority))}>{t.priority}</Badge>
                          </div>
                        ))}
                      </div>
                    </Card>
                  )}

                  {scopeResult.attackSurface && Object.keys(scopeResult.attackSurface).length > 0 && (
                    <Card className="bg-[#252526] border-[#3d3d3d] p-4">
                      <h4 className="text-xs font-semibold text-gray-200 mb-3">Attack Surface</h4>
                      <div className="grid grid-cols-3 gap-3">
                        {Object.entries(scopeResult.attackSurface).map(([key, val]) => (
                          <div key={key} className="bg-[#1e1e1e] border border-[#3d3d3d] rounded p-3 text-center" data-testid={`text-surface-${key}`}>
                            <div className="text-lg font-bold text-cyan-400">{val}</div>
                            <div className="text-[10px] text-gray-500 capitalize">{key}</div>
                          </div>
                        ))}
                      </div>
                    </Card>
                  )}

                  {scopeResult.subdomains && scopeResult.subdomains.length > 0 && (
                    <Card className="bg-[#252526] border-[#3d3d3d] p-4">
                      <h4 className="text-xs font-semibold text-gray-200 mb-3">Subdomains ({scopeResult.subdomains.length})</h4>
                      <div className="space-y-1">
                        {scopeResult.subdomains.map((sub, i) => (
                          <div key={i} className="text-xs text-gray-400 font-mono bg-[#1e1e1e] rounded px-2 py-1" data-testid={`text-subdomain-${i}`}>{sub}</div>
                        ))}
                      </div>
                    </Card>
                  )}

                  {scopeResult.recommendations && scopeResult.recommendations.length > 0 && (
                    <Card className="bg-[#252526] border-[#3d3d3d] p-4">
                      <h4 className="text-xs font-semibold text-gray-200 mb-3">Recommendations</h4>
                      <ul className="space-y-2">
                        {scopeResult.recommendations.map((rec, i) => (
                          <li key={i} className="flex items-start gap-2 text-xs text-gray-400" data-testid={`text-recommendation-${i}`}>
                            <Shield className="w-3.5 h-3.5 text-purple-400 shrink-0 mt-0.5" />
                            {rec}
                          </li>
                        ))}
                      </ul>
                    </Card>
                  )}
                </div>
              )}
            </div>
          )}

          {tab === 'payload' && (
            <div className="space-y-4">
              <Card className="bg-[#252526] border-[#3d3d3d] p-4">
                <div className="flex items-center gap-2 mb-3">
                  <FlaskConical className="w-4 h-4 text-orange-400" />
                  <span className="text-sm font-semibold text-gray-200">Payload Lab</span>
                </div>
                <div className="space-y-3">
                  <div>
                    <label className="text-[10px] text-gray-500 mb-1 block">Category</label>
                    <Select value={payloadCategory} onValueChange={setPayloadCategory}>
                      <SelectTrigger className="bg-[#1e1e1e] border-[#3d3d3d] text-gray-200 h-9" data-testid="select-payload-category">
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="xss">XSS</SelectItem>
                        <SelectItem value="sqli">SQLi</SelectItem>
                        <SelectItem value="ssrf">SSRF</SelectItem>
                        <SelectItem value="xxe">XXE</SelectItem>
                        <SelectItem value="ssti">SSTI</SelectItem>
                        <SelectItem value="lfi">LFI</SelectItem>
                        <SelectItem value="rfi">RFI</SelectItem>
                        <SelectItem value="cmdi">CMDi</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>
                  <div>
                    <label className="text-[10px] text-gray-500 mb-1 block">WAF Type (optional)</label>
                    <Input
                      value={wafType}
                      onChange={(e) => setWafType(e.target.value)}
                      placeholder="e.g., Cloudflare, Akamai, AWS WAF"
                      className="bg-[#1e1e1e] border-[#3d3d3d] text-gray-200 h-9"
                      data-testid="input-waf-type"
                    />
                  </div>
                  <Button
                    onClick={generatePayloads}
                    disabled={payloadLoading}
                    className="w-full bg-orange-600 hover:bg-orange-700 text-white"
                    data-testid="button-generate-payloads"
                  >
                    {payloadLoading ? <Loader2 className="w-4 h-4 animate-spin mr-1" /> : <Zap className="w-4 h-4 mr-1" />}
                    Generate
                  </Button>
                </div>
              </Card>

              {payloadError && (
                <div className="flex items-center gap-2 text-red-400 text-xs bg-red-500/10 border border-red-500/20 rounded p-3" data-testid="text-payload-error">
                  <AlertTriangle className="w-4 h-4" />
                  {payloadError}
                </div>
              )}

              {payloadResult && (
                <div className="space-y-4">
                  {renderPayloadGroup('Base Payloads', payloadResult.base, 'payload-base')}
                  {renderPayloadGroup('Encoded Variants', payloadResult.encoded, 'payload-encoded')}
                  {renderPayloadGroup('WAF Evasion Variants', payloadResult.wafEvasion, 'payload-waf')}
                </div>
              )}
            </div>
          )}

          {tab === 'report-coach' && (
            <div className="space-y-4">
              <Card className="bg-[#252526] border-[#3d3d3d] p-4 space-y-3">
                <div className="flex items-center gap-2 mb-1">
                  <FileCheck className="w-4 h-4 text-purple-400" />
                  <span className="text-sm font-semibold text-gray-200">Report Coach</span>
                </div>
                <div>
                  <label className="text-[10px] text-gray-500 mb-1 block">Title</label>
                  <Input
                    value={reportTitle}
                    onChange={(e) => setReportTitle(e.target.value)}
                    placeholder="Report title"
                    className="bg-[#1e1e1e] border-[#3d3d3d] text-gray-200 h-9"
                    data-testid="input-report-title"
                  />
                </div>
                <div>
                  <label className="text-[10px] text-gray-500 mb-1 block">Severity</label>
                  <Select value={reportSeverity} onValueChange={setReportSeverity}>
                    <SelectTrigger className="bg-[#1e1e1e] border-[#3d3d3d] text-gray-200 h-9" data-testid="select-report-severity">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="critical">Critical</SelectItem>
                      <SelectItem value="high">High</SelectItem>
                      <SelectItem value="medium">Medium</SelectItem>
                      <SelectItem value="low">Low</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
                <div>
                  <label className="text-[10px] text-gray-500 mb-1 block">Report Content</label>
                  <textarea
                    value={reportContent}
                    onChange={(e) => setReportContent(e.target.value)}
                    placeholder="Paste your draft report content here..."
                    rows={8}
                    className="w-full bg-[#1e1e1e] border border-[#3d3d3d] rounded-md px-3 py-2 text-xs text-gray-200 font-mono resize-none focus:outline-none focus:ring-1 focus:ring-purple-500 placeholder:text-gray-600"
                    data-testid="textarea-report-content"
                  />
                </div>
                <Button
                  onClick={analyzeReport}
                  disabled={reportLoading || !reportContent.trim()}
                  className="w-full bg-purple-600 hover:bg-purple-700 text-white"
                  data-testid="button-analyze-report"
                >
                  {reportLoading ? <Loader2 className="w-4 h-4 animate-spin mr-1" /> : <FileCheck className="w-4 h-4 mr-1" />}
                  Analyze Report
                </Button>
              </Card>

              {reportError && (
                <div className="flex items-center gap-2 text-red-400 text-xs bg-red-500/10 border border-red-500/20 rounded p-3" data-testid="text-report-error">
                  <AlertTriangle className="w-4 h-4" />
                  {reportError}
                </div>
              )}

              {reportResult && (
                <div className="space-y-4">
                  {reportResult.scores && Object.keys(reportResult.scores).length > 0 && (
                    <Card className="bg-[#252526] border-[#3d3d3d] p-4">
                      <h4 className="text-xs font-semibold text-gray-200 mb-3">Section Scores</h4>
                      <div className="space-y-2">
                        {Object.entries(reportResult.scores).map(([section, score]) => {
                          const s = score as number;
                          return (
                          <div key={section} className="flex items-center gap-3" data-testid={`text-score-${section}`}>
                            <span className="text-[10px] text-gray-400 w-24 capitalize">{section}</span>
                            <div className="flex-1 h-2 bg-[#1e1e1e] rounded-full overflow-hidden">
                              <div
                                className={cn(
                                  'h-full rounded-full transition-all',
                                  s >= 80 ? 'bg-green-500' : s >= 50 ? 'bg-yellow-500' : 'bg-red-500'
                                )}
                                style={{ width: `${s}%` }}
                              />
                            </div>
                            <span className="text-[10px] text-gray-300 w-8 text-right">{s}%</span>
                          </div>
                          );
                        })}
                      </div>
                    </Card>
                  )}

                  {reportResult.acceptanceChance !== undefined && (
                    <Card className="bg-[#252526] border-[#3d3d3d] p-4">
                      <h4 className="text-xs font-semibold text-gray-200 mb-3">Estimated Acceptance Chance</h4>
                      <div className="flex items-center gap-3" data-testid="text-acceptance-chance">
                        <div className="flex-1 h-4 bg-[#1e1e1e] rounded-full overflow-hidden">
                          <div
                            className={cn(
                              'h-full rounded-full transition-all',
                              reportResult.acceptanceChance >= 70 ? 'bg-green-500' :
                              reportResult.acceptanceChance >= 40 ? 'bg-yellow-500' : 'bg-red-500'
                            )}
                            style={{ width: `${reportResult.acceptanceChance}%` }}
                          />
                        </div>
                        <span className="text-sm font-bold text-gray-200">{reportResult.acceptanceChance}%</span>
                      </div>
                    </Card>
                  )}

                  {reportResult.suggestions && reportResult.suggestions.length > 0 && (
                    <Card className="bg-[#252526] border-[#3d3d3d] p-4">
                      <h4 className="text-xs font-semibold text-gray-200 mb-3">Improvement Suggestions</h4>
                      <ul className="space-y-2">
                        {reportResult.suggestions.map((s, i) => (
                          <li key={i} className="flex items-start gap-2 text-xs text-gray-400" data-testid={`text-suggestion-${i}`}>
                            <CheckCircle2 className="w-3.5 h-3.5 text-cyan-400 shrink-0 mt-0.5" />
                            {s}
                          </li>
                        ))}
                      </ul>
                    </Card>
                  )}

                  {reportResult.missingElements && reportResult.missingElements.length > 0 && (
                    <Card className="bg-[#252526] border-[#3d3d3d] p-4">
                      <h4 className="text-xs font-semibold text-gray-200 mb-3">Missing Elements</h4>
                      <ul className="space-y-2">
                        {reportResult.missingElements.map((m, i) => (
                          <li key={i} className="flex items-start gap-2 text-xs text-orange-400" data-testid={`text-missing-${i}`}>
                            <AlertTriangle className="w-3.5 h-3.5 shrink-0 mt-0.5" />
                            {m}
                          </li>
                        ))}
                      </ul>
                    </Card>
                  )}
                </div>
              )}
            </div>
          )}

          {tab === 'submissions' && (
            <div className="space-y-4">
              <Card className="bg-[#252526] border-[#3d3d3d] p-4 space-y-3">
                <div className="flex items-center gap-2 mb-1">
                  <Upload className="w-4 h-4 text-green-400" />
                  <span className="text-sm font-semibold text-gray-200">Submission Optimizer</span>
                </div>

                <div className="grid grid-cols-2 gap-3">
                  <div>
                    <label className="text-[10px] text-gray-500 mb-1 block">Title</label>
                    <Input
                      value={subTitle}
                      onChange={(e) => setSubTitle(e.target.value)}
                      placeholder="Vulnerability title"
                      className="bg-[#1e1e1e] border-[#3d3d3d] text-gray-200 h-9"
                      data-testid="input-sub-title"
                    />
                  </div>
                  <div>
                    <label className="text-[10px] text-gray-500 mb-1 block">Severity</label>
                    <Select value={subSeverity} onValueChange={setSubSeverity}>
                      <SelectTrigger className="bg-[#1e1e1e] border-[#3d3d3d] text-gray-200 h-9" data-testid="select-sub-severity">
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="critical">Critical</SelectItem>
                        <SelectItem value="high">High</SelectItem>
                        <SelectItem value="medium">Medium</SelectItem>
                        <SelectItem value="low">Low</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>
                </div>

                <div>
                  <label className="text-[10px] text-gray-500 mb-1 block">Vulnerability Type</label>
                  <Input
                    value={subVulnType}
                    onChange={(e) => setSubVulnType(e.target.value)}
                    placeholder="e.g., XSS, IDOR, SSRF"
                    className="bg-[#1e1e1e] border-[#3d3d3d] text-gray-200 h-9"
                    data-testid="input-sub-vuln-type"
                  />
                </div>

                <div>
                  <label className="text-[10px] text-gray-500 mb-1 block">Description</label>
                  <textarea
                    value={subDescription}
                    onChange={(e) => setSubDescription(e.target.value)}
                    placeholder="Describe the vulnerability..."
                    rows={3}
                    className="w-full bg-[#1e1e1e] border border-[#3d3d3d] rounded-md px-3 py-2 text-xs text-gray-200 resize-none focus:outline-none focus:ring-1 focus:ring-cyan-500 placeholder:text-gray-600"
                    data-testid="textarea-sub-description"
                  />
                </div>

                <div>
                  <label className="text-[10px] text-gray-500 mb-1 block">Steps to Reproduce</label>
                  <textarea
                    value={subSteps}
                    onChange={(e) => setSubSteps(e.target.value)}
                    placeholder="1. Navigate to...&#10;2. Enter...&#10;3. Observe..."
                    rows={3}
                    className="w-full bg-[#1e1e1e] border border-[#3d3d3d] rounded-md px-3 py-2 text-xs text-gray-200 resize-none focus:outline-none focus:ring-1 focus:ring-cyan-500 placeholder:text-gray-600"
                    data-testid="textarea-sub-steps"
                  />
                </div>

                <div>
                  <label className="text-[10px] text-gray-500 mb-1 block">Impact</label>
                  <textarea
                    value={subImpact}
                    onChange={(e) => setSubImpact(e.target.value)}
                    placeholder="Describe the security impact..."
                    rows={2}
                    className="w-full bg-[#1e1e1e] border border-[#3d3d3d] rounded-md px-3 py-2 text-xs text-gray-200 resize-none focus:outline-none focus:ring-1 focus:ring-cyan-500 placeholder:text-gray-600"
                    data-testid="textarea-sub-impact"
                  />
                </div>

                <div>
                  <label className="text-[10px] text-gray-500 mb-1 block">Proof of Concept</label>
                  <textarea
                    value={subPoc}
                    onChange={(e) => setSubPoc(e.target.value)}
                    placeholder="Paste PoC code or steps..."
                    rows={3}
                    className="w-full bg-[#1e1e1e] border border-[#3d3d3d] rounded-md px-3 py-2 text-xs text-gray-200 font-mono resize-none focus:outline-none focus:ring-1 focus:ring-cyan-500 placeholder:text-gray-600"
                    data-testid="textarea-sub-poc"
                  />
                </div>

                <div>
                  <label className="text-[10px] text-gray-500 mb-1 block">Affected Endpoint</label>
                  <Input
                    value={subEndpoint}
                    onChange={(e) => setSubEndpoint(e.target.value)}
                    placeholder="e.g., https://example.com/api/users"
                    className="bg-[#1e1e1e] border-[#3d3d3d] text-gray-200 h-9"
                    data-testid="input-sub-endpoint"
                  />
                </div>

                <div>
                  <label className="text-[10px] text-gray-500 mb-1 block">Platform</label>
                  <Select value={subPlatform} onValueChange={setSubPlatform}>
                    <SelectTrigger className="bg-[#1e1e1e] border-[#3d3d3d] text-gray-200 h-9" data-testid="select-sub-platform">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="HackerOne">HackerOne</SelectItem>
                      <SelectItem value="Bugcrowd">Bugcrowd</SelectItem>
                      <SelectItem value="Intigriti">Intigriti</SelectItem>
                      <SelectItem value="Generic">Generic</SelectItem>
                    </SelectContent>
                  </Select>
                </div>

                <Button
                  onClick={optimizeSubmission}
                  disabled={subLoading || !subTitle.trim() || !subDescription.trim()}
                  className="w-full bg-cyan-600 hover:bg-cyan-700 text-white"
                  data-testid="button-optimize-submission"
                >
                  {subLoading ? <Loader2 className="w-4 h-4 animate-spin mr-1" /> : <Zap className="w-4 h-4 mr-1" />}
                  Optimize & Preview
                </Button>
              </Card>

              {subError && (
                <div className="flex items-center gap-2 text-red-400 text-xs bg-red-500/10 border border-red-500/20 rounded p-3" data-testid="text-sub-error">
                  <AlertTriangle className="w-4 h-4" />
                  {subError}
                </div>
              )}

              {subResult && (
                <Card className="bg-[#252526] border-[#3d3d3d] p-4">
                  <div className="flex items-center justify-between mb-3">
                    <h4 className="text-xs font-semibold text-gray-200">Optimized Submission Preview</h4>
                    <button
                      onClick={copySubmission}
                      className="flex items-center gap-1 text-xs text-gray-400 hover:text-white transition-colors"
                      data-testid="button-copy-submission"
                    >
                      {subCopied ? (
                        <>
                          <CheckCircle2 className="w-3.5 h-3.5 text-green-400" />
                          <span className="text-green-400">Copied</span>
                        </>
                      ) : (
                        <>
                          <Copy className="w-3.5 h-3.5" />
                          <span>Copy</span>
                        </>
                      )}
                    </button>
                  </div>
                  <pre
                    className="bg-[#1e1e1e] border border-[#3d3d3d] rounded p-3 text-xs text-gray-300 font-mono whitespace-pre-wrap overflow-auto max-h-96"
                    data-testid="text-submission-preview"
                  >
                    {subResult.optimizedReport || subResult.preview || JSON.stringify(subResult, null, 2)}
                  </pre>
                </Card>
              )}
            </div>
          )}

          {tab === 'campaigns' && <CampaignIntelligence />}
          {tab === 'playbooks' && <PlaybookLibrary />}
          {tab === 'strategy' && <StrategyAdvisor />}
        </div>
      </ScrollArea>
    </div>
  );
}
