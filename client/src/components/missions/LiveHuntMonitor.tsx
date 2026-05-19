import { useState, useEffect, useCallback, useRef, type ReactNode } from 'react';
import { useSharedSocket } from '@/context/SocketContext';
import { csrfFetch } from '@/services/api';
import {
  Rocket, Play, Pause, Square, Target, Shield, Zap, Bug,
  Activity, ChevronRight, AlertTriangle, CheckCircle, XCircle,
  Clock, Loader2, RefreshCw, ArrowRight, Eye, GitBranch,
  Crosshair, Radio, TrendingUp, Cpu, Network,
  Terminal, Search, Wrench, FileSearch, ShieldCheck, Lightbulb, BookOpen, Hash, Brain, Hammer
} from 'lucide-react';

interface HuntTimeline {
  hunt: any;
  memory: {
    endpoints: number;
    technologies: number;
    vulnerabilities: number;
    endpointDetails: any[];
    vulnerabilityDetails: any[];
    notes: string[];
  } | null;
  chainReasoning: {
    active: boolean;
    stats: any;
    pathCount: number;
    chainCount: number;
    injectedEndpoints: string[];
    paths: any[];
    chains: any[];
  };
  agents: any[];
  events: any[];
}

interface LiveEvent {
  id: string;
  type: string;
  text: string;
  severity: string;
  time: string;
  data?: any;
}

const severityColors: Record<string, string> = {
  critical: 'text-red-400',
  high: 'text-orange-400',
  medium: 'text-yellow-400',
  low: 'text-blue-400',
  info: 'text-gray-400',
};

const severityBg: Record<string, string> = {
  critical: 'bg-red-500/20 border-red-500/40',
  high: 'bg-orange-500/20 border-orange-500/40',
  medium: 'bg-yellow-500/20 border-yellow-500/40',
  low: 'bg-blue-500/20 border-blue-500/40',
  info: 'bg-gray-500/20 border-gray-500/40',
};

export function LiveHuntMonitor() {
  const [huntId, setHuntId] = useState<string | null>(null);
  const [timeline, setTimeline] = useState<HuntTimeline | null>(null);
  const [liveEvents, setLiveEvents] = useState<LiveEvent[]>([]);
  const [launching, setLaunching] = useState(false);
  const [target, setTarget] = useState('http://localhost:3050');
  const [goal, setGoal] = useState('Find all vulnerabilities in OWASP Juice Shop - blind test');
  const [pollInterval, setPollInterval] = useState<ReturnType<typeof setInterval> | null>(null);
  const [activeTab, setActiveTab] = useState<'overview' | 'chain' | 'findings' | 'agents' | 'events'>('overview');
  const { socket } = useSharedSocket();
  const eventLogRef = useRef<HTMLDivElement>(null);
  const [autoScroll, setAutoScroll] = useState(true);
  const [activeFilter, setActiveFilter] = useState('all');

  const addLiveEvent = useCallback((type: string, text: string, severity: string, data?: any) => {
    const event: LiveEvent = {
      id: `${Date.now()}-${Math.random().toString(36).substr(2, 6)}`,
      type,
      text,
      severity,
      time: new Date().toLocaleTimeString('en-US', { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' }),
      data,
    };
    setLiveEvents(prev => [...prev, event].slice(-200));
  }, []);

  const fetchTimeline = useCallback(async (id: string) => {
    try {
      const res = await fetch(`/api/orchestration/hunts/${id}/timeline`);
      const data = await res.json();
      if (data.success) {
        setTimeline(data.timeline);
      }
    } catch (err) {
      console.error('Failed to fetch timeline:', err);
    }
  }, []);

  const launchHunt = async () => {
    if (!target) return;
    setLaunching(true);
    try {
      const res = await csrfFetch('/api/orchestration/hunts', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          target,
          goal,
          scope: { inScope: [target], outOfScope: [] },
          priority: 'high',
          autoAdvance: true,
        }),
      });
      const data = await res.json();
      const huntData = data.hunt?.hunt || data.hunt;
      if (data.success && huntData?.id) {
        setHuntId(huntData.id);
        addLiveEvent('launch', `Hunt launched against ${target}`, 'info');
        fetchTimeline(huntData.id);
      } else {
        addLiveEvent('error', `Launch failed: ${data.error}`, 'critical');
      }
    } catch (err) {
      addLiveEvent('error', `Launch error: ${(err as Error).message}`, 'critical');
    }
    setLaunching(false);
  };

  useEffect(() => {
    if (!huntId) return;
    const interval = setInterval(() => fetchTimeline(huntId), 3000);
    setPollInterval(interval);
    return () => clearInterval(interval);
  }, [huntId, fetchTimeline]);

  useEffect(() => {
    if (!socket) return;

    const handlers: Record<string, (data: any) => void> = {
      'chain:started': (d) => addLiveEvent('chain', `Chain reasoning activated for hunt`, 'info', d),
      'chain:stopped': (d) => addLiveEvent('chain', `Chain reasoning stopped`, 'info', d),
      'chain:finding_processed': (d) => {
        const sev = d.finding?.severity || 'medium';
        addLiveEvent('finding', `[${sev.toUpperCase()}] ${d.finding?.title || 'Finding'} at ${d.finding?.endpoint || '?'} → ${d.pathsGenerated} paths`, sev, d);
      },
      'chain:endpoint_injected': (d) => {
        addLiveEvent('inject', `Injected: ${d.url} (${d.technique}, score=${d.score}, depth=${d.depth}) [${d.totalInjected}/${d.maxInjections}]`, 'low', d);
      },
      'chain:scanner_spawned': (d) => {
        const label = d.isVerificationProbe ? 'Verification probe' : 'Scanner agent';
        addLiveEvent('spawn', `${label} spawned (phase=${d.phase}, ${d.endpointCount} endpoints)`, 'info', d);
      },
      'chain:escalation': (d) => {
        addLiveEvent('escalation', `ESCALATION: Critical/high chain detected!`, 'critical', d);
      },
      'hunt:phase_changed': (d) => {
        addLiveEvent('phase', `Phase: ${d.oldPhase || '?'} → ${d.newPhase}`, 'info', d);
      },
      'hunt:completed': (d) => {
        addLiveEvent('complete', `Hunt completed with ${d.findings || 0} findings`, 'low', d);
      },
      'hunt:paused': (d) => addLiveEvent('pause', `Hunt paused`, 'info', d),
      'hunt:resumed': (d) => addLiveEvent('resume', `Hunt resumed`, 'info', d),
      'hunt:started': (d) => addLiveEvent('hunt_start', d.text, d.severity || 'info', d),
      'hunt:step_started': (d) => addLiveEvent('step', d.text, d.severity || 'info', d),
      'hunt:step_completed': (d) => addLiveEvent('step_done', d.text, d.severity || 'low', d),
      'hunt:failed': (d) => addLiveEvent('hunt_fail', d.text, d.severity || 'critical', d),
      'hunt:attack_path': (d) => addLiveEvent('attack_path', d.text, d.severity || 'info', d),
      'hunt:knowledge_extracted': (d) => addLiveEvent('knowledge', d.text, d.severity || 'info', d),
      'chain:path_discovered': (d) => addLiveEvent('chain', d.text, d.severity || 'info', d),
      'tool:started': (d) => addLiveEvent('tool_run', d.text, d.severity || 'info', d),
      'tool:completed': (d) => addLiveEvent('tool_done', d.text, d.severity || 'low', d),
      'tool:shell': (d) => addLiveEvent('shell', d.text, d.severity || 'info', d),
      'agent:task_started': (d) => addLiveEvent('task', d.text, d.severity || 'info', d),
      'agent:task_completed': (d) => addLiveEvent('task_done', d.text, d.severity || 'low', d),
      'agent:task_failed': (d) => addLiveEvent('task_fail', d.text, d.severity || 'high', d),
      'agent:plan_generated': (d) => addLiveEvent('plan', d.text, d.severity || 'info', d),
      'finding:candidate': (d) => addLiveEvent('finding_new', d.text, d.severity || 'medium', d),
      'finding:verified': (d) => addLiveEvent('finding_verify', d.text, d.severity || 'info', d),
      'finding:added': (d) => addLiveEvent('finding_confirm', d.text, d.severity || 'medium', d),
      'scope:validated': (d) => addLiveEvent('scope', d.text, d.severity || 'info', d),
      'scope:changed': (d) => addLiveEvent('scope_change', d.text, d.severity || 'high', d),
      'novelty:checked': (d) => addLiveEvent('novelty', d.text, d.severity || 'info', d),
      'outcome:recorded': (d) => addLiveEvent('outcome', d.text, d.severity || 'info', d),
    };

    for (const [event, handler] of Object.entries(handlers)) {
      socket.on(event, handler);
    }

    return () => {
      for (const event of Object.keys(handlers)) {
        socket.off(event, handlers[event]);
      }
    };
  }, [socket, addLiveEvent]);

  useEffect(() => {
    if (autoScroll && eventLogRef.current) {
      eventLogRef.current.scrollTop = eventLogRef.current.scrollHeight;
    }
  }, [liveEvents, autoScroll]);

  const pauseHunt = async () => {
    if (!huntId) return;
    await csrfFetch(`/api/orchestration/hunts/${huntId}/pause`, { method: 'POST' });
    addLiveEvent('pause', 'Hunt paused', 'info');
  };

  const resumeHunt = async () => {
    if (!huntId) return;
    await csrfFetch(`/api/orchestration/hunts/${huntId}/resume`, { method: 'POST' });
    addLiveEvent('resume', 'Hunt resumed', 'info');
  };

  const eventTypeIcons: Record<string, any> = {
    launch: Rocket,
    chain: GitBranch,
    finding: Bug,
    inject: Crosshair,
    spawn: Cpu,
    escalation: AlertTriangle,
    phase: ArrowRight,
    complete: CheckCircle,
    pause: Pause,
    resume: Play,
    error: XCircle,
    hunt_start: Rocket,
    step: ArrowRight,
    step_done: CheckCircle,
    tool_run: Wrench,
    tool_done: Hammer,
    shell: Terminal,
    task: Cpu,
    task_done: CheckCircle,
    task_fail: XCircle,
    plan: Brain,
    finding_new: Bug,
    finding_verify: Eye,
    finding_confirm: ShieldCheck,
    scope: Shield,
    scope_change: AlertTriangle,
    novelty: Search,
    outcome: TrendingUp,
    attack_path: Network,
    knowledge: BookOpen,
    hunt_fail: XCircle,
  };

  const eventTypeColors: Record<string, string> = {
    launch: 'text-cyan-400',
    chain: 'text-purple-400',
    finding: 'text-orange-400',
    inject: 'text-green-400',
    spawn: 'text-blue-400',
    escalation: 'text-red-400',
    phase: 'text-yellow-400',
    complete: 'text-green-400',
    pause: 'text-yellow-400',
    resume: 'text-cyan-400',
    error: 'text-red-400',
    hunt_start: 'text-cyan-400',
    step: 'text-blue-300',
    step_done: 'text-blue-400',
    tool_run: 'text-amber-400',
    tool_done: 'text-amber-300',
    shell: 'text-gray-300',
    task: 'text-blue-400',
    task_done: 'text-green-400',
    task_fail: 'text-red-400',
    plan: 'text-indigo-400',
    finding_new: 'text-orange-400',
    finding_verify: 'text-cyan-300',
    finding_confirm: 'text-green-400',
    scope: 'text-teal-400',
    scope_change: 'text-red-400',
    novelty: 'text-pink-400',
    outcome: 'text-emerald-400',
    attack_path: 'text-purple-400',
    knowledge: 'text-yellow-300',
    hunt_fail: 'text-red-500',
  };

  const filterCategories = [
    { key: 'all', label: 'ALL' },
    { key: 'hunt', label: 'HUNT', match: ['hunt_start', 'step', 'step_done', 'phase', 'complete', 'pause', 'resume', 'attack_path', 'knowledge', 'hunt_fail', 'launch'] },
    { key: 'tool', label: 'TOOLS', match: ['tool_run', 'tool_done', 'shell'] },
    { key: 'chain', label: 'CHAIN', match: ['chain', 'inject', 'spawn', 'escalation'] },
    { key: 'agent', label: 'AGENT', match: ['task', 'task_done', 'task_fail', 'plan'] },
    { key: 'finding', label: 'FINDS', match: ['finding', 'finding_new', 'finding_verify', 'finding_confirm'] },
    { key: 'intel', label: 'INTEL', match: ['scope', 'scope_change', 'novelty', 'outcome'] },
  ];

  const filteredEvents = activeFilter === 'all'
    ? liveEvents
    : liveEvents.filter(e => {
        const cat = filterCategories.find(c => c.key === activeFilter);
        return cat?.match?.some(m => e.type === m || e.type.startsWith(m));
      });

  if (!huntId) {
    return (
      <div className="h-full bg-[#0d1117] flex flex-col" data-testid="hunt-launcher">
        <div className="border-b border-[#30363d] p-4">
          <div className="flex items-center gap-2 mb-4">
            <Target className="w-5 h-5 text-green-400" />
            <h2 className="text-lg font-bold text-green-400 font-mono">LIVE HUNT MONITOR</h2>
            <span className="text-xs text-gray-500 ml-auto font-mono">BLIND TEST MODE</span>
          </div>
        </div>

        <div className="flex-1 flex items-center justify-center p-8">
          <div className="max-w-lg w-full space-y-6">
            <div className="text-center mb-8">
              <Crosshair className="w-16 h-16 text-green-400 mx-auto mb-4 animate-pulse" />
              <h3 className="text-2xl font-bold text-white font-mono">Launch Blind Hunt</h3>
              <p className="text-gray-400 mt-2 text-sm">
                The system will autonomously discover, scan, and chain vulnerabilities.
                Watch the chain reasoning pipeline fire in real-time.
              </p>
            </div>

            <div className="space-y-4">
              <div>
                <label className="block text-xs text-gray-400 mb-1 font-mono">TARGET</label>
                <input
                  data-testid="input-target"
                  value={target}
                  onChange={(e) => setTarget(e.target.value)}
                  className="w-full bg-[#161b22] border border-[#30363d] rounded px-3 py-2 text-green-400 font-mono text-sm focus:border-green-500 focus:outline-none"
                  placeholder="http://localhost:3050"
                />
              </div>

              <div>
                <label className="block text-xs text-gray-400 mb-1 font-mono">MISSION GOAL</label>
                <input
                  data-testid="input-goal"
                  value={goal}
                  onChange={(e) => setGoal(e.target.value)}
                  className="w-full bg-[#161b22] border border-[#30363d] rounded px-3 py-2 text-white font-mono text-sm focus:border-green-500 focus:outline-none"
                  placeholder="Find all vulnerabilities..."
                />
              </div>

              <button
                data-testid="button-launch-hunt"
                onClick={launchHunt}
                disabled={launching || !target}
                className="w-full bg-green-600 hover:bg-green-500 disabled:bg-gray-700 text-white font-bold py-3 px-6 rounded font-mono text-sm transition-colors flex items-center justify-center gap-2"
              >
                {launching ? (
                  <>
                    <Loader2 className="w-4 h-4 animate-spin" />
                    LAUNCHING...
                  </>
                ) : (
                  <>
                    <Rocket className="w-4 h-4" />
                    LAUNCH AUTONOMOUS HUNT
                  </>
                )}
              </button>
            </div>

            <div className="bg-[#161b22] border border-[#30363d] rounded p-4 text-xs text-gray-400 font-mono space-y-1">
              <p className="text-yellow-400 font-bold">System will autonomously:</p>
              <p>1. Recon → map endpoints, detect technologies</p>
              <p>2. Scan → probe for vulnerabilities with 22 tools</p>
              <p>3. Chain → reason about attack paths from findings</p>
              <p>4. Inject → derive new endpoints from chains</p>
              <p>5. Exploit → verify and escalate findings</p>
            </div>
          </div>
        </div>
      </div>
    );
  }

  const huntPhase = timeline?.hunt?.phase || 'initializing';
  const chainActive = timeline?.chainReasoning?.active || false;
  const stats = timeline?.chainReasoning?.stats;

  return (
    <div className="h-full bg-[#0d1117] flex flex-col overflow-hidden" data-testid="hunt-monitor">
      {/* Header */}
      <div className="border-b border-[#30363d] p-3 flex items-center gap-3 flex-shrink-0">
        <div className="flex items-center gap-2">
          <Radio className="w-4 h-4 text-red-400 animate-pulse" />
          <span className="text-sm font-bold text-green-400 font-mono">LIVE</span>
        </div>
        <div className="text-xs text-gray-400 font-mono truncate flex-1">
          {target} — {huntPhase.toUpperCase()}
        </div>
        <div className="flex items-center gap-2">
          {chainActive && (
            <span className="flex items-center gap-1 text-xs text-purple-400 font-mono">
              <GitBranch className="w-3 h-3" /> CHAIN ACTIVE
            </span>
          )}
          <button onClick={pauseHunt} className="p-1 hover:bg-[#30363d] rounded" data-testid="button-pause-hunt">
            <Pause className="w-4 h-4 text-yellow-400" />
          </button>
          <button onClick={resumeHunt} className="p-1 hover:bg-[#30363d] rounded" data-testid="button-resume-hunt">
            <Play className="w-4 h-4 text-green-400" />
          </button>
        </div>
      </div>

      {/* Stats Bar */}
      <div className="border-b border-[#30363d] p-2 flex items-center gap-4 text-xs font-mono flex-shrink-0 bg-[#161b22]">
        <StatBadge icon={Network} label="Endpoints" value={timeline?.memory?.endpoints || 0} color="text-cyan-400" />
        <StatBadge icon={Bug} label="Vulns" value={timeline?.memory?.vulnerabilities || 0} color="text-red-400" />
        <StatBadge icon={GitBranch} label="Paths" value={stats?.pathsDiscovered || 0} color="text-purple-400" />
        <StatBadge icon={Crosshair} label="Injected" value={stats?.endpointsInjected || 0} color="text-green-400" />
        <StatBadge icon={TrendingUp} label="Depth" value={stats?.maxDepthReached || 0} color="text-yellow-400" />
        <StatBadge icon={Cpu} label="Agents" value={timeline?.agents?.length || 0} color="text-blue-400" />
        <div className="ml-auto text-gray-500">
          Cap: {stats?.capUtilization || '0/50'}
        </div>
      </div>

      {/* Tabs */}
      <div className="border-b border-[#30363d] flex flex-shrink-0">
        {(['overview', 'chain', 'findings', 'agents', 'events'] as const).map(tab => (
          <button
            key={tab}
            data-testid={`tab-${tab}`}
            onClick={() => setActiveTab(tab)}
            className={`px-4 py-2 text-xs font-mono transition-colors ${
              activeTab === tab
                ? 'text-green-400 border-b-2 border-green-400 bg-[#161b22]'
                : 'text-gray-400 hover:text-white'
            }`}
          >
            {tab.toUpperCase()}
          </button>
        ))}
      </div>

      {/* Content + Live Log */}
      <div className="flex-1 flex overflow-hidden">
        {/* Main Content */}
        <div className="flex-1 overflow-auto p-3">
          {activeTab === 'overview' && <OverviewTab timeline={timeline} />}
          {activeTab === 'chain' && <ChainTab timeline={timeline} />}
          {activeTab === 'findings' && <FindingsTab timeline={timeline} />}
          {activeTab === 'agents' && <AgentsTab timeline={timeline} />}
          {activeTab === 'events' && <EventsTab events={timeline?.events || []} />}
        </div>

        {/* Live Event Log (right sidebar) */}
        <div className="w-80 border-l border-[#30363d] flex flex-col flex-shrink-0 bg-[#0d1117]">
          <div className="flex items-center justify-between p-2 border-b border-[#30363d]">
            <span className="text-xs font-mono text-gray-400">LIVE FEED</span>
            <span className="text-[10px] text-gray-600 font-mono">{filteredEvents.length}/{liveEvents.length}</span>
            <button
              onClick={() => setAutoScroll(!autoScroll)}
              className={`text-xs font-mono ${autoScroll ? 'text-green-400' : 'text-gray-500'}`}
              data-testid="button-toggle-autoscroll"
            >
              {autoScroll ? 'AUTO' : 'MANUAL'}
            </button>
          </div>
          <div className="flex flex-wrap gap-1 p-2 border-b border-[#30363d]">
            {filterCategories.map(cat => (
              <button
                key={cat.key}
                data-testid={`filter-${cat.key}`}
                onClick={() => setActiveFilter(cat.key)}
                className={`px-2 py-0.5 text-[10px] font-mono rounded ${
                  activeFilter === cat.key
                    ? 'bg-green-600/30 text-green-400 border border-green-500/50'
                    : 'bg-[#161b22] text-gray-500 border border-[#30363d] hover:text-gray-300'
                }`}
              >
                {cat.label}
              </button>
            ))}
          </div>
          <div ref={eventLogRef} className="flex-1 overflow-auto p-2 space-y-1">
            {filteredEvents.length === 0 ? (
              <div className="text-center text-gray-500 text-xs font-mono mt-8">
                Waiting for events...
              </div>
            ) : (
              filteredEvents.map(event => {
                const Icon = eventTypeIcons[event.type] || Activity;
                const color = eventTypeColors[event.type] || 'text-gray-400';
                return (
                  <div key={event.id} data-testid={`event-${event.id}`}>
                    <div className="flex items-start gap-1.5 text-xs font-mono group">
                      <span className="text-gray-600 flex-shrink-0 w-16">{event.time}</span>
                      <Icon className={`w-3 h-3 flex-shrink-0 mt-0.5 ${color}`} />
                      <span className={`${severityColors[event.severity] || 'text-gray-300'} break-all`}>
                        {event.text}
                      </span>
                    </div>
                    {event.data && (event.data.outputSnippet || event.data.command || event.data.reasoning || event.data.rationale) && (
                      <details className="mt-0.5 ml-[calc(64px+14px)]">
                        <summary className="text-[10px] text-gray-600 cursor-pointer hover:text-gray-400">details</summary>
                        <pre className="text-[10px] text-gray-500 bg-black/30 rounded p-1 mt-0.5 max-h-20 overflow-auto whitespace-pre-wrap">
                          {event.data.outputSnippet || event.data.command || event.data.reasoning || event.data.rationale}
                        </pre>
                      </details>
                    )}
                  </div>
                );
              })
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

function StatBadge({ icon: Icon, label, value, color }: { icon: any; label: string; value: number; color: string }) {
  return (
    <div className="flex items-center gap-1">
      <Icon className={`w-3 h-3 ${color}`} />
      <span className="text-gray-500">{label}:</span>
      <span className={`${color} font-bold`}>{value}</span>
    </div>
  );
}

function OverviewTab({ timeline }: { timeline: HuntTimeline | null }) {
  if (!timeline) return <div className="text-gray-500 text-xs font-mono">Loading...</div>;

  const { hunt, memory, chainReasoning, agents } = timeline;

  return (
    <div className="space-y-4">
      {/* Hunt Status */}
      <Section title="Hunt Status">
        <div className="grid grid-cols-2 gap-3 text-xs font-mono">
          <KV label="ID" value={hunt?.id?.substring(0, 8) + '...'} />
          <KV label="Phase" value={hunt?.phase?.toUpperCase()} valueColor="text-green-400" />
          <KV label="Target" value={hunt?.target} />
          <KV label="Stealth" value={hunt?.stealthMode} />
          <KV label="Auto-Advance" value={hunt?.autoAdvance ? 'YES' : 'NO'} />
          <KV label="Started" value={hunt?.startedAt ? new Date(hunt.startedAt).toLocaleTimeString() : '-'} />
        </div>
      </Section>

      {/* Memory Summary */}
      {memory && (
        <Section title="Mission Memory">
          <div className="grid grid-cols-3 gap-3">
            <MetricCard label="Endpoints" value={memory.endpoints} color="text-cyan-400" />
            <MetricCard label="Technologies" value={memory.technologies} color="text-blue-400" />
            <MetricCard label="Vulnerabilities" value={memory.vulnerabilities} color="text-red-400" />
          </div>
          {memory.notes.length > 0 && (
            <div className="mt-3 space-y-1">
              <span className="text-xs text-gray-500 font-mono">Notes:</span>
              {memory.notes.slice(-5).map((n, i) => (
                <p key={i} className="text-xs text-gray-400 font-mono truncate">{n}</p>
              ))}
            </div>
          )}
        </Section>
      )}

      {/* Chain Reasoning Summary */}
      <Section title="Chain Reasoning">
        <div className="grid grid-cols-2 gap-3 text-xs font-mono">
          <KV label="Status" value={chainReasoning.active ? 'ACTIVE' : 'INACTIVE'} valueColor={chainReasoning.active ? 'text-green-400' : 'text-gray-500'} />
          <KV label="Findings Processed" value={chainReasoning.stats?.findingsProcessed || 0} />
          <KV label="Paths Discovered" value={chainReasoning.stats?.pathsDiscovered || 0} />
          <KV label="Chains Built" value={chainReasoning.stats?.chainsBuilt || 0} />
          <KV label="Endpoints Injected" value={chainReasoning.stats?.endpointsInjected || 0} />
          <KV label="Max Depth" value={chainReasoning.stats?.maxDepthReached || 0} />
        </div>
      </Section>

      {/* Active Agents */}
      <Section title={`Agents (${agents.length})`}>
        {agents.length === 0 ? (
          <p className="text-xs text-gray-500 font-mono">No agents running</p>
        ) : (
          <div className="space-y-2">
            {agents.map(a => (
              <div key={a.id} className="flex items-center justify-between bg-[#161b22] px-3 py-2 rounded border border-[#30363d]">
                <div className="flex items-center gap-2">
                  <Cpu className="w-3 h-3 text-blue-400" />
                  <span className="text-xs text-white font-mono">{a.type}</span>
                  <span className={`text-xs font-mono ${a.status === 'running' ? 'text-green-400' : a.status === 'idle' ? 'text-yellow-400' : 'text-gray-500'}`}>
                    {a.status}
                  </span>
                </div>
                <span className="text-xs text-gray-500 font-mono">{a.invocations} runs / {a.successCount} ok</span>
              </div>
            ))}
          </div>
        )}
      </Section>
    </div>
  );
}

function ChainTab({ timeline }: { timeline: HuntTimeline | null }) {
  if (!timeline) return null;
  const { chainReasoning } = timeline;

  return (
    <div className="space-y-4">
      {/* Injected Endpoints */}
      <Section title={`Injected Endpoints (${chainReasoning.injectedEndpoints.length})`}>
        {chainReasoning.injectedEndpoints.length === 0 ? (
          <p className="text-xs text-gray-500 font-mono">No endpoints injected yet</p>
        ) : (
          <div className="space-y-1">
            {chainReasoning.injectedEndpoints.map((url, i) => (
              <div key={i} className="flex items-center gap-2 text-xs font-mono bg-[#161b22] px-3 py-1.5 rounded border border-[#30363d]">
                <Crosshair className="w-3 h-3 text-green-400 flex-shrink-0" />
                <span className="text-green-400 truncate">{url}</span>
              </div>
            ))}
          </div>
        )}
      </Section>

      {/* Attack Paths */}
      <Section title={`Attack Paths (${chainReasoning.pathCount})`}>
        {chainReasoning.paths.length === 0 ? (
          <p className="text-xs text-gray-500 font-mono">No attack paths discovered yet</p>
        ) : (
          <div className="space-y-2">
            {chainReasoning.paths.map((p: any, i: number) => (
              <div key={i} className={`border rounded p-3 ${severityBg[p.estimatedSeverity] || severityBg.info}`}>
                <div className="flex items-center justify-between mb-1">
                  <span className="text-xs font-mono font-bold text-white">{p.technique}</span>
                  <span className={`text-xs font-mono ${severityColors[p.estimatedSeverity]}`}>
                    {p.estimatedSeverity?.toUpperCase()} ({(p.confidence * 100).toFixed(0)}%)
                  </span>
                </div>
                <p className="text-xs text-gray-400 font-mono">{p.description}</p>
                {p.targetEndpoint && (
                  <p className="text-xs text-green-400 font-mono mt-1">→ {p.targetEndpoint}</p>
                )}
              </div>
            ))}
          </div>
        )}
      </Section>

      {/* Exploit Chains */}
      <Section title={`Exploit Chains (${chainReasoning.chainCount})`}>
        {chainReasoning.chains.length === 0 ? (
          <p className="text-xs text-gray-500 font-mono">No exploit chains built yet</p>
        ) : (
          <div className="space-y-2">
            {chainReasoning.chains.map((c: any, i: number) => (
              <div key={i} className={`border rounded p-3 ${severityBg[c.combinedSeverity] || severityBg.info}`}>
                <div className="flex items-center justify-between">
                  <span className="text-xs font-mono text-white">Chain #{i + 1} — {c.steps} steps</span>
                  <span className={`text-xs font-mono ${severityColors[c.combinedSeverity]}`}>
                    {c.combinedSeverity?.toUpperCase()} ({(c.confidence * 100).toFixed(0)}%)
                  </span>
                </div>
              </div>
            ))}
          </div>
        )}
      </Section>
    </div>
  );
}

function FindingsTab({ timeline }: { timeline: HuntTimeline | null }) {
  if (!timeline?.memory) return <p className="text-xs text-gray-500 font-mono">No memory data</p>;

  const vulns = timeline.memory.vulnerabilityDetails || [];

  return (
    <div className="space-y-4">
      <Section title={`Vulnerabilities (${vulns.length})`}>
        {vulns.length === 0 ? (
          <p className="text-xs text-gray-500 font-mono">No vulnerabilities found yet</p>
        ) : (
          <div className="space-y-2">
            {vulns.map((v: any, i: number) => (
              <div key={i} className={`border rounded p-3 ${severityBg[v.severity] || severityBg.info}`}>
                <div className="flex items-center justify-between mb-1">
                  <span className="text-xs font-mono font-bold text-white">{v.type || v.title || 'Unknown'}</span>
                  <span className={`text-xs font-mono ${severityColors[v.severity]}`}>
                    {v.severity?.toUpperCase()}
                  </span>
                </div>
                {v.endpoint && <p className="text-xs text-cyan-400 font-mono">{v.endpoint}</p>}
                {v.description && <p className="text-xs text-gray-400 font-mono mt-1">{v.description}</p>}
                {v.evidence && (
                  <details className="mt-2">
                    <summary className="text-xs text-gray-500 font-mono cursor-pointer">Evidence</summary>
                    <pre className="text-xs text-gray-400 font-mono mt-1 bg-black/30 p-2 rounded overflow-x-auto max-h-32">
                      {typeof v.evidence === 'string' ? v.evidence : JSON.stringify(v.evidence, null, 2)}
                    </pre>
                  </details>
                )}
              </div>
            ))}
          </div>
        )}
      </Section>

      {/* Discovered Endpoints */}
      <Section title={`Discovered Endpoints (${timeline.memory.endpoints})`}>
        {timeline.memory.endpointDetails.length === 0 ? (
          <p className="text-xs text-gray-500 font-mono">No endpoints discovered yet</p>
        ) : (
          <div className="space-y-1 max-h-64 overflow-auto">
            {timeline.memory.endpointDetails.map((ep: any, i: number) => (
              <div key={i} className="flex items-center gap-2 text-xs font-mono bg-[#161b22] px-3 py-1.5 rounded border border-[#30363d]">
                <span className="text-gray-500 w-10">{ep.method || 'GET'}</span>
                <span className="text-cyan-400 truncate flex-1">{ep.url}</span>
                <span className="text-gray-600 text-[10px]">{ep.discoveredBy || '?'}</span>
              </div>
            ))}
          </div>
        )}
      </Section>
    </div>
  );
}

function AgentsTab({ timeline }: { timeline: HuntTimeline | null }) {
  if (!timeline) return null;
  const { agents } = timeline;

  return (
    <div className="space-y-4">
      <Section title={`Active Agents (${agents.length})`}>
        {agents.length === 0 ? (
          <p className="text-xs text-gray-500 font-mono">No agents</p>
        ) : (
          <div className="space-y-2">
            {agents.map(a => (
              <div key={a.id} className="bg-[#161b22] border border-[#30363d] rounded p-3">
                <div className="flex items-center justify-between mb-2">
                  <div className="flex items-center gap-2">
                    <Cpu className="w-4 h-4 text-blue-400" />
                    <span className="text-sm text-white font-mono font-bold">{a.type}</span>
                  </div>
                  <span className={`text-xs font-mono px-2 py-0.5 rounded ${
                    a.status === 'running' ? 'bg-green-500/20 text-green-400' :
                    a.status === 'idle' ? 'bg-yellow-500/20 text-yellow-400' :
                    'bg-gray-500/20 text-gray-400'
                  }`}>
                    {a.status}
                  </span>
                </div>
                <div className="grid grid-cols-3 gap-2 text-xs font-mono">
                  <KV label="Invocations" value={a.invocations} />
                  <KV label="Success" value={a.successCount} valueColor="text-green-400" />
                  <KV label="Failures" value={a.failureCount} valueColor="text-red-400" />
                </div>
                <p className="text-[10px] text-gray-600 font-mono mt-2">{a.id}</p>
              </div>
            ))}
          </div>
        )}
      </Section>
    </div>
  );
}

function EventsTab({ events }: { events: any[] }) {
  return (
    <div className="space-y-4">
      <Section title={`Event Bus History (${events.length})`}>
        {events.length === 0 ? (
          <p className="text-xs text-gray-500 font-mono">No events</p>
        ) : (
          <div className="space-y-1">
            {events.map((e: any, i: number) => (
              <div key={i} className="flex items-start gap-2 text-xs font-mono bg-[#161b22] px-3 py-1.5 rounded border border-[#30363d]">
                <span className="text-gray-600 flex-shrink-0 w-16">
                  {e.timestamp ? new Date(e.timestamp).toLocaleTimeString('en-US', { hour12: false }) : ''}
                </span>
                <span className="text-yellow-400 flex-shrink-0 w-28">{e.type}</span>
                <span className="text-blue-400 flex-shrink-0 w-20">{e.source}</span>
                <span className="text-gray-400 truncate">{typeof e.data === 'object' ? JSON.stringify(e.data) : e.data}</span>
              </div>
            ))}
          </div>
        )}
      </Section>
    </div>
  );
}

function Section({ title, children }: { title: string; children: ReactNode }) {
  return (
    <div>
      <h3 className="text-xs font-mono text-gray-500 uppercase mb-2 flex items-center gap-1">
        <ChevronRight className="w-3 h-3" />
        {title}
      </h3>
      {children}
    </div>
  );
}

function KV({ label, value, valueColor }: { label: string; value: any; valueColor?: string }) {
  return (
    <div>
      <span className="text-gray-500">{label}: </span>
      <span className={valueColor || 'text-white'}>{String(value ?? '-')}</span>
    </div>
  );
}

function MetricCard({ label, value, color }: { label: string; value: number; color: string }) {
  return (
    <div className="bg-[#161b22] border border-[#30363d] rounded p-3 text-center">
      <div className={`text-2xl font-bold font-mono ${color}`}>{value}</div>
      <div className="text-xs text-gray-500 font-mono">{label}</div>
    </div>
  );
}
