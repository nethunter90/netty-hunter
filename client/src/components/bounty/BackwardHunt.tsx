import { useState, useEffect, useRef } from 'react';
import { Card } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Badge } from '@/components/ui/badge';
import { ScrollArea } from '@/components/ui/scroll-area';
import {
  Play, Target, TrendingUp, Square, Activity, Loader2,
  Brain, DollarSign, Shield, Zap, AlertCircle
} from 'lucide-react';
import { csrfFetch } from '@/services/api';
import { useToast } from '@/hooks/use-toast';
import { useSharedSocket } from '@/context/SocketContext';

interface StrategyRec {
  technique: string;
  adjustedEV: number;
  successProbability: number;
  duplicateProbability: number;
  expectedPayout: number;
}

const HUNT_GOALS = [
  'Account Takeover',
  'Payment Manipulation',
  'PII Exposure',
  'RCE',
  'SSRF',
  'SQL Injection',
  'XSS',
  'IDOR',
  'Auth Bypass',
  'Custom'
];

function evColor(ev: number): string {
  if (ev >= 1000) return 'text-green-400';
  if (ev >= 500) return 'text-yellow-400';
  return 'text-gray-400';
}

function evBadgeClass(ev: number): string {
  if (ev >= 1000) return 'bg-green-500/20 text-green-400 border-green-500/30';
  if (ev >= 500) return 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30';
  return 'bg-gray-500/20 text-gray-400 border-gray-500/30';
}

export function BackwardHunt() {
  const [target, setTarget] = useState('');
  const [goal, setGoal] = useState('Account Takeover');
  const [loading, setLoading] = useState(false);
  const [activeHunts, setActiveHunts] = useState<any[]>([]);
  const [agentStatus, setAgentStatus] = useState<any>(null);
  const [taskQueue, setTaskQueue] = useState<any[]>([]);
  const [strategyRecs, setStrategyRecs] = useState<StrategyRec[]>([]);
  const [strategyLoading, setStrategyLoading] = useState(false);
  const [error, setError] = useState('');
  const socketRef = useRef<any>(null);
  const { toast } = useToast();
  const { socket } = useSharedSocket();

  useEffect(() => {
    if (socket) {
      socketRef.current = socket;
    }
  }, [socket]);

  useEffect(() => {
    fetchHunts();
    const interval = setInterval(fetchHunts, 3000);
    return () => clearInterval(interval);
  }, []);

  useEffect(() => {
    if (!socket) return;

    const handleStatus = (status: any) => {
      setAgentStatus(status);
    };

    const handleQueue = (queue: any[]) => {
      setTaskQueue(queue);
    };

    socket.on('agent:status', handleStatus);
    socket.on('agent:queue', handleQueue);

    return () => {
      socket.off('agent:status', handleStatus);
      socket.off('agent:queue', handleQueue);
    };
  }, [socket]);

  useEffect(() => {
    if (target.trim().length > 3) {
      const debounce = setTimeout(() => fetchStrategyRecs(), 500);
      return () => clearTimeout(debounce);
    } else {
      setStrategyRecs([]);
    }
  }, [target]);

  const fetchStrategyRecs = async () => {
    setStrategyLoading(true);
    try {
      const res = await fetch(`/api/intelligence/unified/quick?programId=default&target=${encodeURIComponent(target.trim())}`);
      const data = await res.json();
      if (data.success && data.data) {
        setStrategyRecs(data.data);
      }
    } catch (err) {
      console.error('Failed to fetch strategy recommendations:', err);
    } finally {
      setStrategyLoading(false);
    }
  };

  const startHunt = async () => {
    if (!target) return;
    setLoading(true);
    setError('');
    try {
      const response = await csrfFetch('/api/bounty/hunts', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          target,
          goal,
          scope: { inScope: [target], outOfScope: [] }
        })
      });
      const data = await response.json();
      if (data.success) {
        setTarget('');
        setStrategyRecs([]);
        fetchHunts();
      } else {
        const message = data.error || 'Failed to start hunt. The server returned an error.';
        setError(message);
        toast({ variant: 'destructive', title: 'Hunt Failed', description: message });
      }
    } catch (err) {
      const message = 'Failed to start hunt. The backend service may be unavailable.';
      setError(message);
      toast({ variant: 'destructive', title: 'Hunt Failed', description: message });
    } finally {
      setLoading(false);
    }
  };

  const stopHunt = async (huntId: string) => {
    try {
      await csrfFetch(`/api/bounty/hunts/${huntId}/stop`, { method: 'POST' });
      fetchHunts();
    } catch (error) {
      console.error('Failed to stop hunt:', error);
    }
  };

  const fetchHunts = async () => {
    try {
      const response = await fetch('/api/bounty/hunts');
      const data = await response.json();
      if (data.success) {
        setActiveHunts(data.hunts);
      }
    } catch (error) {
      console.error('Failed to fetch hunts:', error);
    }
  };

  return (
    <div className="h-full flex flex-col bg-[#1e1e1e] overflow-hidden">
      <ScrollArea className="flex-1">
        <div className="p-6">
          <div className="mb-6">
            <div className="flex items-center gap-3 mb-2">
              <Target className="w-6 h-6 text-cyan-400" />
              <h1 className="text-2xl font-bold text-gray-100">Backward Hunt</h1>
            </div>
            <p className="text-sm text-gray-400">
              Goal-first methodology: Start with what you want to find, work backward to discover the path.
            </p>
          </div>

          {agentStatus && (
            <div className="mb-4 flex items-center gap-4 px-4 py-2 bg-[#252526] rounded-md border border-[#3d3d3d]">
              <div className="flex items-center gap-2">
                <div className={`w-2 h-2 rounded-full ${agentStatus.running ? 'bg-green-400 animate-pulse' : 'bg-red-400'}`} />
                <span className="text-xs text-gray-400">Agent {agentStatus.running ? 'Running' : 'Stopped'}</span>
              </div>
              <div className="text-xs text-gray-500">
                Queue: {agentStatus.queueLength} task(s)
              </div>
              {agentStatus.currentTask && (
                <div className="flex items-center gap-1 text-xs text-cyan-400">
                  <Loader2 className="w-3 h-3 animate-spin" />
                  <span>Executing: {agentStatus.currentTask.description?.slice(0, 40)}...</span>
                </div>
              )}
              {agentStatus.simulationMode && (
                <Badge variant="outline" className="text-xs text-yellow-400 border-yellow-400/30">SIM</Badge>
              )}
            </div>
          )}

          {error && (
            <div className="flex items-center gap-2 p-3 bg-red-500/10 border border-red-500/30 rounded-md mb-4" data-testid="text-error">
              <AlertCircle className="w-4 h-4 text-red-400 flex-shrink-0" />
              <p className="text-xs text-red-400">{error}</p>
            </div>
          )}

          <Card className="bg-[#252526] border-[#3d3d3d] p-6 mb-6">
            <h3 className="text-sm font-semibold text-gray-200 mb-4">Start New Hunt</h3>
            <div className="space-y-4">
              <div>
                <Label className="text-xs text-gray-400 mb-2">Target Domain</Label>
                <Input
                  placeholder="example.com"
                  value={target}
                  onChange={(e) => setTarget(e.target.value)}
                  className="bg-[#1e1e1e] border-[#3d3d3d] text-gray-200 h-10"
                  data-testid="input-hunt-target"
                  onKeyDown={(e) => e.key === 'Enter' && startHunt()}
                />
              </div>
              <div>
                <Label className="text-xs text-gray-400 mb-2">Hunt Goal</Label>
                <Select value={goal} onValueChange={setGoal}>
                  <SelectTrigger className="bg-[#1e1e1e] border-[#3d3d3d] text-gray-200 h-10" data-testid="select-hunt-goal">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {HUNT_GOALS.map(g => (
                      <SelectItem key={g} value={g}>{g}</SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>

              {target.trim().length > 3 && (
                <div className="border-t border-[#3d3d3d] pt-4" data-testid="pre-hunt-strategy-panel">
                  <div className="flex items-center gap-2 mb-3">
                    <Brain className="w-4 h-4 text-emerald-400" />
                    <h4 className="text-sm font-semibold text-gray-200">Pre-Hunt Intelligence Briefing</h4>
                    {strategyLoading && <Loader2 className="w-3 h-3 text-gray-400 animate-spin" />}
                  </div>

                  {strategyLoading && strategyRecs.length === 0 && (
                    <div className="flex items-center justify-center py-4 text-xs text-gray-500">
                      <Loader2 className="w-4 h-4 mr-2 animate-spin text-emerald-400" />
                      Analyzing target intelligence...
                    </div>
                  )}

                  {!strategyLoading && strategyRecs.length === 0 && (
                    <div className="text-xs text-gray-500 py-3 px-2 bg-[#1e1e1e] rounded border border-[#3d3d3d]">
                      No historical data available for this target. Recommendations will improve as the system learns from completed hunts.
                    </div>
                  )}

                  {strategyRecs.length > 0 && (
                    <div className="space-y-2">
                      {strategyRecs.map((rec, idx) => (
                        <div
                          key={rec.technique}
                          className="flex items-center gap-3 px-3 py-2.5 bg-[#1e1e1e] rounded border border-[#3d3d3d] hover:border-emerald-500/30 transition-colors"
                          data-testid={`strategy-rec-${rec.technique}`}
                        >
                          <span className="text-xs text-gray-500 font-mono w-5 text-right">#{idx + 1}</span>

                          <div className="flex-1 min-w-0">
                            <div className="flex items-center gap-2 mb-1">
                              <span className="text-sm font-medium text-gray-200 uppercase">{rec.technique}</span>
                              {idx === 0 && (
                                <Badge variant="outline" className="text-xs text-emerald-400 border-emerald-500/30 bg-emerald-500/10 py-0">
                                  Top Pick
                                </Badge>
                              )}
                            </div>
                            <div className="flex items-center gap-3 text-xs">
                              <span className="flex items-center gap-1 text-cyan-400">
                                <Zap className="w-3 h-3" />
                                {Math.round(rec.successProbability * 100)}% success
                              </span>
                              <span className={`flex items-center gap-1 ${rec.duplicateProbability > 0.5 ? 'text-red-400' : rec.duplicateProbability > 0.3 ? 'text-amber-400' : 'text-gray-400'}`}>
                                <Shield className="w-3 h-3" />
                                {Math.round(rec.duplicateProbability * 100)}% dup risk
                              </span>
                              <span className="flex items-center gap-1 text-yellow-400">
                                <DollarSign className="w-3 h-3" />
                                ${Math.round(rec.expectedPayout)}
                              </span>
                            </div>
                          </div>

                          <Badge variant="outline" className={`text-xs font-mono shrink-0 ${evBadgeClass(rec.adjustedEV)}`}>
                            <TrendingUp className="w-3 h-3 mr-1" />
                            EV ${Math.round(rec.adjustedEV)}
                          </Badge>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              )}

              <Button
                onClick={startHunt}
                disabled={loading || !target}
                className="w-full bg-cyan-600 hover:bg-cyan-700 text-white h-10"
                data-testid="button-start-hunt"
              >
                {loading ? <Loader2 className="w-4 h-4 mr-2 animate-spin" /> : <Play className="w-4 h-4 mr-2" />}
                {loading ? 'Starting Hunt...' : 'Start Hunt'}
              </Button>
            </div>
          </Card>

          {taskQueue.length > 0 && (
            <Card className="bg-[#252526] border-[#3d3d3d] p-4 mb-6">
              <div className="flex items-center gap-2 mb-3">
                <Activity className="w-4 h-4 text-purple-400" />
                <h3 className="text-sm font-semibold text-gray-200">Live Task Queue</h3>
                <Badge variant="outline" className="text-xs">{taskQueue.length}</Badge>
              </div>
              <div className="space-y-2">
                {taskQueue.slice(0, 5).map((task: any, i: number) => (
                  <div key={task.id || i} className="flex items-center gap-3 px-3 py-2 bg-[#1e1e1e] rounded text-xs">
                    <Badge variant="outline" className="text-purple-400 border-purple-400/30 shrink-0">{task.type}</Badge>
                    <span className="text-gray-300 truncate">{task.description}</span>
                    {task.priority === 'high' && <Badge variant="destructive" className="text-xs shrink-0">HIGH</Badge>}
                  </div>
                ))}
                {taskQueue.length > 5 && (
                  <p className="text-xs text-gray-500 text-center">+{taskQueue.length - 5} more tasks</p>
                )}
              </div>
            </Card>
          )}

          <div>
            <h3 className="text-sm font-semibold text-gray-300 mb-3">Active Hunts</h3>
            {activeHunts.length === 0 ? (
              <div className="text-center py-12 text-gray-500 text-sm" data-testid="text-no-hunts">
                No active hunts. Start one above.
              </div>
            ) : (
              <div className="space-y-3">
                {activeHunts.map(hunt => (
                  <Card key={hunt.id} className="bg-[#252526] border-[#3d3d3d] p-4" data-testid={`card-hunt-${hunt.id}`}>
                    <div className="flex items-start justify-between mb-2">
                      <div>
                        <h4 className="font-semibold text-gray-200">{hunt.target}</h4>
                        <p className="text-xs text-gray-400">{hunt.goal}</p>
                      </div>
                      <div className="flex items-center gap-2">
                        <Badge
                          variant={
                            hunt.status === 'active' ? 'default' :
                            hunt.status === 'completed' ? 'secondary' : 'destructive'
                          }
                        >
                          {hunt.status}
                        </Badge>
                        {hunt.status === 'active' && (
                          <button
                            onClick={() => stopHunt(hunt.id)}
                            className="p-1 text-red-400 hover:text-red-300 transition-colors"
                            title="Stop Hunt"
                            data-testid={`button-stop-hunt-${hunt.id}`}
                          >
                            <Square className="w-3.5 h-3.5" />
                          </button>
                        )}
                      </div>
                    </div>

                    {hunt.status === 'active' && (
                      <div className="mb-2">
                        <div className="flex items-center gap-2 text-xs text-cyan-400">
                          <Loader2 className="w-3 h-3 animate-spin" />
                          <span>Step {hunt.currentStep + 1} in progress...</span>
                        </div>
                      </div>
                    )}

                    {hunt.findings && hunt.findings.length > 0 && (
                      <div className="mt-2 space-y-1">
                        <div className="flex items-center gap-2 text-xs text-green-400">
                          <TrendingUp className="w-3 h-3" />
                          {hunt.findings.length} finding(s)
                        </div>
                        {hunt.findings.slice(0, 3).map((f: any, i: number) => (
                          <div key={i} className="flex items-center gap-2 ml-5 text-xs">
                            <Badge variant="outline" className={`text-xs ${
                              f.severity === 'critical' ? 'text-red-400 border-red-400/30' :
                              f.severity === 'high' ? 'text-orange-400 border-orange-400/30' :
                              f.severity === 'medium' ? 'text-yellow-400 border-yellow-400/30' :
                              'text-green-400 border-green-400/30'
                            }`}>{f.severity}</Badge>
                            <span className="text-gray-300">{f.title}</span>
                          </div>
                        ))}
                      </div>
                    )}

                    <div className="mt-2 text-xs text-gray-500">
                      Started: {new Date(hunt.startedAt).toLocaleString()}
                      {hunt.completedAt && <span> | Completed: {new Date(hunt.completedAt).toLocaleString()}</span>}
                    </div>
                  </Card>
                ))}
              </div>
            )}
          </div>
        </div>
      </ScrollArea>
    </div>
  );
}
