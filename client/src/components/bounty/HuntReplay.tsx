import { useState, useEffect, useRef } from 'react';
import { Card } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { ScrollArea } from '@/components/ui/scroll-area';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import {
  RefreshCw, Loader2, AlertCircle, Clock, GitBranch,
  BarChart3, FlaskConical, Activity, Award, Split
} from 'lucide-react';
import { cn } from '@/lib/utils';

interface TraceEvent {
  id: string;
  huntId: string;
  timestamp: number;
  eventType: string;
  sourceSystem: string;
  data: Record<string, any>;
  reasoning?: string;
  confidenceAtEvent: number;
}

interface HuntMetrics {
  huntId: string;
  totalEvents: number;
  duration: number;
  totalPivots: number;
  productivePivots: number;
  wastedPivots: number;
  pivotEfficiencyRatio: number;
  pathAccuracy: number;
  timeToFirstFinding: number;
  falsePositiveRate: number;
  coverageRatio: number;
  confidenceCalibration: CalibrationPoint[];
}

interface CalibrationPoint {
  confidenceBucket: string;
  pivotCount: number;
  successCount: number;
  actualSuccessRate: number;
  avgConfidence: number;
}

interface PivotAnalysis {
  fromStrategy: string;
  toStrategy: string;
  confidenceAtPivot: number;
  cyclesUntilNextFinding: number;
  productive: boolean;
}

interface LabProfile {
  id: string;
  name: string;
  description: string;
  totalChallenges: number;
  vulnCount: number;
}

interface DivergencePoint {
  step: number;
  timestamp: number;
  plannedAction: string;
  plannedGoal: string;
  plannedConfidence: number;
  actualAction: string;
  actualGoal: string;
  actualConfidence: number;
  diverged: boolean;
  divergenceType: 'none' | 'goal_mismatch' | 'path_mismatch' | 'early_pivot' | 'missed_pivot' | 'tool_mismatch';
  insight: string;
}

interface LabScore {
  coverage: number;
  goalAccuracy: number;
  evRankingAccuracy: number;
  cycleEfficiency: number;
  pathSelectionAccuracy: number;
  decisionQualitySummary: {
    topPathCorrect: boolean;
    avgRankDeviation: number;
    overconfidentPaths: number;
    underconfidentPaths: number;
  };
}

interface PivotRegret {
  pivotIndex: number;
  timestamp: number;
  fromStrategy: string;
  toStrategy: string;
  confidenceAtPivot: number;
  counterfactualFindings: number;
  actualFindings: number;
  regretScore: number;
  classification: 'correct_time_correct_vector' | 'correct_time_wrong_vector' | 'wrong_time_correct_vector' | 'wrong_time_wrong_vector';
  insight: string;
}

interface DeterminismResult {
  isDeterministic: boolean;
  top3Stability: number;
  goal: string;
  iterations: number;
  varianceDetails: { pathId: string; ranks: number[]; stddev: number }[];
}

type TabView = 'timeline' | 'pivots' | 'calibration' | 'lab' | 'divergence';

const EVENT_TYPE_COLORS: Record<string, string> = {
  hunt_start: 'bg-cyan-500/20 text-cyan-400 border-cyan-500/30',
  meta_pivot: 'bg-amber-500/20 text-amber-400 border-amber-500/30',
  meta_evaluation: 'bg-blue-500/20 text-blue-400 border-blue-500/30',
  cortex_signal: 'bg-purple-500/20 text-purple-400 border-purple-500/30',
  planner_ranking: 'bg-green-500/20 text-green-400 border-green-500/30',
  verification_event: 'bg-orange-500/20 text-orange-400 border-orange-500/30',
  finding_confirmed: 'bg-green-500/20 text-green-400 border-green-500/30',
  finding_invalidated: 'bg-red-500/20 text-red-400 border-red-500/30',
  tool_selection: 'bg-gray-500/20 text-gray-400 border-gray-500/30',
  hunt_complete: 'bg-cyan-500/20 text-cyan-400 border-cyan-500/30',
};

const DIVERGENCE_TYPE_COLORS: Record<string, string> = {
  none: 'bg-green-500/20 text-green-400 border-green-500/30',
  goal_mismatch: 'bg-red-500/20 text-red-400 border-red-500/30',
  path_mismatch: 'bg-amber-500/20 text-amber-400 border-amber-500/30',
  early_pivot: 'bg-orange-500/20 text-orange-400 border-orange-500/30',
  missed_pivot: 'bg-purple-500/20 text-purple-400 border-purple-500/30',
  tool_mismatch: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30',
};

function formatRelativeTime(timestamp: number, startTime: number): string {
  const diff = Math.max(0, Math.floor((timestamp - startTime) / 1000));
  const hours = Math.floor(diff / 3600);
  const minutes = Math.floor((diff % 3600) / 60);
  const seconds = diff % 60;
  return `T+${hours}:${String(minutes).padStart(2, '0')}:${String(seconds).padStart(2, '0')}`;
}

export function HuntReplay() {
  const [tab, setTab] = useState<TabView>('timeline');
  const [huntIds, setHuntIds] = useState<string[]>([]);
  const [selectedHunt, setSelectedHunt] = useState<string>('');
  const [trace, setTrace] = useState<TraceEvent[]>([]);
  const [metrics, setMetrics] = useState<HuntMetrics | null>(null);
  const [pivots, setPivots] = useState<PivotAnalysis[]>([]);
  const [calibration, setCalibration] = useState<CalibrationPoint[]>([]);
  const [qualityScore, setQualityScore] = useState<number | null>(null);
  const [labProfiles, setLabProfiles] = useState<LabProfile[]>([]);
  const [selectedProfile, setSelectedProfile] = useState<string>('');
  const [labMetrics, setLabMetrics] = useState<HuntMetrics | null>(null);
  const [labScore, setLabScore] = useState<LabScore | null>(null);
  const [divergence, setDivergence] = useState<DivergencePoint[]>([]);
  const [pivotRegret, setPivotRegret] = useState<PivotRegret[]>([]);
  const [determinism, setDeterminism] = useState<DeterminismResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const timelineEndRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    fetchHuntIds();
    fetchLabProfiles();
    fetchCalibration();
    const interval = setInterval(fetchHuntIds, 5000);
    return () => clearInterval(interval);
  }, []);

  useEffect(() => {
    if (selectedHunt) {
      fetchHuntData(selectedHunt);
    } else {
      setTrace([]);
      setMetrics(null);
      setPivots([]);
      setQualityScore(null);
    }
  }, [selectedHunt]);

  useEffect(() => {
    if (tab === 'timeline' && timelineEndRef.current) {
      timelineEndRef.current.scrollIntoView({ behavior: 'smooth' });
    }
  }, [trace, tab]);

  const fetchHuntIds = async () => {
    try {
      const res = await fetch('/api/reasoning/trace/hunts/active');
      const data = await res.json();
      if (data.success) {
        setHuntIds(data.data || []);
        if (!selectedHunt && data.data?.length > 0) {
          setSelectedHunt(data.data[0]);
        }
      }
    } catch (err) {
      console.error('Failed to fetch hunt IDs:', err);
    }
  };

  const fetchHuntData = async (huntId: string) => {
    setLoading(true);
    setError('');
    try {
      const [traceRes, metricsRes, pivotsRes, qualityRes] = await Promise.all([
        fetch(`/api/reasoning/trace/${huntId}`),
        fetch(`/api/reasoning/metrics/${huntId}`),
        fetch(`/api/reasoning/metrics/${huntId}/pivots`),
        fetch(`/api/reasoning/metrics/${huntId}/quality`),
      ]);
      const [traceData, metricsData, pivotsData, qualityData] = await Promise.all([
        traceRes.json(),
        metricsRes.json(),
        pivotsRes.json(),
        qualityRes.json(),
      ]);
      if (traceData.success) setTrace(traceData.data || []);
      if (metricsData.success) setMetrics(metricsData.data || null);
      if (pivotsData.success) setPivots(pivotsData.data || []);
      if (qualityData.success) setQualityScore(qualityData.data?.qualityScore ?? null);
    } catch (err) {
      setError('Failed to load hunt data');
      console.error('Failed to fetch hunt data:', err);
    } finally {
      setLoading(false);
    }
  };

  const fetchCalibration = async () => {
    try {
      const res = await fetch('/api/reasoning/calibration');
      const data = await res.json();
      if (data.success) setCalibration(data.data || []);
    } catch (err) {
      console.error('Failed to fetch calibration:', err);
    }
  };

  const fetchLabProfiles = async () => {
    try {
      const res = await fetch('/api/reasoning/lab/profiles');
      const data = await res.json();
      if (data.success) setLabProfiles(data.data || []);
    } catch (err) {
      console.error('Failed to fetch lab profiles:', err);
    }
  };

  const runLabMetrics = async () => {
    if (!selectedHunt || !selectedProfile) return;
    setLoading(true);
    setError('');
    try {
      const [metricsRes, scoreRes] = await Promise.all([
        fetch(`/api/reasoning/metrics/${selectedHunt}/lab/${selectedProfile}`),
        fetch(`/api/reasoning/metrics/${selectedHunt}/lab/${selectedProfile}/score`),
      ]);
      const [metricsData, scoreData] = await Promise.all([
        metricsRes.json(),
        scoreRes.json(),
      ]);
      if (metricsData.success) setLabMetrics(metricsData.data || null);
      if (scoreData.success) setLabScore(scoreData.data || null);
    } catch (err) {
      setError('Failed to run lab metrics');
      console.error('Failed to run lab metrics:', err);
    } finally {
      setLoading(false);
    }
  };

  const fetchDivergence = async () => {
    if (!selectedHunt || !selectedProfile) return;
    setLoading(true);
    setError('');
    try {
      const [divRes, regretRes] = await Promise.all([
        fetch(`/api/reasoning/metrics/${selectedHunt}/lab/${selectedProfile}/divergence`),
        fetch(`/api/reasoning/metrics/${selectedHunt}/lab/${selectedProfile}/regret`),
      ]);
      const [divData, regretData] = await Promise.all([divRes.json(), regretRes.json()]);
      if (divData.success) setDivergence(divData.data || []);
      if (regretData.success) setPivotRegret(regretData.data || []);
    } catch (err) {
      setError('Failed to load divergence data');
      console.error('Failed to fetch divergence:', err);
    } finally {
      setLoading(false);
    }
  };

  const [huntStatus, setHuntStatus] = useState<string>('');

  const runLabHunt = async () => {
    if (!selectedProfile) return;
    setLoading(true);
    setError('');
    setHuntStatus('Starting hunt...');
    try {
      const res = await fetch('/api/reasoning/lab/run', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ profileId: selectedProfile }),
      });
      const data = await res.json();
      if (data.success && data.data?.huntId) {
        const newHuntId = data.data.huntId;
        setSelectedHunt(newHuntId);
        setHuntIds(prev => [newHuntId, ...prev]);
        setHuntStatus(`Hunt ${newHuntId.substring(0, 8)}... running`);
        setTab('timeline');

        const pollForData = async (attempts: number) => {
          for (let i = 0; i < attempts; i++) {
            await new Promise(r => setTimeout(r, 2000));
            try {
              const traceRes = await fetch(`/api/reasoning/trace/${newHuntId}`);
              const traceData = await traceRes.json();
              if (traceData.success && traceData.data?.length > 0) {
                setTrace(traceData.data);
                setHuntStatus(`Hunt complete — ${traceData.data.length} events`);
                await fetchHuntData(newHuntId);
                return;
              }
              setHuntStatus(`Waiting for trace data... (${i + 1}/${attempts})`);
            } catch (_) {}
          }
          setHuntStatus('Hunt started — check timeline for events');
          await fetchHuntData(newHuntId);
        };
        pollForData(15);
      } else {
        setError(data.error || 'Failed to start hunt');
        setHuntStatus('');
      }
    } catch (err) {
      setError('Failed to start lab hunt');
      setHuntStatus('');
      console.error('Failed to start lab hunt:', err);
    } finally {
      setLoading(false);
    }
  };

  const checkDeterminism = async () => {
    if (!selectedProfile) return;
    setLoading(true);
    setError('');
    try {
      const res = await fetch(`/api/reasoning/lab/determinism/${selectedProfile}?iterations=10`);
      const data = await res.json();
      if (data.success) setDeterminism(data.data || null);
    } catch (err) {
      setError('Failed to check determinism');
      console.error('Failed to check determinism:', err);
    } finally {
      setLoading(false);
    }
  };

  const tabs: { id: TabView; label: string; icon: any }[] = [
    { id: 'timeline', label: 'Timeline', icon: Clock },
    { id: 'pivots', label: 'Pivots', icon: GitBranch },
    { id: 'calibration', label: 'Calibration', icon: BarChart3 },
    { id: 'lab', label: 'Lab', icon: FlaskConical },
    { id: 'divergence', label: 'Divergence', icon: Split },
  ];

  const startTime = trace.length > 0 ? trace[0].timestamp : 0;

  const renderTimeline = () => {
    if (trace.length === 0) {
      return (
        <div className="text-center py-12 text-gray-500 text-sm" data-testid="text-no-events">
          No events yet
        </div>
      );
    }

    return (
      <div className="space-y-3" data-testid="timeline-container">
        {trace.map((event, idx) => {
          const colorClass = EVENT_TYPE_COLORS[event.eventType] || EVENT_TYPE_COLORS.tool_selection;
          const dataKeys = Object.keys(event.data || {}).slice(0, 5);

          return (
            <div
              key={event.id}
              className="flex gap-3 bg-[#252526] border border-[#3e3e3e] rounded-lg p-3"
              data-testid={`trace-event-${idx}`}
            >
              <div className="flex flex-col items-center shrink-0 w-20">
                <span className="text-[10px] font-mono text-gray-500" data-testid={`event-time-${idx}`}>
                  {formatRelativeTime(event.timestamp, startTime)}
                </span>
                <div className="w-px flex-1 bg-[#3e3e3e] mt-1" />
              </div>

              <div className="flex-1 min-w-0 space-y-2">
                <div className="flex items-center gap-2 flex-wrap">
                  <Badge className={cn('text-[10px]', colorClass)} data-testid={`event-type-${idx}`}>
                    {event.eventType}
                  </Badge>
                  <span className="text-[10px] text-gray-500" data-testid={`event-source-${idx}`}>
                    {event.sourceSystem}
                  </span>
                </div>

                {event.reasoning && (
                  <p className="text-xs text-gray-300" data-testid={`event-reasoning-${idx}`}>
                    {event.reasoning}
                  </p>
                )}

                <div className="flex items-center gap-2">
                  <span className="text-[10px] text-gray-500 shrink-0 w-12">Conf:</span>
                  <div className="flex-1 h-2 bg-[#1e1e1e] rounded-full overflow-hidden">
                    <div
                      className={cn(
                        'h-full rounded-full transition-all',
                        event.confidenceAtEvent >= 0.7 ? 'bg-green-500' :
                        event.confidenceAtEvent >= 0.4 ? 'bg-yellow-500' : 'bg-red-500'
                      )}
                      style={{ width: `${Math.round(event.confidenceAtEvent * 100)}%` }}
                      data-testid={`event-confidence-${idx}`}
                    />
                  </div>
                  <span className="text-[10px] text-gray-400 shrink-0 w-8 text-right">
                    {Math.round(event.confidenceAtEvent * 100)}%
                  </span>
                </div>

                {dataKeys.length > 0 && (
                  <div className="flex flex-wrap gap-1">
                    {dataKeys.map((key) => (
                      <Badge
                        key={key}
                        variant="outline"
                        className="text-[10px] text-gray-400 border-[#3e3e3e] bg-[#1e1e1e]"
                        data-testid={`event-data-${idx}-${key}`}
                      >
                        {key}: {String(event.data[key]).slice(0, 30)}
                      </Badge>
                    ))}
                  </div>
                )}
              </div>
            </div>
          );
        })}
        <div ref={timelineEndRef} />
      </div>
    );
  };

  const renderPivots = () => {
    const productive = pivots.filter(p => p.productive).length;
    const wasted = pivots.filter(p => !p.productive && p.cyclesUntilNextFinding !== -1).length;
    const pending = pivots.filter(p => p.cyclesUntilNextFinding === -1 && !p.productive).length;
    const efficiency = pivots.length > 0 ? Math.round((productive / pivots.length) * 100) : 0;

    return (
      <div className="space-y-4" data-testid="pivots-container">
        <Card className="bg-[#252526] border-[#3e3e3e] p-3">
          <div className="flex items-center gap-3 flex-wrap text-xs" data-testid="pivot-summary">
            <span className="text-green-400 font-medium">{productive} productive</span>
            <span className="text-gray-500">/</span>
            <span className="text-red-400 font-medium">{wasted} wasted</span>
            {pending > 0 && (
              <>
                <span className="text-gray-500">/</span>
                <span className="text-gray-400 font-medium">{pending} pending</span>
              </>
            )}
            <span className="text-gray-500">/</span>
            <span className="text-gray-300 font-medium">{pivots.length} total pivots</span>
            <span className="text-gray-500">—</span>
            <span className="text-cyan-400 font-semibold">Efficiency: {efficiency}%</span>
          </div>
        </Card>

        {pivots.length === 0 ? (
          <div className="text-center py-12 text-gray-500 text-sm" data-testid="text-no-pivots">
            No pivots recorded yet
          </div>
        ) : (
          <div className="space-y-2">
            <div className="grid grid-cols-[40px_1fr_80px_80px_90px] gap-2 px-3 py-2 text-[10px] text-gray-500 font-semibold uppercase">
              <span>#</span>
              <span>From → To</span>
              <span>Confidence</span>
              <span>Cycles</span>
              <span>Status</span>
            </div>
            {pivots.map((pivot, idx) => {
              const statusBadge = pivot.productive
                ? 'bg-green-500/20 text-green-400 border-green-500/30'
                : pivot.cyclesUntilNextFinding === -1
                  ? 'bg-gray-500/20 text-gray-400 border-gray-500/30'
                  : 'bg-red-500/20 text-red-400 border-red-500/30';
              const statusLabel = pivot.productive
                ? 'Productive'
                : pivot.cyclesUntilNextFinding === -1
                  ? 'Pending'
                  : 'Wasted';

              return (
                <div
                  key={idx}
                  className="grid grid-cols-[40px_1fr_80px_80px_90px] gap-2 items-center px-3 py-2 bg-[#252526] border border-[#3e3e3e] rounded"
                  data-testid={`pivot-row-${idx}`}
                >
                  <span className="text-xs text-gray-500 font-mono">{idx + 1}</span>
                  <span className="text-xs text-gray-300 truncate" data-testid={`pivot-strategies-${idx}`}>
                    {pivot.fromStrategy} → {pivot.toStrategy}
                  </span>
                  <span className="text-xs text-gray-200 font-mono" data-testid={`pivot-confidence-${idx}`}>
                    {Math.round(pivot.confidenceAtPivot * 100)}%
                  </span>
                  <span className="text-xs text-gray-400 font-mono" data-testid={`pivot-cycles-${idx}`}>
                    {pivot.cyclesUntilNextFinding === -1 ? '—' : pivot.cyclesUntilNextFinding}
                  </span>
                  <Badge className={cn('text-[10px]', statusBadge)} data-testid={`pivot-status-${idx}`}>
                    {statusLabel}
                  </Badge>
                </div>
              );
            })}
          </div>
        )}
      </div>
    );
  };

  const renderCalibration = () => {
    if (calibration.length === 0) {
      return (
        <div className="text-center py-12 text-gray-500 text-sm" data-testid="text-no-calibration">
          Run hunts to populate calibration data
        </div>
      );
    }

    const bucketMidpoints: Record<string, number> = {
      '0.0-0.2': 0.1,
      '0.2-0.4': 0.3,
      '0.4-0.6': 0.5,
      '0.6-0.8': 0.7,
      '0.8-1.0': 0.9,
    };

    const totalError = calibration.reduce((sum, point) => {
      const expected = bucketMidpoints[point.confidenceBucket] ?? 0.5;
      return sum + Math.abs(point.actualSuccessRate - expected);
    }, 0);
    const avgCalibrationError = Math.round((totalError / calibration.length) * 100);

    return (
      <div className="space-y-4" data-testid="calibration-container">
        <Card className="bg-[#252526] border-[#3e3e3e] p-3">
          <div className="flex items-center gap-2 text-sm" data-testid="calibration-summary">
            <BarChart3 className="w-4 h-4 text-cyan-400" />
            <span className="text-gray-300">Calibration error:</span>
            <span className={cn(
              'font-semibold',
              avgCalibrationError <= 10 ? 'text-green-400' :
              avgCalibrationError <= 25 ? 'text-yellow-400' : 'text-red-400'
            )}>
              {avgCalibrationError}%
            </span>
            <span className="text-gray-500 text-xs">(lower is better)</span>
          </div>
        </Card>

        <div className="space-y-3">
          {calibration.map((point, idx) => {
            const expected = bucketMidpoints[point.confidenceBucket] ?? 0.5;
            const diff = Math.abs(point.actualSuccessRate - expected);
            const wellCalibrated = diff < 0.15;
            const barColor = wellCalibrated ? 'bg-green-500' : 'bg-red-500';
            const expectedBarColor = 'bg-cyan-500/40';

            return (
              <Card
                key={point.confidenceBucket}
                className="bg-[#252526] border-[#3e3e3e] p-3"
                data-testid={`calibration-bucket-${idx}`}
              >
                <div className="flex items-center justify-between mb-2">
                  <span className="text-xs font-semibold text-gray-200">
                    Bucket: {point.confidenceBucket}
                  </span>
                  <div className="flex gap-3 text-[10px] text-gray-500">
                    <span>Pivots: <span className="text-gray-300">{point.pivotCount}</span></span>
                    <span>Successes: <span className="text-gray-300">{point.successCount}</span></span>
                  </div>
                </div>

                <div className="space-y-1">
                  <div className="flex items-center gap-2">
                    <span className="text-[10px] text-gray-500 w-16 shrink-0">Expected</span>
                    <div className="flex-1 h-3 bg-[#1e1e1e] rounded-full overflow-hidden">
                      <div
                        className={cn('h-full rounded-full', expectedBarColor)}
                        style={{ width: `${Math.round(expected * 100)}%` }}
                      />
                    </div>
                    <span className="text-[10px] text-gray-400 w-10 text-right">
                      {Math.round(expected * 100)}%
                    </span>
                  </div>
                  <div className="flex items-center gap-2">
                    <span className="text-[10px] text-gray-500 w-16 shrink-0">Actual</span>
                    <div className="flex-1 h-3 bg-[#1e1e1e] rounded-full overflow-hidden">
                      <div
                        className={cn('h-full rounded-full', barColor)}
                        style={{ width: `${Math.round(point.actualSuccessRate * 100)}%` }}
                      />
                    </div>
                    <span className="text-[10px] text-gray-400 w-10 text-right">
                      {Math.round(point.actualSuccessRate * 100)}%
                    </span>
                  </div>
                </div>

                <div className="mt-2 text-right">
                  <Badge
                    variant="outline"
                    className={cn(
                      'text-[10px]',
                      wellCalibrated
                        ? 'text-green-400 border-green-500/30 bg-green-500/10'
                        : 'text-red-400 border-red-500/30 bg-red-500/10'
                    )}
                  >
                    {wellCalibrated ? 'Well calibrated' : `Off by ${Math.round(diff * 100)}%`}
                  </Badge>
                </div>
              </Card>
            );
          })}
        </div>
      </div>
    );
  };

  const renderLab = () => {
    return (
      <div className="space-y-4" data-testid="lab-container">
        <Card className="bg-[#252526] border-[#3e3e3e] p-4">
          <div className="space-y-3">
            <div>
              <span className="text-xs text-gray-400 block mb-1">Lab Profile</span>
              <Select value={selectedProfile} onValueChange={setSelectedProfile}>
                <SelectTrigger
                  className="bg-[#1e1e1e] border-[#3e3e3e] text-gray-200 h-9"
                  data-testid="select-lab-profile"
                >
                  <SelectValue placeholder="Select a lab profile" />
                </SelectTrigger>
                <SelectContent>
                  {labProfiles.map(profile => (
                    <SelectItem key={profile.id} value={profile.id}>
                      {profile.name}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>

            {selectedProfile && labProfiles.find(p => p.id === selectedProfile) && (
              <div className="text-xs text-gray-400 bg-[#1e1e1e] border border-[#3e3e3e] rounded p-2">
                <p>{labProfiles.find(p => p.id === selectedProfile)?.description}</p>
                <div className="flex gap-3 mt-1 text-gray-500">
                  <span>Challenges: {labProfiles.find(p => p.id === selectedProfile)?.totalChallenges}</span>
                  <span>Vulnerabilities: {labProfiles.find(p => p.id === selectedProfile)?.vulnCount}</span>
                </div>
              </div>
            )}

            <div className="grid grid-cols-2 gap-2">
              <Button
                onClick={runLabHunt}
                disabled={loading || !selectedProfile}
                className="bg-green-600 hover:bg-green-700 text-white h-9"
                data-testid="button-run-lab-hunt"
              >
                {loading ? <Loader2 className="w-4 h-4 mr-2 animate-spin" /> : <Activity className="w-4 h-4 mr-2" />}
                Run Hunt
              </Button>
              <Button
                onClick={checkDeterminism}
                disabled={loading || !selectedProfile}
                variant="outline"
                className="bg-[#1e1e1e] border-[#3e3e3e] text-gray-300 hover:bg-[#333] h-9"
                data-testid="button-check-determinism"
              >
                {loading ? <Loader2 className="w-4 h-4 mr-2 animate-spin" /> : <BarChart3 className="w-4 h-4 mr-2" />}
                Determinism
              </Button>
            </div>

            {huntStatus && (
              <div className="flex items-center gap-2 p-2 bg-[#1e1e1e] border border-cyan-500/30 rounded text-xs text-cyan-400" data-testid="text-hunt-status">
                <Activity className="w-3 h-3 animate-pulse" />
                {huntStatus}
              </div>
            )}

            <Button
              onClick={runLabMetrics}
              disabled={loading || !selectedHunt || !selectedProfile}
              className="w-full bg-purple-600 hover:bg-purple-700 text-white h-9"
              data-testid="button-run-lab-metrics"
            >
              {loading ? <Loader2 className="w-4 h-4 mr-2 animate-spin" /> : <FlaskConical className="w-4 h-4 mr-2" />}
              Run Metrics Against Lab
            </Button>
          </div>
        </Card>

        {determinism && (
          <Card className="bg-[#252526] border-[#3e3e3e] p-3" data-testid="determinism-result">
            <div className="flex items-center gap-2 mb-2">
              <BarChart3 className="w-4 h-4 text-cyan-400" />
              <span className="text-xs text-gray-300 font-semibold">Planner Determinism Check</span>
              <Badge className={cn('text-[10px] ml-auto',
                determinism.isDeterministic
                  ? 'bg-green-500/20 text-green-400 border-green-500/30'
                  : 'bg-red-500/20 text-red-400 border-red-500/30'
              )}>
                {determinism.isDeterministic ? 'Deterministic' : 'Non-deterministic'}
              </Badge>
            </div>
            <div className="grid grid-cols-3 gap-2 text-[10px] mb-2">
              <div>
                <span className="text-gray-500 block">Top-3 Stability</span>
                <span className="text-white font-mono">{Math.round(determinism.top3Stability * 100)}%</span>
              </div>
              <div>
                <span className="text-gray-500 block">Iterations</span>
                <span className="text-white font-mono">{determinism.iterations}</span>
              </div>
              <div>
                <span className="text-gray-500 block">Goal</span>
                <span className="text-white font-mono truncate">{determinism.goal}</span>
              </div>
            </div>
            {determinism.varianceDetails.length > 0 && (
              <div className="space-y-1">
                {determinism.varianceDetails.map((v, i) => (
                  <div key={i} className="flex items-center gap-2 text-[10px]">
                    <span className="text-gray-500 w-28 truncate">{v.pathId}</span>
                    <span className="text-gray-400 font-mono">[{v.ranks.join(',')}]</span>
                    <span className={cn('font-mono', v.stddev === 0 ? 'text-green-400' : 'text-amber-400')}>
                      {'\u03C3'}={v.stddev}
                    </span>
                  </div>
                ))}
              </div>
            )}
          </Card>
        )}

        {!selectedHunt && (
          <div className="text-center py-8 text-gray-500 text-sm" data-testid="text-select-hunt-first">
            Select a hunt first to run lab validation
          </div>
        )}

        {labScore && (
          <div className="space-y-2" data-testid="lab-score-results">
            {[
              { label: 'Coverage', value: `${Math.round(labScore.coverage * 100)}%`, detail: 'vulns found vs ground truth', testId: 'lab-score-coverage' },
              { label: 'Goal Accuracy', value: `${Math.round(labScore.goalAccuracy * 100)}%`, detail: 'goal ranking match', testId: 'lab-score-goal' },
              { label: 'EV Ranking Accuracy', value: `${Math.round(labScore.evRankingAccuracy * 100)}%`, detail: 'planner EV rankings vs expected', testId: 'lab-score-ev' },
              { label: 'Cycle Efficiency', value: `${Math.round(labScore.cycleEfficiency * 100)}%`, detail: 'actual vs expected cycles', testId: 'lab-score-cycles' },
              { label: 'Path Selection', value: `${Math.round(labScore.pathSelectionAccuracy * 100)}%`, detail: 'top-3 paths contained actual vuln', testId: 'lab-score-path' },
            ].map((m) => (
              <Card key={m.testId} className="bg-[#252526] border-[#3e3e3e] p-3 flex items-center justify-between" data-testid={m.testId}>
                <div>
                  <span className="text-xs text-gray-400">{m.label}</span>
                  <span className="text-[10px] text-gray-500 ml-2">({m.detail})</span>
                </div>
                <span className="text-sm font-semibold text-white">{m.value}</span>
              </Card>
            ))}

            <Card className="bg-[#252526] border-[#3e3e3e] p-3" data-testid="lab-decision-summary">
              <span className="text-xs text-gray-400 block mb-2">Decision Quality Summary</span>
              <div className="grid grid-cols-2 gap-2 text-[10px]">
                <div className="flex justify-between">
                  <span className="text-gray-500">Top Path Correct</span>
                  <Badge className={cn('text-[10px]', labScore.decisionQualitySummary.topPathCorrect
                    ? 'bg-green-500/20 text-green-400 border-green-500/30'
                    : 'bg-red-500/20 text-red-400 border-red-500/30'
                  )}>
                    {labScore.decisionQualitySummary.topPathCorrect ? 'Yes' : 'No'}
                  </Badge>
                </div>
                <div className="flex justify-between">
                  <span className="text-gray-500">Avg Rank Deviation</span>
                  <span className="text-gray-200 font-mono">{labScore.decisionQualitySummary.avgRankDeviation}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-gray-500">Overconfident Paths</span>
                  <span className={cn('font-mono', labScore.decisionQualitySummary.overconfidentPaths > 0 ? 'text-amber-400' : 'text-gray-200')}>
                    {labScore.decisionQualitySummary.overconfidentPaths}
                  </span>
                </div>
                <div className="flex justify-between">
                  <span className="text-gray-500">Underconfident Paths</span>
                  <span className={cn('font-mono', labScore.decisionQualitySummary.underconfidentPaths > 0 ? 'text-cyan-400' : 'text-gray-200')}>
                    {labScore.decisionQualitySummary.underconfidentPaths}
                  </span>
                </div>
              </div>
            </Card>
          </div>
        )}

        {labMetrics && !labScore && (
          <div className="space-y-2" data-testid="lab-metrics-results">
            {[
              { label: 'Coverage', value: `${Math.round(labMetrics.coverageRatio * 100)}%`, detail: 'findings found', testId: 'lab-metric-coverage' },
              { label: 'Path Accuracy', value: `${Math.round(labMetrics.pathAccuracy * 100)}%`, detail: 'planner ranked correct goals', testId: 'lab-metric-path-accuracy' },
              { label: 'Pivot Efficiency', value: `${Math.round(labMetrics.pivotEfficiencyRatio * 100)}%`, detail: `${labMetrics.productivePivots} of ${labMetrics.totalPivots} pivots productive`, testId: 'lab-metric-pivot-efficiency' },
              { label: 'False Positive Rate', value: `${Math.round(labMetrics.falsePositiveRate * 100)}%`, detail: '', testId: 'lab-metric-fpr' },
              { label: 'Time to First Finding', value: `${Math.round(labMetrics.timeToFirstFinding)}s`, detail: '', testId: 'lab-metric-ttff' },
              { label: 'Decision Quality Score', value: qualityScore !== null ? `${Math.round(qualityScore * 100)}%` : 'N/A', detail: '', testId: 'lab-metric-quality' },
            ].map((metric) => (
              <Card key={metric.testId} className="bg-[#252526] border-[#3e3e3e] p-3 flex items-center justify-between" data-testid={metric.testId}>
                <div>
                  <span className="text-xs text-gray-400">{metric.label}</span>
                  {metric.detail && <span className="text-[10px] text-gray-500 ml-2">({metric.detail})</span>}
                </div>
                <span className="text-sm font-semibold text-white">{metric.value}</span>
              </Card>
            ))}
          </div>
        )}
      </div>
    );
  };

  const renderDivergence = () => {
    const divergedCount = divergence.filter(d => d.diverged).length;
    const alignedCount = divergence.filter(d => !d.diverged).length;

    return (
      <div className="space-y-4" data-testid="divergence-container">
        <Card className="bg-[#252526] border-[#3e3e3e] p-4">
          <div className="space-y-3">
            <div>
              <span className="text-xs text-gray-400 block mb-1">Lab Profile for Divergence Analysis</span>
              <Select value={selectedProfile} onValueChange={setSelectedProfile}>
                <SelectTrigger className="bg-[#1e1e1e] border-[#3e3e3e] text-gray-200 h-9" data-testid="select-divergence-profile">
                  <SelectValue placeholder="Select a lab profile" />
                </SelectTrigger>
                <SelectContent>
                  {labProfiles.map(profile => (
                    <SelectItem key={profile.id} value={profile.id}>{profile.name}</SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>

            <Button
              onClick={fetchDivergence}
              disabled={loading || !selectedHunt || !selectedProfile}
              className="w-full bg-red-600 hover:bg-red-700 text-white h-9"
              data-testid="button-run-divergence"
            >
              {loading ? <Loader2 className="w-4 h-4 mr-2 animate-spin" /> : <Split className="w-4 h-4 mr-2" />}
              Analyze Divergence
            </Button>
          </div>
        </Card>

        {!selectedHunt && (
          <div className="text-center py-8 text-gray-500 text-sm" data-testid="text-divergence-no-hunt">
            Select a hunt first
          </div>
        )}

        {divergence.length > 0 && (
          <>
            <Card className="bg-[#252526] border-[#3e3e3e] p-3">
              <div className="flex items-center gap-3 flex-wrap text-xs" data-testid="divergence-summary">
                <Split className="w-4 h-4 text-red-400" />
                <span className="text-red-400 font-medium">{divergedCount} divergences</span>
                <span className="text-gray-500">/</span>
                <span className="text-green-400 font-medium">{alignedCount} aligned</span>
                <span className="text-gray-500">/</span>
                <span className="text-gray-300">{divergence.length} decision points</span>
                <span className="text-gray-500">—</span>
                <span className={cn('font-semibold',
                  divergedCount === 0 ? 'text-green-400' :
                  divergedCount <= 2 ? 'text-yellow-400' : 'text-red-400'
                )}>
                  {divergence.length > 0 ? Math.round((alignedCount / divergence.length) * 100) : 0}% alignment
                </span>
              </div>
            </Card>

            <div className="space-y-3">
              {divergence.map((dp, idx) => {
                const typeColor = DIVERGENCE_TYPE_COLORS[dp.divergenceType] || DIVERGENCE_TYPE_COLORS.none;

                return (
                  <Card
                    key={idx}
                    className={cn(
                      'border p-3',
                      dp.diverged
                        ? 'bg-red-500/5 border-red-500/30'
                        : 'bg-[#252526] border-[#3e3e3e]'
                    )}
                    data-testid={`divergence-point-${idx}`}
                  >
                    <div className="flex items-center justify-between mb-2">
                      <div className="flex items-center gap-2">
                        <span className="text-[10px] font-mono text-gray-500">#{dp.step}</span>
                        <span className="text-[10px] font-mono text-gray-500">
                          {formatRelativeTime(dp.timestamp, divergence[0]?.timestamp || dp.timestamp)}
                        </span>
                        <Badge className={cn('text-[10px]', typeColor)} data-testid={`divergence-type-${idx}`}>
                          {dp.divergenceType.replace(/_/g, ' ')}
                        </Badge>
                      </div>
                    </div>

                    <div className="grid grid-cols-2 gap-3 mb-2">
                      <div className="bg-[#1e1e1e] border border-[#3e3e3e] rounded p-2">
                        <span className="text-[10px] text-cyan-400 font-semibold block mb-1">PLANNED</span>
                        <p className="text-xs text-gray-300 mb-1" data-testid={`divergence-planned-${idx}`}>
                          {dp.plannedAction}
                        </p>
                        <div className="flex items-center gap-1">
                          <div className="flex-1 h-1.5 bg-[#252526] rounded-full overflow-hidden">
                            <div className="h-full rounded-full bg-cyan-500/50" style={{ width: `${Math.round(dp.plannedConfidence * 100)}%` }} />
                          </div>
                          <span className="text-[10px] text-gray-500">{Math.round(dp.plannedConfidence * 100)}%</span>
                        </div>
                      </div>

                      <div className={cn(
                        'border rounded p-2',
                        dp.diverged ? 'bg-red-500/10 border-red-500/20' : 'bg-[#1e1e1e] border-[#3e3e3e]'
                      )}>
                        <span className={cn('text-[10px] font-semibold block mb-1', dp.diverged ? 'text-red-400' : 'text-green-400')}>
                          ACTUAL
                        </span>
                        <p className="text-xs text-gray-300 mb-1" data-testid={`divergence-actual-${idx}`}>
                          {dp.actualAction}
                        </p>
                        <div className="flex items-center gap-1">
                          <div className="flex-1 h-1.5 bg-[#252526] rounded-full overflow-hidden">
                            <div className={cn('h-full rounded-full', dp.diverged ? 'bg-red-500/50' : 'bg-green-500/50')}
                              style={{ width: `${Math.round(dp.actualConfidence * 100)}%` }} />
                          </div>
                          <span className="text-[10px] text-gray-500">{Math.round(dp.actualConfidence * 100)}%</span>
                        </div>
                      </div>
                    </div>

                    {dp.insight && (
                      <div className={cn(
                        'text-[10px] p-2 rounded',
                        dp.diverged ? 'bg-red-500/10 text-red-300' : 'bg-green-500/10 text-green-300'
                      )} data-testid={`divergence-insight-${idx}`}>
                        {dp.insight}
                      </div>
                    )}
                  </Card>
                );
              })}
            </div>
          </>
        )}

        {pivotRegret.length > 0 && (
          <Card className="bg-[#252526] border-[#3e3e3e] p-3" data-testid="pivot-regret-container">
            <div className="flex items-center gap-2 mb-3">
              <GitBranch className="w-4 h-4 text-amber-400" />
              <span className="text-xs text-gray-300 font-semibold">Pivot Regret Analysis</span>
              <span className="text-[10px] text-gray-500 ml-auto">
                {pivotRegret.filter(r => r.regretScore > 0.5).length} high-regret pivots
              </span>
            </div>
            <div className="grid grid-cols-4 gap-1 mb-3">
              {[
                { key: 'correct_time_correct_vector', label: 'Right/Right', color: 'bg-green-500/20 text-green-400' },
                { key: 'correct_time_wrong_vector', label: 'Right/Wrong', color: 'bg-amber-500/20 text-amber-400' },
                { key: 'wrong_time_correct_vector', label: 'Wrong/Right', color: 'bg-blue-500/20 text-blue-400' },
                { key: 'wrong_time_wrong_vector', label: 'Wrong/Wrong', color: 'bg-red-500/20 text-red-400' },
              ].map(q => (
                <div key={q.key} className={cn('rounded p-2 text-center text-[10px]', q.color)} data-testid={`regret-quadrant-${q.key}`}>
                  <div className="font-semibold">{pivotRegret.filter(r => r.classification === q.key).length}</div>
                  <div className="opacity-70">{q.label}</div>
                </div>
              ))}
            </div>
            <div className="space-y-2">
              {pivotRegret.map((r, i) => {
                const classColor =
                  r.classification === 'correct_time_correct_vector' ? 'border-green-500/30' :
                  r.classification === 'correct_time_wrong_vector' ? 'border-amber-500/30' :
                  r.classification === 'wrong_time_correct_vector' ? 'border-blue-500/30' :
                  'border-red-500/30';
                return (
                  <div key={i} className={cn('bg-[#1e1e1e] border rounded p-2', classColor)} data-testid={`pivot-regret-${i}`}>
                    <div className="flex items-center justify-between mb-1">
                      <span className="text-[10px] font-mono text-gray-500">Pivot #{r.pivotIndex}</span>
                      <div className="flex items-center gap-2">
                        <span className="text-[10px] text-gray-400">{r.fromStrategy} {'\u2192'} {r.toStrategy}</span>
                        <Badge className={cn('text-[10px]',
                          r.regretScore > 0.7 ? 'bg-red-500/20 text-red-400 border-red-500/30' :
                          r.regretScore > 0.3 ? 'bg-amber-500/20 text-amber-400 border-amber-500/30' :
                          'bg-green-500/20 text-green-400 border-green-500/30'
                        )}>
                          Regret: {Math.round(r.regretScore * 100)}%
                        </Badge>
                      </div>
                    </div>
                    <div className="grid grid-cols-3 gap-2 text-[10px] mb-1">
                      <div>
                        <span className="text-gray-500">Confidence</span>
                        <span className="text-white font-mono ml-1">{Math.round(r.confidenceAtPivot * 100)}%</span>
                      </div>
                      <div>
                        <span className="text-gray-500">Actual</span>
                        <span className="text-white font-mono ml-1">{r.actualFindings} findings</span>
                      </div>
                      <div>
                        <span className="text-gray-500">Counterfactual</span>
                        <span className="text-white font-mono ml-1">{r.counterfactualFindings} findings</span>
                      </div>
                    </div>
                    {r.insight && <div className="text-[10px] text-gray-400 italic">{r.insight}</div>}
                  </div>
                );
              })}
            </div>
          </Card>
        )}

        {divergence.length === 0 && selectedHunt && selectedProfile && !loading && (
          <div className="text-center py-8 text-gray-500 text-sm" data-testid="text-no-divergence">
            Click "Analyze Divergence" to compare planned vs actual paths
          </div>
        )}
      </div>
    );
  };

  return (
    <div className="h-full flex flex-col bg-[#1e1e1e] p-4 gap-4" data-testid="hunt-replay-panel">
      <div className="flex items-center gap-3 shrink-0">
        <Activity className="w-5 h-5 text-cyan-400" />
        <h1 className="text-lg font-bold text-gray-100">Hunt Replay</h1>
        <div className="flex-1" />
        {qualityScore !== null && (
          <Badge
            variant="outline"
            className={cn(
              'text-xs font-mono',
              qualityScore >= 0.7 ? 'text-green-400 border-green-500/30 bg-green-500/10' :
              qualityScore >= 0.4 ? 'text-yellow-400 border-yellow-500/30 bg-yellow-500/10' :
              'text-red-400 border-red-500/30 bg-red-500/10'
            )}
            data-testid="badge-quality-score"
          >
            <Award className="w-3 h-3 mr-1" />
            Quality: {Math.round(qualityScore * 100)}%
          </Badge>
        )}
      </div>

      <div className="flex items-center gap-2 shrink-0">
        <Select value={selectedHunt} onValueChange={setSelectedHunt}>
          <SelectTrigger
            className="bg-[#252526] border-[#3e3e3e] text-gray-200 h-9 flex-1"
            data-testid="select-hunt"
          >
            <SelectValue placeholder="Select a hunt..." />
          </SelectTrigger>
          <SelectContent>
            {huntIds.map(id => (
              <SelectItem key={id} value={id}>{id}</SelectItem>
            ))}
          </SelectContent>
        </Select>
        <Button
          variant="outline"
          size="sm"
          onClick={() => {
            fetchHuntIds();
            if (selectedHunt) fetchHuntData(selectedHunt);
          }}
          className="bg-[#252526] border-[#3e3e3e] text-gray-300 hover:bg-[#333] h-9"
          data-testid="button-refresh"
        >
          <RefreshCw className={cn('w-4 h-4', loading && 'animate-spin')} />
        </Button>
      </div>

      {error && (
        <div className="flex items-center gap-2 p-3 bg-red-500/10 border border-red-500/30 rounded-md shrink-0" data-testid="text-error">
          <AlertCircle className="w-4 h-4 text-red-400 flex-shrink-0" />
          <p className="text-xs text-red-400">{error}</p>
        </div>
      )}

      <div className="flex gap-1 bg-[#252526] rounded-lg p-1 shrink-0">
        {tabs.map(t => {
          const Icon = t.icon;
          return (
            <button
              key={t.id}
              onClick={() => setTab(t.id)}
              data-testid={`tab-${t.id}`}
              className={cn(
                'flex-1 flex items-center justify-center gap-1.5 px-2 py-2 text-[11px] font-medium rounded-md transition-colors',
                tab === t.id
                  ? 'bg-[#2d2d2d] text-white'
                  : 'text-gray-500 hover:text-gray-300'
              )}
            >
              <Icon className="w-3.5 h-3.5" />
              {t.label}
            </button>
          );
        })}
      </div>

      {loading && (
        <div className="flex items-center justify-center py-8 shrink-0" data-testid="loading-spinner">
          <Loader2 className="w-6 h-6 animate-spin text-cyan-400" />
        </div>
      )}

      <ScrollArea className="flex-1">
        <div className="pr-2">
          {!loading && tab === 'timeline' && renderTimeline()}
          {!loading && tab === 'pivots' && renderPivots()}
          {!loading && tab === 'calibration' && renderCalibration()}
          {!loading && tab === 'lab' && renderLab()}
          {!loading && tab === 'divergence' && renderDivergence()}
        </div>
      </ScrollArea>
    </div>
  );
}
