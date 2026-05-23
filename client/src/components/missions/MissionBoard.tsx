import { useState, useEffect, useCallback, useRef, useMemo } from 'react';
import { useSharedSocket } from '@/context/SocketContext';
import type { Socket } from 'socket.io-client';
import {
  Rocket, Play, Pause, Square, Trash2, AlertTriangle,
  CheckCircle, XCircle, Clock, Loader2, ChevronRight,
  Target, Shield, Zap, Plus, RefreshCw, AlertOctagon,
  Bug, ArrowRight
} from 'lucide-react';
import { MissionDetails } from './MissionDetails';
import { LaunchMissionModal } from './LaunchMissionModal';
import { csrfFetch } from '@/services/api';

interface MissionStep {
  id: string;
  name: string;
  tool: string;
  status: 'pending' | 'running' | 'completed' | 'failed' | 'skipped';
  output: string | null;
  startedAt: string | null;
  completedAt: string | null;
  duration: number | null;
}

interface MissionFinding {
  id: string;
  type: string;
  severity: 'info' | 'low' | 'medium' | 'high' | 'critical';
  title: string;
  description: string;
  evidence: string | null;
  stepId: string;
  timestamp: string;
}

interface Mission {
  id: string;
  name: string;
  target: string;
  type: 'recon' | 'vuln_scan' | 'exploit' | 'full_audit' | 'custom';
  status: 'queued' | 'active' | 'paused' | 'completed' | 'failed' | 'cancelled';
  priority: 'low' | 'medium' | 'high' | 'critical';
  steps: MissionStep[];
  findings: MissionFinding[];
  config: Record<string, any>;
  progress: number;
  createdAt: string;
  startedAt: string | null;
  completedAt: string | null;
  error: string | null;
  goal?: string;
  threatLevel?: string;
  stealthStatus?: { mode: string; detections: number };
}

interface ActivityEvent {
  id: string;
  type: 'launch' | 'step_start' | 'step_complete' | 'finding' | 'complete' | 'pause' | 'resume' | 'cancel' | 'emergency' | 'create' | 'delete';
  text: string;
  severity: string;
  time: string;
  missionId?: string;
}

const severityColors: Record<string, string> = {
  critical: 'text-red-400 bg-red-400/10 border-red-400/30',
  high: 'text-orange-400 bg-orange-400/10 border-orange-400/30',
  medium: 'text-yellow-400 bg-yellow-400/10 border-yellow-400/30',
  low: 'text-blue-400 bg-blue-400/10 border-blue-400/30',
  info: 'text-gray-400 bg-gray-400/10 border-gray-400/30',
};

const statusColors: Record<string, string> = {
  active: 'text-green-400',
  queued: 'text-cyan-400',
  paused: 'text-yellow-400',
  completed: 'text-blue-400',
  failed: 'text-red-400',
  cancelled: 'text-gray-500',
};

const statusIcons: Record<string, any> = {
  active: Loader2,
  queued: Clock,
  paused: Pause,
  completed: CheckCircle,
  failed: XCircle,
  cancelled: Square,
};

const activityEventColors: Record<string, string> = {
  launch: 'text-cyan-400',
  step_start: 'text-green-400',
  step_complete: 'text-green-400',
  finding: 'text-orange-400',
  complete: 'text-blue-400',
  pause: 'text-yellow-400',
  resume: 'text-cyan-400',
  cancel: 'text-red-400',
  emergency: 'text-red-400',
  create: 'text-cyan-400',
  delete: 'text-gray-400',
};

const activityEventIcons: Record<string, any> = {
  launch: Rocket,
  step_start: Play,
  step_complete: CheckCircle,
  finding: Bug,
  complete: CheckCircle,
  pause: Pause,
  resume: Play,
  cancel: XCircle,
  emergency: AlertOctagon,
  create: Plus,
  delete: Trash2,
};

export function MissionBoard() {
  const [missions, setMissions] = useState<Mission[]>([]);
  const [selectedMissionId, setSelectedMissionId] = useState<string | null>(null);
  const [showLaunchModal, setShowLaunchModal] = useState(false);
  const [activityFeed, setActivityFeed] = useState<ActivityEvent[]>([]);
  const [loading, setLoading] = useState(true);
  const socketRef = useRef<Socket | null>(null);
  const { socket: sharedSocket } = useSharedSocket();
  const activityFeedRef = useRef<HTMLDivElement>(null);

  const stats = useMemo(() => ({
    total: missions.length,
    active: missions.filter(m => m.status === 'active').length,
    queued: missions.filter(m => m.status === 'queued').length,
    completed: missions.filter(m => m.status === 'completed').length,
    failed: missions.filter(m => m.status === 'failed').length,
    paused: missions.filter(m => m.status === 'paused').length,
    totalFindings: missions.reduce((sum, m) => sum + m.findings.length, 0),
    criticalFindings: missions.reduce((sum, m) => sum + m.findings.filter(f => f.severity === 'critical').length, 0),
  }), [missions]);

  const updateMission = useCallback((missionId: string, updater: (m: Mission) => Mission) => {
    setMissions(prev => prev.map(m => m.id === missionId ? updater(m) : m));
  }, []);

  const addActivity = useCallback((type: ActivityEvent['type'], text: string, severity: string, missionId?: string) => {
    const event: ActivityEvent = {
      id: `evt-${Date.now()}-${Math.random().toString(36).substr(2, 6)}`,
      type,
      text,
      severity,
      time: new Date().toLocaleTimeString(),
      missionId,
    };
    setActivityFeed(prev => [...prev, event].slice(-20));
  }, []);

  useEffect(() => {
    if (activityFeedRef.current) {
      activityFeedRef.current.scrollTop = activityFeedRef.current.scrollHeight;
    }
  }, [activityFeed]);

  const fetchMissions = useCallback(async () => {
    try {
      const res = await fetch('/api/missions');
      const data = await res.json();
      if (data.success) {
        setMissions(data.missions);
      }
      setLoading(false);
    } catch (error) {
      console.error('Failed to fetch missions:', error);
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchMissions();
  }, []);

  useEffect(() => {
    if (!sharedSocket) return;

    socketRef.current = sharedSocket;

    const handleCreated = (data: any) => {
      if (data.mission) {
        setMissions(prev => [...prev, data.mission]);
      }
      addActivity('create', `Mission "${data.mission?.name || 'New'}" created`, 'info', data.mission?.id);
    };

    const handleLaunched = (data: any) => {
      updateMission(data.missionId, m => ({ ...m, status: 'active', startedAt: new Date().toISOString() }));
      addActivity('launch', `Mission "${data.name}" launched against ${data.target}`, 'info', data.missionId);
    };

    const handleStepStarted = (data: any) => {
      updateMission(data.missionId, m => ({
        ...m,
        progress: data.progress ?? m.progress,
        steps: m.steps.map(s => s.id === data.stepId ? { ...s, status: 'running' as const, startedAt: new Date().toISOString() } : s),
      }));
      addActivity('step_start', `Step "${data.stepName}" started${data.tool ? ` (${data.tool})` : ''}`, 'info', data.missionId);
    };

    const handleStepCompleted = (data: any) => {
      updateMission(data.missionId, m => ({
        ...m,
        progress: data.progress ?? m.progress,
        steps: m.steps.map(s => s.id === data.stepId ? { ...s, status: 'completed' as const, completedAt: new Date().toISOString() } : s),
      }));
      addActivity('step_complete', `Step "${data.stepName}" completed`, 'low', data.missionId);
    };

    const handleFinding = (data: any) => {
      updateMission(data.missionId, m => ({
        ...m,
        findings: [...m.findings, data.finding],
      }));
      addActivity('finding', `[${data.finding?.severity?.toUpperCase() || 'FINDING'}] ${data.finding?.title || 'New finding'}`, data.finding?.severity || 'medium', data.missionId);
    };

    const handleCompleted = (data: any) => {
      updateMission(data.missionId, m => ({
        ...m,
        status: 'completed',
        progress: 100,
        completedAt: new Date().toISOString(),
      }));
      addActivity('complete', `Mission "${data.name}" completed with ${data.findings} findings in ${data.duration || '?'}s`, 'low', data.missionId);
    };

    const handlePaused = (data: any) => {
      updateMission(data.missionId, m => ({ ...m, status: 'paused' }));
      addActivity('pause', `Mission paused`, 'info', data.missionId);
    };

    const handleResumed = (data: any) => {
      updateMission(data.missionId, m => ({ ...m, status: 'active' }));
      addActivity('resume', `Mission resumed`, 'info', data.missionId);
    };

    const handleCancelled = (data: any) => {
      updateMission(data.missionId, m => ({ ...m, status: 'cancelled' }));
      addActivity('cancel', `Mission cancelled`, 'info', data.missionId);
    };

    const handleEmergencyStop = (data: any) => {
      setMissions(prev => prev.map(m =>
        m.status === 'active' || m.status === 'queued' ? { ...m, status: 'cancelled' as const } : m
      ));
      addActivity('emergency', `EMERGENCY STOP: ${data.cancelled} missions cancelled`, 'critical');
    };

    const handleDeleted = (data: any) => {
      setMissions(prev => prev.filter(m => m.id !== data.missionId));
      addActivity('delete', `Mission deleted`, 'info', data.missionId);
    };

    sharedSocket.on('mission:created', handleCreated);
    sharedSocket.on('mission:launched', handleLaunched);
    sharedSocket.on('mission:step:started', handleStepStarted);
    sharedSocket.on('mission:step:completed', handleStepCompleted);
    sharedSocket.on('mission:finding', handleFinding);
    sharedSocket.on('mission:completed', handleCompleted);
    sharedSocket.on('mission:paused', handlePaused);
    sharedSocket.on('mission:resumed', handleResumed);
    sharedSocket.on('mission:cancelled', handleCancelled);
    sharedSocket.on('mission:emergency-stop', handleEmergencyStop);
    sharedSocket.on('mission:deleted', handleDeleted);

    return () => {
      sharedSocket.off('mission:created', handleCreated);
      sharedSocket.off('mission:launched', handleLaunched);
      sharedSocket.off('mission:step:started', handleStepStarted);
      sharedSocket.off('mission:step:completed', handleStepCompleted);
      sharedSocket.off('mission:finding', handleFinding);
      sharedSocket.off('mission:completed', handleCompleted);
      sharedSocket.off('mission:paused', handlePaused);
      sharedSocket.off('mission:resumed', handleResumed);
      sharedSocket.off('mission:cancelled', handleCancelled);
      sharedSocket.off('mission:emergency-stop', handleEmergencyStop);
      sharedSocket.off('mission:deleted', handleDeleted);
    };
  }, [sharedSocket]);

  const handleAction = async (missionId: string, action: string) => {
    try {
      const url = `/api/missions/${missionId}/${action}`;
      await csrfFetch(url, { method: 'POST', headers: { 'Content-Type': 'application/json' } });
      fetchMissions();
    } catch (error) {
      console.error(`Action ${action} failed:`, error);
    }
  };

  const handleEmergencyStop = async () => {
    try {
      await csrfFetch('/api/missions/emergency-stop', { method: 'POST', headers: { 'Content-Type': 'application/json' } });
      fetchMissions();
    } catch (error) {
      console.error('Emergency stop failed:', error);
    }
  };

  const handleDelete = async (missionId: string) => {
    try {
      await csrfFetch(`/api/missions/${missionId}`, { method: 'DELETE' });
      if (selectedMissionId === missionId) setSelectedMissionId(null);
      fetchMissions();
    } catch (error) {
      console.error('Delete failed:', error);
    }
  };

  const groupedMissions = {
    active: missions.filter(m => m.status === 'active'),
    queued: missions.filter(m => m.status === 'queued'),
    paused: missions.filter(m => m.status === 'paused'),
    completed: missions.filter(m => m.status === 'completed'),
    failed: missions.filter(m => m.status === 'failed'),
    cancelled: missions.filter(m => m.status === 'cancelled'),
  };

  if (loading) {
    return (
      <div className="h-full flex items-center justify-center bg-[#1e1e1e]" data-testid="missions-loading">
        <div className="text-center">
          <Loader2 className="w-8 h-8 text-cyan-400 animate-spin mx-auto mb-2" />
          <p className="text-sm text-gray-400">Loading missions...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="h-full flex bg-[#1e1e1e] overflow-hidden" data-testid="mission-board">
      <div className="w-80 border-r border-[#2d2d2d] flex flex-col shrink-0">
        <div className="px-3 py-3 border-b border-[#2d2d2d] shrink-0">
          <div className="flex items-center justify-between mb-2">
            <div className="flex items-center gap-2">
              <Rocket className="w-4 h-4 text-cyan-400" />
              <h2 className="text-sm font-bold text-gray-100">War Room</h2>
            </div>
            <div className="flex items-center gap-1">
              <button
                onClick={() => setShowLaunchModal(true)}
                className="p-1.5 text-green-400 hover:bg-green-400/10 rounded transition-colors"
                title="New Mission"
                data-testid="button-new-mission"
              >
                <Plus className="w-3.5 h-3.5" />
              </button>
              <button
                onClick={fetchMissions}
                className="p-1.5 text-gray-400 hover:bg-[#2d2d2d] rounded transition-colors"
                title="Refresh"
                data-testid="button-refresh-missions"
              >
                <RefreshCw className="w-3.5 h-3.5" />
              </button>
              {stats.active > 0 && (
                <button
                  onClick={handleEmergencyStop}
                  className="p-1.5 text-red-400 hover:bg-red-400/10 rounded transition-colors"
                  title="Emergency Stop All"
                  data-testid="button-emergency-stop"
                >
                  <AlertOctagon className="w-3.5 h-3.5" />
                </button>
              )}
            </div>
          </div>

          <div className="grid grid-cols-4 gap-1.5">
            <StatBadge label="Active" value={stats.active} color="text-green-400" bg="bg-green-400/10" />
            <StatBadge label="Queue" value={stats.queued} color="text-cyan-400" bg="bg-cyan-400/10" />
            <StatBadge label="Done" value={stats.completed} color="text-blue-400" bg="bg-blue-400/10" />
            <StatBadge label="Finds" value={stats.totalFindings} color="text-orange-400" bg="bg-orange-400/10" />
          </div>
        </div>

        <div className="flex-1 overflow-auto">
          {Object.entries(groupedMissions).map(([status, items]) => {
            if (items.length === 0) return null;
            return (
              <MissionGroup
                key={status}
                status={status}
                missions={items}
                selectedId={selectedMissionId}
                onSelect={(m) => setSelectedMissionId(m.id)}
                onAction={handleAction}
                onDelete={handleDelete}
              />
            );
          })}

          {missions.length === 0 && (
            <div className="flex flex-col items-center justify-center py-12 text-gray-500">
              <Rocket className="w-8 h-8 mb-2 opacity-30" />
              <p className="text-xs">No missions yet</p>
              <button
                onClick={() => setShowLaunchModal(true)}
                className="mt-2 text-[11px] text-cyan-400 hover:underline"
                data-testid="button-create-first-mission"
              >
                Launch your first mission
              </button>
            </div>
          )}
        </div>

        {activityFeed.length > 0 && (
          <div className="border-t border-[#2d2d2d] max-h-40 flex flex-col shrink-0">
            <div className="px-2 py-1.5 text-[10px] text-gray-500 font-semibold uppercase tracking-wider shrink-0">Live Activity</div>
            <div ref={activityFeedRef} className="overflow-auto flex-1">
              {activityFeed.map(evt => {
                const IconComp = activityEventIcons[evt.type] || Zap;
                const colorClass = activityEventColors[evt.type] || 'text-gray-400';
                return (
                  <div key={evt.id} className="px-2 py-1 flex items-start gap-1.5 hover:bg-[#252526]" data-testid={`activity-event-${evt.id}`}>
                    <IconComp className={`w-3 h-3 mt-0.5 shrink-0 ${colorClass}`} />
                    <span className="text-[10px] text-gray-400 flex-1 leading-tight">{evt.text}</span>
                    <span className="text-[9px] text-gray-600 shrink-0">{evt.time}</span>
                  </div>
                );
              })}
            </div>
          </div>
        )}
      </div>

      <div className="flex-1 overflow-auto">
        {selectedMissionId ? (
          <MissionDetails
            missionId={selectedMissionId}
            onAction={handleAction}
            onClose={() => setSelectedMissionId(null)}
          />
        ) : (
          <div className="h-full flex items-center justify-center">
            <div className="text-center text-gray-500">
              <Target className="w-12 h-12 mx-auto mb-3 opacity-20" />
              <p className="text-sm">Select a mission to view details</p>
              <p className="text-xs mt-1">or launch a new one</p>
            </div>
          </div>
        )}
      </div>

      {showLaunchModal && (
        <LaunchMissionModal
          onClose={() => setShowLaunchModal(false)}
          onLaunch={() => {
            setShowLaunchModal(false);
            fetchMissions();
          }}
        />
      )}
    </div>
  );
}

function StatBadge({ label, value, color, bg }: { label: string; value: number; color: string; bg: string }) {
  return (
    <div className={`${bg} rounded px-1.5 py-1 text-center`}>
      <div className={`text-sm font-bold font-mono ${color}`}>{value}</div>
      <div className="text-[9px] text-gray-500">{label}</div>
    </div>
  );
}

function MissionGroup({
  status, missions, selectedId, onSelect, onAction, onDelete
}: {
  status: string;
  missions: Mission[];
  selectedId: string | null;
  onSelect: (m: Mission) => void;
  onAction: (missionId: string, action: string) => void | Promise<void>;
  onDelete: (id: string) => void | Promise<void>;
}) {
  const [expanded, setExpanded] = useState(status === 'active' || status === 'queued');
  const StatusIcon = statusIcons[status] || Clock;

  return (
    <div className="border-b border-[#2d2d2d]">
      <button
        onClick={() => setExpanded(!expanded)}
        className="w-full flex items-center gap-2 px-3 py-1.5 hover:bg-[#252526] transition-colors"
      >
        <ChevronRight className={`w-3 h-3 text-gray-500 transition-transform ${expanded ? 'rotate-90' : ''}`} />
        <StatusIcon className={`w-3.5 h-3.5 ${statusColors[status]} ${status === 'active' ? 'animate-spin' : ''}`} />
        <span className="text-xs text-gray-400 capitalize flex-1 text-left">{status}</span>
        <span className="text-[10px] text-gray-600">{missions.length}</span>
      </button>

      {expanded && (
        <div className="pb-1">
          {missions.map(mission => (
            <div
              key={mission.id}
              onClick={() => onSelect(mission)}
              className={`mx-1 px-2 py-1.5 rounded cursor-pointer transition-colors group ${
                selectedId === mission.id
                  ? 'bg-cyan-400/10 border border-cyan-400/30'
                  : 'hover:bg-[#252526] border border-transparent'
              }`}
              data-testid={`mission-card-${mission.id}`}
            >
              <div className="flex items-center gap-2">
                <span className="text-xs text-gray-200 truncate flex-1">{mission.name}</span>
                {mission.status === 'active' && (
                  <span className="text-[9px] text-green-400 font-mono">{mission.progress}%</span>
                )}
              </div>
              <div className="flex items-center gap-2 mt-0.5">
                <span className="text-[10px] text-gray-500 truncate">{mission.target}</span>
                {mission.goal && (
                  <span className="text-[9px] text-cyan-400/70">{mission.goal}</span>
                )}
                {mission.findings.length > 0 && (
                  <span className="text-[9px] text-orange-400 font-mono">{mission.findings.length} finds</span>
                )}
              </div>

              {mission.status === 'active' && (
                <div className="mt-1 h-1 bg-[#1a1a1a] rounded-full overflow-hidden">
                  <div
                    className="h-full bg-gradient-to-r from-cyan-400 to-green-400 rounded-full transition-all duration-500"
                    style={{ width: `${mission.progress}%` }}
                  />
                </div>
              )}

              <div className="flex items-center gap-1 mt-1 opacity-0 group-hover:opacity-100 transition-opacity">
                {(mission.status === 'queued' || mission.status === 'paused') && (
                  <button
                    onClick={(e) => { e.stopPropagation(); onAction(mission.id, mission.status === 'paused' ? 'resume' : 'launch'); }}
                    className="p-0.5 text-green-400 hover:bg-green-400/10 rounded"
                    title="Launch"
                  >
                    <Play className="w-3 h-3" />
                  </button>
                )}
                {mission.status === 'active' && (
                  <button
                    onClick={(e) => { e.stopPropagation(); onAction(mission.id, 'pause'); }}
                    className="p-0.5 text-yellow-400 hover:bg-yellow-400/10 rounded"
                    title="Pause"
                  >
                    <Pause className="w-3 h-3" />
                  </button>
                )}
                {(mission.status === 'active' || mission.status === 'queued' || mission.status === 'paused') && (
                  <button
                    onClick={(e) => { e.stopPropagation(); onAction(mission.id, 'cancel'); }}
                    className="p-0.5 text-red-400 hover:bg-red-400/10 rounded"
                    title="Cancel"
                  >
                    <Square className="w-3 h-3" />
                  </button>
                )}
                {(mission.status === 'completed' || mission.status === 'failed' || mission.status === 'cancelled') && (
                  <button
                    onClick={(e) => { e.stopPropagation(); onDelete(mission.id); }}
                    className="p-0.5 text-gray-500 hover:bg-red-400/10 hover:text-red-400 rounded"
                    title="Delete"
                  >
                    <Trash2 className="w-3 h-3" />
                  </button>
                )}
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
