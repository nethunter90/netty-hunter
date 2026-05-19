import { useState, useEffect, useRef, useCallback } from 'react';
import { useSharedSocket } from '@/context/SocketContext';
import type { Socket } from 'socket.io-client';
import {
  Target, Play, Pause, Square, Download, Shield,
  CheckCircle, XCircle, Clock, Loader2, Activity,
  TrendingUp, Server, Globe, Eye, AlertTriangle
} from 'lucide-react';
import { StealthIndicator } from './StealthIndicator';
import { AttackPathVisualizer } from './AttackPathVisualizer';
import { FindingsPanel } from './FindingsPanel';

interface MissionDetailsProps {
  missionId: string;
  onAction: (missionId: string, action: string) => void;
  onClose: () => void;
}

type TabType = 'overview' | 'findings' | 'logs' | 'evidence';

const statusColors: Record<string, string> = {
  active: 'bg-green-400/10 text-green-400 border-green-400/30',
  queued: 'bg-cyan-400/10 text-cyan-400 border-cyan-400/30',
  paused: 'bg-yellow-400/10 text-yellow-400 border-yellow-400/30',
  completed: 'bg-blue-400/10 text-blue-400 border-blue-400/30',
  failed: 'bg-red-400/10 text-red-400 border-red-400/30',
  cancelled: 'bg-gray-400/10 text-gray-500 border-gray-400/30',
};

const threatColors: Record<string, string> = {
  critical: 'bg-red-400/10 text-red-400 border-red-400/30',
  high: 'bg-orange-400/10 text-orange-400 border-orange-400/30',
  medium: 'bg-yellow-400/10 text-yellow-400 border-yellow-400/30',
  low: 'bg-blue-400/10 text-blue-400 border-blue-400/30',
};

export function MissionDetails({ missionId, onAction, onClose }: MissionDetailsProps) {
  const [mission, setMission] = useState<any>(null);
  const [activeTab, setActiveTab] = useState<TabType>('overview');
  const [logs, setLogs] = useState<{ id: string; text: string; timestamp: string; type: string }[]>([]);
  const logsEndRef = useRef<HTMLDivElement>(null);
  const socketRef = useRef<Socket | null>(null);
  const { socket: sharedSocket } = useSharedSocket();

  const fetchMission = useCallback(async () => {
    try {
      const res = await fetch(`/api/missions/${missionId}`);
      const data = await res.json();
      if (data.success) {
        setMission(data.mission);
      }
    } catch (error) {
      console.error('Failed to fetch mission:', error);
    }
  }, [missionId]);

  useEffect(() => {
    fetchMission();
    const interval = setInterval(fetchMission, 2000);

    return () => {
      clearInterval(interval);
    };
  }, [missionId, fetchMission]);

  useEffect(() => {
    if (!sharedSocket) return;

    socketRef.current = sharedSocket;

    const handleStepStarted = (data: any) => {
      setLogs(prev => [...prev, {
        id: `log-${Date.now()}-${Math.random().toString(36).substr(2, 6)}`,
        text: `Step started: ${data.stepName || data.step || 'Unknown'}`,
        timestamp: new Date().toISOString(),
        type: 'started'
      }]);
      fetchMission();
    };

    const handleStepCompleted = (data: any) => {
      setLogs(prev => [...prev, {
        id: `log-${Date.now()}-${Math.random().toString(36).substr(2, 6)}`,
        text: `Step completed: ${data.stepName || data.step || 'Unknown'}`,
        timestamp: new Date().toISOString(),
        type: 'completed'
      }]);
      fetchMission();
    };

    const handleFinding = (data: any) => {
      setLogs(prev => [...prev, {
        id: `log-${Date.now()}-${Math.random().toString(36).substr(2, 6)}`,
        text: `Finding: [${data.finding?.severity?.toUpperCase() || 'INFO'}] ${data.finding?.title || 'New finding'}`,
        timestamp: new Date().toISOString(),
        type: 'finding'
      }]);
      fetchMission();
    };

    sharedSocket.on('mission:step:started', handleStepStarted);
    sharedSocket.on('mission:step:completed', handleStepCompleted);
    sharedSocket.on('mission:finding', handleFinding);

    return () => {
      sharedSocket.off('mission:step:started', handleStepStarted);
      sharedSocket.off('mission:step:completed', handleStepCompleted);
      sharedSocket.off('mission:finding', handleFinding);
    };
  }, [sharedSocket, missionId, fetchMission]);

  useEffect(() => {
    if (logsEndRef.current) {
      logsEndRef.current.scrollIntoView({ behavior: 'smooth' });
    }
  }, [logs]);

  const handleExport = async () => {
    try {
      const res = await fetch(`/api/missions/${missionId}/export`);
      const data = await res.json();
      const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `mission-${missionId}-export.json`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    } catch (error) {
      console.error('Export failed:', error);
    }
  };

  if (!mission) {
    return (
      <div className="h-full flex items-center justify-center bg-[#1e1e1e]" data-testid="mission-details-loading">
        <Loader2 className="w-6 h-6 text-cyan-400 animate-spin" />
      </div>
    );
  }

  const tabs: { id: TabType; label: string; icon: typeof Activity }[] = [
    { id: 'overview', label: 'Overview', icon: Activity },
    { id: 'findings', label: 'Findings', icon: AlertTriangle },
    { id: 'logs', label: 'Live Logs', icon: Server },
    { id: 'evidence', label: 'Evidence', icon: Eye },
  ];

  return (
    <div className="h-full flex flex-col bg-[#1e1e1e] overflow-hidden" data-testid="mission-details">
      <div className="border-b border-[#2d2d2d] p-4 shrink-0">
        <div className="flex items-start justify-between mb-3">
          <div className="flex-1">
            <div className="flex items-center gap-3 mb-1">
              <Target className="w-5 h-5 text-cyan-400" />
              <h2 className="text-lg font-bold text-gray-100" data-testid="text-mission-target">{mission.target}</h2>
              <span className={`text-[11px] px-2 py-0.5 rounded border capitalize ${statusColors[mission.status] || statusColors.cancelled}`} data-testid="text-mission-status">
                {mission.status}
              </span>
              <span className={`text-[11px] px-2 py-0.5 rounded border capitalize ${threatColors[mission.threatLevel] || threatColors.medium}`} data-testid="text-threat-level">
                {mission.threatLevel} threat
              </span>
            </div>
            <div className="flex items-center gap-4 text-[11px] text-gray-500">
              <span data-testid="text-mission-goal"><Globe className="w-3 h-3 inline mr-1" />Goal: {mission.goal || 'General'}</span>
              <span data-testid="text-mission-start"><Clock className="w-3 h-3 inline mr-1" />Started: {mission.startedAt ? new Date(mission.startedAt).toLocaleString() : 'Not started'}</span>
              {mission.completedAt && (
                <span data-testid="text-mission-completed"><CheckCircle className="w-3 h-3 inline mr-1" />Completed: {new Date(mission.completedAt).toLocaleString()}</span>
              )}
            </div>
          </div>
          <div className="flex items-center gap-2">
            {mission.status === 'active' && (
              <button
                onClick={() => onAction(missionId, 'pause')}
                className="flex items-center gap-1.5 px-3 py-1.5 text-xs bg-yellow-400/10 text-yellow-400 border border-yellow-400/30 rounded hover:bg-yellow-400/20 transition-colors"
                data-testid="button-pause-mission"
              >
                <Pause className="w-3.5 h-3.5" />
                Pause
              </button>
            )}
            {mission.status === 'paused' && (
              <button
                onClick={() => onAction(missionId, 'resume')}
                className="flex items-center gap-1.5 px-3 py-1.5 text-xs bg-green-400/10 text-green-400 border border-green-400/30 rounded hover:bg-green-400/20 transition-colors"
                data-testid="button-resume-mission"
              >
                <Play className="w-3.5 h-3.5" />
                Resume
              </button>
            )}
            {['active', 'queued', 'paused'].includes(mission.status) && (
              <button
                onClick={() => onAction(missionId, 'cancel')}
                className="flex items-center gap-1.5 px-3 py-1.5 text-xs bg-red-400/10 text-red-400 border border-red-400/30 rounded hover:bg-red-400/20 transition-colors"
                data-testid="button-cancel-mission"
              >
                <Square className="w-3.5 h-3.5" />
                Cancel
              </button>
            )}
            {mission.findings && mission.findings.length > 0 && (
              <button
                onClick={handleExport}
                className="flex items-center gap-1.5 px-3 py-1.5 text-xs bg-blue-400/10 text-blue-400 border border-blue-400/30 rounded hover:bg-blue-400/20 transition-colors"
                data-testid="button-export-mission"
              >
                <Download className="w-3.5 h-3.5" />
                Export
              </button>
            )}
            <button
              onClick={onClose}
              className="p-1.5 text-gray-400 hover:bg-[#2d2d2d] rounded transition-colors"
              data-testid="button-close-details"
            >
              <XCircle className="w-4 h-4" />
            </button>
          </div>
        </div>

        {mission.status === 'active' && (
          <div className="mb-3" data-testid="mission-progress">
            <div className="flex items-center justify-between mb-1">
              <span className="text-[11px] text-gray-400">Progress</span>
              <span className="text-[11px] font-mono text-cyan-400">{mission.progress || 0}%</span>
            </div>
            <div className="w-full h-2 bg-[#2d2d2d] rounded-full overflow-hidden">
              <div
                className="h-full bg-cyan-400 rounded-full transition-all duration-500"
                style={{ width: `${mission.progress || 0}%` }}
              />
            </div>
          </div>
        )}

        <div className="flex items-center justify-between mb-3">
          <StealthIndicator stealthStatus={mission.stealthStatus || { mode: 'auto', detections: 0 }} compact={true} />
        </div>

        <div className="grid grid-cols-4 gap-2">
          <div className="bg-[#252526] border border-[#2d2d2d] rounded p-2 text-center" data-testid="stat-findings">
            <div className="text-sm font-bold font-mono text-orange-400">{mission.findings?.length || 0}</div>
            <div className="text-[9px] text-gray-500">Findings</div>
          </div>
          <div className="bg-[#252526] border border-[#2d2d2d] rounded p-2 text-center" data-testid="stat-evidence">
            <div className="text-sm font-bold font-mono text-blue-400">{mission.evidence?.length || 0}</div>
            <div className="text-[9px] text-gray-500">Evidence</div>
          </div>
          <div className="bg-[#252526] border border-[#2d2d2d] rounded p-2 text-center" data-testid="stat-scope">
            <div className="text-sm font-bold font-mono text-green-400">{mission.scope?.inScope?.length || 0}</div>
            <div className="text-[9px] text-gray-500">In Scope</div>
          </div>
          <div className="bg-[#252526] border border-[#2d2d2d] rounded p-2 text-center" data-testid="stat-stealth">
            <div className="text-sm font-bold font-mono text-cyan-400 capitalize">{mission.stealthStatus?.mode || 'auto'}</div>
            <div className="text-[9px] text-gray-500">Stealth</div>
          </div>
        </div>
      </div>

      <div className="flex border-b border-[#2d2d2d] shrink-0">
        {tabs.map(tab => {
          const Icon = tab.icon;
          return (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={`flex items-center gap-1.5 px-4 py-2.5 text-xs font-medium transition-colors border-b-2 ${
                activeTab === tab.id
                  ? 'text-cyan-400 border-cyan-400 bg-cyan-400/5'
                  : 'text-gray-500 border-transparent hover:text-gray-300 hover:bg-[#252526]'
              }`}
              data-testid={`tab-${tab.id}`}
            >
              <Icon className="w-3.5 h-3.5" />
              {tab.label}
            </button>
          );
        })}
      </div>

      <div className="flex-1 overflow-auto p-4">
        {activeTab === 'overview' && (
          <div className="grid grid-cols-2 gap-4 h-full" data-testid="tab-content-overview">
            <div className="bg-[#252526] border border-[#2d2d2d] rounded p-4 overflow-auto">
              <div className="flex items-center gap-2 mb-3">
                <TrendingUp className="w-4 h-4 text-cyan-400" />
                <h3 className="text-sm font-semibold text-gray-200">Attack Path</h3>
              </div>
              <AttackPathVisualizer attackPath={mission.attackPath || []} />
            </div>
            <div className="bg-[#252526] border border-[#2d2d2d] rounded p-4">
              <div className="flex items-center gap-2 mb-3">
                <Activity className="w-4 h-4 text-cyan-400" />
                <h3 className="text-sm font-semibold text-gray-200">Current Status</h3>
              </div>
              {mission.currentTask ? (
                <div className="space-y-3" data-testid="current-task-info">
                  <div className="bg-[#1e1e1e] border border-[#3d3d3d] rounded p-3">
                    <div className="flex items-center gap-2 mb-2">
                      <Loader2 className="w-3.5 h-3.5 text-cyan-400 animate-spin" />
                      <span className="text-xs font-medium text-gray-200 capitalize">{mission.currentTask.type}</span>
                      <span className={`text-[10px] px-1.5 py-0.5 rounded border capitalize ${
                        mission.currentTask.priority === 'critical' ? 'bg-red-400/10 text-red-400 border-red-400/30' :
                        mission.currentTask.priority === 'high' ? 'bg-orange-400/10 text-orange-400 border-orange-400/30' :
                        mission.currentTask.priority === 'medium' ? 'bg-yellow-400/10 text-yellow-400 border-yellow-400/30' :
                        'bg-blue-400/10 text-blue-400 border-blue-400/30'
                      }`}>
                        {mission.currentTask.priority}
                      </span>
                    </div>
                    <p className="text-[11px] text-gray-400">{mission.currentTask.description}</p>
                  </div>
                </div>
              ) : (
                <div className="flex flex-col items-center justify-center py-12 text-gray-500" data-testid="no-current-task">
                  {mission.status === 'completed' ? (
                    <>
                      <CheckCircle className="w-8 h-8 mb-2 text-green-400 opacity-40" />
                      <p className="text-xs">Mission completed</p>
                    </>
                  ) : (
                    <>
                      <Clock className="w-8 h-8 mb-2 opacity-20" />
                      <p className="text-xs">Waiting for next task</p>
                    </>
                  )}
                </div>
              )}
            </div>
          </div>
        )}

        {activeTab === 'findings' && (
          <div data-testid="tab-content-findings">
            <FindingsPanel findings={mission.findings || []} />
          </div>
        )}

        {activeTab === 'logs' && (
          <div className="h-full flex flex-col" data-testid="tab-content-logs">
            <div className="flex-1 bg-[#252526] border border-[#2d2d2d] rounded p-3 overflow-auto font-mono text-xs">
              {logs.length === 0 ? (
                <div className="flex flex-col items-center justify-center py-12 text-gray-500">
                  <Server className="w-8 h-8 mb-2 opacity-20" />
                  <p className="text-xs">No log entries yet</p>
                  <p className="text-[10px] mt-1">Logs will appear here in real-time</p>
                </div>
              ) : (
                <div className="space-y-1">
                  {logs.map(log => (
                    <div key={log.id} className="flex items-start gap-2 py-0.5" data-testid={`log-entry-${log.id}`}>
                      <span className="text-gray-600 shrink-0">{new Date(log.timestamp).toLocaleTimeString()}</span>
                      <span className={
                        log.type === 'finding' ? 'text-orange-400' :
                        log.type === 'completed' ? 'text-green-400' :
                        log.type === 'started' ? 'text-cyan-400' :
                        'text-gray-400'
                      }>
                        {log.text}
                      </span>
                    </div>
                  ))}
                  <div ref={logsEndRef} />
                </div>
              )}
            </div>
          </div>
        )}

        {activeTab === 'evidence' && (
          <div data-testid="tab-content-evidence">
            {mission.evidence && mission.evidence.length > 0 ? (
              <div className="grid grid-cols-2 gap-3">
                {mission.evidence.map((item: any) => (
                  <div key={item.id} className="bg-[#252526] border border-[#2d2d2d] rounded p-3" data-testid={`evidence-item-${item.id}`}>
                    <div className="flex items-center gap-2 mb-2">
                      <Shield className="w-3.5 h-3.5 text-cyan-400" />
                      <span className="text-xs font-medium text-gray-200 capitalize">{item.type}</span>
                    </div>
                    <div className="text-[11px] text-gray-400 font-mono bg-[#1e1e1e] rounded p-2 mb-2 max-h-24 overflow-auto">
                      {typeof item.data === 'string' ? item.data.substring(0, 200) : JSON.stringify(item.data).substring(0, 200)}
                    </div>
                    <div className="text-[9px] text-gray-600">
                      {new Date(item.timestamp).toLocaleString()}
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              <div className="flex flex-col items-center justify-center py-12 text-gray-500" data-testid="evidence-empty">
                <Eye className="w-8 h-8 mb-2 opacity-20" />
                <p className="text-xs">No evidence collected yet</p>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
