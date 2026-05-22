import React, { useState, useEffect, useRef } from "react";
import {
  Terminal, Play, Square, Crosshair, Target, Zap, Eye, Brain,
  ChevronRight, AlertTriangle, CheckCircle2, Clock, RefreshCw
} from "lucide-react";
import { hunterAPI, bountyAPI } from "../lib/api";
import { getSocket } from "../lib/socket";
import toast from "react-hot-toast";

interface LogEntry {
  time: string;
  type: "info" | "warning" | "success" | "error" | "phase" | "finding";
  message: string;
  data?: Record<string, unknown>;
}

interface ActiveSession {
  sessionUuid: string;
  targetUrl: string;
  status: "running" | "complete" | "error";
  phase: string;
  iteration: number;
  findings: number;
}

export default function HuntConsole() {
  const [programs, setPrograms] = useState<Record<string, unknown>[]>([]);
  const [selectedProgram, setSelectedProgram] = useState<number>(0);
  const [targetUrl, setTargetUrl] = useState("");
  const [huntMode, setHuntMode] = useState<"forward" | "backward">("forward");
  const [goal, setGoal] = useState("");
  const [maxIterations, setMaxIterations] = useState(10);
  const [activeSessions, setActiveSessions] = useState<ActiveSession[]>([]);
  const [logs, setLogs] = useState<LogEntry[]>([]);
  const [loading, setLoading] = useState(false);
  const [templates, setTemplates] = useState<Record<string, unknown>[]>([]);
  const [selectedTemplate, setSelectedTemplate] = useState<string>("");
  const logRef = useRef<HTMLDivElement>(null);
  const socket = getSocket();

  useEffect(() => {
    bountyAPI.getPrograms().then(r => setPrograms(r.data || []));
    bountyAPI.getHuntTemplates().then(r => setTemplates(r.data || []));
  }, []);

  useEffect(() => {
    // Socket event listeners
    const events = [
      "hunt:started", "hunt:phase", "hunt:observations", "hunt:hypotheses",
      "hunt:probing", "hunt:probe_result", "hunt:finding_confirmed", "hunt:update",
      "hunt:complete", "hunt:error", "solver:started", "solver:complete", "solver:finding",
    ];

    events.forEach(event => {
      socket.on(event, (data: Record<string, unknown>) => {
        const entry: LogEntry = {
          time: new Date().toISOString().slice(11, 23),
          type: event.includes("error") ? "error" : event.includes("finding") ? "finding" : event.includes("complete") ? "success" : "info",
          message: formatEventMessage(event, data),
          data,
        };
        setLogs(prev => [...prev.slice(-200), entry]);

        // Update active sessions
        if (event === "hunt:phase") {
          setActiveSessions(prev => prev.map(s =>
            s.sessionUuid === String(data.sessionUuid || "") ? { ...s, phase: String(data.phase || ""), iteration: Number(data.iteration || 0) } : s
          ));
        }
        if (event === "hunt:finding_confirmed") {
          setActiveSessions(prev => prev.map(s => ({ ...s, findings: s.findings + 1 })));
          toast.success(`Finding confirmed: ${String((data.finding as any)?.hypothesis?.vulnClass || "unknown")}`);
        }
        if (event === "hunt:complete") {
          setActiveSessions(prev => prev.map(s =>
            s.sessionUuid === String(data.sessionId || "") ? { ...s, status: "complete" } : s
          ));
        }
      });
    });

    return () => { events.forEach(e => socket.off(e)); };
  }, []);

  // Auto-scroll logs
  useEffect(() => {
    if (logRef.current) logRef.current.scrollTop = logRef.current.scrollHeight;
  }, [logs]);

  const formatEventMessage = (event: string, data: Record<string, unknown>): string => {
    switch (event) {
      case "hunt:started": return `Hunt started on ${String(data.targetUrl || "")}`;
      case "hunt:phase": return `[${String(data.phase || "").toUpperCase()}] iteration ${data.iteration}`;
      case "hunt:observations": return `Generated ${Number(data.count || 0)} observations (anomaly-sorted)`;
      case "hunt:hypotheses": return `Generated ${Number(data.count || 0)} hypotheses`;
      case "hunt:probing": return `Probing: ${String(data.vulnClass || "")} → ${String(data.hypothesisId || "").slice(0, 8)}...`;
      case "hunt:finding_confirmed": return `FINDING CONFIRMED: ${String((data.finding as any)?.hypothesis?.vulnClass || "?")} [${String((data.finding as any)?.severity || "")}]`;
      case "hunt:complete": return `Hunt complete: ${Number(data.findings || 0)} findings in ${Number(data.iterations || 0)} iterations`;
      case "hunt:error": return `ERROR: ${String(data.error || "")}`;
      case "solver:started": return `Solver spawned: ${String(data.vulnClass || "")}`;
      case "solver:complete": return `Solver done: ${String(data.vulnClass || "")} confidence=${Number(data.confidence || 0).toFixed(2)}`;
      case "solver:finding": return `SOLVER FINDING: ${String((data.result as Record<string, unknown>)?.vulnClass || "")}`;
      default: return `${event}: ${JSON.stringify(data).slice(0, 100)}`;
    }
  };

  const startHunt = async () => {
    if (!selectedProgram) return toast.error("Select a program first");
    if (!targetUrl) return toast.error("Enter target URL");
    if (huntMode === "backward" && !goal) return toast.error("Enter hunt goal for backward mode");

    setLoading(true);
    setLogs([]);

    try {
      const res = await hunterAPI.startHunt({
        programId: selectedProgram,
        targetUrl,
        mode: huntMode,
        goal: goal || undefined,
        maxIterations,
        templateId: selectedTemplate || undefined,
        budget: { maxRequests: 2000, maxTime: 3600 },
      });

      const session: ActiveSession = {
        sessionUuid: res.data.sessionUuid || `backward-${res.data.planId}`,
        targetUrl,
        status: "running",
        phase: "observe",
        iteration: 0,
        findings: 0,
      };
      setActiveSessions(prev => [...prev, session]);

      // Subscribe to session events
      if (res.data.sessionUuid) {
        socket.emit("subscribe:hunt", { sessionUuid: res.data.sessionUuid });
      }

      addLog("success", `Hunt started: ${res.data.sessionUuid || res.data.planId}`);
    } catch (err: unknown) {
      const error = err as { response?: { data?: { error?: string } } };
      toast.error(error.response?.data?.error || "Failed to start hunt");
      addLog("error", `Failed to start hunt: ${error.response?.data?.error}`);
    } finally {
      setLoading(false);
    }
  };

  const stopHunt = async (uuid: string) => {
    await hunterAPI.stopHunt(uuid).catch(() => {});
    setActiveSessions(prev => prev.filter(s => s.sessionUuid !== uuid));
    addLog("warning", `Hunt stopped: ${uuid}`);
  };

  const addLog = (type: LogEntry["type"], message: string) => {
    setLogs(prev => [...prev, { time: new Date().toISOString().slice(11, 23), type, message }]);
  };

  const LOG_COLORS: Record<string, string> = {
    info: "text-hack-text", warning: "text-hack-yellow", success: "text-hack-accent",
    error: "text-hack-red", phase: "text-hack-cyan", finding: "text-hack-orange",
  };

  const PHASE_ICONS: Record<string, React.ReactNode> = {
    observe: <Eye className="w-3 h-3 text-hack-cyan" />,
    hypothesize: <Brain className="w-3 h-3 text-hack-purple" />,
    probe: <Target className="w-3 h-3 text-hack-orange" />,
    update: <RefreshCw className="w-3 h-3 text-hack-blue" />,
    complete: <CheckCircle2 className="w-3 h-3 text-hack-accent" />,
  };

  return (
    <div className="h-full flex flex-col overflow-hidden">
      {/* Header */}
      <div className="flex items-center justify-between p-4 border-b border-hack-border flex-shrink-0">
        <div className="flex items-center gap-2">
          <Terminal className="w-4 h-4 text-hack-accent" />
          <span className="text-sm font-mono font-bold text-hack-accent">HUNT CONSOLE</span>
        </div>
        <div className="text-[10px] text-hack-dim font-mono">
          Active: {activeSessions.filter(s => s.status === "running").length}
        </div>
      </div>

      <div className="flex-1 flex overflow-hidden">
        {/* Left: Hunt Config */}
        <div className="w-80 border-r border-hack-border flex flex-col overflow-hidden flex-shrink-0">
          <div className="p-3 space-y-3 overflow-y-auto terminal-scroll flex-1">
            <div>
              <label className="hack-label">Target Program</label>
              <select
                className="hack-input w-full"
                value={selectedProgram}
                onChange={e => setSelectedProgram(parseInt(e.target.value))}
              >
                <option value={0}>-- Select Program --</option>
                {programs.map((p: Record<string, unknown>) => (
                  <option key={Number(p.id)} value={Number(p.id)}>{String(p.name)}</option>
                ))}
              </select>
            </div>

            <div>
              <label className="hack-label">Target URL</label>
              <input
                className="hack-input w-full"
                value={targetUrl}
                onChange={e => setTargetUrl(e.target.value)}
                placeholder="https://target.example.com"
              />
            </div>

            <div>
              <label className="hack-label">Hunt Mode</label>
              <div className="flex gap-1">
                {(["forward", "backward"] as const).map(m => (
                  <button key={m} onClick={() => setHuntMode(m)}
                    className={`flex-1 py-1.5 text-[10px] font-mono uppercase rounded border transition-all ${huntMode === m ? "bg-hack-accent/10 text-hack-accent border-hack-accent/30" : "text-hack-dim border-hack-border hover:text-hack-text"}`}>
                    {m === "forward" ? "→ FORWARD" : "← BACKWARD"}
                  </button>
                ))}
              </div>
              <div className="text-[9px] text-hack-dim font-mono mt-1">
                {huntMode === "forward" ? "Observe → Hypothesize → Probe → Update" : "Goal-first hunting using pre-built attack trees"}
              </div>
            </div>

            {huntMode === "backward" && (
              <div>
                <label className="hack-label">Hunt Goal</label>
                <input
                  className="hack-input w-full"
                  value={goal}
                  onChange={e => setGoal(e.target.value)}
                  placeholder="e.g. Account takeover, RCE, Data exfiltration"
                />
              </div>
            )}

            <div>
              <label className="hack-label">Hunt Template</label>
              <select className="hack-input w-full" value={selectedTemplate} onChange={e => setSelectedTemplate(e.target.value)}>
                <option value="">-- Auto-select --</option>
                {templates.map((t: Record<string, unknown>) => (
                  <option key={String(t.id)} value={String(t.id)}>{String(t.name)}</option>
                ))}
              </select>
              {selectedTemplate && templates.find((t: Record<string, unknown>) => String(t.id) === selectedTemplate) && (
                <div className="text-[9px] text-hack-dim mt-1 font-mono">
                  {String((templates.find((t: Record<string, unknown>) => String(t.id) === selectedTemplate) as Record<string, unknown>)?.description || "")}
                </div>
              )}
            </div>

            <div>
              <label className="hack-label">Max Iterations: {maxIterations}</label>
              <input type="range" min={1} max={50} value={maxIterations} onChange={e => setMaxIterations(parseInt(e.target.value))} className="w-full accent-hack-accent" />
            </div>

            <button
              onClick={startHunt}
              disabled={loading || !selectedProgram || !targetUrl}
              className="hack-btn-primary w-full flex items-center justify-center gap-2 py-2.5 disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {loading ? (
                <span className="w-3 h-3 border border-hack-bg border-t-transparent rounded-full animate-spin" />
              ) : <Play className="w-3.5 h-3.5" />}
              {loading ? "INITIALIZING..." : "LAUNCH HUNT"}
            </button>
          </div>

          {/* Active sessions */}
          {activeSessions.length > 0 && (
            <div className="border-t border-hack-border p-3 space-y-2">
              <div className="text-[10px] text-hack-dim font-mono uppercase mb-2">Active Hunts</div>
              {activeSessions.map(session => (
                <div key={session.sessionUuid} className="hack-panel p-2 text-[10px] font-mono">
                  <div className="flex items-center justify-between mb-1">
                    <div className="flex items-center gap-1.5">
                      <span className={`status-dot ${session.status === "running" ? "status-running" : "status-complete"}`} />
                      <span className="text-hack-text truncate max-w-[120px]">{session.targetUrl}</span>
                    </div>
                    {session.status === "running" && (
                      <button onClick={() => stopHunt(session.sessionUuid)} className="text-hack-red hover:text-hack-red/80">
                        <Square className="w-3 h-3" />
                      </button>
                    )}
                  </div>
                  <div className="flex items-center gap-2 text-hack-dim">
                    {PHASE_ICONS[session.phase]}
                    <span>{session.phase} #{session.iteration}</span>
                    {session.findings > 0 && (
                      <span className="text-hack-orange ml-auto">{session.findings} findings</span>
                    )}
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Right: Terminal Output */}
        <div className="flex-1 flex flex-col overflow-hidden bg-hack-bg">
          <div className="flex items-center gap-2 px-4 py-2 border-b border-hack-border bg-hack-surface flex-shrink-0">
            <div className="flex gap-1.5">
              <div className="w-2.5 h-2.5 rounded-full bg-hack-red/80" />
              <div className="w-2.5 h-2.5 rounded-full bg-hack-yellow/80" />
              <div className="w-2.5 h-2.5 rounded-full bg-hack-accent/80" />
            </div>
            <span className="text-[10px] font-mono text-hack-dim ml-2">hunt-engine — /bin/hunter</span>
            <button onClick={() => setLogs([])} className="ml-auto text-[10px] text-hack-dim hover:text-hack-text font-mono">CLEAR</button>
          </div>

          <div
            ref={logRef}
            className="flex-1 overflow-y-auto terminal-scroll p-4 font-mono text-[11px] space-y-0.5"
          >
            {logs.length === 0 ? (
              <div className="text-hack-dim">
                <div>Welcome to <span className="text-hack-accent">Sentinel Primordial</span> Hunt Console</div>
                <div className="mt-2">Select a program, enter target URL, and launch a hunt.</div>
                <div className="mt-1">The Hunter Engine will autonomously:</div>
                <div className="ml-2 space-y-0.5 mt-1 text-hack-dim/70">
                  <div><span className="text-hack-cyan">→ OBSERVE</span>: Fingerprint target and collect anomalies</div>
                  <div><span className="text-hack-purple">→ HYPOTHESIZE</span>: Generate vulnerability hypotheses via AI</div>
                  <div><span className="text-hack-orange">→ PROBE</span>: Test hypotheses with real security tools</div>
                  <div><span className="text-hack-blue">→ UPDATE</span>: Update confidence scores and persist findings</div>
                </div>
                <div className="mt-3 terminal-cursor">_</div>
              </div>
            ) : logs.map((log, i) => (
              <div key={i} className={`flex gap-2 leading-5 ${LOG_COLORS[log.type]}`}>
                <span className="text-hack-dim flex-shrink-0">[{log.time}]</span>
                <span className="flex-shrink-0">
                  {log.type === "finding" ? <Zap className="w-3 h-3 inline text-hack-orange" /> :
                   log.type === "error" ? <AlertTriangle className="w-3 h-3 inline text-hack-red" /> :
                   log.type === "success" ? <CheckCircle2 className="w-3 h-3 inline text-hack-accent" /> :
                   <ChevronRight className="w-3 h-3 inline text-hack-dim" />}
                </span>
                <span>{log.message}</span>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}
