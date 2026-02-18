import React, { useState, useEffect, useRef } from "react";
import {
  Layers, Play, Square, Shield, Target, Brain, Cpu, CheckCircle2,
  XCircle, Clock, AlertTriangle, ChevronRight, BarChart3, Zap,
  RefreshCw, FileText, Lock
} from "lucide-react";
import { bountyAPI } from "../lib/api";
import { getSocket } from "../lib/socket";
import toast from "react-hot-toast";
import axios from "axios";

// ── Types ──────────────────────────────────────────────────────────────────────

interface LayerStatus {
  layer: number;
  name: string;
  phase: "pending" | "running" | "passed" | "failed" | "skipped";
  startedAt?: number;
  completedAt?: number;
  durationMs?: number;
  result?: Record<string, unknown>;
  error?: string;
}

interface AuditEntry {
  ts: number;
  layer: number;
  event: string;
  detail: Record<string, unknown>;
}

interface OrchestrationState {
  orchestrationId: string;
  campaignId?: number;
  phase: string;
  layers: LayerStatus[];
  findingsCount: number;
  verifiedCount: number;
  startedAt: number;
  audit: AuditEntry[];
}

interface LogEntry {
  ts: string;
  layer?: number;
  type: "info" | "success" | "error" | "warning" | "finding" | "audit";
  message: string;
}

// ── Layer icons & metadata ─────────────────────────────────────────────────────

const LAYER_ICONS = [Lock, Target, Brain, Cpu, CheckCircle2, BarChart3];
const LAYER_COLORS = [
  "text-hack-accent border-hack-accent/30 bg-hack-accent/5",
  "text-hack-blue border-hack-blue/30 bg-hack-blue/5",
  "text-hack-purple border-hack-purple/30 bg-hack-purple/5",
  "text-hack-yellow border-hack-yellow/30 bg-hack-yellow/5",
  "text-hack-orange border-hack-orange/30 bg-hack-orange/5",
  "text-hack-green border-hack-green/30 bg-hack-green/5",
] as const;

const LAYER_DESC = [
  "Scope validation · Policy enforcement · Audit logging",
  "ROI scoring · Attack surface mapping · Vuln class prioritization",
  "Hunt mode selection · Attack trees · Template library",
  "HunterEngine · SolverPool · WAF bypass · Budget enforcement",
  "4-layer anti-hallucination · Playwright gate · Deduplication",
  "Reinforcement learning · CAMS tracking · Reports · Nuclei templates",
];

// ── Component ──────────────────────────────────────────────────────────────────

export default function Orchestration() {
  const [programs, setPrograms] = useState<Record<string, unknown>[]>([]);
  const [selectedProgram, setSelectedProgram] = useState(0);
  const [targetUrl, setTargetUrl] = useState("");
  const [huntMode, setHuntMode] = useState<"forward" | "backward">("forward");
  const [goal, setGoal] = useState("");
  const [maxIterations, setMaxIterations] = useState(10);
  const [maxRequests, setMaxRequests] = useState(2000);

  const [orchestrationId, setOrchestrationId] = useState<string | null>(null);
  const [layers, setLayers] = useState<LayerStatus[]>(
    Array.from({ length: 6 }, (_, i) => ({
      layer: i + 1,
      name: ["GOVERNANCE GATE", "TARGET INTELLIGENCE", "STRATEGY PLANNING",
        "EXECUTION ENGINE", "VERIFICATION GATE", "INTELLIGENCE HARVEST"][i],
      phase: "pending",
    }))
  );
  const [phase, setPhase] = useState<string>("idle");
  const [findings, setFindings] = useState(0);
  const [verified, setVerified] = useState(0);
  const [logs, setLogs] = useState<LogEntry[]>([]);
  const [loading, setLoading] = useState(false);
  const [layerMeta, setLayerMeta] = useState<Record<string, unknown>[]>([]);

  const logRef = useRef<HTMLDivElement>(null);
  const socket = getSocket();

  // ── Init ───────────────────────────────────────────────────────────────────

  useEffect(() => {
    bountyAPI.getPrograms().then(r => setPrograms(r.data || []));
    // Fetch static layer metadata
    axios.get("/api/orchestration/layers").then(r => setLayerMeta(r.data?.layers || [])).catch(() => {});
  }, []);

  useEffect(() => {
    if (logRef.current) {
      logRef.current.scrollTop = logRef.current.scrollHeight;
    }
  }, [logs]);

  // ── Socket.IO wiring ───────────────────────────────────────────────────────

  useEffect(() => {
    const addLog = (type: LogEntry["type"], message: string, layer?: number) => {
      setLogs(prev => [...prev.slice(-300), {
        ts: new Date().toISOString().slice(11, 23),
        type,
        layer,
        message,
      }]);
    };

    socket.on("orchestration:created", ({ orchestrationId: id }: { orchestrationId: string }) => {
      setOrchestrationId(id);
      socket.emit("subscribe:orchestration", { orchestrationId: id });
      addLog("info", `Orchestration created: ${id.slice(0, 8)}…`);
    });

    socket.on("orchestration:started", () => {
      setPhase("running");
      addLog("info", "6-layer orchestration pipeline started");
    });

    socket.on("orchestration:layer_start", (d: { layer: number; name: string }) => {
      setLayers(prev => prev.map(l =>
        l.layer === d.layer ? { ...l, phase: "running", startedAt: Date.now() } : l
      ));
      setPhase(`l${d.layer}_${d.name.toLowerCase().replace(/ /g, "_")}`);
      addLog("info", `→ Layer ${d.layer}: ${d.name} started`, d.layer);
    });

    socket.on("orchestration:layer_complete", (d: {
      layer: number; name: string; passed: boolean; durationMs: number;
    }) => {
      setLayers(prev => prev.map(l =>
        l.layer === d.layer ? {
          ...l,
          phase: d.passed ? "passed" : "failed",
          completedAt: Date.now(),
          durationMs: d.durationMs,
        } : l
      ));
      addLog(
        d.passed ? "success" : "error",
        `✓ Layer ${d.layer}: ${d.name} ${d.passed ? "PASSED" : "FAILED"} (${d.durationMs}ms)`,
        d.layer
      );
    });

    socket.on("orchestration:layer_error", (d: { layer: number; name: string; error: string }) => {
      setLayers(prev => prev.map(l =>
        l.layer === d.layer ? { ...l, phase: "failed", error: d.error } : l
      ));
      addLog("error", `✗ Layer ${d.layer} error: ${d.error}`, d.layer);
    });

    socket.on("orchestration:audit", (d: AuditEntry) => {
      addLog("audit", `[L${d.layer}] ${d.event}: ${JSON.stringify(d.detail).slice(0, 120)}`, d.layer);
    });

    socket.on("orchestration:complete", () => {
      setPhase("complete");
      setLoading(false);
      addLog("success", "✓ All 6 layers complete – orchestration finished");
      toast.success("Orchestration complete!");
    });

    socket.on("orchestration:aborted", (d: { reason: string }) => {
      setPhase("aborted");
      setLoading(false);
      addLog("error", `Orchestration aborted: ${d.reason}`);
      toast.error(`Aborted: ${d.reason}`);
    });

    socket.on("orchestration:error", (d: { error: string }) => {
      setPhase("error");
      setLoading(false);
      addLog("error", `Fatal: ${d.error}`);
      toast.error(`Orchestration error: ${d.error}`);
    });

    // Layer 4 execution events
    socket.on("l4:phase", (d: { phase: string; iteration?: number }) => {
      addLog("info", `  [L4] Phase: ${d.phase}${d.iteration != null ? ` (iter ${d.iteration})` : ""}`, 4);
    });
    socket.on("l4:finding_raw", () => {
      setFindings(f => f + 1);
      addLog("finding", "  [L4] Raw finding detected", 4);
    });
    socket.on("l4:solver_finding", () => {
      setFindings(f => f + 1);
      addLog("finding", "  [L4] Solver finding detected", 4);
    });
    socket.on("l4:error", (d: { error: string }) => {
      addLog("warning", `  [L4] Engine warning: ${d.error}`, 4);
    });

    // Layer 5 verification events
    socket.on("l5:verified", (d: { findingId: number; verdict: string }) => {
      setVerified(v => v + 1);
      addLog("success", `  [L5] Finding #${d.findingId} verified: ${d.verdict}`, 5);
    });
    socket.on("l5:rejected", (d: { findingId: number; verdict: string }) => {
      addLog("warning", `  [L5] Finding #${d.findingId} rejected: ${d.verdict}`, 5);
    });

    // Layer 6 harvest events
    socket.on("l6:report_generated", (d: { findingId: number }) => {
      addLog("success", `  [L6] Report generated for finding #${d.findingId}`, 6);
    });
    socket.on("l6:autonomy_updated", (d: { compositeScore: number }) => {
      addLog("info", `  [L6] CAMS updated: ${d.compositeScore}/100`, 6);
    });

    return () => {
      [
        "orchestration:created", "orchestration:started", "orchestration:layer_start",
        "orchestration:layer_complete", "orchestration:layer_error", "orchestration:audit",
        "orchestration:complete", "orchestration:aborted", "orchestration:error",
        "l4:phase", "l4:finding_raw", "l4:solver_finding", "l4:error",
        "l5:verified", "l5:rejected",
        "l6:report_generated", "l6:autonomy_updated",
      ].forEach(evt => socket.off(evt));
    };
  }, [socket]);

  // ── Actions ────────────────────────────────────────────────────────────────

  const handleRun = () => {
    if (!selectedProgram) return toast.error("Select a program");
    if (!targetUrl) return toast.error("Enter target URL");

    // Reset state
    setLayers(prev => prev.map(l => ({ ...l, phase: "pending", startedAt: undefined, completedAt: undefined, durationMs: undefined, error: undefined })));
    setLogs([]);
    setFindings(0);
    setVerified(0);
    setPhase("starting");
    setLoading(true);
    setOrchestrationId(null);

    socket.emit("orchestration:run", {
      programId: selectedProgram,
      targetUrl,
      mode: huntMode,
      goal: goal || undefined,
      maxIterations,
      budget: { maxRequests, maxTime: 3600 },
    });
  };

  const handleStop = () => {
    if (!orchestrationId) return;
    axios.post(`/api/orchestration/stop/${orchestrationId}`).catch(() => {});
    setPhase("aborting");
    setLoading(false);
    toast("Stop signal sent");
  };

  const isRunning = loading || (phase !== "idle" && phase !== "complete" && phase !== "aborted" && phase !== "error");

  // ── Render ─────────────────────────────────────────────────────────────────

  return (
    <div className="h-full flex flex-col bg-hack-bg font-mono text-hack-text overflow-hidden">
      {/* Header */}
      <div className="flex items-center gap-3 px-4 py-2 border-b border-hack-border bg-hack-surface flex-shrink-0">
        <Layers className="w-4 h-4 text-hack-accent" strokeWidth={1.5} />
        <span className="text-sm font-mono text-hack-accent glow-green tracking-widest">
          6-LAYER ORCHESTRATION & GOVERNANCE MODEL
        </span>
        <div className="ml-auto flex items-center gap-3 text-[10px] text-hack-dim">
          {isRunning && (
            <span className="flex items-center gap-1 text-hack-accent">
              <RefreshCw className="w-3 h-3 animate-spin" />
              {phase.toUpperCase()}
            </span>
          )}
          {phase === "complete" && (
            <span className="flex items-center gap-1 text-hack-green">
              <CheckCircle2 className="w-3 h-3" /> COMPLETE
            </span>
          )}
          {(phase === "aborted" || phase === "error") && (
            <span className="flex items-center gap-1 text-hack-red">
              <XCircle className="w-3 h-3" /> {phase.toUpperCase()}
            </span>
          )}
          {findings > 0 && (
            <span className="text-hack-yellow">{findings} raw · {verified} verified</span>
          )}
        </div>
      </div>

      <div className="flex-1 flex overflow-hidden">
        {/* Left: Config Panel */}
        <div className="w-64 flex-shrink-0 border-r border-hack-border bg-hack-surface flex flex-col overflow-y-auto">
          <div className="p-3 border-b border-hack-border">
            <div className="text-[10px] text-hack-dim tracking-widest mb-3">HUNT CONFIGURATION</div>

            <label className="hack-label">Program</label>
            <select
              className="hack-input w-full mb-2"
              value={selectedProgram}
              onChange={e => setSelectedProgram(Number(e.target.value))}
              disabled={isRunning}
            >
              <option value={0}>-- Select Program --</option>
              {programs.map((p) => (
                <option key={String(p.id)} value={String(p.id)}>
                  {String(p.name)} ({String(p.platform)})
                </option>
              ))}
            </select>

            <label className="hack-label">Target URL</label>
            <input
              type="url"
              className="hack-input w-full mb-2"
              placeholder="https://target.example.com"
              value={targetUrl}
              onChange={e => setTargetUrl(e.target.value)}
              disabled={isRunning}
            />

            <label className="hack-label">Mode</label>
            <div className="flex gap-1 mb-2">
              {(["forward", "backward"] as const).map(m => (
                <button
                  key={m}
                  onClick={() => setHuntMode(m)}
                  disabled={isRunning}
                  className={`flex-1 px-2 py-1 text-[10px] border rounded transition-all ${
                    huntMode === m
                      ? "bg-hack-accent/10 border-hack-accent text-hack-accent"
                      : "border-hack-border text-hack-dim hover:border-hack-text"
                  }`}
                >
                  {m.toUpperCase()}
                </button>
              ))}
            </div>

            {huntMode === "backward" && (
              <>
                <label className="hack-label">Goal</label>
                <textarea
                  className="hack-input w-full mb-2 resize-none"
                  rows={2}
                  placeholder="e.g. Achieve RCE on admin panel"
                  value={goal}
                  onChange={e => setGoal(e.target.value)}
                  disabled={isRunning}
                />
              </>
            )}

            <label className="hack-label">Max Iterations</label>
            <input
              type="number"
              className="hack-input w-full mb-2"
              min={1} max={50}
              value={maxIterations}
              onChange={e => setMaxIterations(Number(e.target.value))}
              disabled={isRunning}
            />

            <label className="hack-label">Max Requests</label>
            <input
              type="number"
              className="hack-input w-full mb-3"
              min={10} max={50000} step={100}
              value={maxRequests}
              onChange={e => setMaxRequests(Number(e.target.value))}
              disabled={isRunning}
            />

            {!isRunning ? (
              <button
                onClick={handleRun}
                disabled={!selectedProgram || !targetUrl}
                className="hack-btn-primary w-full flex items-center justify-center gap-2 py-2 text-xs rounded transition-all disabled:opacity-40 disabled:cursor-not-allowed"
              >
                <Play className="w-3 h-3" />
                LAUNCH ORCHESTRATION
              </button>
            ) : (
              <button
                onClick={handleStop}
                className="hack-btn-danger w-full flex items-center justify-center gap-2 py-2 text-xs rounded"
              >
                <Square className="w-3 h-3" />
                ABORT
              </button>
            )}
          </div>

          {/* Layer legend */}
          <div className="p-3">
            <div className="text-[10px] text-hack-dim tracking-widest mb-2">LAYER MODEL</div>
            {layerMeta.map((lm) => (
              <div key={String(lm.layer)} className="mb-1.5">
                <div className="flex items-center gap-1 text-[10px]">
                  <span className="text-hack-dim">L{String(lm.layer)}</span>
                  {lm.gate && <Lock className="w-2.5 h-2.5 text-hack-red" />}
                  <span className="text-hack-text">{String(lm.name)}</span>
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Center: Layer Status Grid */}
        <div className="flex-1 flex flex-col overflow-hidden">
          <div className="flex-1 overflow-y-auto p-3 space-y-2">
            {layers.map((layer, idx) => {
              const Icon = LAYER_ICONS[idx];
              const colorClass = LAYER_COLORS[idx];
              const isActive = layer.phase === "running";
              const isPassed = layer.phase === "passed";
              const isFailed = layer.phase === "failed";

              return (
                <div
                  key={layer.layer}
                  className={`border rounded p-3 transition-all duration-300 ${
                    isActive ? `${colorClass} shadow-lg` :
                    isPassed ? "border-hack-green/30 bg-hack-green/5" :
                    isFailed ? "border-hack-red/30 bg-hack-red/5" :
                    "border-hack-border bg-hack-surface"
                  }`}
                >
                  <div className="flex items-center gap-3">
                    {/* Layer number */}
                    <div className={`w-7 h-7 rounded flex items-center justify-center flex-shrink-0 border ${
                      isActive ? colorClass :
                      isPassed ? "border-hack-green/40 text-hack-green bg-hack-green/10" :
                      isFailed ? "border-hack-red/40 text-hack-red bg-hack-red/10" :
                      "border-hack-border text-hack-dim bg-hack-muted"
                    }`}>
                      <Icon className="w-3.5 h-3.5" strokeWidth={1.5} />
                    </div>

                    {/* Layer info */}
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2">
                        <span className="text-[10px] text-hack-dim">L{layer.layer}</span>
                        <span className={`text-xs font-semibold tracking-wide ${
                          isActive ? "text-hack-text" :
                          isPassed ? "text-hack-green" :
                          isFailed ? "text-hack-red" :
                          "text-hack-dim"
                        }`}>
                          {layer.name}
                        </span>
                        {isActive && <RefreshCw className="w-3 h-3 text-hack-accent animate-spin" />}
                        {isPassed && <CheckCircle2 className="w-3 h-3 text-hack-green" />}
                        {isFailed && <XCircle className="w-3 h-3 text-hack-red" />}
                      </div>
                      <div className="text-[10px] text-hack-dim mt-0.5 truncate">
                        {LAYER_DESC[idx]}
                      </div>
                      {layer.error && (
                        <div className="text-[10px] text-hack-red mt-0.5 flex items-center gap-1">
                          <AlertTriangle className="w-3 h-3 flex-shrink-0" />
                          {layer.error.slice(0, 80)}
                        </div>
                      )}
                    </div>

                    {/* Status badge */}
                    <div className="flex-shrink-0 text-right">
                      <div className={`text-[10px] px-2 py-0.5 rounded border font-mono ${
                        isActive ? "text-hack-accent border-hack-accent/30 bg-hack-accent/10 animate-pulse" :
                        isPassed ? "text-hack-green border-hack-green/30 bg-hack-green/10" :
                        isFailed ? "text-hack-red border-hack-red/30 bg-hack-red/10" :
                        "text-hack-dim border-hack-border bg-hack-muted"
                      }`}>
                        {layer.phase.toUpperCase()}
                      </div>
                      {layer.durationMs != null && (
                        <div className="text-[9px] text-hack-dim mt-1 flex items-center justify-end gap-1">
                          <Clock className="w-2.5 h-2.5" />
                          {layer.durationMs < 1000 ? `${layer.durationMs}ms` : `${(layer.durationMs / 1000).toFixed(1)}s`}
                        </div>
                      )}
                    </div>
                  </div>

                  {/* Progress bar for active layer */}
                  {isActive && (
                    <div className="mt-2 h-0.5 bg-hack-muted rounded overflow-hidden">
                      <div className="h-full bg-hack-accent animate-pulse w-full" />
                    </div>
                  )}
                </div>
              );
            })}
          </div>

          {/* Bottom stats bar */}
          {(findings > 0 || phase === "complete") && (
            <div className="border-t border-hack-border bg-hack-surface p-2 flex items-center gap-6 text-[10px] flex-shrink-0">
              <div className="flex items-center gap-1.5 text-hack-yellow">
                <Zap className="w-3 h-3" />
                <span>{findings} raw findings</span>
              </div>
              <div className="flex items-center gap-1.5 text-hack-green">
                <CheckCircle2 className="w-3 h-3" />
                <span>{verified} verified</span>
              </div>
              <div className="flex items-center gap-1.5 text-hack-dim">
                <Shield className="w-3 h-3" />
                <span>
                  {findings > 0 ? Math.round((verified / findings) * 100) : 0}% verification rate
                </span>
              </div>
              {orchestrationId && (
                <div className="ml-auto text-hack-dim">
                  ID: {orchestrationId.slice(0, 8)}…
                </div>
              )}
            </div>
          )}
        </div>

        {/* Right: Audit Log */}
        <div className="w-72 flex-shrink-0 border-l border-hack-border bg-hack-bg flex flex-col overflow-hidden">
          <div className="flex items-center gap-2 px-3 py-2 border-b border-hack-border bg-hack-surface flex-shrink-0">
            <FileText className="w-3 h-3 text-hack-dim" strokeWidth={1.5} />
            <span className="text-[10px] text-hack-dim tracking-widest">AUDIT LOG</span>
            <span className="ml-auto text-[9px] text-hack-dim">{logs.length} entries</span>
          </div>

          <div
            ref={logRef}
            className="flex-1 overflow-y-auto p-2 space-y-0.5"
          >
            {logs.length === 0 ? (
              <div className="text-[10px] text-hack-dim text-center mt-6 opacity-60">
                Launch orchestration to see live audit trail
              </div>
            ) : (
              logs.map((log, i) => (
                <div key={i} className="flex items-start gap-1.5 text-[9px] font-mono leading-tight">
                  <span className="text-hack-dim flex-shrink-0">{log.ts}</span>
                  {log.layer && (
                    <span className={`flex-shrink-0 px-1 rounded ${
                      LAYER_COLORS[log.layer - 1].split(" ")[0]
                    }`}>
                      L{log.layer}
                    </span>
                  )}
                  <span className={
                    log.type === "success" ? "text-hack-green" :
                    log.type === "error" ? "text-hack-red" :
                    log.type === "warning" ? "text-hack-yellow" :
                    log.type === "finding" ? "text-hack-orange" :
                    log.type === "audit" ? "text-hack-blue" :
                    "text-hack-dim"
                  }>
                    {log.message}
                  </span>
                </div>
              ))
            )}
          </div>

          {/* Quick-clear log */}
          {logs.length > 0 && (
            <div className="border-t border-hack-border p-1.5 flex-shrink-0">
              <button
                onClick={() => setLogs([])}
                className="text-[9px] text-hack-dim hover:text-hack-text w-full text-center"
              >
                CLEAR LOG
              </button>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
