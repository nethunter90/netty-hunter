import { useState, useEffect } from "react";
import {
  Layers, Play, Square, Shield, Target, Brain, Cpu, CheckCircle2,
  XCircle, Clock, AlertTriangle, BarChart3, Zap, RefreshCw, Lock, ChevronDown, ChevronUp,
} from "lucide-react";
import { bountyAPI, hunterAPI } from "../lib/api";
import { getSocket } from "../lib/socket";
import toast from "react-hot-toast";
import axios from "axios";
import { LiveActivityFeed, ActivityEvent } from "../components/LiveActivityFeed";

// ── Types ──────────────────────────────────────────────────────────────────────

interface LayerStatus {
  layer: number;
  name: string;
  phase: "pending" | "running" | "passed" | "failed" | "skipped";
  startedAt?: number;
  completedAt?: number;
  durationMs?: number;
  error?: string;
}

// ── Layer metadata ─────────────────────────────────────────────────────────────

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

// ── Helpers ────────────────────────────────────────────────────────────────────

function now(): string {
  return new Date().toISOString().slice(11, 23);
}

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
  const [loading, setLoading] = useState(false);
  const [layerMeta, setLayerMeta] = useState<Record<string, unknown>[]>([]);

  const [activityEvents, setActivityEvents] = useState<ActivityEvent[]>([]);
  const [campaigns, setCampaigns] = useState<Array<{id: number; createdAt: string; status: string; findingsTotal?: number; targetUrl?: string}>>([]);
  const [showTimeline, setShowTimeline] = useState(false);

  const socket = getSocket();

  function pushEvent(ev: ActivityEvent) {
    // Cap retained events (~300) so long orchestrations don't grow state unbounded.
    setActivityEvents(prev => [...prev.slice(-299), ev]);
  }

  // ── Init ───────────────────────────────────────────────────────────────────

  useEffect(() => {
    bountyAPI.getPrograms().then(r => setPrograms(r.data || []));
    axios.get("/api/orchestration/layers").then(r => setLayerMeta(r.data?.layers || [])).catch(() => {});
    hunterAPI.getCampaigns().then(r => setCampaigns((r.data || []).slice(0, 20))).catch(() => {});
  }, []);

  // ── Socket.IO wiring ───────────────────────────────────────────────────────

  useEffect(() => {
    socket.on("orchestration:created", ({ orchestrationId: id }: { orchestrationId: string }) => {
      setOrchestrationId(id);
      socket.emit("subscribe:orchestration", { orchestrationId: id });
    });

    socket.on("orchestration:started", () => {
      setPhase("running");
    });

    socket.on("orchestration:layer_start", (d: { layer: number; name: string }) => {
      setLayers(prev => prev.map(l =>
        l.layer === d.layer ? { ...l, phase: "running", startedAt: Date.now() } : l
      ));
      setPhase(`l${d.layer}`);
      pushEvent({ type: "layer_start", ts: now(), layer: d.layer, name: d.name });
    });

    socket.on("orchestration:layer_complete", (d: {
      layer: number; name: string; passed: boolean; durationMs: number;
    }) => {
      setLayers(prev => prev.map(l =>
        l.layer === d.layer ? { ...l, phase: d.passed ? "passed" : "failed", completedAt: Date.now(), durationMs: d.durationMs } : l
      ));
      pushEvent({ type: "layer_done", ts: now(), layer: d.layer, name: d.name, passed: d.passed, durationMs: d.durationMs });
    });

    socket.on("orchestration:layer_error", (d: { layer: number; name: string; error: string }) => {
      setLayers(prev => prev.map(l =>
        l.layer === d.layer ? { ...l, phase: "failed", error: d.error } : l
      ));
      pushEvent({ type: "error", ts: now(), message: `L${d.layer} ${d.name}: ${d.error}` });
    });

    socket.on("orchestration:complete", () => {
      setPhase("complete");
      setLoading(false);
      toast.success("Orchestration complete!");
    });

    socket.on("orchestration:aborted", (d: { reason: string }) => {
      setPhase("aborted");
      setLoading(false);
      pushEvent({ type: "error", ts: now(), message: `Aborted: ${d.reason}` });
      toast.error(`Aborted: ${d.reason}`);
    });

    socket.on("orchestration:error", (d: { error: string }) => {
      setPhase("error");
      setLoading(false);
      pushEvent({ type: "error", ts: now(), message: d.error });
      toast.error(`Orchestration error: ${d.error}`);
    });

    // ── L4 Execution Engine ────────────────────────────────────────────────

    socket.on("l4:phase", (d: { phase: string; iteration?: number }) => {
      pushEvent({ type: "phase", ts: now(), phase: d.phase, iteration: d.iteration ?? 0 });
    });

    socket.on("l4:hypotheses", (d: { count: number; hypotheses?: any[] }) => {
      const hyps: any[] = d.hypotheses ?? [];
      hyps.forEach(h => {
        pushEvent({
          type: "hypothesis",
          ts: now(),
          id: h.id ?? String(Math.random()),
          vulnClass: h.vulnClass ?? "unknown",
          reasoning: h.reasoning ?? h.evidence?.join("; ") ?? "",
          confidence: h.confidence ?? 0,
        });
      });
    });

    socket.on("l4:probing", (d: { hypothesisId: string; vulnClass: string }) => {
      pushEvent({ type: "probe_start", ts: now(), hypothesisId: d.hypothesisId, vulnClass: d.vulnClass });
    });

    socket.on("l4:probe_result", (d: { hypothesisId: string; result: any }) => {
      const r = d.result ?? {};
      pushEvent({
        type: "probe_result",
        ts: now(),
        hypothesisId: d.hypothesisId,
        tool: r.tool ?? "unknown",
        success: !!r.success,
        output: r.output ?? r.parsed?.raw ?? "",
        durationMs: r.duration ?? 0,
      });
    });

    socket.on("l4:finding_raw", (d: { finding?: any }) => {
      const f = d.finding ?? d;
      const h = f.hypothesis ?? {};
      setFindings(n => n + 1);
      pushEvent({
        type: "finding",
        ts: now(),
        vulnClass: h.vulnClass ?? "unknown",
        severity: f.severity ?? "medium",
        confidence: h.confidence ?? 0,
        payload: f.exploitPayload ?? h.evidence?.join("; "),
      });
    });

    socket.on("l4:solver_finding", (d: { result?: any }) => {
      const r = d.result ?? d;
      setFindings(n => n + 1);
      pushEvent({ type: "solver_finding", ts: now(), vulnClass: r.vulnClass ?? "unknown" });
    });

    socket.on("l4:error", (d: { error: string }) => {
      pushEvent({ type: "error", ts: now(), message: `[L4] ${d.error}` });
    });

    // ── L5 Verification ────────────────────────────────────────────────────

    socket.on("l5:verified", (d: { findingId: number; verdict: string }) => {
      setVerified(v => v + 1);
      pushEvent({ type: "verified", ts: now(), findingId: d.findingId, verdict: d.verdict });
    });

    socket.on("l5:rejected", (d: { findingId: number; verdict: string }) => {
      pushEvent({ type: "rejected", ts: now(), findingId: d.findingId, verdict: d.verdict });
    });

    socket.on("l5:public_duplicate", (d: any) => {
      pushEvent({
        type: "public_duplicate",
        ts: now(),
        vulnClass: d.vulnClass ?? "unknown",
        platform: d.platform ?? "unknown",
        reportUrl: d.reportUrl,
        title: d.title,
        warn: !!d.warn,
      });
    });

    // ── L6 Harvest ────────────────────────────────────────────────────────

    socket.on("l6:report_generated", (d: { findingId: number }) => {
      pushEvent({ type: "verified", ts: now(), findingId: d.findingId, verdict: "report generated" });
    });

    socket.on("l6:autonomy_updated", (_d: { compositeScore: number }) => {
      // no visual needed — kept for completeness
    });

    socket.on("hunt:ai_reasoning", (data: any) => {
      pushEvent({
        type: "ai_reasoning",
        ts: now(),
        task: String(data.task ?? "AI"),
        phase: data.phase as "thinking" | "complete" | "decision",
        context: data.context,
        promptPreview: String(data.promptPreview ?? ""),
        rawResponse: String(data.rawResponse ?? ""),
        summary: String(data.summary ?? ""),
        durationMs: Number(data.durationMs ?? 0),
        generatedCount: Number(data.generatedCount ?? 0),
      });
    });

    return () => {
      [
        "orchestration:created", "orchestration:started", "orchestration:layer_start",
        "orchestration:layer_complete", "orchestration:layer_error",
        "orchestration:complete", "orchestration:aborted", "orchestration:error",
        "l4:phase", "l4:hypotheses", "l4:probing", "l4:probe_result",
        "l4:finding_raw", "l4:solver_finding", "l4:error",
        "l5:verified", "l5:rejected", "l5:public_duplicate",
        "l6:report_generated", "l6:autonomy_updated",
        "hunt:ai_reasoning",
      ].forEach(evt => socket.off(evt));
    };
  }, [socket]);

  // ── Actions ────────────────────────────────────────────────────────────────

  const handleRun = () => {
    if (!selectedProgram && selectedProgram !== -1) return toast.error("Select a program");
    if (!targetUrl) return toast.error("Enter target URL");

    setLayers(prev => prev.map(l => ({ ...l, phase: "pending", startedAt: undefined, completedAt: undefined, durationMs: undefined, error: undefined })));
    setActivityEvents([]);
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
        <span className="text-sm font-mono text-hack-accent tracking-widest">
          6-LAYER ORCHESTRATION & GOVERNANCE MODEL
        </span>
        <button
          onClick={() => setShowTimeline(v => !v)}
          className="ml-auto hack-btn text-[10px] flex items-center gap-1"
          title="Toggle campaign timeline"
        >
          {showTimeline ? <ChevronUp className="w-3 h-3" /> : <ChevronDown className="w-3 h-3" />}
          TIMELINE
        </button>
        <div className="flex items-center gap-3 text-[10px] text-hack-dim">
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

      {/* Campaign Timeline */}
      {showTimeline && (
        <div className="border-b border-hack-border bg-hack-surface flex-shrink-0 max-h-48 overflow-y-auto terminal-scroll">
          <div className="px-4 py-2 border-b border-hack-border/50 flex items-center gap-2">
            <span className="text-[10px] font-mono text-hack-accent tracking-widest">CAMPAIGN TIMELINE</span>
            <span className="text-[9px] text-hack-dim font-mono">({campaigns.length} recent)</span>
          </div>
          {campaigns.length === 0 ? (
            <div className="px-4 py-3 text-[10px] text-hack-dim font-mono">No campaigns found.</div>
          ) : (
            <div className="divide-y divide-hack-border/30">
              {campaigns.map(c => {
                const statusColor =
                  c.status === "confirmed" || c.status === "complete" ? "text-hack-green border-hack-green/30 bg-hack-green/5" :
                  c.status === "failed" || c.status === "aborted" ? "text-hack-red border-hack-red/30 bg-hack-red/5" :
                  c.status === "running" ? "text-hack-accent border-hack-accent/30 bg-hack-accent/5" :
                  "text-hack-dim border-hack-border bg-hack-muted";
                const truncatedUrl = c.targetUrl ? (c.targetUrl.length > 40 ? c.targetUrl.slice(0, 40) + "…" : c.targetUrl) : "—";
                return (
                  <div key={c.id} className="px-4 py-1.5 flex items-center gap-3 text-[10px] font-mono hover:bg-hack-muted/20">
                    <span className="text-hack-dim w-16 flex-shrink-0">{new Date(c.createdAt).toISOString().slice(0, 10)}</span>
                    <span className={`px-1.5 py-0.5 rounded border text-[9px] flex-shrink-0 ${statusColor}`}>{c.status.toUpperCase()}</span>
                    {c.findingsTotal != null && (
                      <span className="text-hack-yellow flex-shrink-0">{c.findingsTotal} findings</span>
                    )}
                    <span className="text-hack-dim truncate">{truncatedUrl}</span>
                  </div>
                );
              })}
            </div>
          )}
        </div>
      )}

      <div className="flex-1 flex overflow-hidden">
        {/* Left: Config */}
        <div className="w-60 flex-shrink-0 border-r border-hack-border bg-hack-surface flex flex-col overflow-y-auto">
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
              <option value={-1}>★ Custom / Local Lab</option>
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
                disabled={(!selectedProgram && selectedProgram !== -1) || !targetUrl}
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
                  {!!(lm.gate) && <Lock className="w-2.5 h-2.5 text-hack-red" />}
                  <span className="text-hack-text">{String(lm.name)}</span>
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Center: Layer Status Grid */}
        <div className="w-80 flex-shrink-0 flex flex-col overflow-hidden border-r border-hack-border">
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
                    <div className={`w-7 h-7 rounded flex items-center justify-center flex-shrink-0 border ${
                      isActive ? colorClass :
                      isPassed ? "border-hack-green/40 text-hack-green bg-hack-green/10" :
                      isFailed ? "border-hack-red/40 text-hack-red bg-hack-red/10" :
                      "border-hack-border text-hack-dim bg-hack-muted"
                    }`}>
                      <Icon className="w-3.5 h-3.5" strokeWidth={1.5} />
                    </div>

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
                          {layer.error.slice(0, 60)}
                        </div>
                      )}
                    </div>

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

                  {isActive && (
                    <div className="mt-2 h-0.5 bg-hack-muted rounded overflow-hidden">
                      <div className="h-full bg-hack-accent animate-pulse w-full" />
                    </div>
                  )}
                </div>
              );
            })}
          </div>

          {/* Stats bar */}
          {(findings > 0 || phase === "complete") && (
            <div className="border-t border-hack-border bg-hack-surface p-2 flex items-center gap-4 text-[10px] flex-shrink-0">
              <div className="flex items-center gap-1.5 text-hack-yellow">
                <Zap className="w-3 h-3" />
                <span>{findings} raw</span>
              </div>
              <div className="flex items-center gap-1.5 text-hack-green">
                <CheckCircle2 className="w-3 h-3" />
                <span>{verified} verified</span>
              </div>
              <div className="flex items-center gap-1.5 text-hack-dim">
                <Shield className="w-3 h-3" />
                <span>{findings > 0 ? Math.round((verified / findings) * 100) : 0}%</span>
              </div>
              {orchestrationId && (
                <div className="ml-auto text-hack-dim">{orchestrationId.slice(0, 8)}…</div>
              )}
            </div>
          )}
        </div>

        {/* Right: Live Activity Feed */}
        <div className="flex-1 overflow-hidden">
          <LiveActivityFeed
            events={activityEvents}
            isRunning={isRunning}
            title="EXECUTION STREAM"
          />
        </div>
      </div>
    </div>
  );
}
