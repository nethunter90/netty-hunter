import { useState, useEffect } from "react";
import {
  Layers, Play, Square, Shield, Target, Brain, Cpu, CheckCircle2,
  XCircle, Clock, AlertTriangle, BarChart3, Zap, RefreshCw, Lock, ChevronDown, ChevronUp,
  Wrench,
} from "lucide-react";
import { bountyAPI, hunterAPI } from "../lib/api";
import { getSocket } from "../lib/socket";
import toast from "react-hot-toast";
import axios from "axios";
import { LiveActivityFeed } from "../components/LiveActivityFeed";
import { orchestrationStore, useOrchestrationStore } from "../lib/orchestrationStore";

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
  const [authCookie, setAuthCookie] = useState("");
  const [authBearer, setAuthBearer] = useState("");

  type ToolStatus = { name: string; binary: string; tier: "critical" | "important" | "optional"; available: boolean };
  const [toolStatus, setToolStatus] = useState<ToolStatus[]>([]);
  const [toolStatusExpanded, setToolStatusExpanded] = useState(false);
  const [toolStatusLoading, setToolStatusLoading] = useState(false);

  const [layerMeta, setLayerMeta] = useState<Record<string, unknown>[]>([]);
  const [campaigns, setCampaigns] = useState<Array<{id: number; createdAt: string; status: string; findingsTotal?: number; targetUrl?: string}>>([]);
  const [showTimeline, setShowTimeline] = useState(false);

  // Live orchestration state is owned by orchestrationStore and fed by the
  // always-mounted event bridge (orchestrationEventBridge.ts). This panel is a pure
  // reader — leaving and returning restores the full prior execution stream.
  const {
    orchestrationId, layers, phase, findings, verified, loading,
    launching, stopping, externalHunt, activityEvents,
  } = useOrchestrationStore();

  const socket = getSocket();

  // ── Init ───────────────────────────────────────────────────────────────────

  useEffect(() => {
    bountyAPI.getPrograms().then(r => setPrograms(r.data || []));
    axios.get("/api/orchestration/layers").then(r => setLayerMeta(r.data?.layers || [])).catch(() => {});
    hunterAPI.getCampaigns().then(r => setCampaigns((r.data || []).slice(0, 20))).catch(() => {});

    // Tool preflight
    setToolStatusLoading(true);
    axios.get("/api/hunt/tools/preflight")
      .then(r => setToolStatus(r.data?.tools || []))
      .catch(() => {})
      .finally(() => setToolStatusLoading(false));

    // B3: check for a hunt started from the Hunt Console panel so the launch button
    // is disabled and a banner is shown. Orchestration reconnect below handles the
    // orchestration-kind path; this catches kind==="hunt".
    hunterAPI.getStatus().then((r: { data: { running: boolean; hunt: { id: string; kind: string; targetUrl: string } | null } }) => {
      if (r.data.running && r.data.hunt?.kind === "hunt") {
        orchestrationStore.setExternalHunt(r.data.hunt);
      }
    }).catch(() => {});

    // Reconnect to a running orchestration ONLY on a fresh load (store empty). On
    // panel navigation the always-mounted bridge already holds the live state +
    // full execution stream, so we must not re-hydrate (it would be stale/dup).
    if (!orchestrationStore.getSnapshot().orchestrationId) {
      axios.get("/api/orchestration").then(r => {
        const liveList: Array<{ orchestrationId: string; state: any }> = r.data?.live || [];
        if (liveList.length === 0) return;
        const { orchestrationId: id, state } = liveList[0];
        orchestrationStore.setOrchestrationId(id);
        socket.emit("subscribe:orchestration", { orchestrationId: id });
        orchestrationStore.setPhase("running");
        orchestrationStore.setLoading(true);
        if (state?.findingsCount != null) orchestrationStore.setFindings(state.findingsCount);
        if (state?.verifiedCount != null) orchestrationStore.setVerified(state.verifiedCount);
        if (Array.isArray(state?.layers)) {
          orchestrationStore.updateLayers(prev => prev.map((l, i) => {
            const s = state.layers[i];
            return s ? { ...l, phase: s.phase, startedAt: s.startedAt, completedAt: s.completedAt, durationMs: s.durationMs, error: s.error } : l;
          }));
        }
        orchestrationStore.pushEvent({ type: "phase", ts: now(), phase: "reconnected", iteration: 0 });
      }).catch(() => {});
    }
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);


  // ── Actions ────────────────────────────────────────────────────────────────

  const handleRun = () => {
    if (!selectedProgram && selectedProgram !== -1) return toast.error("Select a program");
    if (!targetUrl) return toast.error("Enter target URL");

    // Reset live state for a fresh run (layers → pending, stream cleared, counts 0).
    orchestrationStore.clearForNewRun();
    // B1: do NOT set phase/loading yet — wait for orchestration:created confirmation.
    // If the server rejects (slot taken), orchestration:error will fire and we stay idle.
    orchestrationStore.setLaunching(true);

    const auth: Record<string, string> = {};
    if (authCookie.trim()) auth.cookie = authCookie.trim();
    if (authBearer.trim()) auth.bearerToken = authBearer.trim();

    socket.emit("orchestration:run", {
      programId: selectedProgram,
      targetUrl,
      mode: huntMode,
      goal: goal || undefined,
      maxIterations,
      budget: { maxRequests, maxTime: 3600 },
      auth: Object.keys(auth).length > 0 ? auth : undefined,
    });
  };

  const handleStop = () => {
    if (!orchestrationId) return;
    // B2: show "stopping" indicator but do NOT flip phase/loading — only the
    // orchestration:aborted socket event (from the actual engine halt) does that.
    orchestrationStore.setStopping(true);
    axios.post(`/api/orchestration/stop/${orchestrationId}`).catch(() => {
      orchestrationStore.setStopping(false);
      toast.error("Stop request failed");
    });
    toast("Stop signal sent");
  };

  const isRunning = launching || loading || (phase !== "idle" && phase !== "complete" && phase !== "aborted" && phase !== "error");

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

            {/* Tool preflight status */}
            {toolStatus.length > 0 && (() => {
              const available = toolStatus.filter(t => t.available).length;
              const missingCritical = toolStatus.filter(t => !t.available && t.tier === "critical");
              const allReady = missingCritical.length === 0;
              return (
                <div className="border-t border-hack-border/40 pt-3 mb-3">
                  <button
                    className="w-full flex items-center justify-between text-left"
                    onClick={() => setToolStatusExpanded(x => !x)}
                  >
                    <div className="flex items-center gap-1.5">
                      <Wrench className="w-3 h-3 text-hack-dim" />
                      <span className="text-[9px] text-hack-dim tracking-widest">TOOLS</span>
                      <span className={`text-[9px] font-mono px-1 rounded ${allReady ? "text-hack-accent" : "text-hack-yellow"}`}>
                        {available}/{toolStatus.length}
                      </span>
                      {!allReady && (
                        <span className="text-[8px] text-hack-red font-mono">
                          {missingCritical.length} critical missing
                        </span>
                      )}
                    </div>
                    {toolStatusExpanded
                      ? <ChevronUp className="w-3 h-3 text-hack-dim" />
                      : <ChevronDown className="w-3 h-3 text-hack-dim" />
                    }
                  </button>
                  {toolStatusExpanded && (
                    <div className="mt-2 grid grid-cols-2 gap-x-2 gap-y-0.5">
                      {toolStatus.map(t => (
                        <div key={t.name} className="flex items-center gap-1 text-[9px] font-mono">
                          <span className={`w-1.5 h-1.5 rounded-full flex-shrink-0 ${
                            t.available ? "bg-hack-accent" :
                            t.tier === "critical" ? "bg-hack-red" :
                            t.tier === "important" ? "bg-hack-yellow" :
                            "bg-hack-dim"
                          }`} />
                          <span className={t.available ? "text-hack-dim" : t.tier === "critical" ? "text-hack-red" : "text-hack-yellow"}>
                            {t.name}
                          </span>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              );
            })()}
            {toolStatusLoading && toolStatus.length === 0 && (
              <div className="text-[9px] text-hack-dim font-mono mb-3 flex items-center gap-1">
                <RefreshCw className="w-3 h-3 animate-spin" /> checking tools…
              </div>
            )}

            <div className="border-t border-hack-border/40 pt-3 mb-3">
              <div className="text-[9px] text-hack-dim tracking-widest mb-2">AUTH (OPTIONAL)</div>
              <label className="hack-label">Session Cookie</label>
              <input
                type="text"
                className="hack-input w-full mb-2 font-mono text-[10px]"
                placeholder="session=abc123; csrf=xyz"
                value={authCookie}
                onChange={e => setAuthCookie(e.target.value)}
                disabled={isRunning}
              />
              <label className="hack-label">Bearer Token</label>
              <input
                type="text"
                className="hack-input w-full mb-0 font-mono text-[10px]"
                placeholder="eyJhbGciOiJIUzI1NiJ9..."
                value={authBearer}
                onChange={e => setAuthBearer(e.target.value)}
                disabled={isRunning}
              />
            </div>

            {externalHunt && (
              <div className="text-[9px] font-mono text-hack-yellow bg-hack-yellow/5 border border-hack-yellow/20 rounded p-2 mb-2">
                <span className="text-hack-yellow/70">{externalHunt.kind.toUpperCase()} running:</span>{" "}
                {externalHunt.targetUrl.length > 28
                  ? externalHunt.targetUrl.slice(0, 28) + "…"
                  : externalHunt.targetUrl}
              </div>
            )}
            {!isRunning ? (
              <button
                onClick={handleRun}
                disabled={(!selectedProgram && selectedProgram !== -1) || !targetUrl || !!externalHunt}
                className="hack-btn-primary w-full flex items-center justify-center gap-2 py-2 text-xs rounded transition-all disabled:opacity-40 disabled:cursor-not-allowed"
              >
                <Play className="w-3 h-3" />
                LAUNCH ORCHESTRATION
              </button>
            ) : (
              <button
                onClick={handleStop}
                // B2: disable while launching (nothing to abort yet) or already stopping
                disabled={launching || stopping || !orchestrationId}
                className="hack-btn-danger w-full flex items-center justify-center gap-2 py-2 text-xs rounded disabled:opacity-50 disabled:cursor-not-allowed"
              >
                <Square className="w-3 h-3" />
                {launching ? "LAUNCHING..." : stopping ? "STOPPING..." : "ABORT"}
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
