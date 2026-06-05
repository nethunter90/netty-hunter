import { useState, useEffect } from "react";
import {
  Terminal, Play, Square, Eye, Brain, Target, RefreshCw, CheckCircle2,
} from "lucide-react";
import { hunterAPI, bountyAPI } from "../lib/api";
import { getSocket } from "../lib/socket";
import toast from "react-hot-toast";
import { LiveActivityFeed, ActivityEvent } from "../components/LiveActivityFeed";
import { EgressPoolPanel } from "../components/hunt/EgressPoolPanel";

interface ActiveSession {
  sessionUuid: string;
  targetUrl: string;
  status: "running" | "complete" | "error";
  phase: string;
  iteration: number;
  findings: number;
}

const PHASE_ICONS: Record<string, React.ReactNode> = {
  observe:     <Eye className="w-3 h-3 text-hack-cyan" />,
  hypothesize: <Brain className="w-3 h-3 text-hack-purple" />,
  probe:       <Target className="w-3 h-3 text-hack-orange" />,
  update:      <RefreshCw className="w-3 h-3 text-hack-blue" />,
  complete:    <CheckCircle2 className="w-3 h-3 text-hack-accent" />,
};

function ts(): string {
  return new Date().toISOString().slice(11, 23);
}

export default function HuntConsole() {
  const [programs, setPrograms] = useState<Record<string, unknown>[]>([]);
  const [selectedProgram, setSelectedProgram] = useState<number>(0);
  const [targetUrl, setTargetUrl] = useState("");
  const [huntMode, setHuntMode] = useState<"forward" | "backward">("forward");
  const [goal, setGoal] = useState("");
  const [maxIterations, setMaxIterations] = useState(10);
  const [activeSessions, setActiveSessions] = useState<ActiveSession[]>([]);
  const [activityEvents, setActivityEvents] = useState<ActivityEvent[]>([]);
  const [hypStats, setHypStats] = useState({ pending: 0, probing: 0, confirmed: 0, rejected: 0 });
  const [loading, setLoading] = useState(false);
  const [templates, setTemplates] = useState<Record<string, unknown>[]>([]);
  const [selectedTemplate, setSelectedTemplate] = useState<string>("");

  const socket = getSocket();

  function push(ev: ActivityEvent) {
    // Cap retained events (~300) so long hunts don't grow state unbounded;
    // the feed only displays the last 150 anyway.
    setActivityEvents(prev => [...prev.slice(-299), ev]);
  }

  useEffect(() => {
    bountyAPI.getPrograms().then(r => setPrograms(r.data || []));
    bountyAPI.getHuntTemplates().then(r => setTemplates(r.data || []));
  }, []);

  useEffect(() => {
    socket.on("hunt:started", (_data: any) => {
      push({ type: "phase", ts: ts(), phase: "observe", iteration: 0 });
    });

    // Replayed when subscribing to an already-running hunt
    socket.on("hunt:state", (data: any) => {
      const state = data.state ?? data;
      if (state?.phase) {
        push({ type: "phase", ts: ts(), phase: String(state.phase), iteration: Number(state.iteration ?? 0) });
      }
    });

    socket.on("hunt:phase", (data: any) => {
      const phase = String(data.phase || "observe");
      const iteration = Number(data.iteration || 0);
      push({ type: "phase", ts: ts(), phase, iteration });
      setActiveSessions(prev => prev.map(s =>
        s.sessionUuid === String(data.sessionUuid || "")
          ? { ...s, phase, iteration }
          : s
      ));
    });

    socket.on("hunt:observations", (_data: any) => {
      // observations are context — no explicit event row needed
    });

    socket.on("hunt:hypotheses", (data: any) => {
      const hyps: any[] = data.hypotheses ?? [];
      hyps.forEach(h => {
        push({
          type: "hypothesis",
          ts: ts(),
          id: h.id ?? String(Math.random()),
          vulnClass: h.vulnClass ?? "unknown",
          reasoning: h.reasoning ?? h.evidence?.join("; ") ?? "",
          confidence: h.confidence ?? 0,
          modelSource: h.modelSource,
        });
      });
      setHypStats(s => ({ ...s, pending: s.pending + hyps.length }));
    });

    socket.on("hunt:probing", (data: any) => {
      push({
        type: "probe_start",
        ts: ts(),
        hypothesisId: String(data.hypothesisId || ""),
        vulnClass: String(data.vulnClass || ""),
      });
      setHypStats(s => ({ ...s, pending: Math.max(0, s.pending - 1), probing: s.probing + 1 }));
    });

    socket.on("hunt:probe_result", (data: any) => {
      const r = data.result ?? data;
      push({
        type: "probe_result",
        ts: ts(),
        hypothesisId: String(data.hypothesisId || ""),
        tool: String(r.tool ?? "unknown"),
        success: !!r.success,
        output: String(r.output ?? r.parsed?.raw ?? ""),
        durationMs: Number(r.duration ?? 0),
        proxyId: data.proxyId ? String(data.proxyId) : undefined,
      });
    });

    socket.on("hunt:finding_confirmed", (data: any) => {
      const f = data.finding ?? data;
      const h = f.hypothesis ?? {};
      push({
        type: "finding",
        ts: ts(),
        vulnClass: h.vulnClass ?? "unknown",
        severity: f.severity ?? "medium",
        confidence: h.confidence ?? 0,
        payload: f.exploitPayload ?? h.evidence?.join("; "),
      });
      setActiveSessions(prev => prev.map(s => ({ ...s, findings: s.findings + 1 })));
      setHypStats(s => ({ ...s, probing: Math.max(0, s.probing - 1), confirmed: s.confirmed + 1 }));
      toast.success(`Finding: ${h.vulnClass ?? "unknown"}`);
    });

    socket.on("hunt:update", (data: any) => {
      // Sync counts from server at the end of each update phase
      const pending = Number(data.pendingHypotheses ?? 0);
      const rejected = Number(data.rejectedHypotheses ?? 0);
      setHypStats(s => ({ ...s, pending, rejected }));
    });

    socket.on("hunt:complete", (data: any) => {
      push({
        type: "complete",
        ts: ts(),
        findings: Number(data.findings ?? 0),
        iterations: Number(data.iterations ?? 0),
      });
      setActiveSessions(prev => prev.map(s =>
        s.sessionUuid === String(data.sessionId || "") ? { ...s, status: "complete" } : s
      ));
    });

    socket.on("hunt:error", (data: any) => {
      push({ type: "error", ts: ts(), message: String(data.error || "Unknown error") });
    });

    socket.on("solver:started", (data: any) => {
      push({ type: "probe_start", ts: ts(), hypothesisId: "solver", vulnClass: String(data.vulnClass || "") });
    });

    socket.on("solver:complete", (data: any) => {
      push({
        type: "probe_result",
        ts: ts(),
        hypothesisId: "solver",
        tool: "solver",
        success: Number(data.confidence ?? 0) > 0.5,
        output: `confidence=${Number(data.confidence ?? 0).toFixed(2)}`,
        durationMs: 0,
      });
    });

    socket.on("solver:finding", (data: any) => {
      const r = data.result ?? data;
      push({ type: "solver_finding", ts: ts(), vulnClass: String(r.vulnClass ?? "unknown") });
      setActiveSessions(prev => prev.map(s => ({ ...s, findings: s.findings + 1 })));
    });

    socket.on("hunt:cve_seeded", (data: any) => {
      push({
        type: "cve_seeded",
        ts: ts(),
        tech: String(data.tech || ""),
        cveIds: Array.isArray(data.cveIds) ? (data.cveIds as unknown[]).map(String) : [],
        maxCvss: Number(data.maxCvss || 0),
      });
    });

    socket.on("hunt:graphql_schema", (data: any) => {
      push({
        type: "graphql_schema",
        ts: ts(),
        endpoint: String(data.endpoint || ""),
        typeCount: Number(data.typeCount || 0),
        injectableCount: Number(data.injectableCount || 0),
      });
    });

    socket.on("hunt:oob_hit", (data: any) => {
      push({
        type: "oob_hit",
        ts: ts(),
        beaconId: String(data.beaconId || ""),
        ip: String(data.ip || "unknown"),
      });
    });

    socket.on("oob:hit", (data: any) => {
      push({
        type: "oob_hit",
        ts: ts(),
        beaconId: String(data.beaconId || ""),
        ip: String(data.ip || "unknown"),
      });
    });

    socket.on("l5:public_duplicate", (data: any) => {
      push({
        type: "public_duplicate",
        ts: ts(),
        vulnClass: String(data.vulnClass ?? "unknown"),
        platform: String(data.platform ?? "unknown"),
        reportUrl: data.reportUrl,
        title: data.title,
        warn: !!data.warn,
      });
    });

    socket.on("hunt:ssrf_pivot", (data: any) => {
      push({
        type: "ssrf_pivot",
        ts: ts(),
        reachable: Array.isArray(data.reachable) ? (data.reachable as unknown[]).map(String) : [],
        cloudMeta: !!data.cloudMeta,
        newHypotheses: Number(data.newHypotheses || 0),
      });
    });

    socket.on("hunt:changes_detected", (data: any) => {
      push({
        type: "changes_detected",
        ts: ts(),
        newEndpoints: Array.isArray(data.newEndpoints) ? (data.newEndpoints as unknown[]).map(String) : [],
        changed: Number(data.changed || 0),
      });
    });

    socket.on("l5:report_submitted", (data: any) => {
      push({
        type: "report_submitted",
        ts: ts(),
        platform: String(data.platform || ""),
        reportId: data.reportId ? String(data.reportId) : undefined,
        reportUrl: data.reportUrl ? String(data.reportUrl) : undefined,
      });
    });

    socket.on("hunt:secrets_found", (data: any) => {
      push({ type: "secrets_found", ts: ts(), count: Number(data.count || 0), types: Array.isArray(data.types) ? data.types.map(String) : [] });
    });
    socket.on("hunt:ws_vulns", (data: any) => {
      push({ type: "ws_vulns", ts: ts(), count: Number(data.count || 0), endpoints: Array.isArray(data.endpoints) ? data.endpoints.map(String) : [], issues: Array.isArray(data.issues) ? data.issues.map(String) : [] });
    });
    socket.on("hunt:bucket_exposed", (data: any) => {
      push({ type: "bucket_exposed", ts: ts(), buckets: Array.isArray(data.buckets) ? data.buckets : [] });
    });
    socket.on("hunt:proto_pollution", (data: any) => {
      push({ type: "proto_pollution", ts: ts(), count: Number(data.count || 0), reflected: Boolean(data.reflected) });
    });
    socket.on("hunt:race_condition", (data: any) => {
      push({ type: "race_condition", ts: ts(), count: Number(data.count || 0), endpoints: Array.isArray(data.endpoints) ? data.endpoints.map(String) : [] });
    });
    socket.on("hunt:tech_payloads", (data: any) => {
      push({ type: "tech_payloads", ts: ts(), techs: Array.isArray(data.techs) ? data.techs.map(String) : [], payloadCount: Number(data.payloadCount || 0) });
    });
    socket.on("hunt:params_discovered", (data: any) => {
      push({ type: "params_discovered", ts: ts(), count: Number(data.count || 0), params: Array.isArray(data.params) ? data.params.map(String) : [] });
    });
    socket.on("hunt:oauth_vulns", (data: any) => {
      push({ type: "oauth_vulns", ts: ts(), count: Number(data.count || 0), issues: Array.isArray(data.issues) ? data.issues.map(String) : [] });
    });
    socket.on("hunt:mass_assignment", (data: any) => {
      push({ type: "mass_assignment", ts: ts(), count: Number(data.count || 0), endpoints: Array.isArray(data.endpoints) ? data.endpoints.map(String) : [] });
    });
    socket.on("hunt:business_logic", (data: any) => {
      push({ type: "business_logic", ts: ts(), count: Number(data.count || 0), types: Array.isArray(data.types) ? data.types.map(String) : [] });
    });
    socket.on("hunt:2fa_bypass", (data: any) => {
      push({ type: "two_fa_bypass", ts: ts(), count: Number(data.count || 0), techniques: Array.isArray(data.techniques) ? data.techniques.map(String) : [] });
    });
    socket.on("hunt:jwt_vulns", (data: any) => {
      push({ type: "jwt_vulns", ts: ts(), count: Number(data.count || 0), techniques: Array.isArray(data.techniques) ? data.techniques.map(String) : [] });
    });
    socket.on("hunt:open_redirect", (data: any) => {
      push({ type: "open_redirect", ts: ts(), count: Number(data.count || 0), chained: Number(data.chained || 0) });
    });
    socket.on("hunt:xxe_found", (data: any) => {
      push({ type: "xxe_found", ts: ts(), count: Number(data.count || 0), oobConfirmed: Boolean(data.oobConfirmed) });
    });
    socket.on("hunt:zap_scan", (data: any) => {
      push({ type: "zap_scan", ts: ts(), alertCount: Number(data.alertCount || 0), hypothesesSeeded: Number(data.hypothesesSeeded || 0), endpointsDiscovered: Number(data.endpointsDiscovered || 0), duration: Number(data.duration || 0) });
    });

    socket.on("hunt:ai_reasoning", (data: any) => {
      push({
        type: "ai_reasoning",
        ts: ts(),
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
        "hunt:started", "hunt:phase", "hunt:observations", "hunt:hypotheses",
        "hunt:probing", "hunt:probe_result", "hunt:finding_confirmed", "hunt:update",
        "hunt:complete", "hunt:error", "solver:started", "solver:complete", "solver:finding",
        "hunt:cve_seeded", "l5:public_duplicate",
        "hunt:graphql_schema", "hunt:oob_hit", "oob:hit",
        "hunt:ssrf_pivot", "hunt:changes_detected", "l5:report_submitted",
        "hunt:secrets_found", "hunt:ws_vulns", "hunt:bucket_exposed",
        "hunt:proto_pollution", "hunt:race_condition",
        "hunt:tech_payloads", "hunt:params_discovered", "hunt:oauth_vulns",
        "hunt:mass_assignment", "hunt:business_logic", "hunt:2fa_bypass",
        "hunt:jwt_vulns", "hunt:open_redirect", "hunt:xxe_found", "hunt:zap_scan",
        "hunt:ai_reasoning", "egress:route_changed", "hunt:state",
      ].forEach(e => socket.off(e));
    };
  }, [socket]);

  const startHunt = async () => {
    if (!selectedProgram && selectedProgram !== -1) return toast.error("Select a program first");
    if (!targetUrl) return toast.error("Enter target URL");
    if (huntMode === "backward" && !goal) return toast.error("Enter hunt goal for backward mode");

    setLoading(true);
    setActivityEvents([]);
    setHypStats({ pending: 0, probing: 0, confirmed: 0, rejected: 0 });

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

      if (res.data.sessionUuid) {
        socket.emit("subscribe:hunt", { sessionUuid: res.data.sessionUuid });
      }
    } catch (err: unknown) {
      const error = err as { response?: { data?: { error?: string } } };
      toast.error(error.response?.data?.error || "Failed to start hunt");
      push({ type: "error", ts: ts(), message: `Failed to start: ${error.response?.data?.error}` });
    } finally {
      setLoading(false);
    }
  };

  const stopHunt = async (uuid: string) => {
    await hunterAPI.stopHunt(uuid).catch(() => {});
    setActiveSessions(prev => prev.filter(s => s.sessionUuid !== uuid));
  };

  const isRunning = activeSessions.some(s => s.status === "running");

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
        {/* Left: Config */}
        <div className="w-72 border-r border-hack-border flex flex-col overflow-hidden flex-shrink-0">
          <div className="p-3 space-y-3 overflow-y-auto flex-1">
            <div>
              <label className="hack-label">Target Program</label>
              <select
                className="hack-input w-full"
                value={selectedProgram}
                onChange={e => setSelectedProgram(parseInt(e.target.value))}
              >
                <option value={0}>-- Select Program --</option>
                <option value={-1}>★ Custom / Local Lab</option>
                {programs.map((p: any) => (
                  <option key={Number(p.id)} value={Number(p.id)}>{String(p.name)}</option>
                ))}
              </select>
              {selectedProgram === -1 && (
                <div className="text-[9px] text-hack-yellow font-mono mt-1">
                  Custom target — scope validation bypassed. For local labs, CTF, Juice Shop, etc.
                </div>
              )}
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
                {templates.map((t: any) => (
                  <option key={String(t.id)} value={String(t.id)}>{String(t.name)}</option>
                ))}
              </select>
              {selectedTemplate && (
                <div className="text-[9px] text-hack-dim mt-1 font-mono">
                  {String((templates.find((t: any) => String(t.id) === selectedTemplate) as any)?.description || "")}
                </div>
              )}
            </div>

            <div>
              <label className="hack-label">Max Iterations: {maxIterations}</label>
              <input type="range" min={1} max={50} value={maxIterations} onChange={e => setMaxIterations(parseInt(e.target.value))} className="w-full accent-hack-accent" />
            </div>

            <button
              onClick={startHunt}
              disabled={loading || (!selectedProgram && selectedProgram !== -1) || !targetUrl}
              className="hack-btn-primary w-full flex items-center justify-center gap-2 py-2.5 disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {loading
                ? <span className="w-3 h-3 border border-hack-bg border-t-transparent rounded-full animate-spin" />
                : <Play className="w-3.5 h-3.5" />}
              {loading ? "INITIALIZING..." : "LAUNCH HUNT"}
            </button>
          </div>

          {/* Active sessions */}
          {activeSessions.length > 0 && (
            <div className="border-t border-hack-border p-3 space-y-2 flex-shrink-0">
              <div className="text-[10px] text-hack-dim font-mono uppercase mb-2">Active Hunts</div>
              {activeSessions.map(session => (
                <div key={session.sessionUuid} className="hack-panel p-2 text-[10px] font-mono">
                  <div className="flex items-center justify-between mb-1">
                    <div className="flex items-center gap-1.5">
                      <span className={`status-dot ${session.status === "running" ? "status-running" : "status-complete"}`} />
                      <span className="text-hack-text truncate max-w-[140px]">{session.targetUrl}</span>
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

          <EgressPoolPanel socket={socket} />
        </div>

        {/* Right: Hypothesis Board + Live Activity Feed */}
        <div className="flex-1 flex flex-col overflow-hidden">
          {/* Hypothesis stats bar — always visible during/after a hunt */}
          {(isRunning || hypStats.confirmed > 0 || hypStats.rejected > 0) && (
            <div className="flex items-center gap-4 px-3 py-1.5 border-b border-hack-border bg-hack-surface flex-shrink-0 text-[9px] font-mono">
              <Brain className="w-3 h-3 text-hack-purple flex-shrink-0" />
              <span className="text-hack-dim tracking-widest uppercase">hypotheses</span>
              <div className="flex items-center gap-3 ml-2">
                <span className="flex items-center gap-1">
                  <span className="w-1.5 h-1.5 rounded-full bg-hack-dim inline-block" />
                  <span className="text-hack-dim">{hypStats.pending} pending</span>
                </span>
                <span className="flex items-center gap-1">
                  <span className="w-1.5 h-1.5 rounded-full bg-hack-orange inline-block animate-pulse" />
                  <span className="text-hack-orange">{hypStats.probing} probing</span>
                </span>
                <span className="flex items-center gap-1">
                  <span className="w-1.5 h-1.5 rounded-full bg-hack-accent inline-block" />
                  <span className="text-hack-accent">{hypStats.confirmed} confirmed</span>
                </span>
                <span className="flex items-center gap-1">
                  <span className="w-1.5 h-1.5 rounded-full bg-hack-red inline-block" />
                  <span className="text-hack-red">{hypStats.rejected} rejected</span>
                </span>
              </div>
            </div>
          )}
          <div className="flex-1 overflow-hidden">
            <LiveActivityFeed
              events={activityEvents}
              isRunning={isRunning}
              title="hunt-engine — /bin/hunter"
            />
          </div>
        </div>
      </div>
    </div>
  );
}
