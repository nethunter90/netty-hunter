import React, { useState, useEffect, useCallback } from "react";
import {
  Crosshair, Play, Square, RefreshCw, ChevronRight,
  Shield, Brain, FileText, BarChart3, Eye, Zap,
  AlertTriangle, CheckCircle2, Clock, Plus, Terminal,
  Target, Activity, Network, Download, Cpu,
} from "lucide-react";
import { sessionAPI, hunterROI, bountyAPI } from "../lib/api";
import AttackPathVisualizer, { AttackPath, AttackStep, StepPhase, StepStatus } from "../components/AttackPathVisualizer";
import toast from "react-hot-toast";

// ── Types ──────────────────────────────────────────────────────────────────────

interface Session {
  id: string;
  sessionUuid?: string;
  target: string;
  status: "running" | "complete" | "error" | "paused";
  phase: string;
  iteration: number;
  findings: number;
  hypotheses: number;
  createdAt: number;
  campaignId?: number;
}

interface WAFData {
  detected: boolean;
  vendor: string;
  confidence: number;
  blockRate: number;
  evasionRanking?: Array<{ technique: string; successRate: number; attempts: number }>;
  temporal?: { pattern: string; peakHour: number; blockClusters: number };
}

interface ROIData {
  globalStats: Record<string, unknown>;
  thresholds: Record<string, unknown>;
}

type DetailTab = "overview" | "attack-path" | "waf" | "reports";

// ── Helpers ────────────────────────────────────────────────────────────────────

function hypothesesToAttackPath(session: Session, hypotheses: Record<string, unknown>[], findings: Record<string, unknown>[]): AttackPath {
  const findingMap = new Map(findings.map(f => [String((f as Record<string, unknown>).hypothesisId || ""), f]));

  const steps: AttackStep[] = hypotheses.map((h, i) => {
    const hyp = h as Record<string, unknown>;
    const isConfirmed = hyp.status === "confirmed";
    const isProbing = hyp.status === "probing";
    const isRejected = hyp.status === "rejected";
    const isPending = hyp.status === "pending";

    const status: StepStatus = isConfirmed ? "completed" : isProbing ? "active" : isRejected ? "failed" : "pending";
    const phase: StepPhase = isConfirmed ? "exploit" : isProbing ? "probe" : "hypothesis";

    const finding = findingMap.get(String(hyp.id || ""));

    return {
      id: String(hyp.id || i),
      step: i + 1,
      phase,
      status,
      title: String(hyp.vulnClass || "unknown").toUpperCase().replace(/_/g, " "),
      description: String(hyp.reasoning || "Hypothesis generated from anomaly observations"),
      vulnClass: String(hyp.vulnClass || ""),
      severity: finding ? (String((finding as Record<string, unknown>).severity || "info") as AttackStep["severity"]) : undefined,
      confidence: Number(hyp.confidence || 0),
      tools: hyp.probeTool ? [String(hyp.probeTool)] : undefined,
      target: String(hyp.targetUrl || session.target),
      evidence: finding ? JSON.stringify((finding as Record<string, unknown>).evidence, null, 2).slice(0, 500) : undefined,
    } satisfies AttackStep;
  });

  // Prepend recon step if we have observations
  const reconStep: AttackStep = {
    id: "recon-0",
    step: 0,
    phase: "recon",
    status: hypotheses.length > 0 ? "completed" : session.phase === "observe" ? "active" : "pending",
    title: "TARGET RECONNAISSANCE",
    description: `Fingerprinting ${session.target} — WAF detection, tech stack, attack surface mapping`,
    target: session.target,
  };

  const allSteps = [reconStep, ...steps];

  // Append verify step for confirmed findings
  const confirmedCount = findings.filter(f => (f as Record<string, unknown>).verificationStatus === "confirmed").length;
  if (findings.length > 0) {
    allSteps.push({
      id: "verify-final",
      step: allSteps.length,
      phase: "verify",
      status: confirmedCount > 0 ? "completed" : session.phase === "complete" ? "completed" : "pending",
      title: "VERIFICATION GATE",
      description: `4-layer anti-hallucination verification — ${confirmedCount}/${findings.length} findings confirmed`,
      confidence: findings.length > 0 ? confirmedCount / findings.length : 0,
    });
  }

  return {
    id: session.id,
    name: session.target.slice(0, 40),
    objective: `Autonomous vulnerability hunt on ${session.target}`,
    steps: allSteps,
    status: session.status === "running" ? "active" :
            session.status === "complete" ? "complete" :
            session.status === "error" ? "failed" : "paused",
    overallConfidence: findings.length > 0 ? confirmedCount / findings.length : 0,
  };
}

// ── Sub-components ─────────────────────────────────────────────────────────────

function SessionCard({ session, selected, onClick }: {
  session: Session;
  selected: boolean;
  onClick: () => void;
}) {
  const STATUS_COLOR: Record<string, string> = {
    running: "text-hack-accent border-hack-accent/30 bg-hack-accent/5",
    complete: "text-hack-green border-hack-green/30 bg-hack-green/5",
    error: "text-hack-red border-hack-red/30 bg-hack-red/5",
    paused: "text-hack-yellow border-hack-yellow/30 bg-hack-yellow/5",
  };
  const STATUS_DOT: Record<string, string> = {
    running: "bg-hack-accent animate-pulse",
    complete: "bg-hack-green",
    error: "bg-hack-red",
    paused: "bg-hack-yellow",
  };

  return (
    <div
      onClick={onClick}
      className={`p-2.5 rounded border cursor-pointer transition-all duration-150 ${
        selected
          ? "border-hack-accent/40 bg-hack-accent/5"
          : "border-hack-border bg-hack-surface hover:border-hack-border/60"
      }`}
    >
      <div className="flex items-center gap-2">
        <span className={`w-1.5 h-1.5 rounded-full flex-shrink-0 ${STATUS_DOT[session.status] || "bg-hack-dim"}`} />
        <span className="text-[10px] font-mono text-hack-text truncate flex-1">{session.target}</span>
        <span className={`text-[8px] font-mono px-1.5 rounded border ${STATUS_COLOR[session.status]}`}>
          {session.status.toUpperCase()}
        </span>
      </div>
      <div className="flex items-center gap-3 mt-1.5 text-[9px] font-mono text-hack-dim">
        <span className="flex items-center gap-0.5">
          <Activity className="w-2.5 h-2.5" />
          {session.phase} #{session.iteration}
        </span>
        {session.findings > 0 && (
          <span className="flex items-center gap-0.5 text-hack-orange">
            <Zap className="w-2.5 h-2.5" />
            {session.findings}
          </span>
        )}
        {session.hypotheses > 0 && (
          <span className="flex items-center gap-0.5 text-hack-purple">
            <Brain className="w-2.5 h-2.5" />
            {session.hypotheses}
          </span>
        )}
      </div>
    </div>
  );
}

function NewSessionForm({ programs, onCreated }: {
  programs: Record<string, unknown>[];
  onCreated: () => void;
}) {
  const [target, setTarget] = useState("");
  const [programId, setProgramId] = useState(0);
  const [mode, setMode] = useState<"forward" | "backward">("forward");
  const [goal, setGoal] = useState("");
  const [loading, setLoading] = useState(false);

  const handleCreate = async () => {
    if (!target) return toast.error("Enter a target URL");
    if (!programId) return toast.error("Select a program");
    setLoading(true);
    try {
      await sessionAPI.create({
        target,
        programId,
        mode,
        huntGoal: goal || undefined,
        requestBudget: 2000,
      });
      toast.success("Session started");
      setTarget("");
      setGoal("");
      onCreated();
    } catch {
      toast.error("Failed to create session");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="space-y-2">
      <label className="hack-label">Program</label>
      <select className="hack-input w-full" value={programId} onChange={e => setProgramId(Number(e.target.value))}>
        <option value={0}>-- Select --</option>
        {programs.map(p => (
          <option key={String(p.id)} value={String(p.id)}>{String(p.name)}</option>
        ))}
      </select>

      <label className="hack-label">Target URL</label>
      <input
        className="hack-input w-full"
        value={target}
        onChange={e => setTarget(e.target.value)}
        placeholder="https://target.example.com"
      />

      <div className="flex gap-1">
        {(["forward", "backward"] as const).map(m => (
          <button key={m} onClick={() => setMode(m)}
            className={`flex-1 py-1.5 text-[10px] font-mono rounded border transition-all ${
              mode === m ? "bg-hack-accent/10 text-hack-accent border-hack-accent/30" : "text-hack-dim border-hack-border hover:text-hack-text"
            }`}>
            {m === "forward" ? "→ FWD" : "← BWD"}
          </button>
        ))}
      </div>

      {mode === "backward" && (
        <>
          <label className="hack-label">Goal</label>
          <input className="hack-input w-full" value={goal} onChange={e => setGoal(e.target.value)}
            placeholder="e.g. Account takeover, RCE" />
        </>
      )}

      <button onClick={handleCreate} disabled={loading}
        className="hack-btn-primary w-full flex items-center justify-center gap-2 py-2 disabled:opacity-50">
        {loading ? <RefreshCw className="w-3 h-3 animate-spin" /> : <Play className="w-3 h-3" />}
        {loading ? "LAUNCHING..." : "LAUNCH"}
      </button>
    </div>
  );
}

// ── WAF Tab ────────────────────────────────────────────────────────────────────

function WAFTab({ sessionId }: { sessionId: string }) {
  const [waf, setWaf] = useState<WAFData | null>(null);
  const [evasion, setEvasion] = useState<WAFData["evasionRanking"]>([]);
  const [temporal, setTemporal] = useState<Record<string, unknown> | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    setLoading(true);
    Promise.all([
      sessionAPI.getWaf(sessionId),
      sessionAPI.getEvasionRanking(sessionId),
      sessionAPI.getTemporalAnalysis(sessionId),
    ]).then(([w, e, t]) => {
      setWaf(w.data);
      setEvasion(e.data?.ranking || []);
      setTemporal(t.data);
    }).catch(() => {}).finally(() => setLoading(false));
  }, [sessionId]);

  if (loading) return <div className="text-[10px] text-hack-dim font-mono p-4 animate-pulse">Loading WAF data...</div>;
  if (!waf) return <div className="text-[10px] text-hack-dim font-mono p-4">No WAF data for this session.</div>;

  return (
    <div className="p-3 space-y-4 overflow-y-auto terminal-scroll h-full">
      {/* WAF Profile */}
      <div className="hack-panel p-3">
        <div className="flex items-center gap-2 mb-3">
          <Shield className="w-3 h-3 text-hack-red" />
          <span className="text-[10px] font-mono text-hack-dim tracking-widest">WAF PROFILE</span>
        </div>
        <div className="grid grid-cols-4 gap-4">
          <div className="text-center">
            <div className="text-lg font-mono font-bold text-hack-orange">{waf.vendor || "UNKNOWN"}</div>
            <div className="text-[9px] text-hack-dim font-mono">VENDOR</div>
          </div>
          <div className="text-center">
            <div className={`text-lg font-mono font-bold ${waf.detected ? "text-hack-red" : "text-hack-accent"}`}>
              {waf.detected ? "YES" : "NO"}
            </div>
            <div className="text-[9px] text-hack-dim font-mono">DETECTED</div>
          </div>
          <div className="text-center">
            <div className="text-lg font-mono font-bold text-hack-yellow">
              {Math.round((waf.confidence || 0) * 100)}%
            </div>
            <div className="text-[9px] text-hack-dim font-mono">CONFIDENCE</div>
          </div>
          <div className="text-center">
            <div className="text-lg font-mono font-bold text-hack-red">
              {Math.round((waf.blockRate || 0) * 100)}%
            </div>
            <div className="text-[9px] text-hack-dim font-mono">BLOCK RATE</div>
          </div>
        </div>
      </div>

      {/* Evasion Ranking */}
      {evasion && evasion.length > 0 && (
        <div className="hack-panel p-3">
          <div className="flex items-center gap-2 mb-3">
            <Target className="w-3 h-3 text-hack-orange" />
            <span className="text-[10px] font-mono text-hack-dim tracking-widest">EVASION RANKING</span>
          </div>
          <div className="space-y-1.5">
            {evasion.slice(0, 8).map((e, i) => (
              <div key={i} className="flex items-center gap-3">
                <span className="text-[9px] font-mono text-hack-dim w-4">{i + 1}.</span>
                <span className="text-[10px] font-mono text-hack-text flex-1 truncate">{e.technique}</span>
                <div className="w-20 h-1 bg-hack-muted rounded-full overflow-hidden">
                  <div className="h-full bg-hack-accent rounded-full" style={{ width: `${Math.round(e.successRate * 100)}%` }} />
                </div>
                <span className="text-[9px] font-mono text-hack-accent w-8 text-right">
                  {Math.round(e.successRate * 100)}%
                </span>
                <span className="text-[9px] font-mono text-hack-dim w-12 text-right">{e.attempts}×</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Temporal Analysis */}
      {temporal && (
        <div className="hack-panel p-3">
          <div className="flex items-center gap-2 mb-3">
            <Clock className="w-3 h-3 text-hack-blue" />
            <span className="text-[10px] font-mono text-hack-dim tracking-widest">TEMPORAL ANALYSIS</span>
          </div>
          <div className="grid grid-cols-3 gap-4 text-center">
            <div>
              <div className="text-sm font-mono font-bold text-hack-blue">{String(temporal.pattern || "N/A")}</div>
              <div className="text-[9px] text-hack-dim font-mono">PATTERN</div>
            </div>
            <div>
              <div className="text-sm font-mono font-bold text-hack-cyan">{String(temporal.peakHour ?? "—")}h</div>
              <div className="text-[9px] text-hack-dim font-mono">PEAK HOUR</div>
            </div>
            <div>
              <div className="text-sm font-mono font-bold text-hack-orange">{String(temporal.blockClusters ?? 0)}</div>
              <div className="text-[9px] text-hack-dim font-mono">BLOCK CLUSTERS</div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

// ── Reports Tab ────────────────────────────────────────────────────────────────

function ReportsTab({ sessionId }: { sessionId: string }) {
  const [reports, setReports] = useState<Record<string, unknown>[]>([]);
  const [templates, setTemplates] = useState<Record<string, unknown>[]>([]);
  const [loading, setLoading] = useState(true);
  const [generating, setGenerating] = useState(false);

  const load = useCallback(() => {
    setLoading(true);
    Promise.all([
      sessionAPI.getReports(sessionId),
      sessionAPI.getNucleiTemplates(sessionId),
    ]).then(([r, t]) => {
      setReports(r.data?.reports || []);
      setTemplates(t.data?.templates || []);
    }).catch(() => {}).finally(() => setLoading(false));
  }, [sessionId]);

  useEffect(() => { load(); }, [load]);

  const generate = async () => {
    setGenerating(true);
    try {
      await sessionAPI.generateReport(sessionId);
      toast.success("Report generated");
      load();
    } catch {
      toast.error("Failed to generate report");
    } finally {
      setGenerating(false);
    }
  };

  if (loading) return <div className="text-[10px] text-hack-dim font-mono p-4 animate-pulse">Loading reports...</div>;

  return (
    <div className="p-3 space-y-4 overflow-y-auto terminal-scroll h-full">
      {/* Reports */}
      <div className="hack-panel p-3">
        <div className="flex items-center justify-between mb-3">
          <div className="flex items-center gap-2">
            <FileText className="w-3 h-3 text-hack-blue" />
            <span className="text-[10px] font-mono text-hack-dim tracking-widest">REPORTS</span>
          </div>
          <button onClick={generate} disabled={generating}
            className="hack-btn flex items-center gap-1 text-[9px]">
            {generating ? <RefreshCw className="w-2.5 h-2.5 animate-spin" /> : <Plus className="w-2.5 h-2.5" />}
            GENERATE
          </button>
        </div>

        {reports.length === 0 ? (
          <div className="text-[10px] text-hack-dim font-mono text-center py-4">
            No reports yet. Generate one above.
          </div>
        ) : (
          <div className="space-y-2">
            {reports.map((r, i) => {
              const report = r as Record<string, unknown>;
              return (
                <div key={i} className="flex items-center gap-3 p-2 border border-hack-border rounded">
                  <FileText className="w-3 h-3 text-hack-blue flex-shrink-0" />
                  <div className="flex-1 min-w-0">
                    <div className="text-[10px] font-mono text-hack-text truncate">
                      {String(report.title || `Report #${i + 1}`)}
                    </div>
                    <div className="text-[9px] font-mono text-hack-dim">
                      {String(report.severity || "")} · {String(report.vulnClass || "")}
                    </div>
                  </div>
                  <button onClick={() => sessionAPI.downloadReport(sessionId, String(report.id || i))}
                    className="text-hack-dim hover:text-hack-cyan transition-colors">
                    <Download className="w-3 h-3" />
                  </button>
                </div>
              );
            })}
          </div>
        )}
      </div>

      {/* Nuclei Templates */}
      <div className="hack-panel p-3">
        <div className="flex items-center justify-between mb-3">
          <div className="flex items-center gap-2">
            <Terminal className="w-3 h-3 text-hack-cyan" />
            <span className="text-[10px] font-mono text-hack-dim tracking-widest">NUCLEI TEMPLATES</span>
            <span className="text-[8px] font-mono text-hack-dim">({templates.length})</span>
          </div>
          {templates.length > 0 && (
            <button onClick={() => sessionAPI.downloadAllTemplates(sessionId)}
              className="hack-btn flex items-center gap-1 text-[9px]">
              <Download className="w-2.5 h-2.5" /> ALL
            </button>
          )}
        </div>

        {templates.length === 0 ? (
          <div className="text-[10px] text-hack-dim font-mono text-center py-4">
            Templates generated when findings are confirmed.
          </div>
        ) : (
          <div className="space-y-1.5">
            {templates.map((t, i) => {
              const tmpl = t as Record<string, unknown>;
              return (
                <div key={i} className="flex items-center gap-2 text-[10px] font-mono py-1 border-b border-hack-border/50">
                  <span className="text-hack-cyan text-[8px]">›</span>
                  <span className="text-hack-text truncate flex-1">{String(tmpl.id || `template-${i}`)}</span>
                  <span className="text-hack-orange text-[9px]">{String(tmpl.severity || "")}</span>
                </div>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
}

// ── Overview Tab ───────────────────────────────────────────────────────────────

function OverviewTab({ sessionId, session }: { sessionId: string; session: Session }) {
  const [coordination, setCoordination] = useState<Record<string, unknown> | null>(null);
  const [plan, setPlan] = useState<Record<string, unknown> | null>(null);
  const [strategy, setStrategy] = useState<Record<string, unknown> | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    setLoading(true);
    Promise.all([
      sessionAPI.getCoordination(sessionId),
      sessionAPI.getPlan(sessionId),
      sessionAPI.getStrategy(sessionId),
    ]).then(([c, p, s]) => {
      setCoordination(c.data);
      setPlan(p.data);
      setStrategy(s.data);
    }).catch(() => {}).finally(() => setLoading(false));
  }, [sessionId]);

  const PHASE_COLORS: Record<string, string> = {
    recon: "text-hack-cyan bg-hack-cyan/10 border-hack-cyan/30",
    hypothesis: "text-hack-purple bg-hack-purple/10 border-hack-purple/30",
    probe: "text-hack-orange bg-hack-orange/10 border-hack-orange/30",
    exploit: "text-hack-red bg-hack-red/10 border-hack-red/30",
    verify: "text-hack-accent bg-hack-accent/10 border-hack-accent/30",
    report: "text-hack-blue bg-hack-blue/10 border-hack-blue/30",
  };

  const AGENT_ICONS: Record<string, React.ReactNode> = {
    coordinator:      <Cpu className="w-3 h-3" />,
    hypothesis_agent: <Brain className="w-3 h-3" />,
    probe_agent:      <Target className="w-3 h-3" />,
    verify_agent:     <CheckCircle2 className="w-3 h-3" />,
    report_agent:     <FileText className="w-3 h-3" />,
  };

  if (loading) return <div className="text-[10px] text-hack-dim font-mono p-4 animate-pulse">Loading session state...</div>;

  return (
    <div className="p-3 space-y-3 overflow-y-auto terminal-scroll h-full">
      {/* Quick Stats */}
      <div className="grid grid-cols-4 gap-2">
        {[
          { label: "PHASE", value: session.phase.toUpperCase(), color: "text-hack-accent" },
          { label: "ITERATION", value: `#${session.iteration}`, color: "text-hack-cyan" },
          { label: "HYPOTHESES", value: session.hypotheses, color: "text-hack-purple" },
          { label: "FINDINGS", value: session.findings, color: "text-hack-orange" },
        ].map(s => (
          <div key={s.label} className="hack-panel p-2 text-center">
            <div className={`text-sm font-mono font-bold ${s.color}`}>{s.value}</div>
            <div className="text-[8px] text-hack-dim font-mono">{s.label}</div>
          </div>
        ))}
      </div>

      {/* Plan Phases */}
      {plan && (
        <div className="hack-panel p-3">
          <div className="flex items-center gap-2 mb-2">
            <Network className="w-3 h-3 text-hack-blue" />
            <span className="text-[10px] font-mono text-hack-dim tracking-widest">HUNT PLAN</span>
            <span className="ml-auto text-[9px] font-mono text-hack-dim">
              Phase: {String((plan as Record<string, unknown>).currentPhase || "—")}
            </span>
          </div>
          {Array.isArray((plan as Record<string, unknown>).phases) && (
            <div className="flex gap-1 flex-wrap mt-2">
              {((plan as Record<string, unknown>).phases as Record<string, unknown>[]).map((ph, i) => (
                <span key={i} className={`text-[9px] font-mono px-2 py-0.5 rounded border ${
                  ph.status === "complete" ? "text-hack-accent border-hack-accent/30 bg-hack-accent/10" :
                  ph.status === "active" ? "text-hack-orange border-hack-orange/30 bg-hack-orange/10 animate-pulse" :
                  PHASE_COLORS[String(ph.phase || "").toLowerCase()] || "text-hack-dim border-hack-border"
                }`}>
                  {String(ph.phase || ph.name || `Phase ${i + 1}`)}
                </span>
              ))}
            </div>
          )}
        </div>
      )}

      {/* Multi-agent Coordination */}
      {coordination && (
        <div className="hack-panel p-3">
          <div className="flex items-center gap-2 mb-2">
            <Cpu className="w-3 h-3 text-hack-purple" />
            <span className="text-[10px] font-mono text-hack-dim tracking-widest">AGENT COORDINATION</span>
          </div>
          <div className="space-y-1.5">
            {Object.entries((coordination as Record<string, unknown>).agents || {}).map(([agentId, agent]) => {
              const a = agent as Record<string, unknown>;
              const isActive = a.status === "active" || a.status === "running";
              return (
                <div key={agentId} className="flex items-center gap-2 text-[10px] font-mono">
                  <span className={`${isActive ? "text-hack-accent" : "text-hack-dim"}`}>
                    {AGENT_ICONS[agentId] || <Cpu className="w-3 h-3" />}
                  </span>
                  <span className={`flex-1 ${isActive ? "text-hack-text" : "text-hack-dim"}`}>
                    {agentId.replace(/_/g, " ")}
                  </span>
                  <span className={`text-[9px] px-1.5 rounded border ${
                    isActive ? "text-hack-accent border-hack-accent/30 bg-hack-accent/10" :
                    a.status === "complete" ? "text-hack-green border-hack-green/30" :
                    "text-hack-dim border-hack-border"
                  }`}>
                    {String(a.status || "idle").toUpperCase()}
                  </span>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* Strategy Steps */}
      {strategy && Array.isArray((strategy as Record<string, unknown>).steps) && (
        <div className="hack-panel p-3">
          <div className="flex items-center gap-2 mb-2">
            <BarChart3 className="w-3 h-3 text-hack-yellow" />
            <span className="text-[10px] font-mono text-hack-dim tracking-widest">HUNT STRATEGY</span>
          </div>
          <div className="space-y-1">
            {((strategy as Record<string, unknown>).steps as Record<string, unknown>[]).map((step, i) => (
              <div key={i} className="flex items-center gap-2 text-[10px] font-mono">
                <span className={`w-4 h-4 rounded flex items-center justify-center text-[8px] flex-shrink-0 ${
                  step.completed ? "bg-hack-accent/20 text-hack-accent" : "bg-hack-muted text-hack-dim"
                }`}>
                  {step.completed ? "✓" : i + 1}
                </span>
                <span className={step.completed ? "text-hack-dim line-through" : "text-hack-text"}>
                  {String(step.description || step.action || `Step ${i + 1}`)}
                </span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

// ── Main Page ──────────────────────────────────────────────────────────────────

export default function Hunter() {
  const [sessions, setSessions] = useState<Session[]>([]);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [hypotheses, setHypotheses] = useState<Record<string, unknown>[]>([]);
  const [findings, setFindings] = useState<Record<string, unknown>[]>([]);
  const [programs, setPrograms] = useState<Record<string, unknown>[]>([]);
  const [roi, setRoi] = useState<ROIData | null>(null);
  const [loading, setLoading] = useState(true);
  const [detailTab, setDetailTab] = useState<DetailTab>("overview");
  const [showNewForm, setShowNewForm] = useState(false);

  const selected = sessions.find(s => s.id === selectedId) || null;

  const loadSessions = useCallback(async () => {
    try {
      const res = await sessionAPI.list();
      const raw = (res.data?.sessions || []) as Record<string, unknown>[];
      setSessions(raw.map(s => ({
        id: String(s.id || s.sessionUuid || ""),
        sessionUuid: String(s.sessionUuid || ""),
        target: String(s.target || s.targetUrl || "unknown"),
        status: (s.status as Session["status"]) || "running",
        phase: String(s.phase || "observe"),
        iteration: Number(s.iteration || 0),
        findings: Number(s.findingsCount || 0),
        hypotheses: Number(s.hypothesesCount || 0),
        createdAt: Number(s.createdAt || Date.now()),
        campaignId: s.campaignId ? Number(s.campaignId) : undefined,
      })));
    } catch {
      // sessions endpoint may not have data yet
    } finally {
      setLoading(false);
    }
  }, []);

  const loadSessionDetail = useCallback(async (id: string) => {
    try {
      const [hRes, fRes] = await Promise.all([
        sessionAPI.getHypotheses(id),
        sessionAPI.getFindings(id),
      ]);
      setHypotheses(hRes.data?.hypotheses || []);
      setFindings(fRes.data?.findings || []);
    } catch {
      setHypotheses([]);
      setFindings([]);
    }
  }, []);

  const loadROI = useCallback(async () => {
    try {
      const [gRes, tRes] = await Promise.all([
        hunterROI.getGlobal(),
        hunterROI.getThresholds(),
      ]);
      setRoi({ globalStats: gRes.data, thresholds: tRes.data.thresholds ?? tRes.data });
    } catch {/* ignore */}
  }, []);

  useEffect(() => {
    Promise.all([
      loadSessions(),
      bountyAPI.getPrograms().then(r => setPrograms(r.data || [])),
      loadROI(),
    ]);
  }, [loadSessions, loadROI]);

  useEffect(() => {
    if (selectedId) {
      loadSessionDetail(selectedId);
      setDetailTab("overview");
    }
  }, [selectedId, loadSessionDetail]);

  const stopSession = async (id: string) => {
    try {
      await sessionAPI.stop(id);
      toast.success("Session stopped");
      loadSessions();
    } catch {
      toast.error("Failed to stop session");
    }
  };

  const attackPath = selected
    ? hypothesesToAttackPath(selected, hypotheses, findings)
    : null;

  const TABS: Array<{ id: DetailTab; icon: React.ElementType; label: string }> = [
    { id: "overview",     icon: Activity,  label: "OVERVIEW" },
    { id: "attack-path",  icon: Crosshair, label: "ATTACK PATH" },
    { id: "waf",          icon: Shield,    label: "WAF INTEL" },
    { id: "reports",      icon: FileText,  label: "REPORTS" },
  ];

  return (
    <div className="h-full flex flex-col overflow-hidden font-mono">
      {/* Header */}
      <div className="flex items-center gap-3 px-4 py-2 border-b border-hack-border bg-hack-surface flex-shrink-0">
        <Crosshair className="w-4 h-4 text-hack-accent" strokeWidth={1.5} />
        <span className="text-sm font-mono text-hack-accent tracking-widest glow-green">HUNTER</span>
        <span className="text-hack-dim text-[10px]">|</span>
        <span className="text-[10px] text-hack-dim">Autonomous Session Manager</span>

        <div className="ml-auto flex items-center gap-3 text-[10px]">
          {roi?.globalStats && (
            <span className="text-hack-dim">
              EV: <span className="text-hack-yellow font-mono">
                ${Number((roi.globalStats as Record<string, unknown>).avgPayout || 0).toFixed(0)}
              </span>
            </span>
          )}
          <span className={`px-2 py-0.5 rounded border text-[9px] ${
            sessions.filter(s => s.status === "running").length > 0
              ? "text-hack-accent border-hack-accent/30 bg-hack-accent/10 animate-pulse"
              : "text-hack-dim border-hack-border"
          }`}>
            {sessions.filter(s => s.status === "running").length} ACTIVE
          </span>
          <button onClick={() => { setShowNewForm(!showNewForm); }} className="hack-btn flex items-center gap-1 text-[10px]">
            <Plus className="w-3 h-3" />
            NEW
          </button>
          <button onClick={loadSessions} className="hack-btn flex items-center gap-1 text-[10px]">
            <RefreshCw className="w-3 h-3" />
          </button>
        </div>
      </div>

      <div className="flex-1 flex overflow-hidden">
        {/* Left: Session list */}
        <div className="w-64 flex-shrink-0 border-r border-hack-border flex flex-col overflow-hidden bg-hack-surface">
          {/* New session form */}
          {showNewForm && (
            <div className="p-3 border-b border-hack-border bg-hack-panel">
              <div className="text-[9px] text-hack-dim font-mono tracking-widest mb-2">NEW SESSION</div>
              <NewSessionForm programs={programs} onCreated={() => { setShowNewForm(false); loadSessions(); }} />
            </div>
          )}

          <div className="text-[9px] text-hack-dim font-mono tracking-widest px-3 py-2 border-b border-hack-border">
            SESSIONS ({sessions.length})
          </div>

          <div className="flex-1 overflow-y-auto terminal-scroll p-2 space-y-1.5">
            {loading ? (
              <div className="text-[10px] text-hack-dim text-center mt-6 animate-pulse">Loading...</div>
            ) : sessions.length === 0 ? (
              <div className="text-center py-8">
                <Eye className="w-5 h-5 text-hack-dim mx-auto mb-2" strokeWidth={1} />
                <div className="text-[10px] text-hack-dim">No sessions yet.</div>
                <button onClick={() => setShowNewForm(true)}
                  className="text-[10px] text-hack-accent hover:text-hack-green mt-1">
                  + Launch one
                </button>
              </div>
            ) : (
              sessions.map(s => (
                <SessionCard
                  key={s.id}
                  session={s}
                  selected={s.id === selectedId}
                  onClick={() => setSelectedId(s.id)}
                />
              ))
            )}
          </div>

          {/* ROI Summary */}
          {roi && (
            <div className="border-t border-hack-border p-3 flex-shrink-0">
              <div className="text-[9px] text-hack-dim font-mono tracking-widest mb-2">ROI THRESHOLDS</div>
              {Object.entries(roi.thresholds as Record<string, unknown>).slice(0, 3).map(([k, v]) => (
                <div key={k} className="flex justify-between text-[9px] font-mono py-0.5">
                  <span className="text-hack-dim">{k}</span>
                  <span className="text-hack-yellow">${String(v)}</span>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Right: Detail panel */}
        {!selected ? (
          <div className="flex-1 flex flex-col items-center justify-center bg-hack-bg text-center">
            <Crosshair className="w-8 h-8 text-hack-dim mx-auto mb-3" strokeWidth={1} />
            <div className="text-sm font-mono text-hack-dim">Select a session</div>
            <div className="text-[10px] text-hack-dim/60 font-mono mt-1">
              or launch a new hunt to get started
            </div>
          </div>
        ) : (
          <div className="flex-1 flex flex-col overflow-hidden">
            {/* Session header bar */}
            <div className="flex items-center gap-3 px-4 py-2 border-b border-hack-border bg-hack-surface flex-shrink-0">
              <div className="flex-1 min-w-0">
                <div className="text-xs font-mono text-hack-text truncate">{selected.target}</div>
                <div className="text-[9px] font-mono text-hack-dim">
                  {selected.phase} · iter #{selected.iteration} ·
                  {selected.findings > 0 && <span className="text-hack-orange ml-1">{selected.findings} findings</span>}
                  {selected.hypotheses > 0 && <span className="text-hack-purple ml-1">{selected.hypotheses} hypotheses</span>}
                </div>
              </div>
              {selected.status === "running" && (
                <button onClick={() => stopSession(selected.id)}
                  className="hack-btn-danger flex items-center gap-1 text-[10px]">
                  <Square className="w-3 h-3" /> STOP
                </button>
              )}
            </div>

            {/* Tab bar */}
            <div className="flex border-b border-hack-border flex-shrink-0 bg-hack-surface">
              {TABS.map(tab => {
                const Icon = tab.icon;
                return (
                  <button
                    key={tab.id}
                    onClick={() => setDetailTab(tab.id)}
                    className={`flex items-center gap-1.5 px-4 py-2 text-[10px] border-b-2 transition-colors ${
                      detailTab === tab.id
                        ? "text-hack-accent border-hack-accent"
                        : "text-hack-dim border-transparent hover:text-hack-text"
                    }`}
                  >
                    <Icon className="w-3 h-3" />
                    {tab.label}
                  </button>
                );
              })}
              <div className="ml-auto flex items-center pr-3">
                <ChevronRight className="w-3 h-3 text-hack-dim" />
                <span className="text-[9px] font-mono text-hack-dim">{selected.id.slice(0, 8)}</span>
              </div>
            </div>

            {/* Tab content */}
            <div className="flex-1 overflow-hidden">
              {detailTab === "overview" && (
                <OverviewTab sessionId={selected.id} session={selected} />
              )}

              {detailTab === "attack-path" && attackPath && (
                <div className="h-full overflow-hidden p-3">
                  <AttackPathVisualizer
                    path={attackPath}
                    onStepClick={(step) => {
                      if (step.status === "completed" || step.status === "failed") {
                        toast(`${step.title}: confidence ${Math.round((step.confidence ?? 0) * 100)}%`);
                      }
                    }}
                  />
                </div>
              )}

              {detailTab === "waf" && (
                <WAFTab sessionId={selected.id} />
              )}

              {detailTab === "reports" && (
                <ReportsTab sessionId={selected.id} />
              )}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
