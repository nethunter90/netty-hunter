import React, { useState, useMemo } from "react";
import {
  Eye, Brain, Target, Zap, CheckCircle2, FileText,
  ChevronDown, ChevronRight, Shield, AlertTriangle,
  Clock, Terminal, Lock, Crosshair, Bug, Radio,
  ArrowDown, Cpu, Fingerprint, Radar,
} from "lucide-react";

// ── Types ──────────────────────────────────────────────────────────────────────

export type StepPhase = "recon" | "hypothesis" | "probe" | "exploit" | "verify" | "report";
export type StepStatus = "completed" | "active" | "pending" | "failed" | "skipped";
export type Severity = "critical" | "high" | "medium" | "low" | "info";

export interface AttackStep {
  id: string;
  step: number;
  phase: StepPhase;
  status: StepStatus;
  title: string;
  description: string;
  vulnClass?: string;
  severity?: Severity;
  confidence?: number;
  tools?: string[];
  durationMs?: number;
  payload?: string;
  evidence?: string;
  target?: string;
  wafBypassed?: boolean;
  childSteps?: AttackStep[];
}

export interface AttackPath {
  id: string;
  name: string;
  objective: string;
  steps: AttackStep[];
  startedAt?: number;
  completedAt?: number;
  overallConfidence?: number;
  status: "active" | "complete" | "failed" | "paused";
}

interface Props {
  path: AttackPath;
  compact?: boolean;
  onStepClick?: (step: AttackStep) => void;
}

// ── Constants ──────────────────────────────────────────────────────────────────

const PHASE_META: Record<StepPhase, {
  icon: React.ElementType;
  color: string;
  bgColor: string;
  borderColor: string;
  glowColor: string;
  label: string;
}> = {
  recon: {
    icon: Eye,
    color: "text-hack-cyan",
    bgColor: "bg-hack-cyan/10",
    borderColor: "border-hack-cyan/30",
    glowColor: "#00d4ff",
    label: "RECON",
  },
  hypothesis: {
    icon: Brain,
    color: "text-hack-purple",
    bgColor: "bg-hack-purple/10",
    borderColor: "border-hack-purple/30",
    glowColor: "#8844ff",
    label: "HYPOTHESIS",
  },
  probe: {
    icon: Target,
    color: "text-hack-orange",
    bgColor: "bg-hack-orange/10",
    borderColor: "border-hack-orange/30",
    glowColor: "#ff8800",
    label: "PROBE",
  },
  exploit: {
    icon: Zap,
    color: "text-hack-red",
    bgColor: "bg-hack-red/10",
    borderColor: "border-hack-red/30",
    glowColor: "#ff3355",
    label: "EXPLOIT",
  },
  verify: {
    icon: CheckCircle2,
    color: "text-hack-accent",
    bgColor: "bg-hack-accent/10",
    borderColor: "border-hack-accent/30",
    glowColor: "#00ff88",
    label: "VERIFY",
  },
  report: {
    icon: FileText,
    color: "text-hack-blue",
    bgColor: "bg-hack-blue/10",
    borderColor: "border-hack-blue/30",
    glowColor: "#4488ff",
    label: "REPORT",
  },
};

const STATUS_STYLES: Record<StepStatus, { dot: string; label: string; text: string }> = {
  completed: { dot: "bg-hack-accent", label: "DONE", text: "text-hack-accent" },
  active:    { dot: "bg-hack-accent animate-pulse", label: "ACTIVE", text: "text-hack-accent" },
  pending:   { dot: "bg-hack-dim", label: "PENDING", text: "text-hack-dim" },
  failed:    { dot: "bg-hack-red", label: "FAILED", text: "text-hack-red" },
  skipped:   { dot: "bg-hack-dim/50", label: "SKIP", text: "text-hack-dim/50" },
};

const SEVERITY_STYLES: Record<Severity, string> = {
  critical: "severity-critical",
  high:     "severity-high",
  medium:   "severity-medium",
  low:      "severity-low",
  info:     "severity-info",
};

// ── Helpers ────────────────────────────────────────────────────────────────────

function formatDuration(ms: number): string {
  if (ms < 1000) return `${ms}ms`;
  if (ms < 60000) return `${(ms / 1000).toFixed(1)}s`;
  return `${Math.floor(ms / 60000)}m ${Math.round((ms % 60000) / 1000)}s`;
}

function getPhaseProgress(steps: AttackStep[]): { completed: number; total: number; percent: number } {
  const completed = steps.filter(s => s.status === "completed").length;
  const total = steps.length;
  return { completed, total, percent: total > 0 ? Math.round((completed / total) * 100) : 0 };
}

// ── Sub-components ─────────────────────────────────────────────────────────────

function ConfidenceMeter({ value, size = "sm" }: { value: number; size?: "sm" | "md" }) {
  const width = Math.round(value * 100);
  const color =
    value >= 0.8 ? "#ff3355" :
    value >= 0.6 ? "#ff8800" :
    value >= 0.4 ? "#ffcc00" :
    "#00d4ff";

  return (
    <div className={`flex items-center gap-1.5 ${size === "md" ? "w-24" : "w-16"}`}>
      <div className="flex-1 h-1 bg-hack-muted rounded-full overflow-hidden">
        <div
          className="h-full rounded-full transition-all duration-500"
          style={{ width: `${width}%`, backgroundColor: color }}
        />
      </div>
      <span className="text-[9px] font-mono" style={{ color }}>{width}%</span>
    </div>
  );
}

function ToolBadge({ tool }: { tool: string }) {
  const colors: Record<string, string> = {
    nuclei: "text-hack-cyan border-hack-cyan/30",
    sqlmap: "text-hack-red border-hack-red/30",
    nmap: "text-hack-blue border-hack-blue/30",
    ffuf: "text-hack-orange border-hack-orange/30",
    burp: "text-hack-purple border-hack-purple/30",
    nikto: "text-hack-yellow border-hack-yellow/30",
    gobuster: "text-hack-green border-hack-green/30",
    curl_probe: "text-hack-dim border-hack-border",
    manual: "text-hack-text border-hack-border",
  };
  const c = colors[tool.toLowerCase()] || "text-hack-dim border-hack-border";
  return (
    <span className={`inline-flex items-center px-1.5 py-0.5 text-[8px] font-mono border rounded ${c}`}>
      {tool}
    </span>
  );
}

function ConnectorLine({ status, isLast }: { status: StepStatus; isLast: boolean }) {
  if (isLast) return null;
  return (
    <div className="flex flex-col items-center ml-[13px] -my-0.5">
      <div className={`w-px h-6 transition-all duration-300 ${
        status === "completed" ? "bg-hack-accent/40" :
        status === "active" ? "bg-hack-accent/30 connector-pulse" :
        status === "failed" ? "bg-hack-red/30" :
        "bg-hack-border"
      }`} />
      {status === "active" && (
        <div className="w-1 h-1 rounded-full bg-hack-accent animate-ping absolute" />
      )}
      <ArrowDown className={`w-2.5 h-2.5 -my-0.5 ${
        status === "completed" ? "text-hack-accent/50" :
        status === "active" ? "text-hack-accent/40" :
        "text-hack-border"
      }`} />
    </div>
  );
}

// ── Step Node ──────────────────────────────────────────────────────────────────

function StepNode({
  step,
  isLast,
  compact,
  onStepClick,
}: {
  step: AttackStep;
  isLast: boolean;
  compact?: boolean;
  onStepClick?: (step: AttackStep) => void;
}) {
  const [expanded, setExpanded] = useState(false);
  const phase = PHASE_META[step.phase];
  const statusStyle = STATUS_STYLES[step.status];
  const PhaseIcon = phase.icon;

  const hasDetails = step.payload || step.evidence || step.vulnClass || (step.childSteps && step.childSteps.length > 0);

  return (
    <>
      <div
        className={`group relative transition-all duration-200 ${
          step.status === "active" ? "scale-[1.01]" : ""
        }`}
      >
        {/* Main node */}
        <div
          onClick={() => {
            if (hasDetails && !compact) setExpanded(!expanded);
            onStepClick?.(step);
          }}
          className={`
            relative flex items-start gap-3 p-2.5 rounded border transition-all duration-200
            ${step.status === "active"
              ? `${phase.borderColor} ${phase.bgColor} shadow-lg`
              : step.status === "completed"
              ? "border-hack-accent/20 bg-hack-accent/5"
              : step.status === "failed"
              ? "border-hack-red/20 bg-hack-red/5"
              : "border-hack-border bg-hack-surface hover:border-hack-border/60"
            }
            ${hasDetails && !compact ? "cursor-pointer" : ""}
          `}
          style={step.status === "active" ? {
            boxShadow: `0 0 12px ${phase.glowColor}15, 0 0 4px ${phase.glowColor}10`,
          } : undefined}
        >
          {/* Phase icon node */}
          <div className={`
            w-7 h-7 rounded flex items-center justify-center flex-shrink-0 border transition-all
            ${step.status === "active"
              ? `${phase.borderColor} ${phase.bgColor} ${phase.color}`
              : step.status === "completed"
              ? "border-hack-accent/30 bg-hack-accent/10 text-hack-accent"
              : step.status === "failed"
              ? "border-hack-red/30 bg-hack-red/10 text-hack-red"
              : "border-hack-border bg-hack-muted text-hack-dim"
            }
          `}>
            {step.status === "active" ? (
              <div className="relative">
                <PhaseIcon className="w-3.5 h-3.5" strokeWidth={1.5} />
                <span className="absolute -top-0.5 -right-0.5 w-1.5 h-1.5 rounded-full bg-hack-accent animate-ping" />
              </div>
            ) : step.status === "completed" ? (
              <CheckCircle2 className="w-3.5 h-3.5" strokeWidth={1.5} />
            ) : step.status === "failed" ? (
              <AlertTriangle className="w-3.5 h-3.5" strokeWidth={1.5} />
            ) : (
              <PhaseIcon className="w-3.5 h-3.5" strokeWidth={1.5} />
            )}
          </div>

          {/* Content */}
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2">
              {/* Phase label */}
              <span className={`text-[8px] font-mono tracking-wider ${phase.color}`}>
                {phase.label}
              </span>

              {/* Step number */}
              <span className="text-[8px] text-hack-dim font-mono">#{step.step}</span>

              {/* Severity badge */}
              {step.severity && (
                <span className={`text-[8px] px-1.5 py-0 rounded border font-mono ${SEVERITY_STYLES[step.severity]}`}>
                  {step.severity.toUpperCase()}
                </span>
              )}

              {/* WAF bypass indicator */}
              {step.wafBypassed && (
                <span className="text-[8px] px-1.5 py-0 rounded border text-hack-yellow border-hack-yellow/30 bg-hack-yellow/10 font-mono flex items-center gap-0.5">
                  <Shield className="w-2 h-2" />
                  WAF
                </span>
              )}

              {/* Expand toggle */}
              {hasDetails && !compact && (
                <span className="ml-auto text-hack-dim opacity-0 group-hover:opacity-100 transition-opacity">
                  {expanded
                    ? <ChevronDown className="w-3 h-3" />
                    : <ChevronRight className="w-3 h-3" />
                  }
                </span>
              )}
            </div>

            {/* Title */}
            <div className={`text-xs font-mono mt-0.5 ${
              step.status === "completed" ? "text-hack-text" :
              step.status === "active" ? "text-hack-text" :
              step.status === "failed" ? "text-hack-red" :
              "text-hack-dim"
            }`}>
              {step.title}
            </div>

            {/* Description */}
            {!compact && (
              <div className="text-[10px] text-hack-dim font-mono mt-0.5 leading-relaxed">
                {step.description}
              </div>
            )}

            {/* Inline metadata row */}
            <div className="flex items-center gap-3 mt-1.5 flex-wrap">
              {/* Confidence */}
              {step.confidence != null && (
                <ConfidenceMeter value={step.confidence} />
              )}

              {/* Tools */}
              {step.tools && step.tools.length > 0 && (
                <div className="flex items-center gap-1">
                  {step.tools.map(t => <ToolBadge key={t} tool={t} />)}
                </div>
              )}

              {/* Vuln class */}
              {step.vulnClass && (
                <span className="text-[9px] font-mono text-hack-orange flex items-center gap-0.5">
                  <Bug className="w-2.5 h-2.5" />
                  {step.vulnClass.toUpperCase()}
                </span>
              )}

              {/* Duration */}
              {step.durationMs != null && (
                <span className="text-[9px] font-mono text-hack-dim flex items-center gap-0.5">
                  <Clock className="w-2.5 h-2.5" />
                  {formatDuration(step.durationMs)}
                </span>
              )}

              {/* Target */}
              {step.target && (
                <span className="text-[9px] font-mono text-hack-dim flex items-center gap-0.5 truncate max-w-[150px]">
                  <Crosshair className="w-2.5 h-2.5 flex-shrink-0" />
                  {step.target}
                </span>
              )}
            </div>
          </div>

          {/* Right status */}
          <div className="flex-shrink-0 flex flex-col items-end gap-1">
            <div className={`flex items-center gap-1.5 text-[9px] font-mono ${statusStyle.text}`}>
              <span className={`w-1.5 h-1.5 rounded-full ${statusStyle.dot}`} />
              {statusStyle.label}
            </div>
          </div>

          {/* Active step scan line */}
          {step.status === "active" && (
            <div className="absolute inset-0 rounded overflow-hidden pointer-events-none">
              <div
                className="absolute left-0 right-0 h-px opacity-40"
                style={{
                  background: `linear-gradient(90deg, transparent, ${phase.glowColor}60, transparent)`,
                  animation: "attack-scan 2s linear infinite",
                }}
              />
            </div>
          )}
        </div>

        {/* Expanded detail panel */}
        {expanded && hasDetails && !compact && (
          <div className="ml-10 mt-1 border-l-2 border-hack-border pl-3 pb-2 space-y-2">
            {/* Payload */}
            {step.payload && (
              <div>
                <div className="text-[8px] text-hack-dim font-mono uppercase tracking-wider mb-0.5">PAYLOAD</div>
                <pre className="text-[10px] font-mono text-hack-orange bg-hack-bg border border-hack-border rounded p-2 overflow-x-auto terminal-scroll">
                  {step.payload}
                </pre>
              </div>
            )}

            {/* Evidence */}
            {step.evidence && (
              <div>
                <div className="text-[8px] text-hack-dim font-mono uppercase tracking-wider mb-0.5">EVIDENCE</div>
                <pre className="text-[10px] font-mono text-hack-cyan bg-hack-bg border border-hack-border rounded p-2 overflow-x-auto terminal-scroll">
                  {step.evidence}
                </pre>
              </div>
            )}

            {/* Child steps (sub-attempts) */}
            {step.childSteps && step.childSteps.length > 0 && (
              <div>
                <div className="text-[8px] text-hack-dim font-mono uppercase tracking-wider mb-1">SUB-STEPS</div>
                {step.childSteps.map((child, i) => (
                  <div key={child.id} className="flex items-center gap-2 text-[9px] font-mono py-0.5">
                    <span className={`w-1 h-1 rounded-full ${STATUS_STYLES[child.status].dot}`} />
                    <span className={STATUS_STYLES[child.status].text}>{child.title}</span>
                    {child.confidence != null && (
                      <span className="text-hack-dim ml-auto">{Math.round(child.confidence * 100)}%</span>
                    )}
                  </div>
                ))}
              </div>
            )}
          </div>
        )}
      </div>

      {/* Connector to next step */}
      <ConnectorLine status={step.status} isLast={isLast} />
    </>
  );
}

// ── Phase Group ────────────────────────────────────────────────────────────────

function PhaseGroup({ phase, steps, compact, onStepClick }: {
  phase: StepPhase;
  steps: AttackStep[];
  compact?: boolean;
  onStepClick?: (step: AttackStep) => void;
}) {
  const meta = PHASE_META[phase];
  const Icon = meta.icon;
  const progress = getPhaseProgress(steps);
  const hasActive = steps.some(s => s.status === "active");

  return (
    <div className="relative">
      {/* Phase header */}
      <div className={`
        flex items-center gap-2 px-2 py-1.5 rounded-t border-b mb-2
        ${hasActive ? `${meta.bgColor} ${meta.borderColor}` : "border-hack-border"}
      `}>
        <Icon className={`w-3 h-3 ${hasActive ? meta.color : "text-hack-dim"}`} strokeWidth={1.5} />
        <span className={`text-[9px] font-mono tracking-widest ${hasActive ? meta.color : "text-hack-dim"}`}>
          {meta.label}
        </span>
        <div className="flex-1" />

        {/* Phase mini-progress */}
        <div className="flex items-center gap-1.5">
          <div className="w-12 h-0.5 bg-hack-muted rounded-full overflow-hidden">
            <div
              className={`h-full rounded-full transition-all duration-500 ${
                progress.percent === 100 ? "bg-hack-accent" : hasActive ? "bg-hack-accent/60" : "bg-hack-dim"
              }`}
              style={{ width: `${progress.percent}%` }}
            />
          </div>
          <span className="text-[8px] text-hack-dim font-mono">
            {progress.completed}/{progress.total}
          </span>
        </div>
      </div>

      {/* Steps */}
      <div className="space-y-0">
        {steps.map((step, idx) => (
          <StepNode
            key={step.id}
            step={step}
            isLast={idx === steps.length - 1}
            compact={compact}
            onStepClick={onStepClick}
          />
        ))}
      </div>
    </div>
  );
}

// ── Main Component ─────────────────────────────────────────────────────────────

export default function AttackPathVisualizer({ path, compact = false, onStepClick }: Props) {
  // Group steps by phase while preserving order
  const phaseGroups = useMemo(() => {
    const groups: Array<{ phase: StepPhase; steps: AttackStep[] }> = [];
    let currentPhase: StepPhase | null = null;

    for (const step of path.steps) {
      if (step.phase !== currentPhase) {
        currentPhase = step.phase;
        groups.push({ phase: step.phase, steps: [] });
      }
      groups[groups.length - 1].steps.push(step);
    }

    return groups;
  }, [path.steps]);

  const progress = getPhaseProgress(path.steps);
  const activeStep = path.steps.find(s => s.status === "active");
  const failedCount = path.steps.filter(s => s.status === "failed").length;
  const totalDuration = path.steps.reduce((sum, s) => sum + (s.durationMs ?? 0), 0);

  return (
    <div className="hack-panel flex flex-col overflow-hidden">
      {/* Terminal-style header */}
      <div className="relative flex items-center gap-2 px-3 py-2 border-b border-hack-border bg-hack-surface">
        {/* Window dots */}
        <div className="flex gap-1.5">
          <div className="w-2 h-2 rounded-full bg-hack-red/70" />
          <div className="w-2 h-2 rounded-full bg-hack-yellow/70" />
          <div className="w-2 h-2 rounded-full bg-hack-accent/70" />
        </div>

        <Terminal className="w-3 h-3 text-hack-dim ml-1" strokeWidth={1.5} />
        <span className="text-[10px] font-mono text-hack-dim">
          attack-path — {path.name}
        </span>

        {/* Status indicator */}
        <div className="ml-auto flex items-center gap-3">
          {path.status === "active" && activeStep && (
            <span className="text-[9px] font-mono text-hack-accent flex items-center gap-1">
              <Radar className="w-3 h-3 animate-spin" style={{ animationDuration: "3s" }} />
              {PHASE_META[activeStep.phase].label}
            </span>
          )}
          <span className={`text-[9px] font-mono px-2 py-0.5 rounded border ${
            path.status === "active"  ? "text-hack-accent border-hack-accent/30 bg-hack-accent/10 animate-pulse" :
            path.status === "complete" ? "text-hack-green border-hack-green/30 bg-hack-green/10" :
            path.status === "failed"  ? "text-hack-red border-hack-red/30 bg-hack-red/10" :
            "text-hack-dim border-hack-border bg-hack-muted"
          }`}>
            {path.status.toUpperCase()}
          </span>
        </div>

        {/* Scan line for active state */}
        {path.status === "active" && (
          <div className="scan-overlay absolute inset-0 pointer-events-none" />
        )}
      </div>

      {/* Objective bar */}
      <div className="px-3 py-2 border-b border-hack-border bg-hack-bg/50 flex items-center gap-3">
        <Fingerprint className="w-3 h-3 text-hack-purple flex-shrink-0" strokeWidth={1.5} />
        <span className="text-[10px] font-mono text-hack-dim">OBJ</span>
        <span className="text-[10px] font-mono text-hack-text truncate">{path.objective}</span>
        {path.overallConfidence != null && (
          <div className="ml-auto flex-shrink-0">
            <ConfidenceMeter value={path.overallConfidence} size="md" />
          </div>
        )}
      </div>

      {/* Global progress bar */}
      <div className="h-1 bg-hack-muted">
        <div
          className={`h-full transition-all duration-700 ${
            failedCount > 0 ? "bg-gradient-to-r from-hack-accent to-hack-red" :
            progress.percent === 100 ? "bg-hack-accent" :
            "bg-gradient-to-r from-hack-accent to-hack-cyan"
          }`}
          style={{ width: `${progress.percent}%` }}
        />
      </div>

      {/* Stats row */}
      <div className="flex items-center gap-4 px-3 py-1.5 border-b border-hack-border text-[9px] font-mono bg-hack-surface/50">
        <span className="text-hack-accent flex items-center gap-1">
          <CheckCircle2 className="w-2.5 h-2.5" />
          {progress.completed}/{progress.total} steps
        </span>
        {failedCount > 0 && (
          <span className="text-hack-red flex items-center gap-1">
            <AlertTriangle className="w-2.5 h-2.5" />
            {failedCount} failed
          </span>
        )}
        {totalDuration > 0 && (
          <span className="text-hack-dim flex items-center gap-1">
            <Clock className="w-2.5 h-2.5" />
            {formatDuration(totalDuration)}
          </span>
        )}
        <span className="text-hack-dim ml-auto">
          {progress.percent}% complete
        </span>
      </div>

      {/* Step visualization */}
      <div className="flex-1 overflow-y-auto terminal-scroll p-3 space-y-4">
        {path.steps.length === 0 ? (
          <div className="text-center py-8">
            <Cpu className="w-6 h-6 text-hack-dim mx-auto mb-2" strokeWidth={1} />
            <div className="text-[10px] text-hack-dim font-mono">
              No attack steps yet
            </div>
            <div className="text-[9px] text-hack-dim/60 font-mono mt-1">
              Steps will appear as the hunt engine progresses
            </div>
          </div>
        ) : phaseGroups.length > 1 ? (
          // Grouped by phase when multiple phases exist
          phaseGroups.map((group, idx) => (
            <React.Fragment key={`${group.phase}-${idx}`}>
              <PhaseGroup
                phase={group.phase}
                steps={group.steps}
                compact={compact}
                onStepClick={onStepClick}
              />
              {/* Phase connector */}
              {idx < phaseGroups.length - 1 && (
                <div className="flex items-center justify-center py-1">
                  <div className="flex items-center gap-2">
                    <div className={`w-8 h-px ${
                      group.steps.every(s => s.status === "completed") ? "bg-hack-accent/30" : "bg-hack-border"
                    }`} />
                    <ArrowDown className={`w-3 h-3 ${
                      group.steps.every(s => s.status === "completed") ? "text-hack-accent/40" : "text-hack-border"
                    }`} />
                    <div className={`w-8 h-px ${
                      group.steps.every(s => s.status === "completed") ? "bg-hack-accent/30" : "bg-hack-border"
                    }`} />
                  </div>
                </div>
              )}
            </React.Fragment>
          ))
        ) : (
          // Flat list when all steps are same phase or single phase
          path.steps.map((step, idx) => (
            <StepNode
              key={step.id}
              step={step}
              isLast={idx === path.steps.length - 1}
              compact={compact}
              onStepClick={onStepClick}
            />
          ))
        )}
      </div>

      {/* Footer with path timing */}
      {(path.startedAt || path.completedAt) && (
        <div className="px-3 py-1.5 border-t border-hack-border text-[8px] font-mono text-hack-dim flex items-center gap-3 bg-hack-surface/50">
          {path.startedAt && (
            <span>START: {new Date(path.startedAt).toISOString().slice(11, 19)}</span>
          )}
          {path.completedAt && (
            <span>END: {new Date(path.completedAt).toISOString().slice(11, 19)}</span>
          )}
          {path.startedAt && path.completedAt && (
            <span className="ml-auto text-hack-accent">
              ELAPSED: {formatDuration(path.completedAt - path.startedAt)}
            </span>
          )}
          {path.startedAt && !path.completedAt && path.status === "active" && (
            <span className="ml-auto text-hack-accent animate-pulse">
              RUNNING...
            </span>
          )}
        </div>
      )}
    </div>
  );
}
