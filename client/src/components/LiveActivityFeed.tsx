import { memo, useEffect, useMemo, useRef, useState } from "react";
import {
  Eye, Brain, Target, RefreshCw, Zap, AlertTriangle, CheckCircle2,
  XCircle, ChevronRight, ChevronDown, Layers, Shield, Server, Globe, Code, Wifi,
} from "lucide-react";
import { ProxyRouteChip } from "./hunt/ProxyRouteChip";

// ── Types ──────────────────────────────────────────────────────────────────────

export type ActivityEvent =
  | { type: "layer_start";    ts: string; layer: number; name: string }
  | { type: "layer_done";     ts: string; layer: number; name: string; passed: boolean; durationMs: number }
  | { type: "phase";          ts: string; phase: string; iteration: number }
  | { type: "hypothesis";     ts: string; id: string; vulnClass: string; reasoning: string; confidence: number; modelSource?: "claude" | "ollama" | "default" }
  | { type: "probe_start";    ts: string; hypothesisId: string; vulnClass: string }
  | { type: "probe_result";   ts: string; hypothesisId: string; tool: string; success: boolean; output: string; durationMs: number; proxyId?: string }
  | { type: "finding";        ts: string; vulnClass: string; severity: string; confidence: number; payload?: string }
  | { type: "solver_finding"; ts: string; vulnClass: string }
  | { type: "verified";       ts: string; findingId: number; verdict: string }
  | { type: "rejected";       ts: string; findingId: number; verdict: string }
  | { type: "pivot";          ts: string; reason: string; newHypotheses: number }
  | { type: "ban";            ts: string; target: string; reason: string }
  | { type: "complete";        ts: string; findings: number; iterations: number }
  | { type: "error";           ts: string; message: string }
  | { type: "public_duplicate"; ts: string; vulnClass: string; platform: string; reportUrl?: string; title?: string; warn?: boolean }
  | { type: "cve_seeded"; ts: string; tech: string; cveIds: string[]; maxCvss: number }
  | { type: "oob_hit"; ts: string; beaconId: string; ip: string }
  | { type: "targets_expanded"; ts: string; count: number; targets: string[] }
  | { type: "graphql_schema"; ts: string; endpoint: string; typeCount: number; injectableCount: number }
  | { type: "ssrf_pivot"; ts: string; reachable: string[]; cloudMeta: boolean; newHypotheses: number }
  | { type: "report_submitted"; ts: string; platform: string; reportId?: string; reportUrl?: string }
  | { type: "changes_detected"; ts: string; newEndpoints: string[]; changed: number }
  | { type: "secrets_found"; ts: string; count: number; types: string[] }
  | { type: "takeover_found"; ts: string; targets: Array<{ subdomain: string; service: string; confidence: number }> }
  | { type: "ws_vulns"; ts: string; count: number; endpoints: string[]; issues: string[] }
  | { type: "bucket_exposed"; ts: string; buckets: Array<{ url: string; provider: string; listable: boolean }> }
  | { type: "proto_pollution"; ts: string; count: number; reflected: boolean }
  | { type: "race_condition"; ts: string; count: number; endpoints: string[] }
  | { type: "tech_payloads"; ts: string; techs: string[]; payloadCount: number }
  | { type: "params_discovered"; ts: string; count: number; params: string[] }
  | { type: "oauth_vulns"; ts: string; count: number; issues: string[] }
  | { type: "mass_assignment"; ts: string; count: number; endpoints: string[] }
  | { type: "business_logic"; ts: string; count: number; types: string[] }
  | { type: "two_fa_bypass"; ts: string; count: number; techniques: string[] }
  | { type: "jwt_vulns"; ts: string; count: number; techniques: string[] }
  | { type: "open_redirect"; ts: string; count: number; chained: number }
  | { type: "xxe_found"; ts: string; count: number; oobConfirmed: boolean }
  | { type: "zap_scan"; ts: string; alertCount: number; hypothesesSeeded: number; endpointsDiscovered: number; duration: number }
  | { type: "ai_reasoning"; ts: string; task: string; phase: "thinking" | "complete" | "decision";
      context?: { observations: number; hypotheses: number; iteration: number };
      promptPreview?: string; rawResponse?: string; summary?: string;
      durationMs?: number; generatedCount?: number; enrichmentActive?: boolean;
      corpusEntries?: { id: string; title: string; category: string; score: number | null; mode: string }[] }
  | { type: "recon_start";    ts: string; domain: string }
  | { type: "recon_complete"; ts: string; subdomains: number; alive: number; interestingUrls: number; historicalPathCount: number };

export interface LiveActivityFeedProps {
  events: ActivityEvent[];
  isRunning: boolean;
  maxEvents?: number;
  title?: string;
}

// ── Helpers ────────────────────────────────────────────────────────────────────

const PHASE_ICONS: Record<string, React.ReactNode> = {
  observe:     <Eye className="w-3 h-3 text-hack-cyan" />,
  hypothesize: <Brain className="w-3 h-3 text-hack-purple" />,
  probe:       <Target className="w-3 h-3 text-hack-orange" />,
  update:      <RefreshCw className="w-3 h-3 text-hack-blue" />,
  complete:    <CheckCircle2 className="w-3 h-3 text-hack-accent" />,
};

const SEVERITY_COLOR: Record<string, string> = {
  critical: "text-hack-red border-hack-red/40 bg-hack-red/10",
  high:     "text-hack-orange border-hack-orange/40 bg-hack-orange/10",
  medium:   "text-hack-yellow border-hack-yellow/40 bg-hack-yellow/10",
  low:      "text-hack-blue border-hack-blue/40 bg-hack-blue/10",
  info:     "text-hack-dim border-hack-border bg-hack-muted",
};

const LAYER_COLORS: Record<number, string> = {
  1: "text-hack-accent",
  2: "text-hack-blue",
  3: "text-hack-purple",
  4: "text-hack-yellow",
  5: "text-hack-orange",
  6: "text-hack-green",
};

function ConfidenceBar({ value }: { value: number }) {
  const pct = Math.round(Math.max(0, Math.min(1, value)) * 100);
  const color = pct >= 70 ? "bg-hack-accent" : pct >= 40 ? "bg-hack-yellow" : "bg-hack-red";
  return (
    <div className="flex items-center gap-1.5 mt-1">
      <div className="flex-1 h-1 bg-hack-muted rounded overflow-hidden">
        <div className={`h-full rounded transition-all ${color}`} style={{ width: `${pct}%` }} />
      </div>
      <span className="text-[9px] text-hack-dim w-7 text-right">{pct}%</span>
    </div>
  );
}

// ── Event row renderers ────────────────────────────────────────────────────────

function LayerSeparator({ ev }: { ev: ActivityEvent & { type: "layer_start" | "layer_done" } }) {
  const c = LAYER_COLORS[ev.layer] ?? "text-hack-dim";
  if (ev.type === "layer_start") {
    return (
      <div className="flex items-center gap-2 py-2 my-1">
        <div className="flex-1 h-px bg-hack-border" />
        <span className={`text-[10px] font-mono tracking-widest px-2 ${c}`}>
          ▶ L{ev.layer} {ev.name}
        </span>
        <div className="flex-1 h-px bg-hack-border" />
      </div>
    );
  }
  return (
    <div className="flex items-center gap-2 py-1 my-0.5">
      <div className="flex-1 h-px bg-hack-border" />
      <span className={`text-[10px] font-mono px-2 ${ev.passed ? "text-hack-green" : "text-hack-red"}`}>
        {ev.passed ? "✓" : "✗"} L{ev.layer} {ev.name} — {ev.durationMs < 1000 ? `${ev.durationMs}ms` : `${(ev.durationMs / 1000).toFixed(1)}s`}
      </span>
      <div className="flex-1 h-px bg-hack-border" />
    </div>
  );
}

function PhaseRow({ ev }: { ev: ActivityEvent & { type: "phase" } }) {
  return (
    <div className="flex items-center gap-2 py-0.5 text-[10px] font-mono text-hack-dim">
      <span className="text-hack-dim">{ev.ts}</span>
      {PHASE_ICONS[ev.phase] ?? <ChevronRight className="w-3 h-3" />}
      <span className="text-hack-text uppercase tracking-wide">{ev.phase}</span>
      <span className="text-hack-dim">· iter {ev.iteration}</span>
    </div>
  );
}

function HypothesisRow({ ev }: { ev: ActivityEvent & { type: "hypothesis" } }) {
  const [expanded, setExpanded] = useState(false);
  return (
    <div className="ml-3 border-l-2 border-hack-purple/30 pl-2 py-1 my-0.5">
      <button
        onClick={() => setExpanded(x => !x)}
        className="flex items-start gap-1.5 w-full text-left group"
      >
        <Brain className="w-3 h-3 text-hack-purple mt-0.5 flex-shrink-0" />
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <span className="text-[10px] px-1.5 py-0.5 rounded border border-hack-purple/40 bg-hack-purple/10 text-hack-purple font-mono uppercase">
              {ev.vulnClass}
            </span>
            {ev.modelSource === "claude" && (
              <span className="text-[9px] px-1 py-0.5 rounded border border-hack-cyan/40 bg-hack-cyan/10 text-hack-cyan font-mono">CLAUDE</span>
            )}
            {ev.modelSource === "ollama" && (
              <span className="text-[9px] px-1 py-0.5 rounded border border-hack-orange/40 bg-hack-orange/10 text-hack-orange font-mono">OLLAMA</span>
            )}
            {expanded
              ? <ChevronDown className="w-3 h-3 text-hack-dim" />
              : <ChevronRight className="w-3 h-3 text-hack-dim" />}
          </div>
          <div className="text-[10px] text-hack-dim mt-0.5 leading-relaxed">
            {expanded ? ev.reasoning : ev.reasoning.slice(0, 120) + (ev.reasoning.length > 120 ? "…" : "")}
          </div>
          <ConfidenceBar value={ev.confidence} />
        </div>
      </button>
    </div>
  );
}

function parseDeepSeekThinking(raw: string): { thinking: string; answer: string } | null {
  const match = raw.match(/<think>([\s\S]*?)<\/think>([\s\S]*)/i);
  if (!match) return null;
  return { thinking: match[1].trim(), answer: match[2].trim() };
}

function AIReasoningRow({ ev }: { ev: ActivityEvent & { type: "ai_reasoning" } }) {
  const [expanded, setExpanded] = useState(false);
  const isDecision = ev.phase === "decision";
  const phaseLabel = ev.phase === "thinking" ? "THINKING" : ev.phase === "complete" ? "COMPLETE" : "DECISION";
  const phaseCls = ev.phase === "thinking"
    ? "text-hack-yellow border-hack-yellow/40 bg-hack-yellow/10"
    : ev.phase === "complete"
    ? "text-hack-accent border-hack-accent/40 bg-hack-accent/10"
    : "text-hack-cyan border-hack-cyan/40 bg-hack-cyan/10";

  const parsed = useMemo(
    () => (ev.rawResponse ? parseDeepSeekThinking(ev.rawResponse) : null),
    [ev.rawResponse]
  );

  return (
    <div className="ml-3 border-l-2 border-hack-purple/40 pl-2 py-1 my-0.5 bg-hack-purple/5 rounded-r">
      <button
        onClick={() => !isDecision && setExpanded(x => !x)}
        className={`flex items-start gap-1.5 w-full text-left ${!isDecision ? "cursor-pointer" : "cursor-default"}`}
      >
        <Brain className="w-3 h-3 text-hack-purple mt-0.5 flex-shrink-0" />
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <span className="text-[10px] font-mono text-hack-purple font-bold">{ev.task}</span>
            <span className={`text-[9px] px-1 py-0.5 rounded border font-mono ${phaseCls}`}>{phaseLabel}</span>
            {ev.phase === "thinking" && ev.enrichmentActive !== undefined && (
              <span className={`text-[9px] px-1 py-0.5 rounded border font-mono ${ev.enrichmentActive ? "text-hack-accent border-hack-accent/30 bg-hack-accent/5" : "text-hack-dim border-hack-border"}`}>
                CORPUS {ev.enrichmentActive ? "ON" : "OFF"}
              </span>
            )}
            {ev.durationMs && ev.durationMs > 0 && (
              <span className="text-[9px] text-hack-dim font-mono ml-auto">
                {ev.durationMs < 1000 ? `${ev.durationMs}ms` : `${(ev.durationMs / 1000).toFixed(1)}s`}
              </span>
            )}
            {!isDecision && (expanded
              ? <ChevronDown className="w-3 h-3 text-hack-dim" />
              : <ChevronRight className="w-3 h-3 text-hack-dim" />)}
          </div>

          {isDecision && ev.summary && (
            <div className="text-[10px] text-hack-dim mt-0.5 leading-relaxed">{ev.summary}</div>
          )}

          {ev.phase === "thinking" && ev.context && !expanded && (
            <div className="text-[9px] text-hack-dim mt-0.5">
              {ev.context.observations} obs · {ev.context.hypotheses} hyp · iter {ev.context.iteration}
            </div>
          )}

          {ev.phase === "complete" && !expanded && ev.generatedCount !== undefined && (
            <div className="text-[9px] text-hack-dim mt-0.5">{ev.generatedCount} hypotheses generated</div>
          )}
        </div>
      </button>

      {expanded && ev.phase === "thinking" && ev.corpusEntries && ev.corpusEntries.length > 0 && (
        <div className="mt-1.5 space-y-1">
          <div className="text-[9px] text-hack-dim font-mono uppercase tracking-wide px-1 flex items-center gap-2">
            <span>Corpus entries injected ({ev.corpusEntries.length})</span>
            {ev.corpusEntries[0].mode === 'keyword' && (
              <span className="text-hack-yellow text-[8px] border border-hack-yellow/30 rounded px-1">KEYWORD FALLBACK</span>
            )}
          </div>
          <div className="space-y-0.5 px-1">
            {ev.corpusEntries.map((entry, i) => {
              const pct = entry.score !== null ? Math.round(entry.score * 100) : null;
              const barColor = pct === null ? 'bg-hack-dim' : pct >= 70 ? 'bg-hack-accent' : pct >= 50 ? 'bg-hack-yellow' : 'bg-hack-red';
              const scoreLabel = pct !== null ? `${pct}%` : 'kw';
              return (
                <div key={i} className="flex items-center gap-1.5 py-0.5">
                  <span className="text-[8px] text-hack-dim w-3 text-right flex-shrink-0">{i + 1}</span>
                  <div className="w-12 flex-shrink-0">
                    <div className="flex items-center gap-0.5">
                      <div className="flex-1 h-1 bg-hack-muted rounded overflow-hidden">
                        <div className={`h-full rounded ${barColor}`} style={{ width: pct !== null ? `${pct}%` : '30%' }} />
                      </div>
                      <span className={`text-[8px] font-mono w-5 text-right flex-shrink-0 ${pct !== null && pct < 50 ? 'text-hack-red' : 'text-hack-dim'}`}>{scoreLabel}</span>
                    </div>
                  </div>
                  <span className="text-[8px] text-hack-blue font-mono flex-shrink-0 max-w-[60px] truncate">{entry.category}</span>
                  <span className="text-[9px] text-hack-text truncate flex-1">{entry.title}</span>
                </div>
              );
            })}
          </div>
          {ev.corpusEntries.some(e => e.score !== null && e.score < 0.45) && (
            <div className="text-[8px] text-hack-red font-mono px-1">
              ⚠ Some entries below 0.45 threshold — low relevance (threshold relaxed, context sparse)
            </div>
          )}
        </div>
      )}

      {expanded && ev.phase === "thinking" && ev.promptPreview && (
        <div className="mt-1.5 space-y-1">
          <div className="text-[9px] text-hack-dim font-mono uppercase tracking-wide px-1">Context sent to model</div>
          <pre className="text-[9px] text-hack-dim bg-hack-muted rounded p-1.5 overflow-x-auto max-h-32 font-mono leading-tight whitespace-pre-wrap">
            {ev.promptPreview}
          </pre>
        </div>
      )}

      {expanded && ev.phase === "complete" && ev.rawResponse && (
        <div className="mt-1.5 space-y-1.5">
          {parsed ? (
            <>
              <div className="text-[9px] text-hack-dim font-mono uppercase tracking-wide px-1">Chain of thought</div>
              <pre className="text-[9px] text-hack-dim italic bg-hack-muted rounded p-1.5 overflow-x-auto max-h-40 font-mono leading-tight whitespace-pre-wrap">
                {parsed.thinking.slice(0, 1200)}
              </pre>
              <div className="text-[9px] text-hack-accent font-mono uppercase tracking-wide px-1">Decision</div>
              <pre className="text-[9px] text-hack-text bg-hack-muted rounded p-1.5 overflow-x-auto max-h-32 font-mono leading-tight whitespace-pre-wrap">
                {parsed.answer.slice(0, 1000)}
              </pre>
            </>
          ) : (
            <>
              <div className="text-[9px] text-hack-dim font-mono uppercase tracking-wide px-1">Model response</div>
              <pre className="text-[9px] text-hack-text bg-hack-muted rounded p-1.5 overflow-x-auto max-h-48 font-mono leading-tight whitespace-pre-wrap">
                {ev.rawResponse.slice(0, 2000)}
              </pre>
            </>
          )}
        </div>
      )}
    </div>
  );
}

function ProbeStartRow({ ev, resolved }: { ev: ActivityEvent & { type: "probe_start" }; resolved: boolean }) {
  return (
    <div className={`flex items-center gap-2 py-0.5 text-[10px] font-mono ml-3 ${resolved ? "opacity-40" : ""}`}>
      <Target className={`w-3 h-3 text-hack-orange flex-shrink-0 ${!resolved ? "animate-pulse" : ""}`} />
      <span className="text-hack-dim">{ev.ts}</span>
      <span className="text-hack-text">→</span>
      <span className="text-hack-orange uppercase">{ev.vulnClass}</span>
      <span className="text-hack-dim truncate">#{ev.hypothesisId.slice(0, 8)}</span>
      {!resolved && <span className="text-hack-dim animate-pulse">…</span>}
    </div>
  );
}

function ProbeResultRow({ ev }: { ev: ActivityEvent & { type: "probe_result" } }) {
  const [expanded, setExpanded] = useState(false);
  const hasOutput = ev.output && ev.output.trim().length > 0;
  return (
    <div className="ml-6 my-0.5">
      <button
        disabled={!hasOutput}
        onClick={() => setExpanded(x => !x)}
        className={`flex items-center gap-2 text-[10px] font-mono w-full text-left ${hasOutput ? "cursor-pointer" : "cursor-default"}`}
      >
        {ev.success
          ? <CheckCircle2 className="w-3 h-3 text-hack-accent flex-shrink-0" />
          : <XCircle className="w-3 h-3 text-hack-red flex-shrink-0" />}
        <span className={ev.success ? "text-hack-accent" : "text-hack-red"}>
          {ev.success ? "✓" : "✗"}
        </span>
        <span className="text-hack-dim">{ev.tool}</span>
        {ev.proxyId && <ProxyRouteChip proxyId={ev.proxyId} />}
        <span className="text-hack-dim">
          {ev.durationMs < 1000 ? `${ev.durationMs}ms` : `${(ev.durationMs / 1000).toFixed(1)}s`}
        </span>
        {hasOutput && (expanded
          ? <ChevronDown className="w-3 h-3 text-hack-dim ml-auto" />
          : <ChevronRight className="w-3 h-3 text-hack-dim ml-auto" />)}
      </button>
      {expanded && hasOutput && (
        <pre className="mt-1 text-[9px] text-hack-dim bg-hack-muted rounded p-1.5 overflow-x-auto max-h-24 font-mono leading-tight">
          {ev.output.slice(0, 800)}
        </pre>
      )}
    </div>
  );
}

function FindingRow({ ev }: { ev: ActivityEvent & { type: "finding" | "solver_finding" } }) {
  const sev = ev.type === "finding" ? ev.severity : "info";
  const vc  = ev.vulnClass;
  const sevColor = SEVERITY_COLOR[sev] ?? SEVERITY_COLOR.info;
  const isSolver = ev.type === "solver_finding";
  return (
    <div className={`border rounded p-2 my-1.5 ${isSolver ? "border-hack-blue/40 bg-hack-blue/5" : "border-hack-orange/40 bg-hack-orange/5"}`}>
      <div className="flex items-center gap-2 flex-wrap">
        <Zap className={`w-3.5 h-3.5 flex-shrink-0 ${isSolver ? "text-hack-blue" : "text-hack-orange"}`} />
        <span className={`text-[10px] px-1.5 py-0.5 rounded border font-mono uppercase font-bold ${isSolver ? "text-hack-blue border-hack-blue/40 bg-hack-blue/10" : "text-hack-orange border-hack-orange/40 bg-hack-orange/10"}`}>
          {vc}
        </span>
        {isSolver && (
          <span className="text-[9px] px-1 py-0.5 rounded border border-hack-blue/30 text-hack-blue bg-hack-blue/10 font-mono">
            SOLVER
          </span>
        )}
        {ev.type === "finding" && (
          <span className={`text-[9px] px-1 py-0.5 rounded border font-mono uppercase ${sevColor}`}>
            {sev}
          </span>
        )}
        <span className="text-[9px] text-hack-dim ml-auto font-mono">{ev.ts}</span>
      </div>
      {ev.type === "finding" && <ConfidenceBar value={ev.confidence} />}
      {ev.type === "finding" && ev.payload && (
        <div className="mt-1 text-[9px] font-mono text-hack-dim bg-hack-muted rounded px-1.5 py-1 truncate">
          {ev.payload.slice(0, 120)}
        </div>
      )}
    </div>
  );
}

function VerifiedRow({ ev }: { ev: ActivityEvent & { type: "verified" | "rejected" } }) {
  return (
    <div className={`flex items-center gap-2 py-0.5 text-[10px] font-mono ml-3 ${ev.type === "verified" ? "text-hack-green" : "text-hack-dim"}`}>
      {ev.type === "verified"
        ? <CheckCircle2 className="w-3 h-3 flex-shrink-0" />
        : <XCircle className="w-3 h-3 flex-shrink-0" />}
      <span>{ev.type === "verified" ? "✓ verified" : "✗ rejected"}</span>
      <span className="text-hack-dim">#{ev.findingId} · {ev.verdict}</span>
    </div>
  );
}

function PivotRow({ ev }: { ev: ActivityEvent & { type: "pivot" } }) {
  return (
    <div className="border border-hack-purple/30 bg-hack-purple/5 rounded p-2 my-1">
      <div className="flex items-center gap-2 text-[10px] font-mono">
        <RefreshCw className="w-3 h-3 text-hack-purple" />
        <span className="text-hack-purple font-bold">Strategy pivot</span>
        <span className="text-hack-dim">+{ev.newHypotheses} new hypotheses</span>
        <span className="text-hack-dim ml-auto">{ev.ts}</span>
      </div>
      <div className="text-[10px] text-hack-dim mt-0.5 ml-5">{ev.reason}</div>
    </div>
  );
}

function BanRow({ ev }: { ev: ActivityEvent & { type: "ban" } }) {
  return (
    <div className="border border-hack-orange/40 bg-hack-orange/5 rounded p-2 my-1">
      <div className="flex items-center gap-2 text-[10px] font-mono">
        <AlertTriangle className="w-3.5 h-3.5 text-hack-orange flex-shrink-0" />
        <span className="text-hack-orange font-bold">Hard IP ban detected</span>
        <span className="text-hack-dim ml-auto">{ev.ts}</span>
      </div>
      <div className="text-[10px] text-hack-dim mt-0.5 ml-5">
        <span className="text-hack-text">{ev.target}</span> — {ev.reason}
      </div>
    </div>
  );
}

function CompleteRow({ ev }: { ev: ActivityEvent & { type: "complete" } }) {
  return (
    <div className="flex items-center gap-2 py-1 text-[10px] font-mono text-hack-accent border-t border-hack-border mt-1 pt-2">
      <CheckCircle2 className="w-3 h-3" />
      <span>Hunt complete</span>
      <span className="text-hack-yellow">{ev.findings} findings</span>
      <span className="text-hack-dim">· {ev.iterations} iterations</span>
      <span className="text-hack-dim ml-auto">{ev.ts}</span>
    </div>
  );
}

function CveSeededRow({ ev }: { ev: ActivityEvent & { type: "cve_seeded" } }) {
  const isCritical = ev.maxCvss >= 9.0;
  const isHigh = ev.maxCvss >= 7.0;
  const scoreColor = isCritical ? "text-hack-red" : isHigh ? "text-hack-orange" : "text-hack-yellow";
  const chipClass = isCritical
    ? "border-hack-red/40 text-hack-red bg-hack-red/10"
    : isHigh
    ? "border-hack-orange/40 text-hack-orange bg-hack-orange/10"
    : "border-hack-yellow/40 text-hack-yellow bg-hack-yellow/10";
  return (
    <div className="border border-hack-cyan/30 bg-hack-cyan/5 rounded p-2 my-1">
      <div className="flex items-center gap-2 text-[10px] font-mono flex-wrap">
        <Shield className="w-3.5 h-3.5 text-hack-cyan flex-shrink-0" />
        <span className="text-hack-cyan font-bold">CVE seeded</span>
        <span className="text-[9px] px-1.5 py-0.5 rounded border border-hack-cyan/30 text-hack-cyan bg-hack-cyan/10 font-mono">
          {ev.tech}
        </span>
        <span className={`text-[9px] font-bold ml-auto font-mono ${scoreColor}`}>
          CVSS {ev.maxCvss.toFixed(1)}
        </span>
        <span className="text-hack-dim">{ev.ts}</span>
      </div>
      <div className="flex flex-wrap gap-1 mt-1 ml-5">
        {ev.cveIds.slice(0, 5).map(cve => (
          <span key={cve} className={`text-[9px] px-1 py-0.5 rounded border font-mono ${chipClass}`}>
            {cve}
          </span>
        ))}
      </div>
    </div>
  );
}

function PublicDuplicateRow({ ev }: { ev: ActivityEvent & { type: "public_duplicate" } }) {
  const isWarn = ev.warn;
  return (
    <div className={`border rounded p-2 my-1 ${isWarn ? "border-hack-yellow/40 bg-hack-yellow/5" : "border-hack-orange/50 bg-hack-orange/8"}`}>
      <div className="flex items-center gap-2 text-[10px] font-mono">
        <AlertTriangle className={`w-3.5 h-3.5 flex-shrink-0 ${isWarn ? "text-hack-yellow" : "text-hack-orange"}`} />
        <span className={isWarn ? "text-hack-yellow" : "text-hack-orange"}>
          {isWarn ? "Likely duplicate" : "Public duplicate — skipped"}
        </span>
        <span className="text-[9px] px-1 py-0.5 rounded border border-hack-dim/30 text-hack-dim font-mono">{ev.platform}</span>
        <span className="text-hack-dim ml-auto">{ev.ts}</span>
      </div>
      <div className="text-[10px] text-hack-dim mt-0.5 ml-5 flex items-center gap-1.5">
        <span className="text-hack-text uppercase font-mono">{ev.vulnClass}</span>
        {ev.title && <span className="truncate">— {ev.title}</span>}
      </div>
      {ev.reportUrl && (
        <div className="text-[9px] text-hack-cyan mt-0.5 ml-5 truncate font-mono">{ev.reportUrl}</div>
      )}
    </div>
  );
}

function OobHitRow({ ev }: { ev: ActivityEvent & { type: "oob_hit" } }) {
  return (
    <div className="border border-hack-red/40 bg-hack-red/5 rounded p-2 my-1">
      <div className="flex items-center gap-2 text-[10px] font-mono flex-wrap">
        <Wifi className="w-3.5 h-3.5 text-hack-red flex-shrink-0 animate-pulse" />
        <span className="text-hack-red font-bold">OOB callback received</span>
        <span className="text-[9px] px-1 py-0.5 rounded border border-hack-red/30 text-hack-dim font-mono truncate max-w-[120px]">
          {ev.beaconId.slice(0, 8)}…
        </span>
        <span className="text-hack-dim ml-auto">{ev.ts}</span>
      </div>
      <div className="text-[9px] text-hack-dim mt-0.5 ml-5 font-mono">from {ev.ip}</div>
    </div>
  );
}

function TargetsExpandedRow({ ev }: { ev: ActivityEvent & { type: "targets_expanded" } }) {
  const [expanded, setExpanded] = useState(false);
  return (
    <div className="border border-hack-blue/40 bg-hack-blue/5 rounded p-2 my-1">
      <button onClick={() => setExpanded(x => !x)} className="flex items-center gap-2 text-[10px] font-mono w-full text-left">
        <Globe className="w-3.5 h-3.5 text-hack-blue flex-shrink-0" />
        <span className="text-hack-blue font-bold">Targets expanded</span>
        <span className="text-[9px] px-1.5 py-0.5 rounded border border-hack-blue/30 text-hack-blue bg-hack-blue/10 font-mono">
          {ev.count} {ev.count === 1 ? "target" : "targets"}
        </span>
        {ev.count > 1 && (expanded
          ? <ChevronDown className="w-3 h-3 text-hack-dim ml-auto" />
          : <ChevronRight className="w-3 h-3 text-hack-dim ml-auto" />)}
      </button>
      {expanded && ev.targets.slice(1).length > 0 && (
        <div className="mt-1 ml-5 space-y-0.5">
          {ev.targets.slice(1, 8).map(t => (
            <div key={t} className="text-[9px] text-hack-dim font-mono truncate">{t}</div>
          ))}
          {ev.targets.length > 9 && (
            <div className="text-[9px] text-hack-dim">…and {ev.targets.length - 9} more</div>
          )}
        </div>
      )}
    </div>
  );
}

function GraphqlSchemaRow({ ev }: { ev: ActivityEvent & { type: "graphql_schema" } }) {
  return (
    <div className="border border-hack-purple/40 bg-hack-purple/5 rounded p-2 my-1">
      <div className="flex items-center gap-2 text-[10px] font-mono flex-wrap">
        <Code className="w-3.5 h-3.5 text-hack-purple flex-shrink-0" />
        <span className="text-hack-purple font-bold">GraphQL schema mapped</span>
        <span className="text-[9px] px-1.5 py-0.5 rounded border border-hack-purple/30 text-hack-purple bg-hack-purple/10 font-mono">
          {ev.typeCount} types
        </span>
        {ev.injectableCount > 0 && (
          <span className="text-[9px] px-1.5 py-0.5 rounded border border-hack-orange/30 text-hack-orange bg-hack-orange/10 font-mono">
            {ev.injectableCount} injectable
          </span>
        )}
        <span className="text-hack-dim ml-auto">{ev.ts}</span>
      </div>
      <div className="text-[9px] text-hack-dim mt-0.5 ml-5 font-mono truncate">{ev.endpoint}</div>
    </div>
  );
}

function SSRFPivotRow({ ev }: { ev: ActivityEvent & { type: "ssrf_pivot" } }) {
  const [expanded, setExpanded] = useState(false);
  return (
    <div className="border border-hack-red/50 bg-hack-red/5 rounded p-2 my-1">
      <button onClick={() => setExpanded(x => !x)} className="flex items-center gap-2 text-[10px] font-mono w-full text-left">
        <Target className="w-3.5 h-3.5 text-hack-red flex-shrink-0" />
        <span className="text-hack-red font-bold">SSRF pivot</span>
        {ev.cloudMeta && (
          <span className="text-[9px] px-1.5 py-0.5 rounded border border-hack-red/40 text-hack-red bg-hack-red/10 font-mono animate-pulse">
            CLOUD METADATA
          </span>
        )}
        <span className="text-[9px] px-1.5 py-0.5 rounded border border-hack-orange/30 text-hack-orange bg-hack-orange/10 font-mono ml-auto">
          {ev.reachable.length} endpoints · +{ev.newHypotheses} hyp
        </span>
        <span className="text-hack-dim">{ev.ts}</span>
      </button>
      {expanded && ev.reachable.length > 0 && (
        <div className="mt-1 ml-5 space-y-0.5">
          {ev.reachable.slice(0, 6).map(r => (
            <div key={r} className="text-[9px] text-hack-dim font-mono">{r}</div>
          ))}
        </div>
      )}
    </div>
  );
}

function ReportSubmittedRow({ ev }: { ev: ActivityEvent & { type: "report_submitted" } }) {
  return (
    <div className="border border-hack-green/40 bg-hack-green/5 rounded p-2 my-1">
      <div className="flex items-center gap-2 text-[10px] font-mono flex-wrap">
        <CheckCircle2 className="w-3.5 h-3.5 text-hack-green flex-shrink-0" />
        <span className="text-hack-green font-bold">Report submitted</span>
        <span className="text-[9px] px-1.5 py-0.5 rounded border border-hack-green/30 text-hack-green bg-hack-green/10 font-mono uppercase">
          {ev.platform}
        </span>
        {ev.reportId && (
          <span className="text-[9px] text-hack-dim font-mono">#{ev.reportId}</span>
        )}
        <span className="text-hack-dim ml-auto">{ev.ts}</span>
      </div>
      {ev.reportUrl && (
        <div className="text-[9px] text-hack-cyan mt-0.5 ml-5 font-mono truncate">{ev.reportUrl}</div>
      )}
    </div>
  );
}

function ChangesDetectedRow({ ev }: { ev: ActivityEvent & { type: "changes_detected" } }) {
  const [expanded, setExpanded] = useState(false);
  return (
    <div className="border border-hack-yellow/40 bg-hack-yellow/5 rounded p-2 my-1">
      <button onClick={() => setExpanded(x => !x)} className="flex items-center gap-2 text-[10px] font-mono w-full text-left">
        <RefreshCw className="w-3.5 h-3.5 text-hack-yellow flex-shrink-0" />
        <span className="text-hack-yellow font-bold">Target changes detected</span>
        {ev.newEndpoints.length > 0 && (
          <span className="text-[9px] px-1.5 py-0.5 rounded border border-hack-yellow/30 text-hack-yellow bg-hack-yellow/10 font-mono">
            {ev.newEndpoints.length} new
          </span>
        )}
        {ev.changed > 0 && (
          <span className="text-[9px] px-1.5 py-0.5 rounded border border-hack-orange/30 text-hack-orange bg-hack-orange/10 font-mono">
            {ev.changed} changed
          </span>
        )}
        <span className="text-hack-dim ml-auto">{ev.ts}</span>
      </button>
      {expanded && ev.newEndpoints.length > 0 && (
        <div className="mt-1 ml-5 space-y-0.5">
          {ev.newEndpoints.slice(0, 5).map(ep => (
            <div key={ep} className="text-[9px] text-hack-dim font-mono truncate">+ {ep}</div>
          ))}
        </div>
      )}
    </div>
  );
}

function WSVulnsRow({ ev }: { ev: ActivityEvent & { type: "ws_vulns" } }) {
  return (
    <div className="border border-hack-cyan/40 bg-hack-cyan/5 rounded p-2 my-1">
      <div className="flex items-center gap-2 text-[10px] font-mono flex-wrap">
        <Wifi className="w-3.5 h-3.5 text-hack-cyan flex-shrink-0" />
        <span className="text-hack-cyan font-bold">WebSocket vulns found</span>
        <span className="text-[9px] px-1.5 py-0.5 rounded border border-hack-cyan/30 text-hack-cyan bg-hack-cyan/10 font-mono">
          {ev.count} {ev.count === 1 ? "issue" : "issues"}
        </span>
        <span className="text-hack-dim ml-auto">{ev.ts}</span>
      </div>
      <div className="flex flex-wrap gap-1 mt-1 ml-5">
        {ev.issues.map(i => (
          <span key={i} className="text-[9px] px-1 py-0.5 rounded border border-hack-orange/30 text-hack-orange bg-hack-orange/10 font-mono">{i}</span>
        ))}
      </div>
    </div>
  );
}

function BucketExposedRow({ ev }: { ev: ActivityEvent & { type: "bucket_exposed" } }) {
  return (
    <div className="border border-hack-red/50 bg-hack-red/8 rounded p-2 my-1">
      <div className="flex items-center gap-2 text-[10px] font-mono flex-wrap">
        <Server className="w-3.5 h-3.5 text-hack-red flex-shrink-0 animate-pulse" />
        <span className="text-hack-red font-bold">Cloud bucket exposed</span>
        <span className="text-[9px] px-1.5 py-0.5 rounded border border-hack-red/40 text-hack-red bg-hack-red/10 font-mono">
          {ev.buckets.length} {ev.buckets.length === 1 ? "bucket" : "buckets"}
        </span>
        <span className="text-hack-dim ml-auto">{ev.ts}</span>
      </div>
      <div className="mt-1 ml-5 space-y-0.5">
        {ev.buckets.slice(0, 3).map(b => (
          <div key={b.url} className="text-[9px] font-mono text-hack-dim">
            <span className="text-hack-text">{b.url}</span>
            <span className="text-hack-orange ml-1">[{b.provider}]</span>
            {b.listable && <span className="text-hack-red ml-1 font-bold">LISTABLE</span>}
          </div>
        ))}
      </div>
    </div>
  );
}

function ProtoPollutionRow({ ev }: { ev: ActivityEvent & { type: "proto_pollution" } }) {
  return (
    <div className="border border-hack-purple/40 bg-hack-purple/5 rounded p-2 my-1">
      <div className="flex items-center gap-2 text-[10px] font-mono flex-wrap">
        <Code className="w-3.5 h-3.5 text-hack-purple flex-shrink-0" />
        <span className="text-hack-purple font-bold">Prototype pollution</span>
        {ev.reflected && (
          <span className="text-[9px] px-1.5 py-0.5 rounded border border-hack-red/40 text-hack-red bg-hack-red/10 font-mono animate-pulse">
            REFLECTED
          </span>
        )}
        <span className="text-[9px] px-1.5 py-0.5 rounded border border-hack-purple/30 text-hack-purple bg-hack-purple/10 font-mono">
          {ev.count} {ev.count === 1 ? "payload" : "payloads"}
        </span>
        <span className="text-hack-dim ml-auto">{ev.ts}</span>
      </div>
    </div>
  );
}

function RaceConditionRow({ ev }: { ev: ActivityEvent & { type: "race_condition" } }) {
  return (
    <div className="border border-hack-orange/50 bg-hack-orange/5 rounded p-2 my-1">
      <div className="flex items-center gap-2 text-[10px] font-mono flex-wrap">
        <RefreshCw className="w-3.5 h-3.5 text-hack-orange flex-shrink-0 animate-spin" />
        <span className="text-hack-orange font-bold">Race condition detected</span>
        <span className="text-[9px] px-1.5 py-0.5 rounded border border-hack-orange/40 text-hack-orange bg-hack-orange/10 font-mono">
          {ev.count} endpoint{ev.count !== 1 ? "s" : ""}
        </span>
        <span className="text-hack-dim ml-auto">{ev.ts}</span>
      </div>
      {ev.endpoints.length > 0 && (
        <div className="mt-1 ml-5 text-[9px] font-mono text-hack-dim truncate">{ev.endpoints[0]}</div>
      )}
    </div>
  );
}

function SecretsFoundRow({ ev }: { ev: ActivityEvent & { type: "secrets_found" } }) {
  return (
    <div className="border border-hack-red/50 bg-hack-red/8 rounded p-2 my-1">
      <div className="flex items-center gap-2 text-[10px] font-mono flex-wrap">
        <AlertTriangle className="w-3.5 h-3.5 text-hack-red flex-shrink-0 animate-pulse" />
        <span className="text-hack-red font-bold">Secrets found</span>
        <span className="text-[9px] px-1.5 py-0.5 rounded border border-hack-red/40 text-hack-red bg-hack-red/10 font-mono">
          {ev.count} {ev.count === 1 ? "match" : "matches"}
        </span>
        <span className="text-hack-dim ml-auto">{ev.ts}</span>
      </div>
      <div className="flex flex-wrap gap-1 mt-1 ml-5">
        {ev.types.slice(0, 6).map(t => (
          <span key={t} className="text-[9px] px-1 py-0.5 rounded border border-hack-orange/30 text-hack-orange bg-hack-orange/10 font-mono">
            {t}
          </span>
        ))}
      </div>
    </div>
  );
}

function TakeoverFoundRow({ ev }: { ev: ActivityEvent & { type: "takeover_found" } }) {
  return (
    <div className="border border-hack-orange/50 bg-hack-orange/5 rounded p-2 my-1">
      <div className="flex items-center gap-2 text-[10px] font-mono flex-wrap">
        <Globe className="w-3.5 h-3.5 text-hack-orange flex-shrink-0" />
        <span className="text-hack-orange font-bold">Subdomain takeover</span>
        <span className="text-[9px] px-1.5 py-0.5 rounded border border-hack-orange/40 text-hack-orange bg-hack-orange/10 font-mono">
          {ev.targets.length} vulnerable
        </span>
        <span className="text-hack-dim ml-auto">{ev.ts}</span>
      </div>
      <div className="mt-1 ml-5 space-y-0.5">
        {ev.targets.slice(0, 4).map(t => (
          <div key={t.subdomain} className="text-[9px] font-mono text-hack-dim">
            <span className="text-hack-text">{t.subdomain}</span> → <span className="text-hack-orange">{t.service}</span>
            <span className="text-hack-dim ml-1">({Math.round(t.confidence * 100)}%)</span>
          </div>
        ))}
      </div>
    </div>
  );
}

function TechPayloadsRow({ ev }: { ev: ActivityEvent & { type: "tech_payloads" } }) {
  return (
    <div className="border border-hack-blue/30 bg-hack-blue/5 rounded p-2 my-1">
      <div className="flex items-center gap-2 text-[10px] font-mono flex-wrap">
        <Code className="w-3.5 h-3.5 text-hack-blue flex-shrink-0" />
        <span className="text-hack-blue font-bold">Tech payloads selected</span>
        <span className="text-[9px] px-1.5 py-0.5 rounded border border-hack-blue/30 text-hack-blue bg-hack-blue/10 font-mono">
          {ev.payloadCount} payloads
        </span>
        <span className="text-hack-dim ml-auto">{ev.ts}</span>
      </div>
      <div className="flex flex-wrap gap-1 mt-1 ml-5">
        {ev.techs.slice(0, 6).map(t => (
          <span key={t} className="text-[9px] px-1 py-0.5 rounded border border-hack-dim/30 text-hack-dim bg-hack-muted font-mono">{t}</span>
        ))}
      </div>
    </div>
  );
}

function ParamsDiscoveredRow({ ev }: { ev: ActivityEvent & { type: "params_discovered" } }) {
  const [expanded, setExpanded] = useState(false);
  return (
    <div className="border border-hack-yellow/30 bg-hack-yellow/5 rounded p-2 my-1">
      <button onClick={() => setExpanded(x => !x)} className="flex items-center gap-2 text-[10px] font-mono w-full text-left">
        <Target className="w-3.5 h-3.5 text-hack-yellow flex-shrink-0" />
        <span className="text-hack-yellow font-bold">Parameters discovered</span>
        <span className="text-[9px] px-1.5 py-0.5 rounded border border-hack-yellow/30 text-hack-yellow bg-hack-yellow/10 font-mono">
          {ev.count} params
        </span>
        {ev.params.length > 0 && (expanded ? <ChevronDown className="w-3 h-3 text-hack-dim ml-auto" /> : <ChevronRight className="w-3 h-3 text-hack-dim ml-auto" />)}
      </button>
      {expanded && ev.params.length > 0 && (
        <div className="flex flex-wrap gap-1 mt-1 ml-5">
          {ev.params.map(p => (
            <span key={p} className="text-[9px] px-1 py-0.5 rounded border border-hack-yellow/30 text-hack-yellow bg-hack-yellow/10 font-mono">{p}</span>
          ))}
        </div>
      )}
    </div>
  );
}

function OAuthVulnsRow({ ev }: { ev: ActivityEvent & { type: "oauth_vulns" } }) {
  return (
    <div className="border border-hack-orange/40 bg-hack-orange/5 rounded p-2 my-1">
      <div className="flex items-center gap-2 text-[10px] font-mono flex-wrap">
        <Shield className="w-3.5 h-3.5 text-hack-orange flex-shrink-0" />
        <span className="text-hack-orange font-bold">OAuth misconfiguration</span>
        <span className="text-[9px] px-1.5 py-0.5 rounded border border-hack-orange/40 text-hack-orange bg-hack-orange/10 font-mono">
          {ev.count} {ev.count === 1 ? "issue" : "issues"}
        </span>
        <span className="text-hack-dim ml-auto">{ev.ts}</span>
      </div>
      <div className="flex flex-wrap gap-1 mt-1 ml-5">
        {ev.issues.map(i => (
          <span key={i} className="text-[9px] px-1 py-0.5 rounded border border-hack-orange/30 text-hack-orange bg-hack-orange/10 font-mono">{i}</span>
        ))}
      </div>
    </div>
  );
}

function MassAssignmentRow({ ev }: { ev: ActivityEvent & { type: "mass_assignment" } }) {
  return (
    <div className="border border-hack-red/40 bg-hack-red/5 rounded p-2 my-1">
      <div className="flex items-center gap-2 text-[10px] font-mono flex-wrap">
        <AlertTriangle className="w-3.5 h-3.5 text-hack-red flex-shrink-0" />
        <span className="text-hack-red font-bold">Mass assignment</span>
        <span className="text-[9px] px-1.5 py-0.5 rounded border border-hack-red/40 text-hack-red bg-hack-red/10 font-mono">
          {ev.count} endpoint{ev.count !== 1 ? "s" : ""}
        </span>
        <span className="text-hack-dim ml-auto">{ev.ts}</span>
      </div>
      {ev.endpoints.length > 0 && (
        <div className="text-[9px] text-hack-dim mt-0.5 ml-5 font-mono truncate">{ev.endpoints[0]}</div>
      )}
    </div>
  );
}

function BusinessLogicRow({ ev }: { ev: ActivityEvent & { type: "business_logic" } }) {
  return (
    <div className="border border-hack-orange/40 bg-hack-orange/5 rounded p-2 my-1">
      <div className="flex items-center gap-2 text-[10px] font-mono flex-wrap">
        <Zap className="w-3.5 h-3.5 text-hack-orange flex-shrink-0" />
        <span className="text-hack-orange font-bold">Business logic flaw</span>
        <span className="text-[9px] px-1.5 py-0.5 rounded border border-hack-orange/30 text-hack-orange bg-hack-orange/10 font-mono">
          {ev.count} {ev.count === 1 ? "issue" : "issues"}
        </span>
        <span className="text-hack-dim ml-auto">{ev.ts}</span>
      </div>
      <div className="flex flex-wrap gap-1 mt-1 ml-5">
        {ev.types.map(t => (
          <span key={t} className="text-[9px] px-1 py-0.5 rounded border border-hack-orange/30 text-hack-orange bg-hack-orange/10 font-mono">{t}</span>
        ))}
      </div>
    </div>
  );
}

function TwoFABypassRow({ ev }: { ev: ActivityEvent & { type: "two_fa_bypass" } }) {
  return (
    <div className="border border-hack-red/50 bg-hack-red/8 rounded p-2 my-1">
      <div className="flex items-center gap-2 text-[10px] font-mono flex-wrap">
        <Shield className="w-3.5 h-3.5 text-hack-red flex-shrink-0 animate-pulse" />
        <span className="text-hack-red font-bold">2FA bypass found</span>
        <span className="text-[9px] px-1.5 py-0.5 rounded border border-hack-red/40 text-hack-red bg-hack-red/10 font-mono">
          {ev.count} technique{ev.count !== 1 ? "s" : ""}
        </span>
        <span className="text-hack-dim ml-auto">{ev.ts}</span>
      </div>
      <div className="flex flex-wrap gap-1 mt-1 ml-5">
        {ev.techniques.map(t => (
          <span key={t} className="text-[9px] px-1 py-0.5 rounded border border-hack-red/30 text-hack-red bg-hack-red/10 font-mono">{t}</span>
        ))}
      </div>
    </div>
  );
}

function JWTVulnsRow({ ev }: { ev: ActivityEvent & { type: "jwt_vulns" } }) {
  return (
    <div className="border border-hack-purple/40 bg-hack-purple/5 rounded p-2 my-1">
      <div className="flex items-center gap-2 text-[10px] font-mono flex-wrap">
        <Code className="w-3.5 h-3.5 text-hack-purple flex-shrink-0" />
        <span className="text-hack-purple font-bold">JWT vulnerability</span>
        <span className="text-[9px] px-1.5 py-0.5 rounded border border-hack-purple/30 text-hack-purple bg-hack-purple/10 font-mono">
          {ev.count} issue{ev.count !== 1 ? "s" : ""}
        </span>
        <span className="text-hack-dim ml-auto">{ev.ts}</span>
      </div>
      <div className="flex flex-wrap gap-1 mt-1 ml-5">
        {ev.techniques.map(t => (
          <span key={t} className="text-[9px] px-1 py-0.5 rounded border border-hack-purple/30 text-hack-purple bg-hack-purple/10 font-mono">{t}</span>
        ))}
      </div>
    </div>
  );
}

function OpenRedirectRow({ ev }: { ev: ActivityEvent & { type: "open_redirect" } }) {
  return (
    <div className="border border-hack-yellow/40 bg-hack-yellow/5 rounded p-2 my-1">
      <div className="flex items-center gap-2 text-[10px] font-mono flex-wrap">
        <Globe className="w-3.5 h-3.5 text-hack-yellow flex-shrink-0" />
        <span className="text-hack-yellow font-bold">Open redirect</span>
        <span className="text-[9px] px-1.5 py-0.5 rounded border border-hack-yellow/30 text-hack-yellow bg-hack-yellow/10 font-mono">
          {ev.count} found
        </span>
        {ev.chained > 0 && (
          <span className="text-[9px] px-1.5 py-0.5 rounded border border-hack-red/30 text-hack-red bg-hack-red/10 font-mono">
            {ev.chained} chained
          </span>
        )}
        <span className="text-hack-dim ml-auto">{ev.ts}</span>
      </div>
    </div>
  );
}

function ZapScanRow({ ev }: { ev: ActivityEvent & { type: "zap_scan" } }) {
  return (
    <div className="border border-hack-green/30 bg-hack-green/5 rounded p-2 my-1">
      <div className="flex items-center gap-2 text-[10px] font-mono flex-wrap">
        <Shield className="w-3.5 h-3.5 text-hack-green flex-shrink-0" />
        <span className="text-hack-green font-bold">ZAP passive scan</span>
        <span className="text-[9px] px-1.5 py-0.5 rounded border border-hack-green/30 text-hack-green bg-hack-green/10">
          {ev.alertCount} alert{ev.alertCount !== 1 ? "s" : ""}
        </span>
        {ev.hypothesesSeeded > 0 && (
          <span className="text-[9px] px-1.5 py-0.5 rounded border border-hack-blue/30 text-hack-blue bg-hack-blue/10">
            +{ev.hypothesesSeeded} hypothesis{ev.hypothesesSeeded !== 1 ? "es" : ""}
          </span>
        )}
        {ev.endpointsDiscovered > 0 && (
          <span className="text-[9px] px-1.5 py-0.5 rounded border border-hack-dim/30 text-hack-dim">
            {ev.endpointsDiscovered} endpoints
          </span>
        )}
        <span className="text-hack-dim ml-auto text-[9px]">{(ev.duration / 1000).toFixed(1)}s</span>
        <span className="text-hack-dim">{ev.ts}</span>
      </div>
    </div>
  );
}

function XXEFoundRow({ ev }: { ev: ActivityEvent & { type: "xxe_found" } }) {
  return (
    <div className="border border-hack-red/40 bg-hack-red/5 rounded p-2 my-1">
      <div className="flex items-center gap-2 text-[10px] font-mono flex-wrap">
        <Target className="w-3.5 h-3.5 text-hack-red flex-shrink-0" />
        <span className="text-hack-red font-bold">XXE found</span>
        {ev.oobConfirmed && (
          <span className="text-[9px] px-1.5 py-0.5 rounded border border-hack-red/40 text-hack-red bg-hack-red/10 font-mono animate-pulse">
            OOB CONFIRMED
          </span>
        )}
        <span className="text-[9px] px-1.5 py-0.5 rounded border border-hack-red/30 text-hack-red bg-hack-red/10 font-mono ml-auto">
          {ev.count} vector{ev.count !== 1 ? "s" : ""}
        </span>
        <span className="text-hack-dim">{ev.ts}</span>
      </div>
    </div>
  );
}

function ErrorRow({ ev }: { ev: ActivityEvent & { type: "error" } }) {
  return (
    <div className="flex items-center gap-2 py-0.5 text-[10px] font-mono text-hack-red">
      <AlertTriangle className="w-3 h-3 flex-shrink-0" />
      <span className="text-hack-dim">{ev.ts}</span>
      <span>{ev.message}</span>
    </div>
  );
}

// ── Main component ─────────────────────────────────────────────────────────────

// Memoized variants of the heaviest rows so they don't re-render when unrelated
// feed state (e.g. the scanning indicator) changes. Each row's `ev` prop is a
// stable object reference, so memo skips re-render across parent updates.
const HypothesisRowMemo = memo(HypothesisRow);
const ProbeResultRowMemo = memo(ProbeResultRow);
const AIReasoningRowMemo = memo(AIReasoningRow);

export function LiveActivityFeed({
  events,
  isRunning,
  maxEvents = 150,
  title = "EXECUTION STREAM",
}: LiveActivityFeedProps) {
  const scrollRef = useRef<HTMLDivElement>(null);
  const lastEventTsRef = useRef<number>(0);
  const [showScanning, setShowScanning] = useState(false);

  const visible = useMemo(() => events.slice(-maxEvents), [events, maxEvents]);
  const truncated = events.length > maxEvents;

  // Auto-scroll
  useEffect(() => {
    if (scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
    }
  }, [events.length]);

  // Record the time of the most recent event in a ref (no re-render / no interval churn)
  useEffect(() => {
    if (events.length > 0) {
      lastEventTsRef.current = Date.now();
      setShowScanning(false);
    }
  }, [events.length]);

  // Show scanning indicator when running but no new events for 3s.
  // Interval is created once per run (reads the ref) so it isn't recreated per event.
  useEffect(() => {
    if (!isRunning) { setShowScanning(false); return; }
    const t = setInterval(() => {
      setShowScanning(Date.now() - lastEventTsRef.current > 3000);
    }, 1000);
    return () => clearInterval(t);
  }, [isRunning]);

  // Track resolved probe IDs for fading the probe_start row
  const resolvedProbes = useMemo(
    () => new Set(
      visible.filter(e => e.type === "probe_result").map(e => (e as any).hypothesisId as string)
    ),
    [visible]
  );

  return (
    <div className="flex flex-col h-full overflow-hidden bg-hack-bg">
      {/* Header */}
      <div className="flex items-center gap-2 px-3 py-2 border-b border-hack-border bg-hack-surface flex-shrink-0">
        <Server className="w-3 h-3 text-hack-dim" strokeWidth={1.5} />
        <span className="text-[10px] font-mono text-hack-dim tracking-widest">{title}</span>
        {isRunning && (
          <span className="ml-auto flex items-center gap-1 text-[9px] text-hack-accent font-mono">
            <RefreshCw className="w-2.5 h-2.5 animate-spin" />
            LIVE
          </span>
        )}
        {!isRunning && events.length > 0 && (
          <span className="ml-auto text-[9px] text-hack-dim font-mono">{events.length} events</span>
        )}
      </div>

      {/* Feed */}
      <div
        ref={scrollRef}
        className="flex-1 overflow-y-auto p-3 space-y-0.5 font-mono text-[11px]"
        style={{ scrollbarWidth: "thin" }}
      >
        {events.length === 0 && !isRunning && (
          <div className="text-hack-dim text-center mt-8 space-y-2">
            <Layers className="w-6 h-6 mx-auto opacity-30" />
            <div className="text-[10px]">Waiting for hunt to start…</div>
            <div className="text-[9px] opacity-60">
              Tool calls · hypotheses · findings will appear here in real time
            </div>
          </div>
        )}

        {truncated && (
          <div className="text-[9px] text-hack-dim text-center py-1 border border-hack-border rounded bg-hack-muted mb-2">
            ↑ {events.length - maxEvents} older events not shown
          </div>
        )}

        {visible.map((ev, i) => {
          const key = `${ev.type}-${ev.ts}-${i}`;
          switch (ev.type) {
            case "layer_start":
            case "layer_done":
              return <LayerSeparator key={key} ev={ev} />;
            case "phase":
              return <PhaseRow key={key} ev={ev} />;
            case "hypothesis":
              return <HypothesisRowMemo key={key} ev={ev} />;
            case "probe_start":
              return <ProbeStartRow key={key} ev={ev} resolved={resolvedProbes.has(ev.hypothesisId)} />;
            case "probe_result":
              return <ProbeResultRowMemo key={key} ev={ev} />;
            case "finding":
            case "solver_finding":
              return <FindingRow key={key} ev={ev as any} />;
            case "verified":
            case "rejected":
              return <VerifiedRow key={key} ev={ev} />;
            case "pivot":
              return <PivotRow key={key} ev={ev} />;
            case "ban":
              return <BanRow key={key} ev={ev} />;
            case "complete":
              return <CompleteRow key={key} ev={ev} />;
            case "cve_seeded":
              return <CveSeededRow key={key} ev={ev} />;
            case "public_duplicate":
              return <PublicDuplicateRow key={key} ev={ev} />;
            case "oob_hit":
              return <OobHitRow key={key} ev={ev} />;
            case "targets_expanded":
              return <TargetsExpandedRow key={key} ev={ev} />;
            case "graphql_schema":
              return <GraphqlSchemaRow key={key} ev={ev} />;
            case "ssrf_pivot":
              return <SSRFPivotRow key={key} ev={ev} />;
            case "report_submitted":
              return <ReportSubmittedRow key={key} ev={ev} />;
            case "changes_detected":
              return <ChangesDetectedRow key={key} ev={ev} />;
            case "secrets_found":
              return <SecretsFoundRow key={key} ev={ev} />;
            case "takeover_found":
              return <TakeoverFoundRow key={key} ev={ev} />;
            case "ws_vulns":
              return <WSVulnsRow key={key} ev={ev} />;
            case "bucket_exposed":
              return <BucketExposedRow key={key} ev={ev} />;
            case "proto_pollution":
              return <ProtoPollutionRow key={key} ev={ev} />;
            case "race_condition":
              return <RaceConditionRow key={key} ev={ev} />;
            case "tech_payloads":
              return <TechPayloadsRow key={key} ev={ev} />;
            case "params_discovered":
              return <ParamsDiscoveredRow key={key} ev={ev} />;
            case "oauth_vulns":
              return <OAuthVulnsRow key={key} ev={ev} />;
            case "mass_assignment":
              return <MassAssignmentRow key={key} ev={ev} />;
            case "business_logic":
              return <BusinessLogicRow key={key} ev={ev} />;
            case "two_fa_bypass":
              return <TwoFABypassRow key={key} ev={ev} />;
            case "jwt_vulns":
              return <JWTVulnsRow key={key} ev={ev} />;
            case "open_redirect":
              return <OpenRedirectRow key={key} ev={ev} />;
            case "xxe_found":
              return <XXEFoundRow key={key} ev={ev} />;
            case "zap_scan":
              return <ZapScanRow key={key} ev={ev} />;
            case "ai_reasoning":
              return <AIReasoningRowMemo key={key} ev={ev} />;
            case "recon_start":
              return (
                <div key={key} className="flex items-center gap-1.5 text-[10px] font-mono py-0.5">
                  <Globe className="w-3 h-3 text-hack-cyan shrink-0" />
                  <span className="text-hack-dim">Phase 0 OSINT</span>
                  <span className="text-hack-cyan">{ev.domain}</span>
                  <span className="text-hack-dim">— crt.sh + Wayback CDX running…</span>
                </div>
              );
            case "recon_complete":
              return (
                <div key={key} className="flex items-center gap-1.5 text-[10px] font-mono py-0.5">
                  <CheckCircle2 className="w-3 h-3 text-hack-accent shrink-0" />
                  <span className="text-hack-dim">Recon complete —</span>
                  <span className="text-hack-accent">{ev.alive}/{ev.subdomains} subdomains alive</span>
                  {ev.interestingUrls > 0 && (
                    <span className="text-hack-orange">{ev.interestingUrls} interesting paths</span>
                  )}
                  <span className="text-hack-dim">{ev.historicalPathCount.toLocaleString()} historical URLs</span>
                </div>
              );
            case "error":
              return <ErrorRow key={key} ev={ev} />;
            default:
              return null;
          }
        })}

        {isRunning && showScanning && (
          <div className="flex items-center gap-1.5 text-[10px] font-mono text-hack-dim animate-pulse py-1">
            <span className="text-hack-accent">▸</span>
            <span>scanning…</span>
          </div>
        )}
      </div>
    </div>
  );
}

export default LiveActivityFeed;
