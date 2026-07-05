/**
 * Orchestration event bridge — the lifted socket subscription for the 6-layer
 * orchestration panel. Registers every orchestration:* / l4:* / l5:* / l6:* listener
 * ONCE, above the panel routing (mounted by AppLayout via useOrchestrationEvents),
 * and writes all progress into orchestrationStore. Because it lives above the panels,
 * the store keeps receiving events regardless of which panel is mounted — so leaving
 * the Orchestration panel and returning restores the full execution stream.
 *
 * The panel (Orchestration.tsx) is now a pure reader of orchestrationStore.
 */
import { useEffect } from 'react';
import toast from 'react-hot-toast';
import { getSocket } from './socket';
import { orchestrationStore } from './orchestrationStore';

function ts(): string {
  return new Date().toISOString().slice(11, 23);
}

const EVENT_NAMES = [
  'orchestration:created', 'orchestration:started', 'orchestration:layer_start',
  'orchestration:layer_complete', 'orchestration:layer_error',
  'orchestration:complete', 'orchestration:aborted', 'orchestration:error',
  'l4:phase', 'l4:hypotheses', 'l4:probing', 'l4:probe_result',
  'l4:finding_raw', 'l4:solver_finding', 'l4:error', 'l4:ai_reasoning',
  'l5:verified', 'l5:rejected', 'l5:public_duplicate',
  'l6:report_generated', 'l6:autonomy_updated',
  'hunt:ai_reasoning',
];

let attached = false;

export function attachOrchestrationEvents(): () => void {
  const socket = getSocket();
  if (attached) return () => {};
  attached = true;

  const s = orchestrationStore;

  socket.on('orchestration:created', ({ orchestrationId: id }: { orchestrationId: string }) => {
    s.setOrchestrationId(id);
    s.setLaunching(false);
    s.setLoading(true);
    s.setExternalHunt(null);
    socket.emit('subscribe:orchestration', { orchestrationId: id });
  });

  socket.on('orchestration:started', () => { s.setPhase('running'); });

  socket.on('orchestration:layer_start', (d: { layer: number; name: string }) => {
    s.updateLayers(prev => prev.map(l => l.layer === d.layer ? { ...l, phase: 'running', startedAt: Date.now() } : l));
    s.setPhase(`l${d.layer}`);
    s.pushEvent({ type: 'layer_start', ts: ts(), layer: d.layer, name: d.name });
  });

  socket.on('orchestration:layer_complete', (d: { layer: number; name: string; passed: boolean; durationMs: number }) => {
    s.updateLayers(prev => prev.map(l => l.layer === d.layer
      ? { ...l, phase: d.passed ? 'passed' : 'failed', completedAt: Date.now(), durationMs: d.durationMs } : l));
    s.pushEvent({ type: 'layer_done', ts: ts(), layer: d.layer, name: d.name, passed: d.passed, durationMs: d.durationMs });
  });

  socket.on('orchestration:layer_error', (d: { layer: number; name: string; error: string }) => {
    s.updateLayers(prev => prev.map(l => l.layer === d.layer ? { ...l, phase: 'failed', error: d.error } : l));
    s.pushEvent({ type: 'error', ts: ts(), message: `L${d.layer} ${d.name}: ${d.error}` });
  });

  socket.on('orchestration:aborted', (d: { reason: string }) => {
    s.setPhase('aborted'); s.setLoading(false); s.setStopping(false);
    s.pushEvent({ type: 'error', ts: ts(), message: `Aborted: ${d.reason}` });
    toast.error(`Aborted: ${d.reason}`);
  });

  socket.on('orchestration:complete', () => {
    s.setPhase('complete'); s.setLoading(false); s.setStopping(false); s.setExternalHunt(null);
    toast.success('Orchestration complete!');
  });

  socket.on('orchestration:error', (d: { error: string; activeHunt?: { id: string; kind: string; targetUrl: string } }) => {
    s.setPhase('error'); s.setLaunching(false); s.setLoading(false); s.setStopping(false);
    if (d.activeHunt) s.setExternalHunt(d.activeHunt);
    s.pushEvent({ type: 'error', ts: ts(), message: d.error });
    toast.error(`Orchestration error: ${d.error}`);
  });

  // ── L4 Execution Engine ──
  socket.on('l4:phase', (d: { phase: string; iteration?: number }) => {
    s.pushEvent({ type: 'phase', ts: ts(), phase: d.phase, iteration: d.iteration ?? 0 });
  });

  socket.on('l4:hypotheses', (d: { count: number; hypotheses?: any[] }) => {
    (d.hypotheses ?? []).forEach((h: any) => {
      s.pushEvent({
        type: 'hypothesis', ts: ts(), id: h.id ?? String(Math.random()),
        vulnClass: h.vulnClass ?? 'unknown', reasoning: h.reasoning ?? h.evidence?.join('; ') ?? '',
        confidence: h.confidence ?? 0,
      });
    });
  });

  socket.on('l4:probing', (d: { hypothesisId: string; vulnClass: string }) => {
    s.pushEvent({ type: 'probe_start', ts: ts(), hypothesisId: d.hypothesisId, vulnClass: d.vulnClass });
  });

  socket.on('l4:probe_result', (d: { hypothesisId: string; result: any }) => {
    const r = d.result ?? {};
    s.pushEvent({
      type: 'probe_result', ts: ts(), hypothesisId: d.hypothesisId, tool: r.tool ?? 'unknown',
      success: !!r.success, output: r.output ?? r.parsed?.raw ?? '', durationMs: r.duration ?? 0,
    });
  });

  socket.on('l4:finding_raw', (d: { finding?: any }) => {
    const f = d.finding ?? d; const h = f.hypothesis ?? {};
    s.incFindings();
    s.pushEvent({
      type: 'finding', ts: ts(), vulnClass: h.vulnClass ?? 'unknown', severity: f.severity ?? 'medium',
      confidence: h.confidence ?? 0, payload: f.exploitPayload ?? h.evidence?.join('; '),
    });
  });

  socket.on('l4:solver_finding', (d: { result?: any }) => {
    const r = d.result ?? d;
    s.incFindings();
    s.pushEvent({ type: 'solver_finding', ts: ts(), vulnClass: r.vulnClass ?? 'unknown' });
  });

  socket.on('l4:error', (d: { error: string }) => {
    s.pushEvent({ type: 'error', ts: ts(), message: `[L4] ${d.error}` });
  });

  // ── L5 Verification ──
  socket.on('l5:verified', (d: { findingId: number; verdict: string }) => {
    s.incVerified();
    s.pushEvent({ type: 'verified', ts: ts(), findingId: d.findingId, verdict: d.verdict });
  });

  socket.on('l5:rejected', (d: { findingId: number; verdict: string }) => {
    s.pushEvent({ type: 'rejected', ts: ts(), findingId: d.findingId, verdict: d.verdict });
  });

  socket.on('l5:public_duplicate', (d: any) => {
    s.pushEvent({
      type: 'public_duplicate', ts: ts(), vulnClass: d.vulnClass ?? 'unknown',
      platform: d.platform ?? 'unknown', reportUrl: d.reportUrl, title: d.title, warn: !!d.warn,
    });
  });

  // ── L6 Harvest ──
  socket.on('l6:report_generated', (d: { findingId: number }) => {
    s.pushEvent({ type: 'verified', ts: ts(), findingId: d.findingId, verdict: 'report generated' });
  });
  socket.on('l6:autonomy_updated', () => { /* no visual */ });

  const pushAIReasoning = (data: any) => {
    s.pushEvent({
      type: 'ai_reasoning', ts: ts(), task: String(data.task ?? 'AI'),
      phase: data.phase as 'thinking' | 'complete' | 'decision', context: data.context,
      promptPreview: String(data.promptPreview ?? ''), rawResponse: String(data.rawResponse ?? ''),
      summary: String(data.summary ?? ''), durationMs: Number(data.durationMs ?? 0),
      generatedCount: Number(data.generatedCount ?? 0),
    });
  };
  socket.on('l4:ai_reasoning', pushAIReasoning);
  socket.on('hunt:ai_reasoning', pushAIReasoning);

  return () => {
    EVENT_NAMES.forEach(e => socket.off(e));
    attached = false;
  };
}

/** Mount the orchestration event bridge once, from an always-mounted layer. */
export function useOrchestrationEvents(): void {
  useEffect(() => attachOrchestrationEvents(), []);
}
