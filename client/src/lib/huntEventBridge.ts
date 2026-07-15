/**
 * Hunt event bridge — the lifted socket subscription.
 *
 * Registers every hunt-related socket listener ONCE, above the panel routing
 * (mounted by AppLayout via useHuntEvents), and writes all progress into the
 * module-level huntStore. Because this lives above the panels, the store keeps
 * receiving events regardless of which panel is mounted — so switching away from
 * the Hunt panel and back no longer loses history.
 *
 * The Hunt panel (HuntConsole) is now a pure reader of huntStore; it no longer
 * owns the subscription. This file is the single owner of the hunt event stream.
 */
import { useEffect } from 'react';
import toast from 'react-hot-toast';
import { getSocket } from './socket';
import { huntStore } from './huntStore';
import type { ActivityEvent } from '../components/LiveActivityFeed';

function ts(): string {
  return new Date().toISOString().slice(11, 23);
}

function push(ev: ActivityEvent): void {
  huntStore.pushEvent(ev);
}

const EVENT_NAMES = [
  'hunt:started', 'hunt:phase', 'hunt:observations', 'hunt:hypotheses',
  'hunt:probing', 'hunt:probe_result', 'hunt:finding_confirmed', 'hunt:update',
  'hunt:complete', 'hunt:aborted', 'hunt:error', 'solver:started', 'solver:complete', 'solver:finding',
  'hunt:cve_seeded', 'l5:public_duplicate',
  'hunt:graphql_schema', 'hunt:oob_hit', 'oob:hit',
  'hunt:ssrf_pivot', 'hunt:changes_detected', 'l5:report_queued',
  'hunt:secrets_found', 'hunt:ws_vulns', 'hunt:bucket_exposed',
  'hunt:proto_pollution', 'hunt:race_condition',
  'hunt:tech_payloads', 'hunt:params_discovered', 'hunt:oauth_vulns',
  'hunt:mass_assignment', 'hunt:business_logic', 'hunt:2fa_bypass',
  'hunt:jwt_vulns', 'hunt:open_redirect', 'hunt:xxe_found', 'hunt:zap_scan',
  'hunt:ai_reasoning', 'egress:route_changed', 'hunt:state',
  'recon:start', 'recon:complete',
];

let attached = false;

/** Re-emit room subscriptions for any running sessions (page reload / reconnect). */
function resubscribeRunning(socket: ReturnType<typeof getSocket>): void {
  huntStore.activeSessions
    .filter(s => s.status === 'running' || s.status === 'stopping')
    .forEach(s => socket.emit('subscribe:hunt', { sessionUuid: s.sessionUuid }));
}

/**
 * Register all hunt listeners on the singleton socket. Idempotent: a second call
 * is a no-op (StrictMode double-invoke can't stack duplicate listeners).
 * Returns a detach() that removes them.
 */
export function attachHuntEvents(): () => void {
  const socket = getSocket();
  if (attached) return () => {};
  attached = true;

  socket.on('hunt:started', (_data: any) => {
    push({ type: 'phase', ts: ts(), phase: 'observe', iteration: 0 });
  });

  // Replayed when subscribing to an already-running hunt (including reattaching
  // to a hunt that was already in progress before a page reload).
  socket.on('hunt:state', (data: any) => {
    const state = data.state ?? data;
    if (state?.phase) {
      push({ type: 'phase', ts: ts(), phase: String(state.phase), iteration: Number(state.iteration ?? 0) });
      huntStore.updateSessions(prev => prev.map(s =>
        s.sessionUuid === String(state.sessionId || '')
          ? { ...s, phase: String(state.phase), iteration: Number(state.iteration ?? 0), findings: Number(state.confirmedFindings?.length ?? s.findings) }
          : s
      ));
    }
  });

  socket.on('hunt:phase', (data: any) => {
    const phase = String(data.phase || 'observe');
    const iteration = Number(data.iteration || 0);
    push({ type: 'phase', ts: ts(), phase, iteration });
    huntStore.updateSessions(prev => prev.map(s =>
      s.sessionUuid === String(data.sessionUuid || '')
        ? { ...s, phase, iteration }
        : s
    ));
  });

  socket.on('hunt:observations', (_data: any) => {
    // observations are context — no explicit event row needed
  });

  socket.on('hunt:hypotheses', (data: any) => {
    const hyps: any[] = data.hypotheses ?? [];
    hyps.forEach(h => {
      push({
        type: 'hypothesis',
        ts: ts(),
        id: h.id ?? String(Math.random()),
        vulnClass: h.vulnClass ?? 'unknown',
        reasoning: h.reasoning ?? h.evidence?.join('; ') ?? '',
        confidence: h.confidence ?? 0,
        modelSource: h.modelSource,
      });
    });
    huntStore.updateHypStats(s => ({ ...s, pending: s.pending + hyps.length }));
  });

  socket.on('hunt:probing', (data: any) => {
    push({
      type: 'probe_start',
      ts: ts(),
      hypothesisId: String(data.hypothesisId || ''),
      vulnClass: String(data.vulnClass || ''),
    });
    huntStore.updateHypStats(s => ({ ...s, pending: Math.max(0, s.pending - 1), probing: s.probing + 1 }));
  });

  socket.on('hunt:probe_result', (data: any) => {
    const r = data.result ?? data;
    push({
      type: 'probe_result',
      ts: ts(),
      hypothesisId: String(data.hypothesisId || ''),
      tool: String(r.tool ?? 'unknown'),
      success: !!r.success,
      output: String(r.output ?? r.parsed?.raw ?? ''),
      durationMs: Number(r.duration ?? 0),
      proxyId: data.proxyId ? String(data.proxyId) : undefined,
    });
  });

  socket.on('hunt:finding_confirmed', (data: any) => {
    const f = data.finding ?? data;
    const h = f.hypothesis ?? {};
    push({
      type: 'finding',
      ts: ts(),
      vulnClass: h.vulnClass ?? 'unknown',
      severity: f.severity ?? 'medium',
      confidence: h.confidence ?? 0,
      payload: f.exploitPayload ?? h.evidence?.join('; '),
    });
    huntStore.updateSessions(prev => prev.map(s => ({ ...s, findings: s.findings + 1 })));
    huntStore.updateHypStats(s => ({ ...s, probing: Math.max(0, s.probing - 1), confirmed: s.confirmed + 1 }));
    toast.success(`Finding: ${h.vulnClass ?? 'unknown'}`);
  });

  socket.on('hunt:update', (data: any) => {
    // Sync counts from server at the end of each update phase
    const pending = Number(data.pendingHypotheses ?? 0);
    const rejected = Number(data.rejectedHypotheses ?? 0);
    huntStore.updateHypStats(s => ({ ...s, pending, rejected }));
  });

  socket.on('hunt:complete', (data: any) => {
    push({
      type: 'complete',
      ts: ts(),
      findings: Number(data.findings ?? 0),
      iterations: Number(data.iterations ?? 0),
    });
    huntStore.updateSessions(prev => prev.map(s =>
      s.sessionUuid === String(data.sessionId || '') ? { ...s, status: 'complete' } : s
    ));
    huntStore.setExternalHunt(null);
  });

  // Backend confirmation that the engine actually halted.
  socket.on('hunt:aborted', (_data: any) => {
    huntStore.updateSessions(prev => prev.filter(s => s.status !== 'stopping'));
    huntStore.setExternalHunt(null);
  });

  socket.on('hunt:error', (data: any) => {
    push({ type: 'error', ts: ts(), message: String(data.error || 'Unknown error') });
  });

  socket.on('solver:started', (data: any) => {
    push({ type: 'probe_start', ts: ts(), hypothesisId: 'solver', vulnClass: String(data.vulnClass || '') });
  });

  socket.on('solver:complete', (data: any) => {
    push({
      type: 'probe_result',
      ts: ts(),
      hypothesisId: 'solver',
      tool: 'solver',
      success: Number(data.confidence ?? 0) > 0.5,
      output: `confidence=${Number(data.confidence ?? 0).toFixed(2)}`,
      durationMs: 0,
    });
  });

  socket.on('solver:finding', (data: any) => {
    const r = data.result ?? data;
    push({ type: 'solver_finding', ts: ts(), vulnClass: String(r.vulnClass ?? 'unknown') });
    huntStore.updateSessions(prev => prev.map(s => ({ ...s, findings: s.findings + 1 })));
  });

  socket.on('hunt:cve_seeded', (data: any) => {
    push({
      type: 'cve_seeded',
      ts: ts(),
      tech: String(data.tech || ''),
      cveIds: Array.isArray(data.cveIds) ? (data.cveIds as unknown[]).map(String) : [],
      maxCvss: Number(data.maxCvss || 0),
    });
  });

  socket.on('hunt:graphql_schema', (data: any) => {
    push({
      type: 'graphql_schema',
      ts: ts(),
      endpoint: String(data.endpoint || ''),
      typeCount: Number(data.typeCount || 0),
      injectableCount: Number(data.injectableCount || 0),
    });
  });

  socket.on('hunt:oob_hit', (data: any) => {
    push({ type: 'oob_hit', ts: ts(), beaconId: String(data.beaconId || ''), ip: String(data.ip || 'unknown') });
  });

  socket.on('oob:hit', (data: any) => {
    push({ type: 'oob_hit', ts: ts(), beaconId: String(data.beaconId || ''), ip: String(data.ip || 'unknown') });
  });

  socket.on('l5:public_duplicate', (data: any) => {
    push({
      type: 'public_duplicate',
      ts: ts(),
      vulnClass: String(data.vulnClass ?? 'unknown'),
      platform: String(data.platform ?? 'unknown'),
      reportUrl: data.reportUrl,
      title: data.title,
      warn: !!data.warn,
    });
  });

  socket.on('hunt:ssrf_pivot', (data: any) => {
    push({
      type: 'ssrf_pivot',
      ts: ts(),
      reachable: Array.isArray(data.reachable) ? (data.reachable as unknown[]).map(String) : [],
      cloudMeta: !!data.cloudMeta,
      newHypotheses: Number(data.newHypotheses || 0),
    });
  });

  socket.on('hunt:changes_detected', (data: any) => {
    push({
      type: 'changes_detected',
      ts: ts(),
      newEndpoints: Array.isArray(data.newEndpoints) ? (data.newEndpoints as unknown[]).map(String) : [],
      changed: Number(data.changed || 0),
    });
  });

  socket.on('l5:report_queued', (data: any) => {
    push({
      type: 'report_queued',
      ts: ts(),
      platform: String(data.platform || ''),
      submissionId: String(data.submissionId || ''),
    });
  });

  socket.on('hunt:secrets_found', (data: any) => {
    push({ type: 'secrets_found', ts: ts(), count: Number(data.count || 0), types: Array.isArray(data.types) ? data.types.map(String) : [] });
  });
  socket.on('hunt:ws_vulns', (data: any) => {
    push({ type: 'ws_vulns', ts: ts(), count: Number(data.count || 0), endpoints: Array.isArray(data.endpoints) ? data.endpoints.map(String) : [], issues: Array.isArray(data.issues) ? data.issues.map(String) : [] });
  });
  socket.on('hunt:bucket_exposed', (data: any) => {
    push({ type: 'bucket_exposed', ts: ts(), buckets: Array.isArray(data.buckets) ? data.buckets : [] });
  });
  socket.on('hunt:proto_pollution', (data: any) => {
    push({ type: 'proto_pollution', ts: ts(), count: Number(data.count || 0), reflected: Boolean(data.reflected) });
  });
  socket.on('hunt:race_condition', (data: any) => {
    push({ type: 'race_condition', ts: ts(), count: Number(data.count || 0), endpoints: Array.isArray(data.endpoints) ? data.endpoints.map(String) : [] });
  });
  socket.on('hunt:tech_payloads', (data: any) => {
    push({ type: 'tech_payloads', ts: ts(), techs: Array.isArray(data.techs) ? data.techs.map(String) : [], payloadCount: Number(data.payloadCount || 0) });
  });
  socket.on('hunt:params_discovered', (data: any) => {
    push({ type: 'params_discovered', ts: ts(), count: Number(data.count || 0), params: Array.isArray(data.params) ? data.params.map(String) : [] });
  });
  socket.on('hunt:oauth_vulns', (data: any) => {
    push({ type: 'oauth_vulns', ts: ts(), count: Number(data.count || 0), issues: Array.isArray(data.issues) ? data.issues.map(String) : [] });
  });
  socket.on('hunt:mass_assignment', (data: any) => {
    push({ type: 'mass_assignment', ts: ts(), count: Number(data.count || 0), endpoints: Array.isArray(data.endpoints) ? data.endpoints.map(String) : [] });
  });
  socket.on('hunt:business_logic', (data: any) => {
    push({ type: 'business_logic', ts: ts(), count: Number(data.count || 0), types: Array.isArray(data.types) ? data.types.map(String) : [] });
  });
  socket.on('hunt:2fa_bypass', (data: any) => {
    push({ type: 'two_fa_bypass', ts: ts(), count: Number(data.count || 0), techniques: Array.isArray(data.techniques) ? data.techniques.map(String) : [] });
  });
  socket.on('hunt:jwt_vulns', (data: any) => {
    push({ type: 'jwt_vulns', ts: ts(), count: Number(data.count || 0), techniques: Array.isArray(data.techniques) ? data.techniques.map(String) : [] });
  });
  socket.on('hunt:open_redirect', (data: any) => {
    push({ type: 'open_redirect', ts: ts(), count: Number(data.count || 0), chained: Number(data.chained || 0) });
  });
  socket.on('hunt:xxe_found', (data: any) => {
    push({ type: 'xxe_found', ts: ts(), count: Number(data.count || 0), oobConfirmed: Boolean(data.oobConfirmed) });
  });
  socket.on('hunt:zap_scan', (data: any) => {
    push({ type: 'zap_scan', ts: ts(), alertCount: Number(data.alertCount || 0), hypothesesSeeded: Number(data.hypothesesSeeded || 0), endpointsDiscovered: Number(data.endpointsDiscovered || 0), duration: Number(data.duration || 0) });
  });

  socket.on('hunt:ai_reasoning', (data: any) => {
    push({
      type: 'ai_reasoning',
      ts: ts(),
      task: String(data.task ?? 'AI'),
      phase: data.phase as 'thinking' | 'complete' | 'decision',
      context: data.context,
      promptPreview: String(data.promptPreview ?? ''),
      rawResponse: String(data.rawResponse ?? ''),
      summary: String(data.summary ?? ''),
      durationMs: Number(data.durationMs ?? 0),
      generatedCount: Number(data.generatedCount ?? 0),
      enrichmentActive: typeof data.enrichmentActive === 'boolean' ? data.enrichmentActive : undefined,
      corpusEntries: Array.isArray(data.corpusEntries) ? data.corpusEntries : undefined,
    });
  });

  socket.on('recon:start', (data: any) => {
    push({ type: 'recon_start', ts: ts(), domain: String(data.domain ?? '') });
  });

  socket.on('recon:complete', (data: any) => {
    push({
      type: 'recon_complete',
      ts: ts(),
      subdomains: Number(data.subdomains ?? 0),
      alive: Number(data.alive ?? 0),
      interestingUrls: Number(data.interestingUrls ?? 0),
      historicalPathCount: Number(data.historicalPathCount ?? 0),
    });
  });

  // Room membership is per-connection: re-subscribe on (re)connect so a page
  // reload or socket reconnect keeps receiving live events for running hunts.
  resubscribeRunning(socket);
  socket.on('connect', () => resubscribeRunning(socket));

  return () => {
    EVENT_NAMES.forEach(e => socket.off(e));
    socket.off('connect');
    attached = false;
  };
}

/** Mount the hunt event bridge once, from an always-mounted layer (AppLayout). */
export function useHuntEvents(): void {
  useEffect(() => attachHuntEvents(), []);
}
