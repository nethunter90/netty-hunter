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

/** Pure parse of a hunt:paused socket payload — factored out of the handler
 *  below so it's directly unit-testable without a socket. Three reasons now
 *  (HunterEngine.ts has three hunt:paused emit call sites): budget pauses
 *  always carry budgetDimension, auth pauses carry authReason, scope/policy
 *  pauses carry scopeReason (and always the literal reason
 *  "scope_changed_mid_hunt") — each field's presence is the discriminator,
 *  but `reason` is checked first since it's the one stable literal across
 *  all three emit sites. */
export function parseHuntPausedEvent(data: any): {
  sessionId: string; dimension: 'budget' | 'auth' | 'scope'; reason: string; scopeReason?: string;
  findings: number; iterations: number;
} {
  const dimension: 'budget' | 'auth' | 'scope' =
    data.reason === 'scope_changed_mid_hunt' || data.scopeReason !== undefined ? 'scope'
    : data.budgetDimension !== undefined ? 'budget'
    : 'auth';
  // For auth pauses, `reason` is a generic constant ("auth_session_lost") —
  // the actual cause (e.g. which liveness check failed) is in `authReason`.
  // Prefer it so the operator sees the specific drop cause, not the label.
  // Scope/policy pauses are the same shape: `reason` is the generic constant,
  // `scopeReason` is the actual before/after description.
  const reason = String(
    (dimension === 'auth' ? data.authReason : dimension === 'scope' ? data.scopeReason : undefined) ?? data.reason
    ?? (dimension === 'budget' ? 'LLM budget exhausted' : dimension === 'scope' ? 'Scope/policy changed' : 'Auth session lost')
  );
  return {
    sessionId: String(data.sessionId || ''),
    dimension, reason,
    scopeReason: dimension === 'scope' ? String(data.scopeReason ?? reason) : undefined,
    findings: Number(data.findings ?? 0), iterations: Number(data.iterations ?? 0),
  };
}

const EVENT_NAMES = [
  'hunt:started', 'hunt:phase', 'hunt:observations', 'hunt:hypotheses',
  'hunt:probing', 'hunt:probe_result', 'hunt:finding_confirmed', 'hunt:update',
  'hunt:complete', 'hunt:aborted', 'hunt:error', 'hunt:paused', 'hunt:spend_update', 'hunt:scope_blocked', 'hunt:scope_context', 'solver:started', 'solver:complete', 'solver:finding',
  'hunt:preflight_warnings', 'hunt:auth_failed', 'hunt:auth_liveness_inactive',
  'hunt:cve_seeded', 'l5:public_duplicate',
  'hunt:graphql_schema', 'hunt:oob_hit', 'oob:hit',
  'hunt:ssrf_pivot', 'hunt:changes_detected', 'l5:report_queued',
  'l5:report_submitted', 'l5:report_submit_failed',
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

  // UI trust fix #6: live LLM spend, pushed once per iteration from the real
  // ClaudeClient ledger (see HunterEngine.ts's runLoop) -- not a DB field
  // that's only accurate at pause/completion.
  socket.on('hunt:spend_update', (data: any) => {
    huntStore.updateSessions(prev => prev.map(s =>
      s.sessionUuid === String(data.sessionId || '')
        ? { ...s, costUsd: Number(data.costUsd ?? 0), llmCallCount: Number(data.callCount ?? 0) }
        : s
    ));
  });

  // UI trust fix #5/7: real-vs-lab + in-effect scope, emitted once per hunt.
  socket.on('hunt:scope_context', (data: any) => {
    huntStore.updateSessions(prev => prev.map(s =>
      s.sessionUuid === String(data.sessionId || '')
        ? {
            ...s,
            provenance: String(data.provenance || 'unknown'),
            scope: Array.isArray(data.scope) ? data.scope.map(String) : [],
            outOfScope: Array.isArray(data.outOfScope) ? data.outOfScope.map(String) : [],
          }
        : s
    ));
  });

  // UI trust fix #5/7: the scope guard blocked an out-of-scope egress
  // attempt for THIS hunt -- previously only ever reached a server log.
  // Phase A's cloud-bucket probe organically produced this exact signal.
  socket.on('hunt:scope_blocked', (data: any) => {
    push({ type: 'scope_blocked', ts: ts(), url: String(data.url || ''), reason: String(data.reason || '') });
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

  // A paused hunt is NOT a running hunt and NOT a completed one — it's its own
  // state, and the engine has already released it server-side (activeHunts
  // registry). Before this handler existed, huntStore.status simply kept
  // whatever `hunt:phase` last set it to (== "running"), so a paused hunt
  // showed as live/LIVE forever — the UI analog of the $0-spend bug for the
  // operator's single most important "is this still going" signal.
  socket.on('hunt:paused', (data: any) => {
    const { sessionId, dimension, reason, scopeReason, findings, iterations } = parseHuntPausedEvent(data);
    push({ type: 'paused', ts: ts(), dimension, reason, scopeReason, findings, iterations });
    const status = dimension === 'budget' ? 'paused_budget' : dimension === 'scope' ? 'paused_scope' : 'paused_auth';
    huntStore.updateSessions(prev => prev.map(s =>
      s.sessionUuid === sessionId ? { ...s, status, pausedReason: reason } : s
    ));
    toast.error(`Hunt paused — ${reason}`, { duration: 8000 });
  });

  // Behavioral-rules pre-flight (blocker #3) — WARN-only, never blocks a
  // launch, but an unspecified policy silently degrades what the hunt can
  // test (waf-bypass/exploitation-tools/automated-scanning/fuzzing all
  // fail-closed to BLOCKED). Previously logged server-side only.
  socket.on('hunt:preflight_warnings', (data: any) => {
    const warnings = Array.isArray(data.warnings)
      ? data.warnings.map((w: any) => ({ code: String(w.code ?? ''), message: String(w.message ?? '') }))
      : [];
    if (warnings.length === 0) return;
    push({ type: 'preflight_warnings', ts: ts(), warnings });
    toast(`${warnings.length} pre-flight warning${warnings.length === 1 ? '' : 's'} — hunt started degraded`, { icon: '⚠️', duration: 6000 });
  });

  // Auth was configured but login produced no usable session — the hunt
  // proceeds UNAUTHENTICATED, which silently drops idor/auth_bypass/
  // business_logic/authed-info_disclosure coverage. Previously a server log
  // only; the operator had no way to know a hunt's auth silently failed.
  socket.on('hunt:auth_failed', (data: any) => {
    const reason = String(data.reason || 'Login produced no session');
    push({ type: 'auth_failed', ts: ts(), loginUrl: data.loginUrl ? String(data.loginUrl) : undefined, reason });
    toast.error(`Auth failed — hunting unauthenticated: ${reason}`, { duration: 8000 });
  });

  // No baseline distinguishes authenticated from unauthenticated responses,
  // so a mid-hunt auth-session drop can't be detected for this hunt — fires
  // once per hunt. Previously only a contextWriter.alert (file), invisible
  // in the live UI.
  socket.on('hunt:auth_liveness_inactive', (data: any) => {
    const message = String(
      data.message
      ?? 'No configured/discovered baseline distinguishes authenticated from unauthenticated responses — a mid-hunt auth-session drop cannot be detected for this hunt.'
    );
    push({ type: 'auth_liveness_inactive', ts: ts(), message });
    toast(`Auth liveness undetectable — ${message}`, { icon: '⚠️', duration: 8000 });
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

  // Fired from the /approve REST route once a human review-approves a queued
  // draft — this is the only remaining signal that a report actually reached
  // the platform (or failed to); without it the feed goes silent forever
  // after "queued for review".
  socket.on('l5:report_submitted', (data: any) => {
    push({
      type: 'report_submitted',
      ts: ts(),
      platform: String(data.platform || ''),
      reportId: data.reportId ? String(data.reportId) : undefined,
      reportUrl: data.reportUrl ? String(data.reportUrl) : undefined,
    });
  });

  socket.on('l5:report_submit_failed', (data: any) => {
    push({
      type: 'report_submit_failed',
      ts: ts(),
      platform: String(data.platform || ''),
      error: data.error ? String(data.error) : undefined,
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
