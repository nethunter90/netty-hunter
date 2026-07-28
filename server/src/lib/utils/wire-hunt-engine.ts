import type { Server } from 'socket.io';
import type { HunterEngine } from '../../agents/HunterEngine';

export function wireHuntEngineToSocket(engine: HunterEngine, sessionUuid: string, io: Server): void {
  const room = `hunt:${sessionUuid}`;
  const fwd = (evt: string) => engine.on(evt, (d: unknown) => io.to(room).emit(evt, d));

  fwd('hunt:phase');
  fwd('hunt:spend_update');
  fwd('hunt:scope_blocked');
  fwd('hunt:scope_context');
  fwd('hunt:observations');
  fwd('hunt:hypotheses');
  fwd('hunt:probing');
  fwd('hunt:probe_result');
  fwd('hunt:finding_confirmed');
  fwd('hunt:update');
  fwd('hunt:error');
  fwd('hunt:cve_seeded');
  fwd('hunt:graphql_schema');
  fwd('hunt:ssrf_pivot');
  fwd('hunt:changes_detected');
  fwd('hunt:oob_hit');
  fwd('hunt:secrets_found');
  fwd('hunt:ws_vulns');
  fwd('hunt:bucket_exposed');
  fwd('hunt:proto_pollution');
  fwd('hunt:race_condition');
  fwd('hunt:host_header');
  fwd('hunt:crlf');
  fwd('hunt:cookie_flags');
  fwd('hunt:endpoints_discovered');
  fwd('hunt:plan_seeded');
  fwd('hunt:tech_payloads');
  fwd('hunt:params_discovered');
  fwd('hunt:oauth_vulns');
  fwd('hunt:mass_assignment');
  fwd('hunt:business_logic');
  fwd('hunt:2fa_bypass');
  fwd('hunt:jwt_vulns');
  fwd('hunt:open_redirect');
  fwd('hunt:xxe_found');
  fwd('hunt:chain_seeded');
  fwd('hunt:pivot');
  fwd('hunt:ai_reasoning');
  fwd('recon:start');
  fwd('recon:subdomains_raw');
  fwd('recon:complete');
  fwd('hunt:solver_finding');
  fwd('hunt:solver_started');
  fwd('hunt:solver_complete');
  // Fix 3 (safety-events bridge): these three were previously never
  // forwarded at all — server-side alerts (pre-flight policy warnings, a
  // failed auth login, an undetectable auth-liveness baseline) reached only
  // a log line, never the live UI.
  fwd('hunt:preflight_warnings');
  fwd('hunt:auth_failed');
  fwd('hunt:auth_liveness_inactive');
  // hunt:aborted — emitted immediately by engine.stop(); clients use this to
  // confirm a stop request was honoured rather than relying on optimistic UI state.
  fwd('hunt:aborted');
  fwd('hunt:resumed');
  // hunt:complete and hunt:paused are handled separately by the caller (both need
  // single-flight-slot release + activeHuntSessions cleanup logic — see routes/hunt.ts).
  engine.on('hunt:complete', (d: unknown) => io.to(room).emit('hunt:complete', d));
  engine.on('hunt:paused', (d: unknown) => io.to(room).emit('hunt:paused', d));

  // NOTE: preflight_warnings and auth_failed fire SYNCHRONOUSLY inside
  // startHunt(), which every caller awaits BEFORE calling this function —
  // and the launching client only learns its sessionUuid (and joins this
  // room via subscribe:hunt) after that same await resolves server-side.
  // So a room-broadcast replay placed here would ALWAYS run before any
  // client — including the one that just launched this hunt — could
  // possibly have joined `room`. The real replay lives in index.ts's
  // subscribe:hunt handler instead, which is the one point guaranteed to
  // have an actual listening socket (covers both "just launched" and a
  // later page-reload/reconnect). Don't re-add a replay here.
}
