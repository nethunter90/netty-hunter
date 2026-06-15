import type { Server } from 'socket.io';
import type { HunterEngine } from '../../agents/HunterEngine';

export function wireHuntEngineToSocket(engine: HunterEngine, sessionUuid: string, io: Server): void {
  const room = `hunt:${sessionUuid}`;
  const fwd = (evt: string) => engine.on(evt, (d: unknown) => io.to(room).emit(evt, d));

  fwd('hunt:phase');
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
  // hunt:complete handled separately by caller (needs cleanup logic)
  engine.on('hunt:complete', (d: unknown) => io.to(room).emit('hunt:complete', d));
}
