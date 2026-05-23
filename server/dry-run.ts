// Orchestration dry-run: exercises all 6 layers without real tools or Ollama.
// Usage: npx tsx dry-run.ts
// Expected runtime: 60-90 seconds. REAL_TOOLS must NOT be set.

import { huntOrchestrator } from './src/lib/orchestration/layer1-hunt-orchestrator';
import { eventBus } from './src/lib/orchestration/layer3-event-bus';
import { missionMemory } from './src/lib/orchestration/mission-memory';
import type { AgentEvent } from './src/lib/orchestration/types';

const POLL_INTERVAL_MS = 2000;
const MAX_WAIT_MS = 300_000;

interface EventRecord {
  type: string;
  huntId: string;
  data: Record<string, any>;
  ts: number;
}

async function main(): Promise<void> {
  console.log('\n╔══════════════════════════════════════╗');
  console.log('║   ORCHESTRATION DRY-RUN (simulation) ║');
  console.log('╚══════════════════════════════════════╝\n');

  if (process.env.REAL_TOOLS === 'true') {
    console.error('[ERROR] REAL_TOOLS=true — dry-run must run without real tools. Unset it first.');
    process.exit(1);
  }

  const capturedEvents: EventRecord[] = [];

  function capture(type: string) {
    eventBus.on(type, (ev: AgentEvent) => {
      capturedEvents.push({ type, huntId: ev.huntId, data: ev.data, ts: Date.now() });
      console.log(`  [event] ${type} | hunt=${ev.huntId.slice(0, 8)} | ${JSON.stringify(ev.data).slice(0, 80)}`);
    });
  }

  capture('phase_changed');
  capture('vulnerability_found');
  capture('scan_complete');
  capture('endpoint_characterized');
  capture('hunt_complete');

  // ── 1. Create hunt ───────────────────────────────────────────────────────────
  console.log('[1/4] Creating hunt...');
  const hunt = await huntOrchestrator.createHunt({
    target: 'http://testphp.vulnweb.com',
    goal: 'Find SQL injection and XSS vulnerabilities',
    scope: { inScope: ['testphp.vulnweb.com'], outOfScope: [] },
    priority: 'medium',
    autoAdvance: true,
    stealthMode: 'aggressive',  // disables stealth delays so dry-run completes quickly
    resourceClass: 'standard',
  });
  console.log(`    id=${hunt.id}`);
  console.log(`    phase=${hunt.phase}  status=${hunt.status}\n`);

  // ── 2. Start hunt ────────────────────────────────────────────────────────────
  console.log('[2/4] Starting hunt...');
  await huntOrchestrator.startHunt(hunt.id);
  console.log(`    phase=${huntOrchestrator.getHunt(hunt.id)?.phase}\n`);

  // ── 3. Poll until completed or timeout ──────────────────────────────────────
  console.log('[3/4] Polling for completion (max 120s)...\n');
  const startMs = Date.now();
  let lastPhase = hunt.phase;
  let lastLogMs = 0;

  while (Date.now() - startMs < MAX_WAIT_MS) {
    await new Promise(r => setTimeout(r, POLL_INTERVAL_MS));

    const current = huntOrchestrator.getHunt(hunt.id);
    if (!current) {
      console.error('[ERROR] Hunt disappeared from registry');
      process.exit(1);
    }

    const elapsedS = Math.round((Date.now() - startMs) / 1000);

    if (current.phase !== lastPhase) {
      console.log(`\n  ► Phase: ${lastPhase} → ${current.phase}  (${elapsedS}s elapsed)\n`);
      lastPhase = current.phase;
    } else if (Date.now() - lastLogMs > 10_000) {
      const mem = missionMemory.get(hunt.id);
      console.log(
        `  ... ${elapsedS}s | phase=${current.phase} | endpoints=${mem?.endpoints.length ?? 0}` +
        ` vulns=${mem?.vulnerabilities.length ?? 0} events=${capturedEvents.length}`
      );
      lastLogMs = Date.now();
    }

    if (current.status === 'completed' || current.phase === 'completed') break;
  }

  // ── 4. Results ───────────────────────────────────────────────────────────────
  const finalHunt = huntOrchestrator.getHunt(hunt.id);
  const memory = missionMemory.get(hunt.id);
  const elapsedTotal = Math.round((Date.now() - startMs) / 1000);

  console.log('\n╔══════════════════════════════════════╗');
  console.log('║           DRY-RUN RESULTS            ║');
  console.log('╚══════════════════════════════════════╝');
  console.log(`  Status:          ${finalHunt?.status}`);
  console.log(`  Final phase:     ${finalHunt?.phase}`);
  console.log(`  Elapsed:         ${elapsedTotal}s`);
  console.log(`  Findings:        ${finalHunt?.findings?.length ?? 0}`);
  console.log(`  Endpoints:       ${memory?.endpoints?.length ?? 0}`);
  console.log(`  Technologies:    ${memory?.technologies?.length ?? 0}`);
  console.log(`  Subdomains:      ${memory?.subdomains?.length ?? 0}`);
  console.log(`  Vulnerabilities: ${memory?.vulnerabilities?.length ?? 0}`);
  console.log(`  Events fired:    ${capturedEvents.length}`);

  const phaseEvents = capturedEvents.filter(e => e.type === 'phase_changed');
  if (phaseEvents.length > 0) {
    console.log(`\n  Phase transitions (${phaseEvents.length}):`);
    phaseEvents.forEach(e => {
      const rel = Math.round((e.ts - startMs) / 1000);
      console.log(`    +${rel}s  ${e.data.oldPhase} → ${e.data.newPhase}`);
    });
  }

  if (finalHunt?.findings?.length) {
    console.log(`\n  Findings:`);
    finalHunt.findings.slice(0, 5).forEach((f: any) => {
      console.log(`    [${f.severity?.toUpperCase() ?? 'INFO'}] ${f.title} @ ${f.endpoint}`);
    });
  }

  // ── 5. Assertions ────────────────────────────────────────────────────────────
  console.log('\n  Assertions:');
  const checks: [string, boolean][] = [
    ['Hunt object exists in registry', !!finalHunt],
    ['Hunt reaches reporting or completed phase', finalHunt?.phase === 'completed' || finalHunt?.phase === 'reporting'],
    ['Hunt status is completed', finalHunt?.status === 'completed'],
    ['At least 1 phase_changed event fired', phaseEvents.length >= 1],
    ['MissionMemory initialized for hunt', !!memory],
    ['No timeout (finished within 300s)', elapsedTotal < 300],
  ];

  let failures = 0;
  for (const [label, ok] of checks) {
    const icon = ok ? 'PASS' : 'FAIL';
    console.log(`    [${icon}] ${label}`);
    if (!ok) failures++;
  }

  if (failures > 0) {
    console.log(`\n  ✗ ${failures} check(s) failed\n`);
    process.exit(1);
  }

  console.log('\n  ✓ All checks passed — orchestration dry-run SUCCESSFUL\n');
}

main().catch(err => {
  console.error('\n[FATAL] Uncaught error during dry-run:');
  console.error(err);
  process.exit(1);
});
