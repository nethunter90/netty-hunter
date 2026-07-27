/**
 * UI trust fix #6 (live cost) -- Part B: feed a hunt:spend_update-shaped
 * payload (matching the real shape proven live in
 * server/scripts/live-spend-emit-proof.ts) through the real huntStore
 * mutator the bridge calls, and confirm the session's displayed cost climbs
 * across two updates -- exercising the real store module, not a copy.
 *
 * Run (from client/): npx tsx scripts/spend-store-proof.ts
 */
import { huntStore } from "../src/lib/huntStore";

let failures = 0;
function assert(cond: boolean, label: string): void {
  if (cond) console.log(`  PASS  ${label}`);
  else { failures++; console.log(`  FAIL  ${label}`); }
}

// Mirrors the real socket.on('hunt:spend_update', ...) handler body in
// huntEventBridge.ts exactly.
function handleSpendUpdate(data: { sessionId: string; costUsd: number; callCount: number }): void {
  huntStore.updateSessions(prev => prev.map(s =>
    s.sessionUuid === data.sessionId
      ? { ...s, costUsd: data.costUsd, llmCallCount: data.callCount }
      : s
  ));
}

function main(): void {
  const sessionUuid = "spend-proof-session";
  huntStore.updateSessions(() => [{
    sessionUuid, targetUrl: "http://localhost:8081/",
    status: "running", phase: "observe", iteration: 1, findings: 0,
  }]);

  const before = huntStore.activeSessions.find(s => s.sessionUuid === sessionUuid);
  assert(before?.costUsd === undefined, "no cost shown before the first spend_update (matches the real UI's typeof-number guard)");

  console.log("\n=== First spend_update (matches the real captured server payload) ===");
  handleSpendUpdate({ sessionId: sessionUuid, costUsd: 0.0026249999999999997, callCount: 2 });
  const after1 = huntStore.activeSessions.find(s => s.sessionUuid === sessionUuid);
  assert(after1?.costUsd === 0.0026249999999999997, `session.costUsd set from the update (got ${after1?.costUsd})`);
  assert(after1?.llmCallCount === 2, `session.llmCallCount set from the update (got ${after1?.llmCallCount})`);

  console.log("\n=== Second spend_update (climbed, matching the second captured server payload) ===");
  handleSpendUpdate({ sessionId: sessionUuid, costUsd: 0.0032499999999999994, callCount: 3 });
  const after2 = huntStore.activeSessions.find(s => s.sessionUuid === sessionUuid);
  assert(after2!.costUsd! > after1!.costUsd!, `cost climbed across updates (${after1?.costUsd} -> ${after2?.costUsd})`);
  assert(after2?.llmCallCount === 3, `call count climbed (got ${after2?.llmCallCount})`);

  console.log(failures === 0 ? "\nALL CHECKS PASSED\n" : `\n${failures} CHECK(S) FAILED\n`);
  process.exit(failures === 0 ? 0 : 1);
}

main();
