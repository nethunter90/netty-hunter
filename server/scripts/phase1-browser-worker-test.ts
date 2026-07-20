/**
 * Phase 1 adversarial case 7 — the shared-context worker (VerifierAgent's
 * Layer 3 playwright-worker.ts). Its browser CONTEXT is created once and
 * reused across the worker's whole lifetime; a fresh PAGE is created per
 * replay() call. Proves: two replay() calls with DIFFERENT programIds on
 * the SAME long-lived context each enforce their OWN scope, with no leak
 * in either direction — using the identical target URL for both, so the
 * only variable is which programId was supplied.
 *
 * Spawns the real playwright-worker.ts as an actual worker_thread and drives
 * it via the exact message protocol VerifierAgent.ts uses — not a mock.
 *
 * Run: npx tsx scripts/phase1-browser-worker-test.ts
 */
import "dotenv/config";
import { Worker } from "worker_threads";
import path from "path";
import { readFileSync } from "fs";

const PROGRAM_A = 1147; // scope=["localhost:9991"]  outOfScope=["127.0.0.1:9992"]
const PROGRAM_B = 1148; // scope=["127.0.0.1:9994"]   outOfScope=["127.0.0.1:9992"]
const SHARED_TARGET = "http://[::1]:9994/"; // in-scope for B, NOT in-scope for A

const INSCOPE_B_LOG = "/tmp/claude-1000/-home-kali-Desktop-netty-hunter/9c701b6a-e045-44b9-b400-855c6f8eb116/scratchpad/inscope_b_access.log";

function hitCount(logPath: string): number {
  try {
    return readFileSync(logPath, "utf-8").split("\n").filter(l => l.trim().length > 0).length;
  } catch {
    return 0;
  }
}

function postAndWait(worker: Worker, msg: any): Promise<any> {
  return new Promise((resolve, reject) => {
    const onMessage = (m: any) => {
      if (m.id === msg.id || (msg.type === "init" && m.type === "ready")) {
        worker.off("message", onMessage);
        resolve(m);
      } else if (m.type === "error" && m.id === msg.id) {
        worker.off("message", onMessage);
        reject(new Error(m.message));
      }
    };
    worker.on("message", onMessage);
    worker.postMessage(msg);
  });
}

async function main() {
  const workerSrc = path.join(__dirname, "..", "src", "workers", "playwright-worker.ts");
  // playwright-worker.ts is a .ts file; run it through tsx's loader by spawning
  // via execArgv, matching how VerifierAgent falls back when no compiled .js exists.
  const worker = new Worker(workerSrc, { execArgv: ["--require", "tsx/cjs"] });

  let pass = true;
  try {
    console.log("=== Initializing worker (real browser launch) ===");
    await postAndWait(worker, { type: "init" });
    console.log("Worker ready.\n");

    console.log(`Hits on port-9994 server BEFORE any replay: ${hitCount(INSCOPE_B_LOG)}`);

    console.log("\n=== REPLAY 1: programId=A navigating to a URL in-scope for B, NOT for A → must be BLOCKED ===");
    const r1 = await postAndWait(worker, {
      type: "replay",
      id: "replay-1",
      result: {
        taskId: "t1", endpoint: SHARED_TARGET, vulnClass: "info_disclosure",
        payload: "", found: false, confidence: 0, request: SHARED_TARGET,
        programId: PROGRAM_A,
      },
    });
    console.log("Replay 1 result:", JSON.stringify(r1.data));
    const hitsAfterReplay1 = hitCount(INSCOPE_B_LOG);
    console.log(`Hits on port-9994 server after replay 1 (programId=A): ${hitsAfterReplay1} (must be 0 — A's scope must apply, not B's)`);
    if (hitsAfterReplay1 !== 0) { console.log("FAIL — cross-program scope leak: A's replay reached B's in-scope host"); pass = false; }

    console.log("\n=== REPLAY 2: programId=B navigating to the SAME URL → must be ALLOWED (B's own scope covers it) ===");
    const r2 = await postAndWait(worker, {
      type: "replay",
      id: "replay-2",
      result: {
        taskId: "t2", endpoint: SHARED_TARGET, vulnClass: "info_disclosure",
        payload: "", found: false, confidence: 0, request: SHARED_TARGET,
        programId: PROGRAM_B,
      },
    });
    console.log("Replay 2 result:", JSON.stringify(r2.data));
    const hitsAfterReplay2 = hitCount(INSCOPE_B_LOG);
    console.log(`Hits on port-9994 server after replay 2 (programId=B): ${hitsAfterReplay2} (must be exactly 1 — B's own replay, and only B's, reached it)`);
    if (hitsAfterReplay2 !== 1) { console.log("FAIL — expected exactly 1 hit (B's legitimate access)"); pass = false; }

    console.log("\n=== REPLAY 3: programId=A again, same target → must STILL be BLOCKED (no stale-allow from replay 2's context reuse) ===");
    const r3 = await postAndWait(worker, {
      type: "replay",
      id: "replay-3",
      result: {
        taskId: "t3", endpoint: SHARED_TARGET, vulnClass: "info_disclosure",
        payload: "", found: false, confidence: 0, request: SHARED_TARGET,
        programId: PROGRAM_A,
      },
    });
    console.log("Replay 3 result:", JSON.stringify(r3.data));
    const hitsAfterReplay3 = hitCount(INSCOPE_B_LOG);
    console.log(`Hits on port-9994 server after replay 3 (programId=A again): ${hitsAfterReplay3} (must STILL be exactly 1 — no new hit from A)`);
    if (hitsAfterReplay3 !== 1) { console.log("FAIL — A's second replay leaked through, possibly using a stale/cached scope decision from replay 2"); pass = false; }

  } finally {
    worker.postMessage({ type: "close" });
    await new Promise(r => setTimeout(r, 500));
    await worker.terminate();
  }

  console.log("\n=== FINAL ===");
  console.log(pass ? "ALL TESTS PASS — no cross-program scope leak on the shared worker context" : "AT LEAST ONE TEST FAILED");
  process.exit(pass ? 0 : 1);
}

main().catch(err => {
  console.error("Harness error:", err);
  process.exit(1);
});
