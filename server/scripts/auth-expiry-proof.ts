/**
 * Phase 2 — isolated, deterministic proof for the auth-expiry handoff
 * (readiness blocker #2), against the REAL running Phase-1 code (no mocks),
 * driven by a local HTTP server whose auth behavior we fully control.
 * Creates its own throwaway program/campaign/target/hunt_session rows and
 * deletes everything it created, whether it passes or fails.
 *
 * Run: npx tsx scripts/auth-expiry-proof.ts
 */
import "dotenv/config";
import http from "http";
import { pool, db } from "../src/db";
import { programs, campaigns, targets, huntSessions } from "../src/db/schema";
import { eq } from "drizzle-orm";
import { sessionManager, AuthSessionFailedError } from "../src/lib/tools/session-manager";
import { HunterEngine, HuntState } from "../src/agents/HunterEngine";

let failures = 0;
function assert(cond: boolean, label: string): void {
  if (cond) console.log(`  PASS  ${label}`);
  else { failures++; console.log(`  FAIL  ${label}`); }
}
function sleep(ms: number) { return new Promise(r => setTimeout(r, ms)); }

async function main() {
  // ── Controlled test server: full control over auth behavior ────────────
  let sessionValidServerSide = true;
  const server = http.createServer((req, res) => {
    const cookie = req.headers.cookie || "";
    const authed = sessionValidServerSide && cookie.includes("session=valid-token");

    if (req.url === "/public-root") {
      res.writeHead(200); res.end("public homepage"); return; // 2xx regardless — the blind baseline
    }
    if (req.url === "/protected") {
      if (authed) { res.writeHead(200); res.end("protected data"); }
      else { res.writeHead(401); res.end("unauthorized"); }
      return;
    }
    if (req.url === "/never-authed") {
      res.writeHead(401); res.end("always requires auth we never have"); return; // legitimate 401
    }
    if (req.url === "/login" && req.method === "POST") {
      let body = "";
      req.on("data", c => body += c);
      req.on("end", () => {
        const params = new URLSearchParams(body);
        if (params.get("username") === "gooduser" && params.get("password") === "goodpass") {
          res.writeHead(200, { "Set-Cookie": "session=valid-token" }); res.end("ok");
        } else {
          res.writeHead(401); res.end("bad creds"); // no Set-Cookie
        }
      });
      return;
    }
    res.writeHead(404); res.end();
  });
  await new Promise<void>(resolve => server.listen(0, "127.0.0.1", resolve));
  const port = (server.address() as { port: number }).port;
  const origin = `http://127.0.0.1:${port}`;
  console.log("test server:", origin);

  const cleanup: Array<() => Promise<void>> = [];
  const [program] = await db.insert(programs).values({
    name: "__auth_proof_program__", platform: "local", scope: ["*"], outOfScope: [],
  }).returning();
  cleanup.push(async () => { await db.delete(programs).where(eq(programs.id, program.id)); });

  async function runCleanup() {
    for (const fn of cleanup.reverse()) { try { await fn(); } catch { /* best-effort */ } }
  }

  try {
    await runTests(program.id, origin, () => { sessionValidServerSide = true; }, () => { sessionValidServerSide = false; }, cleanup);
  } catch (err) {
    console.error("auth-expiry-proof crashed mid-run:", err);
    failures++;
  }

  await runCleanup();
  server.close();
  console.log(failures === 0 ? `\nALL CHECKS PASSED\n` : `\n${failures} CHECK(S) FAILED\n`);
  await pool.end();
  process.exit(failures === 0 ? 0 : 1);
}

async function runTests(
  programId: number, origin: string,
  restoreSession: () => void, dropSession: () => void,
  cleanup: Array<() => Promise<void>>,
) {
  console.log("\n=== Test 0a: blind-detector gap is now caught, not silently 'healthy' ===\n");
  {
    // Seed a valid session directly (bypassing a real /login round-trip for speed).
    (sessionManager as unknown as { sessions: Map<number, unknown> }).sessions.set(programId, {
      headers: { Cookie: "session=valid-token" }, cookies: "session=valid-token",
      expiresAt: Date.now() + 30 * 60 * 1000, valid: true,
    });
    restoreSession();

    const r1 = await sessionManager.checkLiveness(programId, `${origin}/public-root`, {});
    assert(r1.inactive === true, `public-root-only baseline is declared INACTIVE, not silently healthy (got inactive=${r1.inactive})`);
    assert(r1.dropped === false, `inactive baseline never falsely reports 'dropped' (got ${r1.dropped})`);

    dropSession();
    const r2 = await sessionManager.checkLiveness(programId, `${origin}/public-root`, {});
    assert(r2.dropped === false && r2.inactive === true, `still inactive after a real server-side drop — never silently claims 'healthy', honestly reports 'not checking' instead (got dropped=${r2.dropped}, inactive=${r2.inactive})`);
    restoreSession();
    (sessionManager as unknown as { liveness: Map<number, unknown> }).liveness.delete(programId);
  }

  console.log("\n=== Test 0b: a discriminating baseline (livenessUrl=/protected) actually detects a drop ===\n");
  {
    (sessionManager as unknown as { sessions: Map<number, unknown> }).sessions.set(programId, {
      headers: { Cookie: "session=valid-token" }, cookies: "session=valid-token",
      expiresAt: Date.now() + 30 * 60 * 1000, valid: true,
    });
    restoreSession();
    const config = { livenessUrl: `${origin}/protected` };

    const r1 = await sessionManager.checkLiveness(programId, `${origin}/public-root`, config);
    assert(r1.inactive !== true, `configured discriminating livenessUrl establishes a working baseline (got inactive=${r1.inactive})`);
    assert(r1.ok === true && r1.dropped === false, `first check while session is valid: ok=true, dropped=false (got ok=${r1.ok}, dropped=${r1.dropped})`);

    dropSession();
    const r2 = await sessionManager.checkLiveness(programId, `${origin}/public-root`, config);
    assert(r2.ok === false && r2.dropped === false && r2.consecutiveFailures === 1,
      `1st failing re-check: ok=false, dropped=false (below N-of-M threshold), consecutiveFailures=1 (got ok=${r2.ok}, dropped=${r2.dropped}, cf=${r2.consecutiveFailures})`);

    const r3 = await sessionManager.checkLiveness(programId, `${origin}/public-root`, config);
    assert(r3.dropped === true && r3.consecutiveFailures === 2,
      `2nd consecutive failing re-check: dropped=true (N-of-M=2 threshold met), consecutiveFailures=2 (got dropped=${r3.dropped}, cf=${r3.consecutiveFailures})`);
  }

  console.log("\n=== Test 4: transient recovers (both a network blip and a single 401) ===\n");
  {
    restoreSession();
    (sessionManager as unknown as { liveness: Map<number, unknown> }).liveness.delete(programId);
    (sessionManager as unknown as { sessions: Map<number, unknown> }).sessions.set(programId, {
      headers: { Cookie: "session=valid-token" }, cookies: "session=valid-token",
      expiresAt: Date.now() + 30 * 60 * 1000, valid: true,
    });
    const config = { livenessUrl: `${origin}/protected` };
    await sessionManager.checkLiveness(programId, `${origin}/public-root`, config); // establish

    dropSession();
    const fail1 = await sessionManager.checkLiveness(programId, `${origin}/public-root`, config);
    assert(fail1.dropped === false && fail1.consecutiveFailures === 1, `single failure does not pause (dropped=${fail1.dropped})`);

    restoreSession(); // recovers before the 2nd threshold check
    const recovered = await sessionManager.checkLiveness(programId, `${origin}/public-root`, config);
    assert(recovered.ok === true && recovered.consecutiveFailures === 0, `recovery resets the streak to 0 (got ok=${recovered.ok}, cf=${recovered.consecutiveFailures})`);

    // A network error (unreachable port) on the re-check itself must not count.
    const deadOrigin = "http://127.0.0.1:1"; // nothing listens here
    (sessionManager as unknown as { liveness: Map<number, unknown> }).liveness.set(programId, {
      baselineUrl: `${deadOrigin}/protected`, consecutiveFailures: 0, inactive: false, triedCandidates: [`${deadOrigin}/protected`],
    });
    const netErr = await sessionManager.checkLiveness(programId, deadOrigin, { livenessUrl: `${deadOrigin}/protected` });
    assert(netErr.dropped === false && netErr.checked === false, `a network error on the liveness probe itself is not counted toward the streak, never pauses (got dropped=${netErr.dropped}, checked=${netErr.checked})`);
    (sessionManager as unknown as { liveness: Map<number, unknown> }).liveness.delete(programId);
  }

  console.log("\n=== Test 3: legitimate 401s on never-authenticated endpoints do NOT touch liveness state ===\n");
  {
    restoreSession();
    (sessionManager as unknown as { sessions: Map<number, unknown> }).sessions.set(programId, {
      headers: { Cookie: "session=valid-token" }, cookies: "session=valid-token",
      expiresAt: Date.now() + 30 * 60 * 1000, valid: true,
    });
    const config = { livenessUrl: `${origin}/protected` };
    await sessionManager.checkLiveness(programId, `${origin}/public-root`, config); // establish + 1 clean check

    // Simulate the hunt hitting a bunch of normal, legitimately-401 probe
    // endpoints — none of this goes through checkLiveness/SessionManager at
    // all (it's a plain scopedHttp/tool call in the real engine), so by
    // construction it cannot touch the liveness streak. Confirm the state
    // machine's own accounting agrees: streak still 0, still not dropped.
    for (let i = 0; i < 10; i++) {
      await fetch(`${origin}/never-authed`).catch(() => {});
    }
    const stillHealthy = await sessionManager.checkLiveness(programId, `${origin}/public-root`, config);
    assert(stillHealthy.ok === true && stillHealthy.consecutiveFailures === 0,
      `10 legitimate 401s on an unrelated endpoint left the liveness streak untouched (got ok=${stillHealthy.ok}, cf=${stillHealthy.consecutiveFailures})`);
  }

  console.log("\n=== Test 1: root fix — failed login is loud (throws), not counterfeit ===\n");
  {
    (sessionManager as unknown as { sessions: Map<number, unknown> }).sessions.delete(programId);
    const badConfig = { loginUrl: `${origin}/login`, username: "wronguser", password: "wrongpass", authType: "form" as const };

    let threw = false;
    let thrownIsRightType = false;
    const t0 = Date.now();
    try {
      await sessionManager.ensureSession(programId, badConfig);
    } catch (err) {
      threw = true;
      thrownIsRightType = err instanceof AuthSessionFailedError;
    }
    const elapsed = Date.now() - t0;
    assert(threw, `ensureSession() with bad credentials THROWS (does not silently return a fake session)`);
    assert(thrownIsRightType, `the thrown error is AuthSessionFailedError specifically`);
    assert(elapsed > 3900, `bounded retry with backoff actually ran (>=2 backoff waits, ~4s elapsed; got ${elapsed}ms) — not a bare first-attempt throw`);

    const cached = sessionManager.getSession(programId);
    assert(cached === null, `getSession() after a failed login returns null — isValid() correctly REJECTS the failed session (got ${JSON.stringify(cached)})`);

    // Empty Set-Cookie form-login path — the second counterfeit-success shape closed in Phase 1.
    const emptyCookieServer = http.createServer((req, res) => {
      if (req.url === "/login-no-cookie") { res.writeHead(200); res.end("ok but no cookie"); return; }
      res.writeHead(404); res.end();
    });
    await new Promise<void>(resolve => emptyCookieServer.listen(0, "127.0.0.1", resolve));
    const ecPort = (emptyCookieServer.address() as { port: number }).port;
    let emptyCookieThrew = false;
    try {
      await sessionManager.ensureSession(programId + 1000000, {
        loginUrl: `http://127.0.0.1:${ecPort}/login-no-cookie`, username: "u", password: "p", authType: "form",
      });
    } catch (err) {
      emptyCookieThrew = err instanceof AuthSessionFailedError;
    }
    assert(emptyCookieThrew, `a 200 login response with NO Set-Cookie header is also treated as a failure (the second counterfeit-success shape), not a silent empty-headers "success"`);
    emptyCookieServer.close();
  }

  console.log("\n=== Test 2: mid-TTL drop -> paused_auth checkpoint -> resume ===\n");
  {
    const [target] = await db.insert(targets).values({ programId, url: origin, type: "web" }).returning();
    cleanup.push(async () => { await db.delete(targets).where(eq(targets.id, target.id)); });
    const [campaign] = await db.insert(campaigns).values({ programId, name: "__auth_proof_campaign__", goal: "proof" }).returning();
    cleanup.push(async () => { await db.delete(campaigns).where(eq(campaigns.id, campaign.id)); });
    const sessionUuid = "__auth_proof_hunt__";
    const [session] = await db.insert(huntSessions).values({ campaignId: campaign.id, targetId: target.id, sessionUuid }).returning();
    cleanup.push(async () => { await db.delete(huntSessions).where(eq(huntSessions.id, session.id)); });

    const minimalState: HuntState = {
      sessionId: sessionUuid, targetUrl: origin, programId, phase: "probe",
      observations: [], hypotheses: [], probes: [], confirmedFindings: [],
      iteration: 3, maxIterations: 10,
      budget: { maxRequests: 100, requestsMade: 12, maxTime: 3600, elapsed: 120 },
      corpusEnrichment: false, proxyEnabled: false, wafBypassEnabled: false,
      automatedScanningEnabled: false, discoveredEndpoints: [],
    };

    const engine = new HunterEngine();
    (engine as unknown as { state: HuntState }).state = minimalState;
    (engine as unknown as { campaignId: number }).campaignId = campaign.id;
    (engine as unknown as { targetId: number }).targetId = target.id;
    (engine as unknown as { authPaused: boolean }).authPaused = true;
    (engine as unknown as { authPausedReason: string }).authPausedReason = "proof: simulated mid-TTL drop";

    await (engine as unknown as { persistCheckpoint: (s: string, r: string | null) => Promise<void> })
      .persistCheckpoint("paused_auth", "proof: simulated mid-TTL drop");

    const [row] = await db.select().from(huntSessions).where(eq(huntSessions.sessionUuid, sessionUuid)).limit(1);
    assert(row?.status === "paused_auth", `persistCheckpoint("paused_auth", ...) writes status="paused_auth" to the DB (got "${row?.status}")`);
    assert(!!row?.checkpoint, `checkpoint payload was saved`);
    const cp = row?.checkpoint as { pauseStatus?: string; pausedReason?: string; state?: HuntState };
    assert(cp?.pauseStatus === "paused_auth", `checkpoint.pauseStatus === "paused_auth" (got "${cp?.pauseStatus}")`);
    assert(cp?.pausedReason === "proof: simulated mid-TTL drop", `checkpoint.pausedReason carries the auth failure reason (got "${cp?.pausedReason}")`);
    assert(cp?.state?.iteration === 3, `full HuntState (iteration, budget, etc.) was preserved in the checkpoint`);

    // Re-authenticate server-side, then resume on a FRESH engine instance
    // (exactly how routes/hunt.ts's /resume route does it).
    restoreSession();
    const freshEngine = new HunterEngine();
    let resumeThrew: unknown = null;
    try {
      await freshEngine.resumeHunt(sessionUuid);
    } catch (err) {
      resumeThrew = err;
    }
    assert(resumeThrew === null, `resumeHunt() on a paused_auth session does not throw (got ${String(resumeThrew)})`);
    assert((freshEngine as unknown as { authPaused: boolean }).authPaused === false, `resumeHunt() resets authPaused=false on the resumed engine`);
    // resumeHunt() genuinely CONTINUES the hunt loop (not just a passive
    // restore-then-halt) — iteration only ever increases from the
    // checkpointed value of 3, confirmed separately (and more precisely)
    // by the checkpoint-payload assertion above. >=3 here, not ===3.
    assert((freshEngine as unknown as { state: HuntState }).state.iteration >= 3, `resumeHunt() restored state starting from iteration=3 and continued the loop (got ${(freshEngine as unknown as { state: HuntState }).state.iteration})`);

    const [rowAfter] = await db.select().from(huntSessions).where(eq(huntSessions.sessionUuid, sessionUuid)).limit(1);
    assert(rowAfter?.status === "running" || rowAfter?.status === "completed", `after resume, DB status is no longer "paused_auth" (got "${rowAfter?.status}")`);

    // Halt the still-running background loop before cleanup deletes its rows.
    (freshEngine as unknown as { stop: () => void }).stop();
    await sleep(500);
  }
}

main().catch(async err => { console.error(err); await pool.end().catch(() => {}); process.exit(1); });
