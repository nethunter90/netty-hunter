/**
 * Kali-Web-IDE target supervisor — keeps the hunt target alive across a run,
 * without erasing the evidence that it died.
 *
 * Fix 2c (target-crash handoff, 2026-07-03): the crawler's build-orchestrator
 * interaction reliably crashes Kali-Web-IDE's own dev server (ECONNREFUSED on
 * :5000), and it does not come back without a manual `npm run dev`.
 * HunterEngine now (a) doesn't mislabel this as an IP ban, (b) records it as a
 * candidate `service_disruption` hypothesis, and (c) no longer halts the whole
 * hunt when it happens — it just keeps probing, on the assumption that
 * *something* will bring the target back. This script is that something.
 *
 * The restart can't be silent. A supervisor that quietly runs `npm run dev` on
 * death and says nothing would resurrect the target and erase the evidence
 * that the crawler just took it down. So on every death this script, in order:
 *   1. Records the crash (timestamp + restart count) to a JSONL log, plus a
 *      tail of the engine's own combined.log at that moment — the engine logs
 *      each probe/hypothesis, so whatever it was doing right before the crash
 *      is sitting in that tail. This is the artifact 2b's captured hypothesis
 *      (also timestamped) correlates against after the fact.
 *   2. Restarts `npm run dev` and gates on real port-readiness before
 *      considering the target "back" — resuming too early just produces a
 *      second false crash record when the engine's next probe hits a
 *      still-booting server.
 *
 * Death detection is deliberately narrow: only the child process exiting on
 * its own, or an explicit ECONNREFUSED on a fresh TCP connect, count as
 * "dead." A connect *timeout* is ambiguous (could just be a slow response
 * under load) and must NOT trigger a restart — killing and restarting a
 * healthy-but-slow server would corrupt the run as badly as not restarting
 * a dead one.
 *
 * Restarts are capped (MAX_RESTARTS) so a reliably-reproducible crash doesn't
 * spin forever (click -> crash -> restart -> click -> crash). Hitting the cap
 * isn't just a failsafe — if every restart was triggered by the same
 * preceding action, that's corroboration for 2b's finding (a repeatable
 * unauthenticated crash), so it's logged as strengthening the finding, not
 * just "gave up."
 *
 * This is test-harness/infra, deliberately kept OUT of HunterEngine — the
 * engine hunts, this owns the target's lifecycle. The engine doesn't know or
 * need to know it's being babysat.
 *
 * Caveat worth carrying into the finding writeup: this only works because the
 * target is local and disposable. On a real program, crashing the service
 * once means you're done (and possibly in violation of scope/DoS policy) —
 * there's no supervisor to page. Note in the finding: "reproducible service
 * crash — high impact, but check program DoS policy before ever triggering
 * this on a live target."
 *
 * Run: npx tsx scripts/kali-web-ide-supervisor.ts [path-to-Kali-Web-IDE]
 * Stop: Ctrl-C (sends SIGTERM to the child and exits cleanly)
 */
import { spawn, ChildProcess } from "child_process";
import net from "net";
import fs from "fs";
import path from "path";

const TARGET_DIR = process.argv[2] || "/home/kali/Desktop/Kali-Web-IDE";
const PORT = parseInt(process.env.TARGET_PORT || "5000", 10);
const HOST = "127.0.0.1";
const HEALTHY_STARTUP_TIMEOUT_MS = 30_000;
const POLL_INTERVAL_MS = 3_000;
const RESTART_BACKOFF_MS = [1_000, 3_000, 5_000, 10_000];
const MAX_RESTARTS = 5;

const CRASH_LOG_PATH = path.join(__dirname, "..", "workspace", "target-crashes.jsonl");
const ENGINE_LOG_PATH = path.join(__dirname, "..", "logs", "combined.log");
const ENGINE_LOG_TAIL_LINES = 20;

let child: ChildProcess | null = null;
let restartCount = 0;
let capReached = false;
let shuttingDown = false;
let killedByLivenessPoll = false; // suppresses the exit handler's own record+reschedule for a kill we already handled

function log(msg: string) {
  console.log(`[supervisor] ${new Date().toISOString()} ${msg}`);
}

type LivenessResult = "open" | "refused" | "timeout" | "other";

function checkLiveness(): Promise<LivenessResult> {
  return new Promise((resolve) => {
    const socket = net.createConnection({ host: HOST, port: PORT }, () => {
      socket.end();
      resolve("open");
    });
    socket.setTimeout(2000);
    socket.on("error", (err: NodeJS.ErrnoException) => {
      resolve(err.code === "ECONNREFUSED" ? "refused" : "other");
    });
    socket.on("timeout", () => { socket.destroy(); resolve("timeout"); });
  });
}

async function waitForHealthy(timeoutMs: number): Promise<boolean> {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    if ((await checkLiveness()) === "open") return true;
    await new Promise((r) => setTimeout(r, 1000));
  }
  return false;
}

function tailEngineLog(lines: number): string[] {
  try {
    const content = fs.readFileSync(ENGINE_LOG_PATH, "utf8");
    const allLines = content.split("\n").filter(Boolean);
    return allLines.slice(-lines);
  } catch {
    return [];
  }
}

function recordCrash(trigger: string, detail: Record<string, unknown>) {
  const record = {
    timestamp: new Date().toISOString(),
    trigger,
    restartNumber: restartCount + 1,
    ...detail,
    // Best-effort correlation: whatever the engine was logging right before
    // this crash was detected is almost certainly the action that caused it.
    engineLogTailAtCrash: tailEngineLog(ENGINE_LOG_TAIL_LINES),
  };
  try {
    fs.mkdirSync(path.dirname(CRASH_LOG_PATH), { recursive: true });
    fs.appendFileSync(CRASH_LOG_PATH, JSON.stringify(record) + "\n");
  } catch (err) {
    log(`failed to write crash record: ${err}`);
  }
  log(`crash recorded (#${record.restartNumber}) -> ${CRASH_LOG_PATH}`);
}

function startTarget() {
  log(`starting target: npm run dev (cwd=${TARGET_DIR})`);
  child = spawn("npm", ["run", "dev"], {
    cwd: TARGET_DIR,
    env: { ...process.env, PORT: String(PORT) },
    stdio: ["ignore", "pipe", "pipe"],
  });

  child.stdout?.on("data", (d) => process.stdout.write(`[target] ${d}`));
  child.stderr?.on("data", (d) => process.stderr.write(`[target] ${d}`));

  child.on("exit", (code, signal) => {
    child = null;
    if (shuttingDown) return;
    if (killedByLivenessPoll) {
      // Already recorded and scheduled by the liveness-poll branch — this exit
      // event is just the tail end of the kill() we issued there.
      killedByLivenessPoll = false;
      return;
    }
    recordCrash("process_exit", { code, signal });
    scheduleRestart();
  });
}

function scheduleRestart() {
  if (restartCount >= MAX_RESTARTS) {
    if (!capReached) {
      capReached = true;
      log(`restart cap (${MAX_RESTARTS}) reached — NOT restarting again. ` +
          `${MAX_RESTARTS} restarts from what appears to be the same trigger is strong ` +
          `corroboration this is a reliably-reproducible unauthenticated crash, not a fluke — ` +
          `treat that as strengthening the 2b finding, not just a failsafe tripping. Target left down.`);
    }
    return;
  }
  const delay = RESTART_BACKOFF_MS[Math.min(restartCount, RESTART_BACKOFF_MS.length - 1)];
  restartCount++;
  log(`restarting in ${delay}ms (restart #${restartCount}/${MAX_RESTARTS})`);
  setTimeout(async () => {
    startTarget();
    const healthy = await waitForHealthy(HEALTHY_STARTUP_TIMEOUT_MS);
    if (healthy) {
      log(`target healthy again on :${PORT} — gate cleared, hunt can resume probing`);
    } else {
      log(`target did not come up within ${HEALTHY_STARTUP_TIMEOUT_MS}ms — will retry`);
      scheduleRestart();
    }
  }, delay);
}

async function main() {
  const initialCheck = await checkLiveness();
  if (initialCheck === "open") {
    log(`something is already listening on :${PORT} — not spawning a second instance. ` +
        `Kill the existing process first if you want the supervisor to own it.`);
    return;
  }

  startTarget();
  const healthy = await waitForHealthy(HEALTHY_STARTUP_TIMEOUT_MS);
  if (!healthy) {
    log(`WARNING: target did not become healthy within ${HEALTHY_STARTUP_TIMEOUT_MS}ms of first start`);
  } else {
    log(`target healthy on :${PORT} — supervising (max ${MAX_RESTARTS} restarts/hunt)`);
  }

  // Independent liveness poll — catches the case where the child process is
  // still technically running but the port has been refusing connections
  // (e.g. it crashed and something else respawned it outside our control, or
  // it's in a broken half-dead state). Only ECONNREFUSED counts as death here;
  // a timeout just means "slow right now" and is left alone on purpose so a
  // healthy-but-loaded server never gets killed mid-hunt.
  setInterval(async () => {
    if (shuttingDown || !child || capReached) return;
    const result = await checkLiveness();
    if (result === "refused") {
      log(`liveness poll: :${PORT} actively refusing connections while child is still running — real death, restarting`);
      recordCrash("liveness_poll_refused", {});
      killedByLivenessPoll = true;
      child.kill("SIGKILL");
      scheduleRestart();
    }
    // "timeout" and "other" are deliberately ignored — not a confirmed death.
  }, POLL_INTERVAL_MS);
}

function shutdown() {
  shuttingDown = true;
  log("shutting down — stopping target");
  if (child) child.kill("SIGTERM");
  process.exit(0);
}

process.on("SIGINT", shutdown);
process.on("SIGTERM", shutdown);

main().catch((err) => {
  log(`fatal: ${err}`);
  process.exit(1);
});
