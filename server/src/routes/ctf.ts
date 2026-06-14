import { Router, Request, Response } from "express";
import fs from "fs/promises";
import path from "path";
import { v4 as uuidv4 } from "uuid";
import logger from "../utils/logger";

// CTF benchmark router.
//
// Models the same runner pattern xbow.ts / juiceshop.ts use: runs are persisted
// as JSON files under workspace/lab-runs and replayed for history. The synthetic
// CTF challenge set does not ship with this build yet, so /challenges returns an
// empty list (see TODO below); history/current/run/abort are fully wired to the
// shared on-disk runner so the client behaves identically to the other modes.

const router = Router();
const LAB_RUNS_DIR = path.join(process.cwd(), "workspace", "lab-runs");

const abortFlags = new Map<string, boolean>();
// The most recent in-flight run, exposed via GET /benchmark/current.
let currentRun: { id: string; run: any } | null = null;

let dirReady = false;
async function ensureDir(): Promise<void> {
  if (dirReady) return;
  await fs.mkdir(LAB_RUNS_DIR, { recursive: true });
  dirReady = true;
}

async function saveRun(run: any): Promise<void> {
  await ensureDir();
  await fs.writeFile(
    path.join(LAB_RUNS_DIR, `ctf-${run.id}.json`),
    JSON.stringify(run, null, 2)
  );
}

async function loadHistory(): Promise<any[]> {
  await ensureDir();
  const files = await fs.readdir(LAB_RUNS_DIR).catch(() => [] as string[]);
  const runs = await Promise.all(
    files
      .filter(f => f.startsWith("ctf-") && f.endsWith(".json"))
      .map(async f => {
        try {
          return JSON.parse(await fs.readFile(path.join(LAB_RUNS_DIR, f), "utf8"));
        } catch { return null; }
      })
  );
  return runs
    .filter(Boolean)
    .sort((a, b) => new Date(b.startedAt).getTime() - new Date(a.startedAt).getTime());
}

// TODO: No synthetic CTF challenge dataset ships with this build. When one is
// added (e.g. server/data/ctf/*.json or a lab-profile), load it here and return
// real challenges + stats. Until then the suite exposes an empty challenge list.
function loadChallenges(): { challenges: any[]; stats: any } {
  return {
    challenges: [],
    stats: { total: 0, byDifficulty: { easy: 0, medium: 0, hard: 0 }, byCategory: {}, maxPoints: 0 },
  };
}

// ── Routes ──────────────────────────────────────────────────────────────────

router.get("/challenges", (_req: Request, res: Response) => {
  try {
    return res.json(loadChallenges());
  } catch (err: any) {
    logger.error("ctf:/challenges failed", { err: err.message });
    return res.status(500).json({ error: err.message });
  }
});

router.get("/benchmark/history", async (_req: Request, res: Response) => {
  try {
    const runs = await loadHistory();
    // Client reads `data.runs` for the synthetic suite.
    return res.json({ runs });
  } catch (err: any) {
    logger.error("ctf:/benchmark/history failed", { err: err.message });
    return res.status(500).json({ error: err.message });
  }
});

router.get("/benchmark/current", (_req: Request, res: Response) => {
  if (currentRun) {
    return res.json({ running: true, run: currentRun.run });
  }
  return res.json({ running: false, run: null });
});

router.post("/benchmark/run", async (req: Request, res: Response) => {
  const { difficulty } = req.body as { difficulty?: string };

  const runId = uuidv4();
  abortFlags.set(runId, false);

  const startedAt = new Date().toISOString();
  const { challenges } = loadChallenges();
  const filtered = difficulty
    ? challenges.filter((c: any) => c.difficulty === difficulty)
    : challenges;

  // Mark this run as the live one for /benchmark/current polling.
  currentRun = {
    id: runId,
    run: {
      id: runId,
      status: "running",
      startedAt,
      results: [],
      totalScore: 0,
      maxPossibleScore: 0,
      passRate: 0,
      byDifficulty: {},
      challengeCount: filtered.length,
      passedCount: 0,
      failedCount: 0,
    },
  };

  try {
    // No runnable synthetic challenges yet — produce an empty, completed run so
    // the client renders cleanly. Real per-challenge execution is added here once
    // a challenge dataset exists (mirror xbow.ts's spawn/probe loop).
    const results: any[] = [];

    const run = {
      id: runId,
      status: abortFlags.get(runId) ? ("aborted" as const) : ("completed" as const),
      startedAt,
      completedAt: new Date().toISOString(),
      results,
      totalScore: 0,
      maxPossibleScore: 0,
      passRate: 0,
      byDifficulty: {},
      challengeCount: results.length,
      passedCount: 0,
      failedCount: 0,
    };

    await saveRun(run);
    return res.json(run);
  } catch (err: any) {
    logger.error("ctf:/benchmark/run failed", { err: err.message });
    return res.status(500).json({ error: err.message });
  } finally {
    abortFlags.delete(runId);
    if (currentRun?.id === runId) currentRun = null;
  }
});

router.post("/benchmark/abort", (req: Request, res: Response) => {
  const { runId } = req.body as { runId?: string };
  if (runId) {
    abortFlags.set(runId, true);
  } else {
    for (const [id] of abortFlags) abortFlags.set(id, true);
  }
  return res.json({ ok: true });
});

export default router;
