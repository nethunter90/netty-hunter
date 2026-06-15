import { Router, Request, Response } from "express";
import fs from "fs/promises";
import path from "path";
import logger from "../utils/logger";
import { db } from "../db";
import { findings } from "../db/schema";
import { sql } from "drizzle-orm";

// Evidence router.
//
//  GET /stats – computes real artifact statistics by walking the evidence/
//               directory (the CampaignOrchestrator + browser verifier write
//               screenshots/traces to evidence/<id>/) and counts findings from
//               the DB. Shape matches CTFBenchmark.tsx evidenceStats.

const router = Router();
const EVIDENCE_DIR = path.join(process.cwd(), "evidence");

async function walkDir(dir: string): Promise<{ files: number; bytes: number }> {
  let files = 0;
  let bytes = 0;
  let entries: import("fs").Dirent[];
  try {
    entries = await fs.readdir(dir, { withFileTypes: true });
  } catch {
    return { files, bytes };
  }
  for (const entry of entries) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      const sub = await walkDir(full);
      files += sub.files;
      bytes += sub.bytes;
    } else if (entry.isFile()) {
      try {
        const st = await fs.stat(full);
        files++;
        bytes += st.size;
      } catch { /* ignore unreadable file */ }
    }
  }
  return { files, bytes };
}

// ── GET /stats ────────────────────────────────────────────────────────────────
router.get("/stats", async (_req: Request, res: Response) => {
  try {
    // Each top-level subdirectory of evidence/ corresponds to one finding /
    // verification mission (named by finding id or verification id).
    let missionDirs: import("fs").Dirent[] = [];
    try {
      missionDirs = (await fs.readdir(EVIDENCE_DIR, { withFileTypes: true })).filter(d => d.isDirectory());
    } catch {
      // evidence/ does not exist yet — no artifacts captured so far.
      missionDirs = [];
    }

    const { files: totalArtifacts, bytes: totalSizeBytes } = await walkDir(EVIDENCE_DIR);

    // Total findings recorded in the database.
    let totalFindings = 0;
    try {
      const rows = await db.select({ count: sql<number>`count(*)` }).from(findings);
      totalFindings = Number(rows[0]?.count ?? 0);
    } catch (err: any) {
      logger.warn("evidence:/stats DB count failed (continuing)", { err: err.message });
    }

    return res.json({
      totalMissions: missionDirs.length,
      totalFindings,
      totalArtifacts,
      totalSizeBytes,
    });
  } catch (err: any) {
    logger.error("evidence:/stats failed", { err: err.message });
    return res.status(500).json({ error: err.message });
  }
});

export default router;
