import { Router, Request, Response } from "express";
import { metaReasoner } from "../lib/intelligence/meta-reasoning";
import { contextualToolSelector } from "../lib/intelligence/contextual-tool-selector";
import { backwardPlanner } from "../lib/intelligence/backward-planner";
import {
  PIVOT_PLAYBOOKS,
  ATTACK_PATHS,
  MITRE_TECHNIQUES,
} from "../lib/intelligence/seed-knowledge";
import { writeupScraper } from "../lib/intelligence/writeup-scraper";
import { db } from "../db";
import { scrapedIntelligence } from "../db/schema";
import { count } from "drizzle-orm";

const router = Router();

// ─── Playbooks ────────────────────────────────────────────────────────────────

router.get("/playbooks", (_req: Request, res: Response) => {
  try {
    res.json({ playbooks: PIVOT_PLAYBOOKS });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

// ─── Tools ────────────────────────────────────────────────────────────────────

router.get("/tools", (_req: Request, res: Response) => {
  try {
    const implications = contextualToolSelector.getImplications();
    const allTools = new Set<string>();
    for (const impl of implications) {
      for (const tool of impl.suggestedTools) {
        allTools.add(tool);
      }
    }
    res.json({ tools: Array.from(allTools) });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

router.post("/tools/select", (req: Request, res: Response) => {
  try {
    const { context } = req.body;
    const { huntId, availableTools } = context || {};
    if (!huntId || !availableTools) {
      return res
        .status(400)
        .json({ error: "context.huntId and context.availableTools are required" });
    }
    const ranked = contextualToolSelector.select(huntId, availableTools);
    res.json({ tools: ranked });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

// ─── Strategy ─────────────────────────────────────────────────────────────────

router.post("/strategy", (req: Request, res: Response) => {
  try {
    const { goal, target, context } = req.body;
    const huntId = context?.huntId || `strategy-${Date.now()}`;
    const targetProfile = context?.targetProfile;
    const programContext = context?.programContext;
    const plan = backwardPlanner.planHunt(huntId, goal, targetProfile, programContext);
    res.json({ huntId, goal, target, plan });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

// ─── Attack Paths ─────────────────────────────────────────────────────────────

router.get("/attack-paths", (_req: Request, res: Response) => {
  try {
    res.json({ attackPaths: ATTACK_PATHS });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

// ─── Techniques ───────────────────────────────────────────────────────────────

router.get("/techniques", (_req: Request, res: Response) => {
  try {
    res.json({ techniques: MITRE_TECHNIQUES });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

// ─── Pivot ────────────────────────────────────────────────────────────────────

router.post("/pivot", (req: Request, res: Response) => {
  try {
    const { huntId, trigger } = req.body;
    if (!huntId || !trigger) {
      return res.status(400).json({ error: "huntId and trigger are required" });
    }
    const decision = metaReasoner.evaluate(huntId);
    const pivotSuggestions = backwardPlanner.suggestPivot(huntId, trigger);
    res.json({
      huntId,
      trigger,
      decision,
      pivotSuggestions: pivotSuggestions || [],
    });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

// ─── Campaigns ────────────────────────────────────────────────────────────────

router.get("/campaigns", (_req: Request, res: Response) => {
  res.json({ campaigns: [], message: "use /api/hunt/campaigns" });
});

// ─── Writeup Intelligence ─────────────────────────────────────────────────────

router.post("/scrape-writeups", async (_req: Request, res: Response) => {
  try {
    const result = await writeupScraper.scrapeAll();
    res.json({ scraped: result.hackerone + result.nvd, breakdown: result });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

router.get("/scraped-count", async (_req: Request, res: Response) => {
  try {
    const [row] = await db.select({ count: count() }).from(scrapedIntelligence);
    const status = writeupScraper.getStatus();
    res.json({ count: Number(row?.count ?? 0), lastScrape: status.lastScrape });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

export default router;
