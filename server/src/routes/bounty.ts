import { Router, Request, Response } from "express";
import { db } from "../db";
import { programs, targets, wafProfiles, reinforcementStore, autonomyMetrics, exploitChains } from "../db/schema";
import { eq, desc } from "drizzle-orm";
import { z } from "zod";
import TargetSelectionIntelligence from "../intelligence/TargetSelection";
import ROIModel from "../intelligence/ROIModel";
import UnifiedReinforcementStore from "../intelligence/ReinforcementStore";
import AutonomyMaturityTracker from "../intelligence/AutonomyTracker";
import ExploitChainIntelligence from "../intelligence/ExploitChain";
import { ModelRouter } from "../intelligence/ModelRouter";
import { HuntStrategyBuilder } from "./huntStrategy";
import logger from "../utils/logger";

const router = Router();
const targetSelection = new TargetSelectionIntelligence();
const roiModel = new ROIModel();
const rlStore = UnifiedReinforcementStore.getInstance();
const autonomyTracker = AutonomyMaturityTracker.getInstance();
const exploitChainIntel = new ExploitChainIntelligence();

// ── Programs ──────────────────────────────────────────────────────────────────
const ProgramSchema = z.object({
  name: z.string().min(1).max(200),
  platform: z.enum(["hackerone", "bugcrowd", "intigriti", "synack", "yeswehack", "other"]),
  programHandle: z.string().optional(),
  scope: z.array(z.string()).default([]),
  outOfScope: z.array(z.string()).default([]),
  maxPayout: z.number().int().min(0).default(0),
  avgPayout: z.number().min(0).default(0),
  responseTime: z.number().min(0).default(72),
  tags: z.array(z.string()).default([]),
});

router.get("/programs", async (_req: Request, res: Response) => {
  const allPrograms = await db.select().from(programs).orderBy(desc(programs.roiScore));
  return res.json(allPrograms);
});

router.post("/programs", async (req: Request, res: Response) => {
  const parsed = ProgramSchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: parsed.error.flatten() });

  const [program] = await db.insert(programs).values(parsed.data).returning();
  return res.status(201).json(program);
});

router.get("/programs/:id", async (req: Request, res: Response) => {
  const [program] = await db.select().from(programs).where(eq(programs.id, parseInt(req.params.id))).limit(1);
  if (!program) return res.status(404).json({ error: "Program not found" });

  const targetList = await db.select().from(targets).where(eq(targets.programId, program.id));
  return res.json({ program, targets: targetList });
});

router.patch("/programs/:id", async (req: Request, res: Response) => {
  const parsed = ProgramSchema.partial().safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: parsed.error.flatten() });
  const [updated] = await db.update(programs)
    .set({ ...parsed.data, updatedAt: new Date() })
    .where(eq(programs.id, parseInt(req.params.id))).returning();
  if (!updated) return res.status(404).json({ error: "Not found" });
  return res.json(updated);
});

router.delete("/programs/:id", async (req: Request, res: Response) => {
  await db.update(programs).set({ active: false }).where(eq(programs.id, parseInt(req.params.id)));
  return res.json({ ok: true });
});

// ── Target Selection Intelligence ─────────────────────────────────────────────
router.get("/rank-programs", async (_req: Request, res: Response) => {
  const scores = await targetSelection.scorePrograms();
  // Persist computed ROI scores back to the programs table
  await Promise.all(scores.map(s =>
    db.update(programs).set({ roiScore: s.roiScore }).where(eq(programs.id, s.programId))
  ));
  return res.json(scores);
});

router.get("/recommend-target", async (req: Request, res: Response) => {
  const exclude = req.query.exclude ? String(req.query.exclude).split(",").map(Number) : [];
  const recommendation = await targetSelection.recommendNextTarget(exclude);
  return res.json(recommendation);
});

// ── ROI Model ─────────────────────────────────────────────────────────────────
router.get("/roi/:vulnClass", async (req: Request, res: Response) => {
  const maxPayout = parseInt(String(req.query.maxPayout || "10000"));
  const programId = req.query.programId ? parseInt(String(req.query.programId)) : undefined;
  const roi = await roiModel.calculateExpectedValue(req.params.vulnClass, maxPayout, programId);
  return res.json(roi);
});

router.get("/roi-ranking", async (req: Request, res: Response) => {
  const maxPayout = parseInt(String(req.query.maxPayout || "10000"));
  const programId = req.query.programId ? parseInt(String(req.query.programId)) : undefined;
  const ranking = await roiModel.rankVulnClasses(maxPayout, programId);
  return res.json(ranking);
});

// ── Reinforcement Learning Store ───────────────────────────────────────────────
router.get("/rl-stats", async (_req: Request, res: Response) => {
  const stats = await rlStore.getStats();
  const brierScore = await rlStore.computeBrierScore();
  return res.json({ stats, brierScore });
});

router.post("/rl-record", async (req: Request, res: Response) => {
  const { domain, key, success } = req.body;
  if (!domain || !key) return res.status(400).json({ error: "domain and key required" });
  const validDomains = ["tool_success", "framework_vuln", "program_type", "confidence_calibration", "exploration"];
  if (!validDomains.includes(domain)) return res.status(400).json({ error: "invalid domain" });
  await rlStore.record(domain, key, Boolean(success));
  return res.json({ ok: true });
});

// ── Autonomy Maturity ─────────────────────────────────────────────────────────
router.get("/autonomy", async (_req: Request, res: Response) => {
  const report = await autonomyTracker.getLatestReport();
  return res.json(report);
});

router.get("/autonomy/history", async (req: Request, res: Response) => {
  const limit = parseInt(String(req.query.limit || "20"));
  const history = await autonomyTracker.getProgressHistory(limit);
  return res.json(history);
});

// ── Exploit Chains ─────────────────────────────────────────────────────────────
router.get("/exploit-chains", async (_req: Request, res: Response) => {
  const chains = await db.select().from(exploitChains).orderBy(desc(exploitChains.createdAt));
  return res.json(chains);
});

router.post("/exploit-chains", async (req: Request, res: Response) => {
  const { campaignId, name, steps, finalObjective } = req.body;
  const chain = await exploitChainIntel.createChain({ campaignId, name, steps, finalObjective });
  return res.status(201).json(chain);
});

router.get("/exploit-chains/prebuilt", (_req: Request, res: Response) => {
  const { ATTACK_TREES } = require("../intelligence/ExploitChain");
  return res.json(ATTACK_TREES);
});

// ── WAF Profiles ───────────────────────────────────────────────────────────────
router.get("/waf-profiles", async (_req: Request, res: Response) => {
  const profiles = await db.select().from(wafProfiles).orderBy(desc(wafProfiles.lastUpdated));
  return res.json(profiles);
});

// ── Hunt Templates ─────────────────────────────────────────────────────────────
router.get("/hunt-templates", (_req: Request, res: Response) => {
  return res.json(HuntStrategyBuilder.getTemplates());
});

// ── AI Chat ────────────────────────────────────────────────────────────────────
router.post("/ai/chat", async (req: Request, res: Response) => {
  const { message, context } = req.body;
  if (!message) return res.status(400).json({ error: "message required" });

  const modelRouter = ModelRouter.getInstance();
  const systemContext = context ? `Context: ${JSON.stringify(context)}\n\n` : "";

  try {
    const response = await modelRouter.chat(`${systemContext}${message}`);
    return res.json({ response });
  } catch (err) {
    return res.status(500).json({ error: "AI unavailable", details: String(err) });
  }
});

// ── Models ─────────────────────────────────────────────────────────────────────
router.get("/models", async (_req: Request, res: Response) => {
  const modelRouter = ModelRouter.getInstance();
  const models = await modelRouter.getModels();
  return res.json(models);
});

export default router;
