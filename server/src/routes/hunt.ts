import { Router, Request, Response } from "express";
import { db } from "../db";
import { campaigns, huntSessions, findings, targets, programs } from "../db/schema";
import { eq, desc, and } from "drizzle-orm";
import { z } from "zod";
import { Server as SocketServer } from "socket.io";
import { HunterEngine } from "../agents/HunterEngine";
import { SolverPool } from "../agents/SolverPool";
import { VerifierAgent } from "../agents/VerifierAgent";
import { BackwardHuntEngine } from "../intelligence/BackwardHunt";
import { HuntStrategyBuilder } from "./huntStrategy";
import { wireHuntEngineToSocket } from "../lib/utils/wire-hunt-engine";
import { activeHuntSessions } from "../lib/state/hunt-sessions";
import { metaReasoner } from "../lib/intelligence/meta-reasoning";
import { strategyWeightLearner } from "../lib/learning/strategy-weight-learner";
import logger from "../utils/logger";

const router = Router();
const verifierAgent = new VerifierAgent();
const backwardHunt = new BackwardHuntEngine();

// Initialize Playwright verifier
verifierAgent.initialize().catch(err => logger.warn("Verifier init failed", { err }));

// ── Schema Validation ─────────────────────────────────────────────────────────
const StartHuntSchema = z.object({
  // -1 signals a custom/local-lab target — no bug-bounty platform required.
  programId: z.number().int().min(-1),
  targetUrl: z.string().url(),
  mode: z.enum(["forward", "backward"]).default("forward"),
  goal: z.string().min(5).max(500).optional(),
  maxIterations: z.number().int().min(1).max(50).default(10),
  templateId: z.string().optional(),
  budget: z.object({
    maxRequests: z.number().int().min(10).max(10000).default(2000),
    maxTime: z.number().int().min(60).max(86400).default(3600),
  }).optional(),
});

// ── Routes ────────────────────────────────────────────────────────────────────

// Start a new hunt
router.post("/start", async (req: Request, res: Response) => {
  const parsed = StartHuntSchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: parsed.error.flatten() });

  const { programId: rawProgramId, targetUrl, mode, goal, maxIterations, budget, templateId } = parsed.data;

  // Resolve effective program — for custom/local-lab hunts (programId === -1) we
  // find-or-create a synthetic "Custom Lab" program so FK constraints are satisfied.
  let programId = rawProgramId;
  if (rawProgramId === -1) {
    const [existing] = await db.select().from(programs)
      .where(eq(programs.platform, "local"))
      .limit(1);
    if (existing) {
      programId = existing.id;
    } else {
      const [created] = await db.insert(programs).values({
        name: "Custom / Local Lab",
        platform: "local",
        scope: ["*"],
        outOfScope: [],
      }).returning();
      programId = created.id;
    }
  } else {
    // Verify real program exists
    const [program] = await db.select().from(programs).where(eq(programs.id, rawProgramId)).limit(1);
    if (!program) return res.status(404).json({ error: "Program not found" });
  }

  // Create campaign
  const [campaign] = await db.insert(campaigns).values({
    programId,
    name: `Hunt: ${targetUrl} - ${new Date().toISOString()}`,
    goal: goal || `Hunt for vulnerabilities on ${targetUrl}`,
    status: "running",
    huntMode: mode,
    strategy: {},
    startedAt: new Date(),
  }).returning();

  // Add target
  const [target] = await db.insert(targets).values({
    programId,
    url: targetUrl,
    type: "web",
    status: "scanning",
  }).returning();

  // Resolve template's focus vuln classes if a template was selected
  let focusVulnClasses: string[] | undefined;
  if (templateId) {
    const templates = HuntStrategyBuilder.getTemplates();
    const tmpl = templates.find(t => t.id === templateId);
    if (tmpl?.vulnClasses?.length) focusVulnClasses = tmpl.vulnClasses;
  }

  try {
    if (mode === "backward" && goal) {
      // Backward hunt: build plan then immediately execute via HunterEngine
      const plan = await backwardHunt.createPlan({
        campaignId: campaign.id,
        objective: goal,
        targetUrl,
      });

      // Auto-execute: seed HunterEngine with the plan's attack approaches as hypotheses
      const engine = new HunterEngine();
      const approaches = await backwardHunt.getNextActions(plan);
      const sessionUuid = await engine.startHunt({
        targetUrl,
        programId,
        campaignId: campaign.id,
        targetId: target.id,
        maxIterations,
        budget,
        // Use approach vuln classes as focus; fall back to template if provided
        focusVulnClasses: approaches.map(a => a.vulnClass).slice(0, 6),
      });

      const io = req.app.get("io") as SocketServer;
      wireHuntEngineToSocket(engine, sessionUuid, io);
      // Replay hunt:started since it fired before wiring was in place
      io.to(`hunt:${sessionUuid}`).emit("hunt:started", { sessionUuid, targetUrl });
      activeHuntSessions.set(sessionUuid, engine);
      engine.on("hunt:complete", (data: unknown) => {
        const d = data as Record<string, unknown> | null;
        const finalScore = typeof d?.score === 'number' ? d.score : 0.5;
        metaReasoner.completeHunt(sessionUuid, finalScore).catch(() => {});
        strategyWeightLearner.learn().catch(() => {});
        setTimeout(() => activeHuntSessions.delete(sessionUuid), 60_000);
      });

      logger.info("Backward hunt started", { campaignId: campaign.id, planId: plan.planId, sessionUuid });
      return res.json({
        campaignId: campaign.id,
        targetId: target.id,
        sessionUuid,
        mode: "backward",
        planId: plan.planId,
        objective: plan.objective,
        status: "running",
      });
    }

    // Forward hunt
    const engine = new HunterEngine();
    const sessionUuid = await engine.startHunt({
      targetUrl,
      programId,
      campaignId: campaign.id,
      targetId: target.id,
      maxIterations,
      budget,
      focusVulnClasses,
    });

    const io = req.app.get("io") as SocketServer;
    wireHuntEngineToSocket(engine, sessionUuid, io);
    // Replay hunt:started since it fired before wiring was in place
    io.to(`hunt:${sessionUuid}`).emit("hunt:started", { sessionUuid, targetUrl });
    activeHuntSessions.set(sessionUuid, engine);

    // Auto-cleanup after hunt completes; trigger cross-hunt learning
    engine.on("hunt:complete", (data: unknown) => {
      const d = data as Record<string, unknown> | null;
      const finalScore = typeof d?.score === 'number' ? d.score : 0.5;
      metaReasoner.completeHunt(sessionUuid, finalScore).catch(() => {});
      strategyWeightLearner.learn().catch(() => {});
      setTimeout(() => activeHuntSessions.delete(sessionUuid), 60_000);
    });

    logger.info("Hunt started", { campaignId: campaign.id, sessionUuid, targetUrl });
    return res.json({
      campaignId: campaign.id,
      targetId: target.id,
      sessionUuid,
      status: "running",
    });
  } catch (err) {
    logger.error("Failed to start hunt", { err });
    return res.status(500).json({ error: "Failed to start hunt", details: String(err) });
  }
});

// Stop an active hunt
router.post("/stop/:sessionUuid", (req: Request, res: Response) => {
  const engine = activeHuntSessions.get(req.params.sessionUuid);
  if (!engine) return res.status(404).json({ error: "Session not found" });
  engine.emit("hunt:stop");
  activeHuntSessions.delete(req.params.sessionUuid);
  return res.json({ ok: true });
});

// Get hunt session state
router.get("/session/:sessionUuid", async (req: Request, res: Response) => {
  const engine = activeHuntSessions.get(req.params.sessionUuid);
  if (engine) {
    return res.json({ live: true, state: engine.getState() });
  }

  // Fetch from DB
  const [session] = await db.select().from(huntSessions)
    .where(eq(huntSessions.sessionUuid, req.params.sessionUuid)).limit(1);
  if (!session) return res.status(404).json({ error: "Session not found" });
  return res.json({ live: false, session });
});

// Get all campaigns
router.get("/campaigns", async (req: Request, res: Response) => {
  const programId = req.query.programId ? Number(req.query.programId) : undefined;
  const query = db.select().from(campaigns)
    .orderBy(desc(campaigns.createdAt));

  const results = programId
    ? await db.select().from(campaigns).where(eq(campaigns.programId, programId)).orderBy(desc(campaigns.createdAt))
    : await query;

  return res.json(results);
});

// Get campaign details with findings
router.get("/campaigns/:id", async (req: Request, res: Response) => {
  const id = parseInt(req.params.id);
  const [campaign] = await db.select().from(campaigns).where(eq(campaigns.id, id)).limit(1);
  if (!campaign) return res.status(404).json({ error: "Campaign not found" });

  const sessionList = await db.select().from(huntSessions).where(eq(huntSessions.campaignId, id));
  const findingList = await db.select().from(findings).where(eq(findings.campaignId, id));

  return res.json({ campaign, sessions: sessionList, findings: findingList });
});

// Get all findings with filters — applied in SQL (indexed) rather than in JS
router.get("/findings", async (req: Request, res: Response) => {
  const { campaignId, severity, vulnType, status } = req.query;

  const conditions = [];
  if (campaignId) {
    const cid = parseInt(String(campaignId), 10);
    if (!Number.isNaN(cid)) conditions.push(eq(findings.campaignId, cid));
  }
  if (severity) conditions.push(eq(findings.severity, String(severity)));
  if (vulnType) conditions.push(eq(findings.vulnType, String(vulnType)));
  if (status) conditions.push(eq(findings.status, String(status)));

  const results = await db.select().from(findings)
    .where(conditions.length ? and(...conditions) : undefined)
    .orderBy(desc(findings.createdAt))
    .limit(500);

  return res.json(results);
});

// Get finding details
router.get("/findings/:id", async (req: Request, res: Response) => {
  const [finding] = await db.select().from(findings)
    .where(eq(findings.id, parseInt(req.params.id))).limit(1);
  if (!finding) return res.status(404).json({ error: "Finding not found" });
  return res.json(finding);
});

// Update finding (title, severity, description, impact)
router.patch("/findings/:id", async (req: Request, res: Response) => {
  const [finding] = await db.select().from(findings)
    .where(eq(findings.id, parseInt(req.params.id))).limit(1);
  if (!finding) return res.status(404).json({ error: "Finding not found" });

  const allowed = ["title", "severity", "description", "impact"] as const;
  const updates: Record<string, unknown> = {};
  for (const key of allowed) {
    if (req.body[key] !== undefined) updates[key] = req.body[key];
  }
  if (Object.keys(updates).length === 0) return res.status(400).json({ error: "No updatable fields provided" });

  await db.update(findings).set({ ...updates, updatedAt: new Date() }).where(eq(findings.id, parseInt(req.params.id)));
  const [updated] = await db.select().from(findings).where(eq(findings.id, parseInt(req.params.id))).limit(1);
  return res.json(updated);
});

// Verify a finding (run 4-layer pipeline)
router.post("/findings/:id/verify", async (req: Request, res: Response) => {
  const [finding] = await db.select().from(findings)
    .where(eq(findings.id, parseInt(req.params.id))).limit(1);
  if (!finding) return res.status(404).json({ error: "Finding not found" });

  try {
    // Build a mock SolverResult from the finding for verification
    const mockResult = {
      taskId: String(finding.id),
      solverId: "manual",
      endpoint: finding.targetId ? String(finding.targetId) : "",
      vulnClass: finding.vulnType as Parameters<typeof verifierAgent.verify>[0]["vulnClass"],
      found: true,
      confidence: finding.confidence,
      evidence: (finding.evidence as Record<string, unknown>[])[0] || {},
      payload: finding.exploitPayload || "",
      request: "",
      response: "",
      duration: 0,
      toolsUsed: [],
    };

    const verification = await verifierAgent.verify(mockResult);

    // Update finding with verification result
    await db.update(findings).set({
      verificationStatus: verification.finalVerdict,
      verificationLog: [verification] as unknown as Record<string, unknown>[],
      confidence: verification.finalConfidence,
      dedupHash: verification.dedupHash,
      updatedAt: new Date(),
    }).where(eq(findings.id, parseInt(req.params.id)));

    return res.json(verification);
  } catch (err) {
    return res.status(500).json({ error: "Verification failed", details: String(err) });
  }
});

// Generate nuclei template for a finding
router.post("/findings/:id/nuclei-template", async (req: Request, res: Response) => {
  const { NucleiTemplateGenerator } = await import("../intelligence/NucleiGenerator");
  const [finding] = await db.select().from(findings)
    .where(eq(findings.id, parseInt(req.params.id))).limit(1);
  if (!finding) return res.status(404).json({ error: "Finding not found" });

  const generator = new NucleiTemplateGenerator();
  const mockSolverResult = {
    taskId: String(finding.id),
    solverId: "manual",
    endpoint: String(finding.targetId || ""),
    vulnClass: finding.vulnType as Parameters<typeof generator.generateTemplate>[0]["vulnClass"],
    found: true,
    confidence: finding.confidence,
    evidence: {},
    payload: finding.exploitPayload || "",
    request: "",
    response: "",
    duration: 0,
    toolsUsed: [],
  };

  const mockVerification = {
    findingId: String(finding.id),
    layer1_dedup: { isDuplicate: false },
    layer2_reprobe: { confirmed: true, statusCode: 200, responseSnippet: "" },
    layer3_playwright: { confirmed: true, consoleAlerts: [], networkRequests: [] },
    layer4_ai: { confirmed: true, reasoning: "", confidenceAdjustment: 0 },
    finalVerdict: "confirmed" as const,
    finalConfidence: finding.confidence,
    dedupHash: finding.dedupHash || "",
  };

  const template = generator.generateTemplate(mockSolverResult, mockVerification, {
    severity: finding.severity,
    programName: "Bug Bounty Program",
  });

  // Save template to finding
  await db.update(findings).set({ nucleiTemplate: template }).where(eq(findings.id, parseInt(req.params.id)));
  res.setHeader("Content-Type", "text/plain");
  return res.send(template);
});

// Generate bug bounty report for a finding
router.post("/findings/:id/report", async (req: Request, res: Response) => {
  const { DraftReportGenerator } = await import("../intelligence/ReportGenerator");
  const [finding] = await db.select().from(findings)
    .where(eq(findings.id, parseInt(req.params.id))).limit(1);
  if (!finding) return res.status(404).json({ error: "Finding not found" });

  const generator = new DraftReportGenerator();
  const mockSolverResult = {
    taskId: String(finding.id), solverId: "manual",
    endpoint: String(finding.targetId || ""), vulnClass: finding.vulnType as Parameters<typeof generator.generate>[0]["vulnClass"],
    found: true, confidence: finding.confidence, evidence: {},
    payload: finding.exploitPayload || "", request: "", response: "",
    duration: 0, toolsUsed: [],
  };
  const mockVerification = {
    findingId: String(finding.id),
    layer1_dedup: { isDuplicate: false },
    layer2_reprobe: { confirmed: true, statusCode: 200, responseSnippet: "" },
    layer3_playwright: { confirmed: true, consoleAlerts: [], networkRequests: [] },
    layer4_ai: { confirmed: true, reasoning: "", confidenceAdjustment: 0 },
    finalVerdict: "confirmed" as const,
    finalConfidence: finding.confidence,
    dedupHash: finding.dedupHash || "",
  };

  // Extract raw HTTP evidence and video PoC path stored by the hunt engine
  const evidenceArr = (finding.evidence as Array<Record<string, unknown>>) ?? [];
  const rawHttpEntry = evidenceArr.find(e => e.type === "raw_http");
  const videoEntry = evidenceArr.find(e => e.type === "video_poc");

  const report = await generator.generate(mockSolverResult, mockVerification, {
    severity: finding.severity,
    programName: req.body.programName || "Target Program",
    targetUrl: String(finding.targetId || ""),
    huntDate: finding.createdAt.toISOString().split("T")[0],
    rawEvidence: rawHttpEntry ? String(rawHttpEntry.data ?? "") : undefined,
    videoPath: videoEntry ? String(videoEntry.path ?? "") : undefined,
  });

  // Save report draft
  await db.update(findings).set({ reportDraft: report.reportMarkdown }).where(eq(findings.id, parseInt(req.params.id)));
  return res.json(report);
});

// Export findings as CSV or JSON
router.get("/findings/export", async (req: Request, res: Response) => {
  const format = String(req.query.format || "json");
  const rows = await db.select().from(findings).orderBy(desc(findings.createdAt));

  if (format === "csv") {
    const headers = ["id", "title", "vulnType", "severity", "confidence", "verificationStatus", "targetId", "cvssScore", "dedupHash", "createdAt"];
    const csv = [
      headers.join(","),
      ...rows.map(f => headers.map(h => {
        const v = (f as Record<string, unknown>)[h];
        const s = v == null ? "" : String(v);
        return s.includes(",") || s.includes('"') || s.includes("\n") ? `"${s.replace(/"/g, '""')}"` : s;
      }).join(","))
    ].join("\n");
    res.setHeader("Content-Type", "text/csv");
    res.setHeader("Content-Disposition", `attachment; filename="findings-${Date.now()}.csv"`);
    return res.send(csv);
  }

  res.setHeader("Content-Type", "application/json");
  res.setHeader("Content-Disposition", `attachment; filename="findings-${Date.now()}.json"`);
  return res.json(rows);
});

// Spawn solver pool on a specific endpoint
router.post("/solve", async (req: Request, res: Response) => {
  const { endpoint, programId, observations } = req.body;
  if (!endpoint) return res.status(400).json({ error: "endpoint required" });

  const pool = new SolverPool(3);
  try {
    const results = await pool.spawnSolvers(endpoint, observations || {}, { programId: programId || 0, sessionId: 0 });
    return res.json({ results, stats: pool.getStats() });
  } catch (err) {
    return res.status(500).json({ error: String(err) });
  }
});

// Hunt strategy builder
router.post("/strategy", async (req: Request, res: Response) => {
  const { programId, targetUrl, goal } = req.body;
  try {
    const strategy = await HuntStrategyBuilder.build({ programId, targetUrl, goal });
    return res.json(strategy);
  } catch (err) {
    return res.status(500).json({ error: String(err) });
  }
});

export default router;
