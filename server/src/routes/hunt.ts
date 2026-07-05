import { Router, Request, Response } from "express";
import { execSync } from "child_process";
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
import { activeHunts } from "../lib/state/active-hunts";
import { metaReasoner } from "../lib/intelligence/meta-reasoning";
import { strategyWeightLearner } from "../lib/learning/strategy-weight-learner";
import { verifyAndPersistFinding, verifyPendingForSession } from "../lib/verification/verify-finding";
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
  auth: z.object({
    cookie: z.string().optional(),
    bearerToken: z.string().optional(),
    headers: z.record(z.string()).optional(),
  }).optional(),
  corpusEnrichment: z.boolean().optional().default(false),
  proxyEnabled: z.boolean().optional().default(false),
});

// ── Routes ────────────────────────────────────────────────────────────────────

// Global hunt status — single source of truth for all UI panels.
// Returns the currently active hunt (or null) so panels can disable their
// launch buttons and show a banner without relying on local optimistic state.
router.get("/status", (_req: Request, res: Response) => {
  const current = activeHunts.current();
  return res.json({ running: current !== null, hunt: current });
});

// Start a new hunt
router.post("/start", async (req: Request, res: Response) => {
  const parsed = StartHuntSchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: parsed.error.flatten() });

  const { programId: rawProgramId, targetUrl, mode, goal, maxIterations, budget, templateId, auth, corpusEnrichment, proxyEnabled } = parsed.data;

  // ── Single-flight gate (cost-safety core) ───────────────────────────────────
  // Claim the one global hunt slot SYNCHRONOUSLY before any await. If a hunt OR
  // orchestration is already running (or reserved), reject with 409 — never queue
  // a second. This is what makes ~60 rapid clicks → 1 hunt instead of 60. The
  // unified registry supersedes the earlier activeHuntSessions.size check: it is
  // race-safe across the async setup window and also covers running orchestrations.
  if (!activeHunts.reserve(targetUrl)) {
    const current = activeHunts.current();
    return res.status(409).json({
      error: "A hunt is already in progress. Stop it before starting a new one.",
      activeHunt: current ? { id: current.id, kind: current.kind, targetUrl: current.targetUrl } : undefined,
    });
  }

  // Everything past the reserve() claim runs inside this guard so the single-
  // flight slot is released on ANY failure path (DB error, 404, engine throw)
  // and is only converted to a bound run via activeHunts.bind() on success.
  try {
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
    if (!program) { activeHunts.release(); return res.status(404).json({ error: "Program not found" }); }
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
        auth,
        corpusEnrichment,
        proxyEnabled,
      });

      const io = req.app.get("io") as SocketServer;
      wireHuntEngineToSocket(engine, sessionUuid, io);
      // Replay hunt:started since it fired before wiring was in place
      io.to(`hunt:${sessionUuid}`).emit("hunt:started", { sessionUuid, targetUrl });
      activeHuntSessions.set(sessionUuid, engine);
      // Promote the single-flight reservation into a bound, stoppable run.
      activeHunts.bind({ id: sessionUuid, kind: "hunt", handle: engine, targetUrl, startedAt: Date.now() });
      engine.on("hunt:complete", (data: unknown) => {
        const d = data as Record<string, unknown> | null;
        const finalScore = typeof d?.score === 'number' ? d.score : 0.5;
        metaReasoner.completeHunt(sessionUuid, finalScore).catch(() => {});
        strategyWeightLearner.learn().catch(() => {});
        // Release the single-flight slot the moment the hunt finishes so the next
        // legitimate launch can proceed (don't wait the 60s state-cleanup window).
        activeHunts.release(sessionUuid);
        (async () => {
          try {
            io.to(`hunt:${sessionUuid}`).emit("hunt:verifying", { sessionUuid });
            const { verified, confirmed } = await verifyPendingForSession(verifierAgent, sessionUuid, targetUrl);
            io.to(`hunt:${sessionUuid}`).emit("hunt:verification_complete", { sessionUuid, verified, confirmed });
            logger.info("Auto-verification complete", { sessionUuid, verified, confirmed });
          } catch (err) {
            logger.warn("Auto-verification pass failed", { sessionUuid, err: String(err) });
          }
        })();
        setTimeout(() => activeHuntSessions.delete(sessionUuid), 60_000);
      });
      engine.on("hunt:error", () => activeHunts.release(sessionUuid));

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
      auth,
      corpusEnrichment,
      proxyEnabled,
    });

    const io = req.app.get("io") as SocketServer;
    wireHuntEngineToSocket(engine, sessionUuid, io);
    // Replay hunt:started since it fired before wiring was in place
    io.to(`hunt:${sessionUuid}`).emit("hunt:started", { sessionUuid, targetUrl });
    activeHuntSessions.set(sessionUuid, engine);
    // Promote the single-flight reservation into a bound, stoppable run.
    activeHunts.bind({ id: sessionUuid, kind: "hunt", handle: engine, targetUrl, startedAt: Date.now() });

    // Auto-cleanup after hunt completes; trigger cross-hunt learning
    engine.on("hunt:complete", (data: unknown) => {
      const d = data as Record<string, unknown> | null;
      const finalScore = typeof d?.score === 'number' ? d.score : 0.5;
      metaReasoner.completeHunt(sessionUuid, finalScore).catch(() => {});
      strategyWeightLearner.learn().catch(() => {});
      // Release the single-flight slot immediately on completion.
      activeHunts.release(sessionUuid);
      // Auto-verify: console-launched hunts don't pass through CampaignOrchestrator
      // Layer 5, so run the 4-layer pipeline on every pending finding here. This is
      // what removes the need to click "verify" on each finding by hand.
      (async () => {
        try {
          io.to(`hunt:${sessionUuid}`).emit("hunt:verifying", { sessionUuid });
          const { verified, confirmed } = await verifyPendingForSession(verifierAgent, sessionUuid, targetUrl);
          io.to(`hunt:${sessionUuid}`).emit("hunt:verification_complete", { sessionUuid, verified, confirmed });
          logger.info("Auto-verification complete", { sessionUuid, verified, confirmed });
        } catch (err) {
          logger.warn("Auto-verification pass failed", { sessionUuid, err: String(err) });
        }
      })();
      setTimeout(() => activeHuntSessions.delete(sessionUuid), 60_000);
    });
    engine.on("hunt:error", () => activeHunts.release(sessionUuid));

    logger.info("Hunt started", { campaignId: campaign.id, sessionUuid, targetUrl });
    return res.json({
      campaignId: campaign.id,
      targetId: target.id,
      sessionUuid,
      status: "running",
    });
  } catch (err) {
    // Engine-section failure (after DB setup). Release the slot so it isn't stuck.
    activeHunts.release();
    logger.error("Failed to start hunt", { err });
    return res.status(500).json({ error: "Failed to start hunt", details: String(err) });
  }
  } catch (outerErr) {
    // DB-setup failure (program/campaign/target creation) before the engine ran.
    activeHunts.release();
    logger.error("Failed to start hunt (setup)", { err: outerErr });
    return res.status(500).json({ error: "Failed to start hunt", details: String(outerErr) });
  }
});

// Stop an active hunt — REAL abort: propagate stop() into the running engine so
// model calls cease, then release the single-flight slot. The old code emitted
// an unhandled "hunt:stop" event and deleted the registry entry, leaving the
// engine running (and spending) — the lying-button bug this fixes.
router.post("/stop/:sessionUuid", (req: Request, res: Response) => {
  const sessionUuid = req.params.sessionUuid;
  const stopped = activeHunts.stop(sessionUuid);
  const engine = activeHuntSessions.get(sessionUuid);
  if (engine) {
    engine.stop();                          // idempotent — covers stop() before bind()
    activeHuntSessions.delete(sessionUuid);
  }
  if (!stopped && !engine) {
    return res.status(404).json({ error: "Session not found or already stopped" });
  }
  logger.info("Hunt stop requested", { sessionUuid, stopped });
  return res.json({ ok: true, stopped: true, sessionUuid });
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
  const { campaignId, programId, severity, vulnType, status } = req.query;

  const conditions = [];
  if (campaignId) {
    const cid = parseInt(String(campaignId), 10);
    if (!Number.isNaN(cid)) conditions.push(eq(findings.campaignId, cid));
  }
  if (programId !== undefined && programId !== "") {
    const pid = parseInt(String(programId), 10);
    if (!Number.isNaN(pid)) conditions.push(eq(findings.programId, pid));
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

  // Resolve the real target URL for this finding so L2 reprobe / L3 replay
  // have a valid host to hit (used as fallback when the finding's own
  // evidence/title don't already carry a URL).
  let fallbackUrl = "";
  if (finding.targetId) {
    const [tgt] = await db.select({ url: targets.url })
      .from(targets).where(eq(targets.id, finding.targetId)).limit(1);
    fallbackUrl = tgt?.url ?? "";
  }

  try {
    const verification = await verifyAndPersistFinding(verifierAgent, finding, fallbackUrl);
    if (!verification) {
      return res.status(422).json({ error: "No usable URL to verify this finding against" });
    }
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
    endpoint: finding.affectedUrl || "",
    vulnClass: finding.vulnType as Parameters<typeof generator.generateTemplate>[0]["vulnClass"],
    found: true,
    confidence: finding.confidence,
    evidence: {},
    payload: finding.exploitPayload || "",
    request: finding.affectedUrl || "",
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
    endpoint: finding.affectedUrl || "", vulnClass: finding.vulnType as Parameters<typeof generator.generate>[0]["vulnClass"],
    found: true, confidence: finding.confidence, evidence: {},
    payload: finding.exploitPayload || "", request: finding.affectedUrl || "", response: "",
    duration: 0, toolsUsed: [],
  };
  // Use the finding's REAL verification result (with real L2/L3/L4 evidence and,
  // when applicable, the adaptation record) instead of a hardcoded fake — a
  // fake all-"confirmed" stub with empty reasoning/response silently discarded
  // the actual proof and left the report with nothing real to cite.
  const realVerificationLog = (finding.verificationLog as unknown as Array<Record<string, unknown>>) ?? [];
  const realVerification = realVerificationLog[realVerificationLog.length - 1];
  const mockVerification = realVerification ?? {
    findingId: String(finding.id),
    layer1_dedup: { isDuplicate: false },
    layer2_reprobe: { confirmed: false, statusCode: 0, responseSnippet: "" },
    layer3_playwright: { confirmed: false, consoleAlerts: [], networkRequests: [] },
    layer4_ai: { confirmed: false, reasoning: "", confidenceAdjustment: 0 },
    finalVerdict: "inconclusive" as const,
    finalConfidence: finding.confidence,
    dedupHash: finding.dedupHash || "",
  };

  // Extract raw HTTP evidence and video PoC path stored by the hunt engine —
  // prefer the LAST matching entry (adaptation evidence is appended after any
  // pre-existing raw_http entry from the original hunt-loop discovery).
  const evidenceArr = (finding.evidence as Array<Record<string, unknown>>) ?? [];
  const rawHttpEntry = [...evidenceArr].reverse().find(e => e.type === "raw_http");
  const videoEntry = evidenceArr.find(e => e.type === "video_poc");

  const report = await generator.generate(mockSolverResult, mockVerification as unknown as Parameters<typeof generator.generate>[1], {
    severity: finding.severity,
    programName: req.body.programName || "Target Program",
    targetUrl: finding.affectedUrl || "",
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

// Tool preflight — check which hunt engine binaries are installed
const HUNT_TOOLS: Array<{ name: string; binary: string; tier: "critical" | "important" | "optional" }> = [
  { name: "nmap",      binary: "nmap",      tier: "critical"  },
  { name: "nuclei",    binary: "nuclei",    tier: "critical"  },
  { name: "ffuf",      binary: "ffuf",      tier: "critical"  },
  { name: "sqlmap",    binary: "sqlmap",    tier: "critical"  },
  { name: "nikto",     binary: "nikto",     tier: "important" },
  { name: "gobuster",  binary: "gobuster",  tier: "important" },
  { name: "whatweb",   binary: "whatweb",   tier: "important" },
  { name: "dalfox",    binary: "dalfox",    tier: "important" },
  { name: "tplmap",    binary: "tplmap",    tier: "important" },
  { name: "jwt_tool",  binary: "jwt_tool",  tier: "optional"  },
  { name: "xsser",     binary: "xsser",     tier: "optional"  },
  { name: "ssrfmap",   binary: "ssrfmap",   tier: "optional"  },
  { name: "nosqlmap",  binary: "nosqlmap",  tier: "optional"  },
  { name: "corsy",     binary: "corsy",     tier: "optional"  },
  { name: "smuggler",  binary: "smuggler",  tier: "optional"  },
];

router.get("/tools/preflight", (_req: Request, res: Response) => {
  const results = HUNT_TOOLS.map(t => {
    try {
      const path = execSync(`which ${t.binary} 2>/dev/null`, { encoding: "utf8", timeout: 2000 }).trim();
      return { ...t, available: Boolean(path), path: path || undefined };
    } catch {
      return { ...t, available: false };
    }
  });

  const missing = results.filter(r => !r.available);
  const missingCritical = missing.filter(r => r.tier === "critical");

  return res.json({
    tools: results,
    summary: {
      total: results.length,
      available: results.filter(r => r.available).length,
      missingCritical: missingCritical.map(r => r.name),
      ready: missingCritical.length === 0,
    },
  });
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
