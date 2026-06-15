/**
 * Orchestration Routes
 * REST API for the 6-layer Campaign Orchestrator.
 *
 * POST /api/orchestration/run       – Start a full orchestrated hunt
 * POST /api/orchestration/stop/:id  – Abort an active orchestration
 * GET  /api/orchestration/:id       – Get orchestration state
 * GET  /api/orchestration           – List recent orchestrations
 * GET  /api/orchestration/layers    – Describe all 6 layers
 */
import { Router, Request, Response } from "express";
import { z } from "zod";
import { db } from "../db";
import { campaigns, findings } from "../db/schema";
import { desc, like } from "drizzle-orm";
import { CampaignOrchestrator, OrchestratorState } from "../agents/CampaignOrchestrator";
import logger from "../utils/logger";
import { Server as SocketServer } from "socket.io";

const router = Router();

// In-memory active orchestrations (orchestrationId → orchestrator)
const activeOrchestrations = new Map<string, CampaignOrchestrator>();
// Track completed results
const completedResults = new Map<string, {
  state: OrchestratorState;
  completedAt: number;
}>();

// ── Schema ─────────────────────────────────────────────────────────────────────
const RunOrchestrationSchema = z.object({
  // -1 signals a custom/local-lab target — the orchestrator's L1 governance gate
  // find-or-creates a synthetic "Custom / Local Lab" program (scope ["*"]) so a
  // bare URL can run the full 6-layer pipeline without a real bug-bounty program.
  programId: z.number().int().min(-1),
  targetUrl: z.string().url(),
  mode: z.enum(["forward", "backward"]).default("forward"),
  goal: z.string().min(5).max(500).optional(),
  maxIterations: z.number().int().min(1).max(50).default(10),
  focusVulnClasses: z.array(z.string()).max(10).optional(),
  budget: z.object({
    maxRequests: z.number().int().min(10).max(50000).default(2000),
    maxTime: z.number().int().min(60).max(86400).default(3600),
  }).optional(),
});

// ── Layer metadata endpoint ────────────────────────────────────────────────────
router.get("/layers", (_req: Request, res: Response) => {
  return res.json({
    model: "6-Layer Orchestration & Governance Model",
    version: "1.0.0",
    layers: [
      {
        layer: 1,
        name: "GOVERNANCE GATE",
        description: "Policy enforcement, scope validation, audit trail generation. Fail-closed – rejects all out-of-scope or policy-violating requests.",
        components: ["ScopeGuard", "ProgramValidator", "BudgetGuard", "AuditLogger"],
        gate: true,
      },
      {
        layer: 2,
        name: "TARGET INTELLIGENCE",
        description: "ROI scoring, vulnerability class prioritization, attack surface mapping. Ranks targets and vuln classes by expected value.",
        components: ["TargetSelectionIntelligence", "ROIModel", "ProgramScorer"],
        gate: false,
      },
      {
        layer: 3,
        name: "STRATEGY PLANNING",
        description: "Hunt mode selection (forward/backward), attack tree construction, template library selection, external plan memory.",
        components: ["HuntStrategyBuilder", "BackwardHuntEngine", "AttackTreeBuilder"],
        gate: false,
      },
      {
        layer: 4,
        name: "EXECUTION ENGINE",
        description: "HunterEngine coordination (Observe→Hypothesize→Probe→Update), SolverPool dynamic spawning, WAF bypass integration, budget enforcement.",
        components: ["HunterEngine", "SolverPool", "WAFBypass", "BudgetCheckpoint"],
        gate: false,
      },
      {
        layer: 5,
        name: "VERIFICATION GATE",
        description: "4-layer anti-hallucination pipeline: deduplication → HTTP re-probe → Playwright browser replay (mandatory for critical) → AI confirmation.",
        components: ["VerifierAgent", "PlaywrightGate", "DeduplicationEngine", "AIConfirmation"],
        gate: true,
      },
      {
        layer: 6,
        name: "INTELLIGENCE HARVEST",
        description: "Reinforcement learning updates, autonomy maturity tracking (CAMS), Nuclei template generation, submission-ready report generation.",
        components: ["ReinforcementStore", "AutonomyMaturityTracker", "NucleiGenerator", "DraftReportGenerator"],
        gate: false,
      },
    ],
  });
});

// ── Start orchestration ────────────────────────────────────────────────────────
router.post("/run", async (req: Request, res: Response) => {
  const parsed = RunOrchestrationSchema.safeParse(req.body);
  if (!parsed.success) {
    return res.status(400).json({ error: parsed.error.flatten() });
  }

  const orchestrator = new CampaignOrchestrator();
  const orchestrationId = (orchestrator.getState() as OrchestratorState & { orchestrationId: string }).orchestrationId;

  // Wire orchestrator events to Socket.IO
  const io: SocketServer | undefined = req.app.get("io");
  if (io) {
    const room = `orchestration:${orchestrationId}`;

    orchestrator.on("orchestration:started", (d) => io.to(room).emit("orchestration:started", d));
    orchestrator.on("orchestration:layer_start", (d) => io.to(room).emit("orchestration:layer_start", d));
    orchestrator.on("orchestration:layer_complete", (d) => io.to(room).emit("orchestration:layer_complete", d));
    orchestrator.on("orchestration:layer_error", (d) => io.to(room).emit("orchestration:layer_error", d));
    orchestrator.on("orchestration:audit", (d) => io.to(room).emit("orchestration:audit", d));
    orchestrator.on("orchestration:aborted", (d) => io.to(room).emit("orchestration:aborted", d));

    // Layer-specific events
    ["l4:hunt_started", "l4:phase", "l4:observations", "l4:hypotheses",
      "l4:probing", "l4:probe_result", "l4:finding_raw", "l4:strategy_update",
      "l4:solver_finding", "l4:error", "l4:ai_reasoning",
      "l5:verifying", "l5:verified", "l5:rejected", "l5:public_duplicate",
      "l6:report_generated", "l6:autonomy_updated",
    ].forEach(evt => {
      orchestrator.on(evt, (d) => io.to(room).emit(evt, d));
    });

    orchestrator.on("orchestration:complete", (d) => {
      io.to(room).emit("orchestration:complete", d);
      completedResults.set(orchestrationId, { state: d.state, completedAt: Date.now() });
      activeOrchestrations.delete(orchestrationId);
    });
  }

  activeOrchestrations.set(orchestrationId, orchestrator);

  // Return immediately with orchestrationId; run async
  res.json({
    orchestrationId,
    status: "running",
    message: "Orchestration started. Subscribe to Socket.IO room orchestration:<id> for real-time updates.",
    wsRoom: `orchestration:${orchestrationId}`,
  });

  // Fire and forget
  orchestrator.orchestrate(parsed.data).then((result) => {
    completedResults.set(orchestrationId, {
      state: orchestrator.getState(),
      completedAt: Date.now(),
    });
    activeOrchestrations.delete(orchestrationId);
    logger.info("Orchestration finished", { orchestrationId, findings: result.findingsTotal });
  }).catch((err) => {
    logger.error("Orchestration failed", { orchestrationId, err });
    activeOrchestrations.delete(orchestrationId);
  });
});

// ── Stop orchestration ─────────────────────────────────────────────────────────
router.post("/stop/:id", (req: Request, res: Response) => {
  const orchestrator = activeOrchestrations.get(req.params.id);
  if (!orchestrator) {
    return res.status(404).json({ error: "Orchestration not found or already complete" });
  }
  orchestrator.emit("orchestration:stop");
  activeOrchestrations.delete(req.params.id);
  return res.json({ ok: true, orchestrationId: req.params.id, status: "aborted" });
});

// ── Stats endpoint (must be before /:id to avoid swallowing "stats") ──────────
router.get("/stats/summary", async (_req: Request, res: Response) => {
  try {
    const allFindings = await db.select().from(findings).orderBy(desc(findings.createdAt)).limit(100);
    const verified = allFindings.filter(f => f.verificationStatus === "confirmed" || f.verificationStatus === "probable");
    const bySeverity = allFindings.reduce<Record<string, number>>((acc, f) => {
      acc[f.severity] = (acc[f.severity] || 0) + 1;
      return acc;
    }, {});
    const byVulnType = allFindings.reduce<Record<string, number>>((acc, f) => {
      acc[f.vulnType] = (acc[f.vulnType] || 0) + 1;
      return acc;
    }, {});

    return res.json({
      activeOrchestrations: activeOrchestrations.size,
      totalFindings: allFindings.length,
      verifiedFindings: verified.length,
      verificationRate: allFindings.length > 0
        ? Math.round((verified.length / allFindings.length) * 100) / 100
        : 0,
      bySeverity,
      byVulnType,
    });
  } catch (err) {
    return res.status(500).json({ error: String(err) });
  }
});

// ── Get orchestration state ────────────────────────────────────────────────────
router.get("/:id", (req: Request, res: Response) => {
  const active = activeOrchestrations.get(req.params.id);
  if (active) {
    return res.json({ live: true, state: active.getState() });
  }

  const completed = completedResults.get(req.params.id);
  if (completed) {
    return res.json({ live: false, state: completed.state, completedAt: completed.completedAt });
  }

  return res.status(404).json({ error: "Orchestration not found" });
});

// ── List recent orchestrations (from campaigns) ────────────────────────────────
router.get("/", async (_req: Request, res: Response) => {
  try {
    const recentCampaigns = await db.select().from(campaigns)
      .where(like(campaigns.name, "[ORC]%"))
      .orderBy(desc(campaigns.createdAt))
      .limit(20);

    // Augment with live status
    const result = recentCampaigns.map(c => ({
      ...c,
      live: false, // campaigns don't track orchestrationId directly
    }));

    // Also include any currently active orchestrations
    const liveList = Array.from(activeOrchestrations.entries()).map(([id, orch]) => ({
      orchestrationId: id,
      live: true,
      state: orch.getState(),
    }));

    return res.json({ live: liveList, recent: result });
  } catch (err) {
    return res.status(500).json({ error: String(err) });
  }
});

export default router;
