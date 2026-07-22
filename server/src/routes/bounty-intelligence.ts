import { Router, Request, Response } from "express";
import { BountyIntelligenceService } from "../lib/bounty-intelligence";

const router = Router();
const service = new BountyIntelligenceService();

// 2026-07-22: runFullPipeline -> runRecon previously shelled out to
// subfinder/whatweb with the raw request-body `target` (2026-07-21 RCE
// stopgap gated this route entirely pending a real fix). Now dispatchTool()
// (execFile + array args + a real ScopeGuard.isInScope() check immediately
// before spawn, via a per-target resolveCustomTargetProgram()) closes the
// shell-injection class structurally at the point of execution — see
// lib/bounty-intelligence/index.ts's reconSubdomains/reconTechnologies/
// reconEndpoints. No route-level gate needed anymore.

// ─── Status ──────────────────────────────────────────────────────────────────

router.get("/status", (_req: Request, res: Response) => {
  try {
    const modules = [
      "scope-analyzer",
      "payout-scorer",
      "duplicate-detector",
      "report-coach",
      "org-memory",
      "payload-mutator",
      "stealth-scheduler",
      "submission-optimizer",
      "post-mortem-learner",
      "bounty-recon-agent",
      "campaign-learning",
      "tool-synergy",
      "failure-prediction",
      "payout-optimization",
      "duplicate-avoidance",
      "triage-predictor",
    ];
    res.json({ status: "ok", modules });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

// ─── Pipeline ─────────────────────────────────────────────────────────────────

router.post("/pipeline/run", async (req: Request, res: Response) => {
  try {
    const { target, program } = req.body;
    const result = await service.runFullPipeline(target, program);
    res.json(result);
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

// ─── Scope ────────────────────────────────────────────────────────────────────

router.post("/scope/analyze", async (req: Request, res: Response) => {
  try {
    const { target, outOfScope, bountyRange, programType } = req.body;
    const result = await service.analyzeScope(target, { outOfScope, bountyRange, programType });
    res.json(result);
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

// ─── Payload ──────────────────────────────────────────────────────────────────

router.post("/payload/mutate", async (req: Request, res: Response) => {
  try {
    const { context } = req.body;
    const result = await service.mutatePayloads(context);
    res.json(result);
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

// ─── Report ───────────────────────────────────────────────────────────────────

router.post("/report/coach", async (req: Request, res: Response) => {
  try {
    const { report } = req.body;
    const result = await service.coachReport(report);
    res.json(result);
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

// ─── Submission ───────────────────────────────────────────────────────────────

router.post("/submission/optimize", async (req: Request, res: Response) => {
  try {
    const { report } = req.body;
    const result = await service.optimizeSubmission(report);
    res.json(result);
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

router.post("/submission/record", async (req: Request, res: Response) => {
  try {
    const { submission } = req.body;
    await service.recordSubmission(submission);
    res.json({ ok: true });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

// ─── Payout ───────────────────────────────────────────────────────────────────

router.post("/payout/estimate", async (req: Request, res: Response) => {
  try {
    const { vulnerability } = req.body;
    const result = await service.estimatePayout(vulnerability);
    res.json(result);
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

// ─── Duplicate ────────────────────────────────────────────────────────────────

router.post("/duplicate/check", async (req: Request, res: Response) => {
  try {
    const { finding } = req.body;
    const result = await service.checkDuplicate(finding);
    res.json(result);
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

router.post("/duplicate/known", async (req: Request, res: Response) => {
  try {
    const { finding } = req.body;
    await service.addKnownFinding(finding);
    res.json({ ok: true });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

// ─── Org Memory ───────────────────────────────────────────────────────────────

router.post("/org-memory", async (req: Request, res: Response) => {
  try {
    const { program, knowledge } = req.body;
    await service.storeOrgMemory(program, knowledge);
    res.json({ ok: true });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

router.get("/org-memory/:program", async (req: Request, res: Response) => {
  try {
    const result = await service.retrieveOrgMemory(req.params.program);
    res.json({ data: result });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

// ─── Programs (org memory list) ───────────────────────────────────────────────

router.get("/programs", async (_req: Request, res: Response) => {
  try {
    const result = await service.listPrograms();
    res.json({ programs: result });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

// ─── Post-Mortem ──────────────────────────────────────────────────────────────

router.post("/postmortem", async (_req: Request, res: Response) => {
  try {
    const result = await service.analyzePostMortems();
    res.json(result);
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

// ─── ProgramFetcher sub-service ───────────────────────────────────────────────

router.get("/programs/status", (_req: Request, res: Response) => {
  try {
    const result = (service.programFetcher as any).getStatus
      ? (service.programFetcher as any).getStatus()
      : {
          programs: service.programFetcher.listPrograms().length,
          autoFetchEnabled: (service.programFetcher as any).autoFetchEnabled ?? false,
          lastAutoFetch: (service.programFetcher as any).lastAutoFetch ?? null,
        };
    res.json(result);
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

router.get("/programs/changes/recent", (req: Request, res: Response) => {
  try {
    const limit = Math.min(parseInt(String(req.query.limit ?? "50"), 10) || 50, 500);
    if (typeof (service.programFetcher as any).getRecentChanges === "function") {
      const result = (service.programFetcher as any).getRecentChanges(limit);
      res.json({ changes: result });
    } else {
      res.json({ changes: [], message: "not yet available" });
    }
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

router.post("/programs/add", async (req: Request, res: Response) => {
  try {
    const { config } = req.body;
    const result = await service.programFetcher.addProgram(config);
    res.json(result);
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

// NOTE: HackerOne account sync moved to POST /api/bounty/programs/sync-hackerone —
// this file's programFetcher is a file-based store disconnected from the real
// Postgres `programs` table that ScopeGuard/hunts actually read from, so syncing
// into it produced programs nothing could ever hunt against. See routes/bounty.ts.

router.post("/programs/fetch-all", async (_req: Request, res: Response) => {
  try {
    if (typeof (service.programFetcher as any).fetchAll === "function") {
      const result = await (service.programFetcher as any).fetchAll();
      res.json({ result });
    } else {
      await service.programFetcher.loadPrograms();
      const programs = service.programFetcher.listPrograms();
      res.json({ programs, message: "reloaded local programs" });
    }
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

router.post("/programs/auto-fetch", (_req: Request, res: Response) => {
  try {
    service.programFetcher.startAutoFetch(3600000);
    res.json({ ok: true, interval: 3600000 });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

router.post("/programs/:id/fetch", async (req: Request, res: Response) => {
  try {
    if (typeof (service.programFetcher as any).fetchProgram === "function") {
      const result = await (service.programFetcher as any).fetchProgram(req.params.id);
      res.json(result);
    } else {
      const doc = service.programFetcher.getProgram(req.params.id);
      res.json({ data: doc, message: "returned cached data" });
    }
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

router.delete("/programs/:id", async (req: Request, res: Response) => {
  try {
    await service.programFetcher.removeProgram(req.params.id);
    res.json({ ok: true });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

// ─── CrossCampaignLearning sub-service ───────────────────────────────────────

router.get("/campaigns", (_req: Request, res: Response) => {
  try {
    const campaigns = service.campaignLearning.listCampaigns();
    res.json({ campaigns });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

router.post("/campaigns/record", async (req: Request, res: Response) => {
  try {
    const campaign = req.body;
    await service.campaignLearning.saveCampaign(campaign);
    res.json({ ok: true });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

router.get("/campaigns/recommendations", async (req: Request, res: Response) => {
  try {
    const { techStack, domain } = req.query;
    const targetProfile = { domain: (domain as string) || 'unknown' } as { domain: string; techStack?: unknown };
    if (techStack) targetProfile.techStack = techStack;
    const results = await service.campaignLearning.findSimilar(targetProfile as Parameters<typeof service.campaignLearning.findSimilar>[0], 10);
    res.json({ recommendations: results });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

// ─── ToolSynergy ──────────────────────────────────────────────────────────────

router.get("/tools/synergy", async (req: Request, res: Response) => {
  try {
    const { vulnType } = req.query;
    const targetProfile: Record<string, any> = {};
    if (vulnType) targetProfile.vulnType = vulnType;
    const result = await service.toolSynergy.recommendPlaybooks(targetProfile);
    res.json({ recommendations: result });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

// ─── TriagePredictor ─────────────────────────────────────────────────────────

router.post("/triage/predict", async (req: Request, res: Response) => {
  try {
    const { submission } = req.body;
    const { programId, severity, reportQuality } = submission || req.body;
    const result = await service.triagePredictor.predictTriageTime(
      programId,
      severity,
      reportQuality,
    );
    res.json(result);
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

export default router;
