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
import { BountyIntelligenceService } from "../lib/bounty-intelligence";
import type { ToolExecutionRecord, PredictionFeatureVector } from "../lib/bounty-intelligence";

const router = Router();

// Shared bounty-intelligence service instance (same modules backing /api/bounty-intelligence)
const bountyService = new BountyIntelligenceService();

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

router.post("/tools/select", async (req: Request, res: Response) => {
  try {
    const { context } = req.body;
    const { huntId, availableTools } = context || {};
    if (!huntId || !availableTools) {
      return res
        .status(400)
        .json({ error: "context.huntId and context.availableTools are required" });
    }
    const ranked = await contextualToolSelector.selectWithGraphBoost(huntId, availableTools);
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

// ─── Unified Quick Intelligence ─────────────────────────────────────────────
// GET /unified/quick?programId=&target=
// Composes a "quick intelligence briefing": ranked techniques with EV, success
// probability, duplicate risk and expected payout. Backed by the real
// failure-prediction (strategy) + duplicate-avoidance + payout-optimization
// services from BountyIntelligenceService.

router.get("/unified/quick", async (req: Request, res: Response) => {
  try {
    const programId = String(req.query.programId || "default");
    const target = String(req.query.target || "").trim();

    // Minimal feature vector — most fields unknown for a pre-hunt quick snapshot.
    const featureVector: PredictionFeatureVector = {
      techStack: {
        language: null,
        framework: null,
        server: null,
        database: null,
        cdn: null,
        jsLibraries: [],
      },
      defenseProfile: {
        wafType: null,
        wafStrictness: "moderate",
        rateLimiting: { detected: false, threshold: null, resetWindow: null },
        errorVerbosity: "standard",
        cspPolicy: { present: false, strictness: "none", reportOnly: false },
        securityHeaders: { hsts: false, xFrameOptions: false, xContentType: false, referrerPolicy: null },
        cookieFlags: { httpOnly: false, secure: false, sameSite: null },
        authMechanisms: [],
        apiStyle: "rest",
      },
      industry: "general",
      huntGoal: "find-vulns",
      campaignState: {
        tasksCompleted: 0,
        findingsSoFar: 0,
        timeElapsedMinutes: 0,
        techniquesAttempted: [],
        blockedTechniques: [],
      },
    } as PredictionFeatureVector;

    const strategy = await bountyService.failurePrediction.predict(featureVector);

    const targetArea = target ? "/" : "/";
    const top = strategy.rankedStrategies.slice(0, 8);

    const data = await Promise.all(
      top.map(async (node) => {
        let duplicateProbability = 0;
        try {
          const dup = await bountyService.duplicateAvoidance.predictDuplicate(
            programId,
            node.technique,
            targetArea,
          );
          duplicateProbability = dup.duplicateProbability;
        } catch {
          // best-effort enrichment only
        }
        return {
          technique: node.technique,
          name: node.technique,
          evScore: node.evScore,
          ev: node.evScore,
          successProbability: node.baseProbability,
          baseProbability: node.baseProbability,
          duplicateRisk: duplicateProbability,
          duplicateProbability,
          expectedPayout: node.expectedPayout,
          payout: node.expectedPayout,
          expectedSeverity: node.expectedSeverity,
          expectedTimeMinutes: node.expectedTimeMinutes,
        };
      }),
    );

    res.json({
      success: true,
      data,
      meta: {
        target,
        programId,
        optimalPath: strategy.optimalPath,
        totalExpectedValue: strategy.totalExpectedValue,
        confidence: strategy.confidence,
        reasoning: strategy.reasoning,
      },
    });
  } catch (err: any) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// ─── Strategy / Vulnerability Prediction ────────────────────────────────────
// POST /predict  { featureVector }
// Backed by FailurePredictionEngine.predict (real EV-ranked strategy model).

router.post("/predict", async (req: Request, res: Response) => {
  try {
    const { featureVector, availableTechniques } = req.body || {};
    if (!featureVector) {
      return res.status(400).json({ success: false, error: "featureVector is required" });
    }
    const result = await bountyService.failurePrediction.predict(
      featureVector as PredictionFeatureVector,
      availableTechniques,
    );
    res.json({ success: true, data: result });
  } catch (err: any) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// ─── Payout ─────────────────────────────────────────────────────────────────
// GET /payout/estimate?program=&vulnType=&severity=&impactType=
// GET equivalent of bounty-intelligence POST /payout/estimate, backed by the
// PayoutOptimization service (median/p75/p95).

router.get("/payout/estimate", async (req: Request, res: Response) => {
  try {
    const program = String(req.query.program || "default");
    // Accept vulnType or impactType (DraftReports uses impactType); severity is a fallback.
    const vulnType = String(
      req.query.vulnType || req.query.impactType || req.query.severity || "",
    ).trim();
    if (!vulnType) {
      return res.status(400).json({ success: false, error: "vulnType (or impactType) is required" });
    }
    const result = await bountyService.payoutOptimization.estimatePayout(program, vulnType);
    res.json({ success: true, data: result });
  } catch (err: any) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// GET /payout/framing?vulnType=&context=  (context is optional JSON string)
router.get("/payout/framing", async (req: Request, res: Response) => {
  try {
    const vulnType = String(req.query.vulnType || "").trim();
    if (!vulnType) {
      return res.status(400).json({ success: false, error: "vulnType is required" });
    }
    let context: Record<string, any> | undefined;
    if (req.query.context) {
      try {
        context = JSON.parse(String(req.query.context));
      } catch {
        context = undefined;
      }
    }
    const result = await bountyService.payoutOptimization.getFramingSuggestions(vulnType, context);
    res.json({ success: true, data: result });
  } catch (err: any) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// GET /payout/escalations?vulnType=
router.get("/payout/escalations", async (req: Request, res: Response) => {
  try {
    const vulnType = String(req.query.vulnType || "").trim();
    if (!vulnType) {
      return res.status(400).json({ success: false, error: "vulnType is required" });
    }
    const result = await bountyService.payoutOptimization.getEscalationChains(vulnType);
    res.json({ success: true, data: result });
  } catch (err: any) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// ─── Duplicate Prediction ───────────────────────────────────────────────────
// GET /duplicates/predict?program=&vulnType=&area=
// Backed by PredictiveDuplicateAvoidance.predictDuplicate (real heuristic model).

router.get("/duplicates/predict", async (req: Request, res: Response) => {
  try {
    const program = String(req.query.program || "default");
    const vulnType = String(req.query.vulnType || "").trim();
    const area = String(req.query.area || req.query.targetArea || "").trim();
    if (!vulnType || !area) {
      return res.status(400).json({ success: false, error: "vulnType and area are required" });
    }
    const result = await bountyService.duplicateAvoidance.predictDuplicate(program, vulnType, area);
    res.json({ success: true, data: result });
  } catch (err: any) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// ─── Triage Prediction (GET) ────────────────────────────────────────────────
// GET /triage/predict?program=&severity=&quality=
// GET equivalent of bounty-intelligence POST /triage/predict.

router.get("/triage/predict", async (req: Request, res: Response) => {
  try {
    const program = String(req.query.program || req.query.programId || "default");
    const severity = String(req.query.severity || "").trim();
    if (!severity) {
      return res.status(400).json({ success: false, error: "severity is required" });
    }
    const qualityRaw = req.query.quality ?? req.query.reportQuality;
    const quality = qualityRaw !== undefined ? Number(qualityRaw) : undefined;
    const result = await bountyService.triagePredictor.predictTriageTime(
      program,
      severity,
      Number.isFinite(quality as number) ? (quality as number) : undefined,
    );
    res.json({ success: true, data: result });
  } catch (err: any) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// ─── Synergy ────────────────────────────────────────────────────────────────
// POST /synergy/analyze  { toolRecords?: ToolExecutionRecord[] }
// Records any provided tool executions then returns the real synergy map
// (pairs + topChains) from ToolSynergyEngine.

router.post("/synergy/analyze", async (req: Request, res: Response) => {
  try {
    const { toolRecords } = req.body || {};
    if (Array.isArray(toolRecords) && toolRecords.length > 0) {
      const byCampaign = new Set<string>();
      for (const record of toolRecords as ToolExecutionRecord[]) {
        await bountyService.toolSynergy.recordExecution(record);
        if (record.campaignId) byCampaign.add(record.campaignId);
      }
      // Finalize each campaign DAG so synergy scores get recomputed.
      for (const campaignId of byCampaign) {
        await bountyService.toolSynergy.completeCampaignDAG(campaignId);
      }
    }
    const synergyMap = await bountyService.toolSynergy.getSynergyMap();
    res.json({ success: true, data: synergyMap });
  } catch (err: any) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// ─── Playbooks (bounty-intelligence backed) ─────────────────────────────────
// NOTE: register the literal /playbooks/generate BEFORE the param /playbooks/:id
// so "generate" is not captured as an :id.

// POST /playbooks/generate  { toolRecords: ToolExecutionRecord[] }
// Records executions, completes the campaign DAG (which generates playbooks),
// and returns the most recently generated playbook summary.
router.post("/playbooks/generate", async (req: Request, res: Response) => {
  try {
    const { toolRecords } = req.body || {};
    if (!Array.isArray(toolRecords) || toolRecords.length === 0) {
      return res
        .status(400)
        .json({ success: false, error: "toolRecords (non-empty array) is required" });
    }

    const before = new Set((await bountyService.toolSynergy.listPlaybooks()).map((p) => p.id));

    const campaigns = new Set<string>();
    for (const record of toolRecords as ToolExecutionRecord[]) {
      await bountyService.toolSynergy.recordExecution(record);
      if (record.campaignId) campaigns.add(record.campaignId);
    }
    for (const campaignId of campaigns) {
      await bountyService.toolSynergy.completeCampaignDAG(campaignId);
    }

    const after = await bountyService.toolSynergy.listPlaybooks();
    const generated = after.find((p) => !before.has(p.id)) || after[0] || null;
    res.json({ success: true, data: generated });
  } catch (err: any) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// GET /playbooks/bounty — full bounty-intelligence playbook summaries
// (the existing GET /playbooks returns the static PIVOT_PLAYBOOKS seed set).
router.get("/playbooks/bounty", async (_req: Request, res: Response) => {
  try {
    const playbooks = await bountyService.toolSynergy.listPlaybooks();
    res.json({ success: true, data: playbooks });
  } catch (err: any) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// GET /playbooks/:id — detail for a single bounty-intelligence playbook.
router.get("/playbooks/:id", async (req: Request, res: Response) => {
  try {
    const playbook = await bountyService.toolSynergy.getPlaybook(req.params.id);
    if (!playbook) {
      return res.status(404).json({ success: false, error: "Playbook not found" });
    }
    res.json({ success: true, data: playbook });
  } catch (err: any) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// ─── Campaign Similarity ────────────────────────────────────────────────────
// POST /campaigns/similar  { targetProfile, limit? }
// Backed by CrossCampaignLearning.findSimilar.

router.post("/campaigns/similar", async (req: Request, res: Response) => {
  try {
    const { targetProfile, limit } = req.body || {};
    if (!targetProfile || !targetProfile.domain) {
      return res
        .status(400)
        .json({ success: false, error: "targetProfile.domain is required" });
    }
    const results = await bountyService.campaignLearning.findSimilar(
      targetProfile,
      typeof limit === "number" ? limit : 10,
    );
    res.json({ success: true, data: results });
  } catch (err: any) {
    res.status(500).json({ success: false, error: err.message });
  }
});

export default router;
