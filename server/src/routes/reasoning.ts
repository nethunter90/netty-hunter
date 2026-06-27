import { Router, Request, Response } from "express";
import { metaReasoner } from "../lib/intelligence/meta-reasoning";
import { decisionTraceLogger, huntMetricsCollector } from "../lib/intelligence/decision-trace";
import { huntLabRunner } from "../lib/intelligence/hunt-lab-runner";
import { huntCortex } from "../lib/intelligence/hunt-cortex";
import { adaptiveThresholdTuner } from "../lib/intelligence/adaptive-threshold-tuner";
import { labScorer } from "../lib/intelligence/lab-profiles";
import { decisionJournal } from "../lib/intelligence/decision-journal";
import { strategyWeightLearner } from "../lib/learning/strategy-weight-learner";

const router = Router();

// Extract confirmed-finding identifiers from a hunt's decision trace so lab
// scoring can match them against ground-truth vulnerabilities.
function confirmedFindingsFromTrace(huntId: string): string[] {
  const trace = decisionTraceLogger.getTrace(huntId);
  return trace
    .filter((e) => e.eventType === "finding_confirmed")
    .map((e) =>
      String(
        e.data?.findingType ||
          e.data?.vulnerability ||
          e.data?.description ||
          e.data?.goal ||
          ""
      )
    )
    .filter(Boolean);
}

// ─── Trace ────────────────────────────────────────────────────────────────────

// List currently/recently active hunt ids for the Hunt Replay picker.
// Data source: decisionTraceLogger buffered + persisted hunt ids (decision_traces table).
// Registered before /trace/:huntId so the two static segments don't collide.
router.get("/trace/hunts/active", async (_req: Request, res: Response) => {
  try {
    const huntIds = await decisionTraceLogger.getAllHuntIds();
    res.json({ success: true, data: huntIds });
  } catch (err: any) {
    res.status(500).json({ success: false, error: err.message });
  }
});

router.get("/trace/:huntId", (req: Request, res: Response) => {
  try {
    const trace = decisionTraceLogger.getTrace(req.params.huntId);
    // HuntReplay reads `traceData.data` (the events array) gated on `.success`.
    res.json({ success: true, data: trace, huntId: req.params.huntId });
  } catch (err: any) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// ─── Calibration ──────────────────────────────────────────────────────────────

router.get("/calibration", (_req: Request, res: Response) => {
  try {
    const stats = metaReasoner.getStats();
    // HuntReplay reads `data.data` gated on `.success`.
    res.json({ success: true, data: stats });
  } catch (err: any) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// ─── Hunt Health ──────────────────────────────────────────────────────────────

router.get("/health/:huntId", (req: Request, res: Response) => {
  try {
    const health = huntCortex.computeHuntHealth(req.params.huntId);
    res.json({ huntId: req.params.huntId, health });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

// ─── Signals ──────────────────────────────────────────────────────────────────

router.get("/signals/:huntId", (req: Request, res: Response) => {
  try {
    const signals = huntCortex.recentSignals({ huntId: req.params.huntId });
    res.json({ huntId: req.params.huntId, signals });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

// ─── Lab ──────────────────────────────────────────────────────────────────────

router.post("/lab/run", async (req: Request, res: Response) => {
  try {
    const { profileId, huntConfig } = req.body;
    const pid = profileId || "juice-shop";
    const goalOverride = huntConfig?.goal;
    const result = await huntLabRunner.runHunt(pid, goalOverride, huntConfig);
    res.json(result);
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

router.post("/lab/stop", (req: Request, res: Response) => {
  try {
    const { huntId } = req.body;
    if (!huntId) return res.status(400).json({ success: false, error: "huntId is required" });
    const { stopped } = huntLabRunner.stopHunt(String(huntId));
    return res.json({ success: true, stopped });
  } catch (err: any) {
    return res.status(500).json({ success: false, error: err.message });
  }
});

router.get("/lab/profiles", (_req: Request, res: Response) => {
  try {
    const profiles = labScorer.getAllProfiles();
    // HuntReplay reads `data.data` gated on `.success`, and renders `vulnCount`.
    const shaped = profiles.map((p) => ({
      ...p,
      vulnCount: Array.isArray(p.vulnerabilities) ? p.vulnerabilities.length : 0,
    }));
    res.json({ success: true, data: shaped });
  } catch (err: any) {
    res.status(500).json({ success: false, error: err.message });
  }
});

router.get("/lab/results", async (_req: Request, res: Response) => {
  try {
    const huntIds = await decisionTraceLogger.getAllHuntIds();
    const results = huntIds.map((id) => ({
      huntId: id,
      eventCount: decisionTraceLogger.getTrace(id).length,
    }));
    res.json({ results });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

// ─── Thresholds ───────────────────────────────────────────────────────────────

router.get("/thresholds/:goalType", async (req: Request, res: Response) => {
  try {
    const thresholds = await adaptiveThresholdTuner.getThresholds(req.params.goalType);
    res.json({ goalType: req.params.goalType, thresholds });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

// ─── Strategy Weights ─────────────────────────────────────────────────────────

router.post("/recompute-weights", async (_req: Request, res: Response) => {
  try {
    await strategyWeightLearner.learn();
    res.json({ ok: true });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

// ─── Divergence ───────────────────────────────────────────────────────────────

router.get("/divergence/:huntId", (req: Request, res: Response) => {
  try {
    const signals = huntCortex.recentSignals({ huntId: req.params.huntId });
    const counterfactuals = metaReasoner.checkCounterfactuals(req.params.huntId);
    res.json({
      huntId: req.params.huntId,
      signals: signals.map((s) => ({
        type: s.signalType,
        confidence: s.confidence,
        timestamp: s.timestamp,
      })),
      counterfactuals,
    });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

// ─── Metrics ────────────────────────────────────────────────────────────────

// Reasoning metrics summary for a hunt.
// Data source: huntMetricsCollector.computeMetrics over the decision trace.
router.get("/metrics/:huntId", (req: Request, res: Response) => {
  try {
    const metrics = huntMetricsCollector.computeMetrics(req.params.huntId);
    res.json({ success: true, data: metrics });
  } catch (err: any) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// Strategy pivots for a hunt.
// Data source: meta_pivot trace events analysed by huntMetricsCollector.getPivotAnalysis.
router.get("/metrics/:huntId/pivots", (req: Request, res: Response) => {
  try {
    const pivots = huntMetricsCollector.getPivotAnalysis(req.params.huntId);
    res.json({ success: true, data: pivots });
  } catch (err: any) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// Hypothesis/finding quality metrics for a hunt.
// Data source: huntMetricsCollector.getDecisionQualityScore + finding-confirmation
// trace events and decision_journal entry stats for this hunt.
router.get("/metrics/:huntId/quality", async (req: Request, res: Response) => {
  try {
    const huntId = req.params.huntId;
    const qualityScore = huntMetricsCollector.getDecisionQualityScore(huntId);
    const metrics = huntMetricsCollector.computeMetrics(huntId);
    const trace = decisionTraceLogger.getTrace(huntId);
    const confirmed = trace.filter((e) => e.eventType === "finding_confirmed").length;
    const invalidated = trace.filter((e) => e.eventType === "finding_invalidated").length;
    const journalEntries = await decisionJournal.getRecentEntries(huntId, 200);
    res.json({
      success: true,
      data: {
        huntId,
        qualityScore,
        confirmedFindings: confirmed,
        invalidatedFindings: invalidated,
        falsePositiveRate: metrics.falsePositiveRate,
        pivotEfficiencyRatio: metrics.pivotEfficiencyRatio,
        pathAccuracy: metrics.pathAccuracy,
        journalEntryCount: journalEntries.length,
      },
    });
  } catch (err: any) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// Metrics evaluated under a lab profile's ground truth.
// Data source: huntMetricsCollector.computeMetrics with labScorer.getGroundTruth(profile).
router.get("/metrics/:huntId/lab/:profile", (req: Request, res: Response) => {
  try {
    const { huntId, profile } = req.params;
    const groundTruth = labScorer.getGroundTruth(profile);
    const metrics = huntMetricsCollector.computeMetrics(huntId, groundTruth);
    res.json({ success: true, data: metrics });
  } catch (err: any) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// Lab score for a hunt against a profile.
// Data source: labScorer.scoreHunt using confirmed findings + trace from the decision trace.
router.get("/metrics/:huntId/lab/:profile/score", (req: Request, res: Response) => {
  try {
    const { huntId, profile } = req.params;
    const trace = decisionTraceLogger.getTrace(huntId);
    const confirmedFindings = confirmedFindingsFromTrace(huntId);
    const score = labScorer.scoreHunt(huntId, profile, confirmedFindings, trace);
    res.json({ success: true, data: score });
  } catch (err: any) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// Planned-vs-actual divergence points for a hunt under a lab profile.
// Data source: labScorer.computeDivergence over the decision trace.
router.get("/metrics/:huntId/lab/:profile/divergence", (req: Request, res: Response) => {
  try {
    const { huntId, profile } = req.params;
    const trace = decisionTraceLogger.getTrace(huntId);
    const divergence = labScorer.computeDivergence(huntId, profile, trace);
    res.json({ success: true, data: divergence });
  } catch (err: any) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// Pivot regret analysis for a hunt under a lab profile.
// Data source: huntLabRunner.computePivotRegret over meta_pivot/finding trace events.
router.get("/metrics/:huntId/lab/:profile/regret", (req: Request, res: Response) => {
  try {
    const { huntId, profile } = req.params;
    const regret = huntLabRunner.computePivotRegret(huntId, profile);
    res.json({ success: true, data: regret });
  } catch (err: any) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// ─── Lab Determinism ──────────────────────────────────────────────────────────

// Planner determinism check for a profile.
// Data source: huntLabRunner.checkDeterminism (repeated backwardPlanner rankings).
router.get("/lab/determinism/:profile", (req: Request, res: Response) => {
  try {
    const iterations = req.query.iterations ? parseInt(String(req.query.iterations), 10) : undefined;
    const result = huntLabRunner.checkDeterminism(req.params.profile, iterations);
    // rankDistribution is a Map (not JSON-serializable / not consumed by the client) — drop it.
    const { rankDistribution, ...serializable } = result;
    res.json({ success: true, data: serializable });
  } catch (err: any) {
    res.status(500).json({ success: false, error: err.message });
  }
});

export default router;
