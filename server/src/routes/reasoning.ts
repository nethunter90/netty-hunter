import { Router, Request, Response } from "express";
import { metaReasoner } from "../lib/intelligence/meta-reasoning";
import { decisionTraceLogger } from "../lib/intelligence/decision-trace";
import { huntLabRunner } from "../lib/intelligence/hunt-lab-runner";
import { huntCortex } from "../lib/intelligence/hunt-cortex";
import { adaptiveThresholdTuner } from "../lib/intelligence/adaptive-threshold-tuner";
import { labScorer } from "../lib/intelligence/lab-profiles";

const router = Router();

// ─── Trace ────────────────────────────────────────────────────────────────────

router.get("/trace/:huntId", (req: Request, res: Response) => {
  try {
    const trace = decisionTraceLogger.getTrace(req.params.huntId);
    res.json({ huntId: req.params.huntId, events: trace });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

// ─── Calibration ──────────────────────────────────────────────────────────────

router.get("/calibration", (_req: Request, res: Response) => {
  try {
    const stats = metaReasoner.getStats();
    res.json({ calibration: stats });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
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

router.get("/lab/profiles", (_req: Request, res: Response) => {
  try {
    const profiles = labScorer.getAllProfiles();
    res.json({ profiles });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
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

export default router;
