/**
 * Applies RL/ROI reinforcement only once a finding's real verdict is known —
 * the counterpart to HunterEngine.update()'s fast-path confidence threshold
 * (:3284), which used to call onHypothesisOutcome()/updateSuccessRate()
 * unconditionally the moment a no-model confidence blend crossed 0.7, before
 * any verification existed. That meant the RL store learned from every
 * heuristic "confirmed" regardless of what the 4-layer verifier later did
 * with it — a finding the verifier went on to reject had already reinforced
 * the store as a positive outcome, with nothing to walk it back.
 *
 * This is a standalone function, not a method on ReinforcementWiring,
 * because verification runs decoupled from the HunterEngine instance that
 * discovered the finding — both call sites (CampaignOrchestrator's Layer 5
 * gate and routes/hunt.ts's post-hunt verifyPendingForSession) operate
 * purely off a DB `findings` row, often long after the originating engine
 * is gone. It re-resolves provenance from the row's programId the same way
 * ReinforcementWiring.onHuntStart() does, rather than threading a live
 * per-hunt config through.
 *
 * Scope note: this covers the two RL writes that operate on data actually
 * persisted to the findings row (vulnType, confidence, programId) —
 * onHypothesisOutcome's confidence-calibration write and ROIModel's
 * success-rate write. Three sibling writes at the original call site
 * (recordModelOutcome, onRetryTechniqueOutcome, the chain-synthesis credit)
 * depend on hypothesis fields (modelSource, retryTechnique, chainedFrom)
 * that are NOT persisted to the findings table, so they cannot be deferred
 * the same way without either adding new columns or keeping the engine
 * instance alive until verification completes — both real structural
 * changes, deliberately left as a flagged follow-up rather than bundled
 * here. They still fire at heuristic-confirmation time (HunterEngine.ts,
 * next to where this comment is referenced) — a known, narrower residual.
 */
import { UnifiedReinforcementStore } from "../../intelligence/ReinforcementStore";
import { ROIModel } from "../../intelligence/ROIModel";
import { resolveProvenance } from "../hunter/custom-target-program";
import logger from "../../utils/logger";

export type VerifiedRlVerdict = "confirmed" | "rejected" | "inconclusive" | "deduplicated";

const roiModel = new ROIModel();

export interface VerifiedRlOutcomeInput {
  vulnType: string;
  confidence: number;
  programId: number | null | undefined;
}

/**
 * `deduplicated` intentionally applies NO RL write: it's a bookkeeping
 * outcome ("this exact vuln already exists as another row"), not a signal
 * about whether the hypothesis class or predicted confidence was justified.
 * `confirmed` reinforces positively; `rejected`/`inconclusive` both
 * reinforce negatively — the verifier could not confirm the hypothesis
 * either way, so the predicted confidence was not justified.
 */
export async function applyVerifiedRlOutcome(
  finding: VerifiedRlOutcomeInput,
  verdict: VerifiedRlVerdict,
): Promise<void> {
  if (verdict === "deduplicated") return;

  const actuallyFound = verdict === "confirmed";
  const provenance = await resolveProvenance(finding.programId);

  try {
    UnifiedReinforcementStore.getInstance()
      .recordConfidenceCalibration(finding.vulnType, finding.confidence, actuallyFound, provenance)
      .catch(() => {});
    await roiModel.updateSuccessRate(finding.vulnType, actuallyFound, provenance);
    logger.debug("[RL] Verified outcome recorded", {
      vulnType: finding.vulnType, verdict, actuallyFound, provenance,
    });
  } catch (err) {
    logger.warn("[RL] applyVerifiedRlOutcome failed (non-critical)", { err: String(err) });
  }
}
