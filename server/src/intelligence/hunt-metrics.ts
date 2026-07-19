/**
 * Shared hunt-outcome → AutonomyMaturityTracker input derivation.
 *
 * Both the orchestration pipeline (CampaignOrchestrator's Layer 6) and
 * console-launched hunts (routes/hunt.ts's auto-verify path) need to feed
 * AutonomyMaturityTracker.recordHuntOutcome() from the same ground truth —
 * a hunt's findings and their verification outcomes. Previously only the
 * orchestration path computed this, so console-launched hunts (the common
 * case) never updated autonomy_metrics at all. Deriving it once here from a
 * flat findings array (rather than re-deriving it per call site from
 * whatever in-memory state happens to be available) means both paths score
 * a hunt the same way — no risk of the two drifting into different
 * definitions of "correct tool" or "false positive".
 */
import type { findings } from "../db/schema";

type FindingRow = typeof findings.$inferSelect;

export interface AutonomyHuntMetrics {
  hypothesesGenerated: number;
  hypothesesCorrect: number;
  toolsSelected: number;
  toolsCorrect: number;
  outOfScopeAttempts: number;
  falsePositives: number;
  confirmedFindings: number;
  chainDepth: number;
  reportQualityScore: number;
}

/** Tool names recorded on a finding's evidence entries (each probe tags its tool). */
function extractTools(finding: FindingRow): string[] {
  const ev = (finding.evidence as Array<Record<string, unknown>>) || [];
  return ev.map(e => (e?.tool as string) || "").filter(Boolean);
}

/**
 * Derive AutonomyMaturityTracker.recordHuntOutcome()'s input from a hunt's
 * full findings list (all verification statuses — confirmed, rejected,
 * inconclusive, pending). `reportsGenerated` is the count of findings a
 * report/Nuclei-template pass actually ran for; pass 0 if none ran yet.
 */
export function deriveAutonomyHuntMetrics(
  findingRows: FindingRow[],
  reportsGenerated: number,
): AutonomyHuntMetrics {
  const confirmed = findingRows.filter(f => f.verificationStatus === "confirmed");
  const rejected = findingRows.filter(f => f.verificationStatus !== "confirmed");

  const correctTools = new Set<string>();
  confirmed.forEach(f => extractTools(f).forEach(t => correctTools.add(t)));
  const selectedTools = new Set<string>(correctTools);
  rejected.forEach(f => extractTools(f).forEach(t => selectedTools.add(t)));

  const totalProcessed = findingRows.length;
  const confirmedCount = confirmed.length;

  return {
    hypothesesGenerated: totalProcessed,
    hypothesesCorrect: confirmedCount,
    toolsSelected: Math.max(selectedTools.size, 1),
    toolsCorrect: correctTools.size,
    outOfScopeAttempts: 0,
    falsePositives: Math.max(0, totalProcessed - confirmedCount),
    confirmedFindings: confirmedCount,
    chainDepth: confirmedCount > 0 ? 1 : 0,
    reportQualityScore: reportsGenerated > 0 ? 0.8 : 0,
  };
}
