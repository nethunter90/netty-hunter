/**
 * Reinforcement Wiring
 * Connects hunt lifecycle events to the UnifiedReinforcementStore.
 * Called from HunterEngine at key lifecycle points.
 *
 * PROVENANCE (2026-07-23 readiness handoff): provenance ("real"/"lab"/
 * "unknown") is resolved ONCE per hunt in onHuntStart() via
 * resolveProvenance() (custom-target-program.ts, wraps the existing
 * isCrossCampaignEligible() discriminator) and cached on this.config.
 * Every this.rl.* call below threads that cached value through — this is
 * the chokepoint's WRITE side; ReinforcementStore.ts's key-prefixing is the
 * READ side. Neither alone would segregate anything.
 */
import { UnifiedReinforcementStore, Provenance } from '../../intelligence/ReinforcementStore';
import { resolveProvenance } from './custom-target-program';
import logger from '../../utils/logger';

export interface WiringConfig {
  sessionId: string;
  programId: number;
  programType: string; // "web_app" | "api" | "mobile" | "infrastructure"
}

export class ReinforcementWiring {
  private readonly rl = UnifiedReinforcementStore.getInstance();
  private config: (WiringConfig & { provenance: Provenance }) | null = null;

  async onHuntStart(config: WiringConfig): Promise<void> {
    const provenance = await resolveProvenance(config.programId);
    this.config = { ...config, provenance };
    logger.info('[RL] Hunt started', {
      sessionId: config.sessionId, programType: config.programType, provenance,
    });
  }

  /** Exposed so callers outside this class (e.g. HunterEngine's own
   *  ROIModel calls) can reuse the same per-hunt provenance resolution
   *  instead of re-deriving it — one resolution per hunt, not one per call. */
  getProvenance(): Provenance {
    return this.config?.provenance ?? "unknown";
  }

  onToolResult(tool: string, vulnClass: string, success: boolean, confidence: number): void {
    if (!this.config) return;
    const provenance = this.config.provenance;
    this.rl.recordToolOutcome(tool, vulnClass, success, provenance).catch(() => {});
    // Record exploration: mark this endpoint pattern + vuln class as tested
    const sessionPattern = `session:${this.config.sessionId}`;
    this.rl.recordExploration(sessionPattern, vulnClass, provenance).catch(() => {});
    logger.debug('[RL] Tool result recorded', { tool, vulnClass, success, confidence, provenance });
  }

  onHypothesisOutcome(vulnClass: string, predictedConfidence: number, actuallyFound: boolean): void {
    if (!this.config) return;
    this.rl.recordConfidenceCalibration(vulnClass, predictedConfidence, actuallyFound, this.config.provenance).catch(() => {});
    logger.debug('[RL] Hypothesis calibration recorded', { vulnClass, predictedConfidence, actuallyFound });
  }

  recordModelOutcome(model: string, vulnClass: string, confirmed: boolean): void {
    const provenance = this.config?.provenance ?? "unknown";
    this.rl.recordModelOutcome(model, vulnClass, confirmed, provenance).catch(() => {});
    logger.debug('[RL] Model outcome recorded', { model, vulnClass, confirmed, provenance });
  }

  /**
   * Records which reason-routed retry technique won or lost once a
   * hypothesis reaches a definitive confirmed/rejected verdict — the
   * write-path half of the gray-zone retry classifier (see
   * retry-failure-classifier.ts and HunterEngine's probe()/update()).
   * axisKey is the WAF vendor for "waf_blocked", the app stack for
   * "reflected_not_executed" — callers must never mix the two up, since the
   * two domains below are kept separate for exactly that reason.
   */
  onRetryTechniqueOutcome(
    reason: 'waf_blocked' | 'reflected_not_executed',
    axisKey: string,
    vulnClass: string,
    technique: string,
    success: boolean,
  ): void {
    const provenance = this.config?.provenance ?? "unknown";
    if (reason === 'waf_blocked') {
      this.rl.recordWafEvasionOutcome(axisKey, vulnClass, technique, success, provenance).catch(() => {});
    } else {
      this.rl.recordPayloadMutationOutcome(axisKey, vulnClass, technique, success, provenance).catch(() => {});
    }
    logger.debug('[RL] Retry technique outcome recorded', { reason, axisKey, vulnClass, technique, success, provenance });
  }

  getFrameworkPriorities(framework: string): Promise<string[]> {
    const provenance = this.config?.provenance ?? "unknown";
    return this.rl.getVulnsForFramework(framework, provenance).then(vulns => vulns.map(v => v.vulnClass));
  }

  /**
   * Pick the best-performing tool for a vuln class from a candidate list using
   * learned success rates. Closes the tool-selection RL loop — these rates were
   * recorded every hunt via onToolResult() but never read back.
   *
   * Cold-start safe: getToolSuccessRate returns 0.5 for tools with no data, so
   * on a fresh store every candidate ties and we return the caller's default
   * (preserving current behavior). As data accumulates, a tool that beats the
   * default by a clear margin wins. Untried tools keep their 0.5 prior so they
   * still get explored rather than being permanently shut out.
   *
   * PROVENANCE-GATED: reads only this.config.provenance's own namespace — a
   * "real" hunt never sees a "lab" hunt's learned rates, and vice versa.
   */
  async getBestTool(candidates: string[], vulnClass: string, fallback: string): Promise<string> {
    if (candidates.length <= 1) return fallback;
    const provenance = this.config?.provenance ?? "unknown";
    try {
      const rates = await Promise.all(
        candidates.map(async t => [t, await this.rl.getToolSuccessRate(t, vulnClass, provenance)] as const)
      );
      const fallbackRate = rates.find(([t]) => t === fallback)?.[1] ?? 0.5;
      let best = fallback;
      let bestRate = fallbackRate;
      for (const [tool, rate] of rates) {
        // Require a clear margin over the default to switch — avoids churn on noise.
        if (rate > bestRate + 0.05) { best = tool; bestRate = rate; }
      }
      if (best !== fallback) {
        logger.debug('[RL] Tool selection override', { vulnClass, fallback, chosen: best, rate: bestRate, provenance });
      }
      return best;
    } catch {
      return fallback;
    }
  }

  onHuntComplete(config: WiringConfig & {
    confirmedFindings: number;
    totalProbes: number;
    chainIds: string[];
  }): void {
    const { programType, confirmedFindings, totalProbes } = config;
    const provenance = this.config?.provenance ?? "unknown";
    const strategy = confirmedFindings > 0 ? 'found_vulns' : 'no_vulns';
    this.rl.recordProgramTypeHeuristic(programType, strategy, confirmedFindings > 0, provenance).catch(() => {});

    // Also record efficiency as a heuristic
    if (totalProbes > 0) {
      const efficient = confirmedFindings / totalProbes > 0.1;
      this.rl.recordProgramTypeHeuristic(programType, 'efficient_hunt', efficient, provenance).catch(() => {});
    }

    logger.info('[RL] Hunt complete wired', {
      programType,
      confirmedFindings,
      totalProbes,
      strategy,
      provenance,
    });
  }
}
