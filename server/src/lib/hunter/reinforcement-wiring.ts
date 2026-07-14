/**
 * Reinforcement Wiring
 * Connects hunt lifecycle events to the UnifiedReinforcementStore.
 * Called from HunterEngine at key lifecycle points.
 */
import { UnifiedReinforcementStore } from '../../intelligence/ReinforcementStore';
import logger from '../../utils/logger';

export interface WiringConfig {
  sessionId: string;
  programId: number;
  programType: string; // "web_app" | "api" | "mobile" | "infrastructure"
}

export class ReinforcementWiring {
  private readonly rl = UnifiedReinforcementStore.getInstance();
  private config: WiringConfig | null = null;

  onHuntStart(config: WiringConfig): void {
    this.config = config;
    logger.debug('[RL] Hunt started', { sessionId: config.sessionId, programType: config.programType });
  }

  onToolResult(tool: string, vulnClass: string, success: boolean, confidence: number): void {
    if (!this.config) return;
    this.rl.recordToolOutcome(tool, vulnClass, success).catch(() => {});
    // Record exploration: mark this endpoint pattern + vuln class as tested
    const sessionPattern = `session:${this.config.sessionId}`;
    this.rl.recordExploration(sessionPattern, vulnClass).catch(() => {});
    logger.debug('[RL] Tool result recorded', { tool, vulnClass, success, confidence });
  }

  onHypothesisOutcome(vulnClass: string, predictedConfidence: number, actuallyFound: boolean): void {
    if (!this.config) return;
    this.rl.recordConfidenceCalibration(vulnClass, predictedConfidence, actuallyFound).catch(() => {});
    logger.debug('[RL] Hypothesis calibration recorded', { vulnClass, predictedConfidence, actuallyFound });
  }

  recordModelOutcome(model: string, vulnClass: string, confirmed: boolean): void {
    this.rl.recordModelOutcome(model, vulnClass, confirmed).catch(() => {});
    logger.debug('[RL] Model outcome recorded', { model, vulnClass, confirmed });
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
    if (reason === 'waf_blocked') {
      this.rl.recordWafEvasionOutcome(axisKey, vulnClass, technique, success).catch(() => {});
    } else {
      this.rl.recordPayloadMutationOutcome(axisKey, vulnClass, technique, success).catch(() => {});
    }
    logger.debug('[RL] Retry technique outcome recorded', { reason, axisKey, vulnClass, technique, success });
  }

  getFrameworkPriorities(framework: string): Promise<string[]> {
    return this.rl.getVulnsForFramework(framework).then(vulns => vulns.map(v => v.vulnClass));
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
   */
  async getBestTool(candidates: string[], vulnClass: string, fallback: string): Promise<string> {
    if (candidates.length <= 1) return fallback;
    try {
      const rates = await Promise.all(
        candidates.map(async t => [t, await this.rl.getToolSuccessRate(t, vulnClass)] as const)
      );
      const fallbackRate = rates.find(([t]) => t === fallback)?.[1] ?? 0.5;
      let best = fallback;
      let bestRate = fallbackRate;
      for (const [tool, rate] of rates) {
        // Require a clear margin over the default to switch — avoids churn on noise.
        if (rate > bestRate + 0.05) { best = tool; bestRate = rate; }
      }
      if (best !== fallback) {
        logger.debug('[RL] Tool selection override', { vulnClass, fallback, chosen: best, rate: bestRate });
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
    const strategy = confirmedFindings > 0 ? 'found_vulns' : 'no_vulns';
    this.rl.recordProgramTypeHeuristic(programType, strategy, confirmedFindings > 0).catch(() => {});

    // Also record efficiency as a heuristic
    if (totalProbes > 0) {
      const efficient = confirmedFindings / totalProbes > 0.1;
      this.rl.recordProgramTypeHeuristic(programType, 'efficient_hunt', efficient).catch(() => {});
    }

    logger.info('[RL] Hunt complete wired', {
      programType,
      confirmedFindings,
      totalProbes,
      strategy,
    });
  }
}
