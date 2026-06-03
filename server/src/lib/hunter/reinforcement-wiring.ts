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

  getFrameworkPriorities(framework: string): Promise<string[]> {
    return this.rl.getVulnsForFramework(framework).then(vulns => vulns.map(v => v.vulnClass));
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
