import { completeAgents, CompleteAgentType } from './layer5-complete-agents';

interface PassKConfig {
  k: number;
  task: {
    agentType: string;
    tool: string;
    target: string;
    parameters: Record<string, any>;
  };
  confidenceThreshold: number;
  timeout?: number;
}

interface PassKResult {
  bestResult: any;
  bestConfidence: number;
  allResults: Array<{
    attempt: number;
    result: any;
    confidence: number;
    duration: number;
    success: boolean;
  }>;
  totalAttempts: number;
  successRate: number;
  averageConfidence: number;
  selectedAttempt: number;
}

class PassKEvaluator {
  async evaluate(config: PassKConfig): Promise<PassKResult> {
    const agent = completeAgents[config.task.agentType as CompleteAgentType];
    if (!agent) {
      throw new Error(`Unknown agent type: ${config.task.agentType}`);
    }

    const allResults: PassKResult['allResults'] = [];

    for (let i = 0; i < config.k; i++) {
      const startTime = Date.now();
      let result: any = null;
      let confidence = 0.5;
      let success = false;

      try {
        const agentResult = await agent.execute(`passk-${config.task.agentType}-${i}`, {
          tool: config.task.tool,
          target: config.task.target,
          parameters: config.task.parameters
        });

        success = agentResult.success;
        result = agentResult.result;

        if (result && typeof result === 'object' && 'confidence' in result) {
          confidence = result.confidence;
        }
      } catch {
        success = false;
        result = null;
      }

      const duration = Date.now() - startTime;

      allResults.push({
        attempt: i + 1,
        result,
        confidence,
        duration,
        success
      });
    }

    const successfulResults = allResults.filter(r => r.success);
    const successRate = allResults.length > 0 ? successfulResults.length / allResults.length : 0;
    const totalConfidence = allResults.reduce((sum, r) => sum + r.confidence, 0);
    const averageConfidence = allResults.length > 0 ? totalConfidence / allResults.length : 0;

    let meetsThreshold = allResults.filter(r => r.success && r.confidence >= config.confidenceThreshold);
    let selected: PassKResult['allResults'][0];

    if (meetsThreshold.length > 0) {
      selected = meetsThreshold.reduce((best, current) => current.confidence > best.confidence ? current : best);
    } else {
      selected = allResults.reduce((best, current) => current.confidence > best.confidence ? current : best);
    }

    return {
      bestResult: selected.result,
      bestConfidence: selected.confidence,
      allResults,
      totalAttempts: config.k,
      successRate,
      averageConfidence,
      selectedAttempt: selected.attempt
    };
  }
}

// DEFAULT_K_VALUES represent the maximum (turbo/intensive) attempts per agent type.
// Scaled down for standard resource class to conserve LLM inference budget.
export const DEFAULT_K_VALUES: Record<string, number> = {
  recon: 2,
  exploit: 3,
  credential: 2,
  intel: 2,
  blueteam: 1,
  pivot: 3,
  report: 1,
  wordlist: 1,
  simgen: 1,
  smart: 2,
  scanner: 1,
  support: 1,
};

// Payout tier → k multiplier. High-payout programs justify more LLM attempts.
const PAYOUT_K_TIERS: Array<{ minPayout: number; k: number }> = [
  { minPayout: 5000, k: 3 },
  { minPayout: 1000, k: 2 },
  { minPayout: 0,    k: 1 },
];

export class PassKEvaluatorService extends PassKEvaluator {
  /**
   * Resolve how many attempts to run for an agent type given the resource class
   * and optional expected program payout. Uses the DEFAULT_K_VALUES as the
   * maximum ceiling and scales down for lower resource classes.
   */
  resolveK(
    agentType: string,
    resourceClass: 'lightweight' | 'standard' | 'enterprise' = 'standard',
    expectedPayout?: number
  ): number {
    const base = DEFAULT_K_VALUES[agentType] ?? 2;

    // Payout-based override takes priority when a payout estimate is available
    if (expectedPayout !== undefined) {
      const tier = PAYOUT_K_TIERS.find(t => expectedPayout >= t.minPayout);
      const payoutK = tier?.k ?? 1;
      // Cap at the DEFAULT for this agent type so expensive agents don't over-run
      return Math.min(payoutK, base);
    }

    // Resource class scaling: enterprise → full k, standard → default, lightweight → halved
    switch (resourceClass) {
      case 'enterprise':  return Math.min(base + 1, 4);
      case 'standard':    return base;
      case 'lightweight': return Math.max(Math.floor(base / 2), 1);
    }
  }
}

export const passKEvaluator = new PassKEvaluatorService();
