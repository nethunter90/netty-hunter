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
  smart: 2
};

export const passKEvaluator = new PassKEvaluator();
