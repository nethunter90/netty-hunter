import { ObservationIngestion, Observation } from './observation-ingestion';
import { reasoningEngine } from './reasoning-engine';
import { decisionEngine } from './decision-engine';
import { circuitBreaker } from './circuit-breaker';
import logger from '../../utils/logger';

export class AutonomousBrain {
  private ingestion: ObservationIngestion;

  constructor() {
    this.ingestion = new ObservationIngestion();
    this.setupEventHandlers();
  }

  private setupEventHandlers() {
    decisionEngine.on('decision:made', (decision) => {
      logger.info(`[Brain] Decision: ${decision.chosenAction?.tool} → ${decision.chosenAction?.target}`);
    });

    circuitBreaker.on('circuit:opened', ({ tool }: { tool: string }) => {
      logger.warn(`[Brain] Circuit breaker opened for ${tool}`);
    });

    reasoningEngine.on('memory:updated', async ({ missionId }: { missionId: string }) => {
      try {
        const decision = await decisionEngine.makeDecision(missionId);
        logger.debug(`[Brain] Next action: ${decision.chosenAction?.tool}`);
      } catch { /* mission may not have enough data yet */ }
    });
  }

  async processObservation(obs: Observation) {
    const ingested = await this.ingestion.ingest(obs);

    if (obs.missionId) {
      // Ensure mission is initialized
      if (!reasoningEngine.getMissionMemory(obs.missionId)) {
        reasoningEngine.initializeMission(obs.missionId, obs.target || '', obs.huntGoal || '');
      }
      reasoningEngine.updateMemory(obs.missionId, ingested);
    }

    return ingested;
  }

  async getNextAction(missionId: string) {
    const decision = await decisionEngine.makeDecision(missionId);
    const circuit = circuitBreaker.canExecute(decision.chosenAction.tool);

    if (!circuit.allowed) {
      logger.warn(`[Brain] Tool ${decision.chosenAction.tool} unavailable`);
      if (circuit.fallback) {
        logger.info(`[Brain] Using fallback: ${circuit.fallback}`);
        decision.chosenAction.tool = circuit.fallback;
      }
    }

    return decision;
  }

  recordActionResult(missionId: string, tool: string, success: boolean, outcome: string) {
    if (success) {
      circuitBreaker.recordSuccess(tool);
    } else {
      circuitBreaker.recordFailure(tool, outcome);
    }

    reasoningEngine.recordAction(missionId, {
      id: `action-${Date.now()}`,
      timestamp: new Date().toISOString(),
      tool,
      target: '',
      success,
      outcome,
      confidence: success ? 0.9 : 0.3
    });
  }

  getMissionState(missionId: string) {
    const memory = reasoningEngine.getMissionMemory(missionId);
    const priorities = reasoningEngine.getAllPriorities(missionId);
    const beliefs = reasoningEngine.getBeliefs(missionId);

    return {
      memory,
      priorities,
      beliefs,
      discoveredTechs: memory?.discoveredTechnologies.size || 0,
      discoveredVulns: memory?.discoveredVulnerabilities.size || 0,
      discoveredEndpoints: memory?.discoveredEndpoints.size || 0
    };
  }

  async getAggregatedIntelligence(missionId: string) {
    return this.ingestion.aggregateIntelligence(missionId);
  }
}

let brainInstance: AutonomousBrain | null = null;

export function initializeAutonomousBrain(): AutonomousBrain {
  if (!brainInstance) {
    brainInstance = new AutonomousBrain();
  }
  return brainInstance;
}

export function getAutonomousBrain(): AutonomousBrain {
  if (!brainInstance) throw new Error('Autonomous brain not initialized');
  return brainInstance;
}

export { ObservationIngestion, reasoningEngine, decisionEngine, circuitBreaker };
export type { Observation };
