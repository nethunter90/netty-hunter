import { ObservationIngestion, Observation } from './observation-ingestion';
import { reasoningEngine } from './reasoning-engine';
import { decisionEngine } from './decision-engine';
import { circuitBreaker } from './circuit-breaker';
import { graphWiring } from './graph-wiring';
import logger from '../../utils/logger';

export class AutonomousBrain {
  private ingestion: ObservationIngestion;
  private initialized: boolean = false;

  constructor() {
    this.ingestion = new ObservationIngestion(process.env.OLLAMA_URL || 'http://localhost:11434');
    this.setupEventHandlers();
    graphWiring.initialize();
    this.initialized = true;
    logger.info('[Brain] Autonomous intelligence core initialized');
  }

  private setupEventHandlers() {
    decisionEngine.on('decision:made', (decision) => {
      logger.info(`[Brain] Decision: ${decision.chosenAction?.tool} → ${decision.chosenAction?.target}`);
    });

    circuitBreaker.on('circuit:opened', ({ tool }: { tool: string }) => {
      logger.warn(`[Brain] Circuit breaker opened for ${tool}`);
    });

    circuitBreaker.on('circuit:closed', ({ tool }: { tool: string }) => {
      logger.info(`[Brain] Circuit breaker recovered for ${tool}`);
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
    const memory = reasoningEngine.getSerializableMemory(missionId);
    const priorities = reasoningEngine.getAllPriorities(missionId);
    const beliefs = reasoningEngine.getBeliefs(missionId);

    return {
      memory,
      priorities,
      beliefs,
      discoveredTechs: memory?.stats?.techCount || 0,
      discoveredVulns: memory?.stats?.vulnCount || 0,
      discoveredEndpoints: memory?.stats?.endpointCount || 0
    };
  }

  async getAggregatedIntelligence(missionId: string) {
    return this.ingestion.aggregateIntelligence(missionId);
  }

  getObservations(missionId?: string) {
    return this.ingestion.getObservations(missionId);
  }

  getExpectationEngine() {
    return this.ingestion.getExpectationEngine();
  }

  isInitialized(): boolean {
    return this.initialized;
  }

  getSystemStatus() {
    const circuitStats = circuitBreaker.getStats();
    const decisionStats = decisionEngine.getStats();
    const activeMissions = reasoningEngine.getAllMissions();

    return {
      initialized: this.initialized,
      activeMissions: activeMissions.length,
      missionIds: activeMissions,
      observations: this.ingestion.getObservations().length,
      circuits: circuitStats,
      decisions: decisionStats,
      supportedGoals: this.ingestion.getExpectationEngine().getAllGoals()
    };
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

export function getBrainOrNull(): AutonomousBrain | null {
  return brainInstance;
}

export { ObservationIngestion, reasoningEngine, decisionEngine, circuitBreaker };
export type { Observation };
export { metaReasoner } from './meta-reasoning';
export type { Evidence, HuntContext, StrategyDecision, CounterfactualResult, HuntState } from './meta-reasoning';
export { graphWiring } from './graph-wiring';
export { contextualToolSelector } from './contextual-tool-selector';
export { verificationLifecycle } from './verification-lifecycle';
export { huntCortex, SignalType } from './hunt-cortex';
export type { CortexSignal } from './hunt-cortex';
export { decisionJournal } from './decision-journal';
export type { JournalEntry } from './decision-journal';
export { adaptiveThresholdTuner } from './adaptive-threshold-tuner';
export type { ThresholdSet } from './adaptive-threshold-tuner';
export { backwardPlanner } from './backward-planner';
export type { HuntPlan, RankedAttackPath } from './backward-planner';
export { mitrePrereqTree } from './mitre-prereq-tree';
export type { AttackChain, PrerequisiteAnalysis, ChokePoint } from './mitre-prereq-tree';
export { offensiveGraphDB } from './offensive-graph-db';
export { ATTACK_PATHS, MITRE_TECHNIQUES, TOOL_FALLBACK_CHAINS, TOOL_CATEGORIES, INTENT_PATTERNS, GOAL_PAYOUT_DATA, HUNT_GOAL_PATHS, PIVOT_PLAYBOOKS } from './seed-knowledge';
export type { AttackPath, MitreTechnique, ToolFallbackChain, IntentPattern, GoalPayoutData, HuntGoalPath, PivotPlaybook } from './seed-knowledge';
export { decisionTraceLogger, huntMetricsCollector } from './decision-trace';
export type { TraceEvent, TraceEventType, HuntMetrics, ConfidenceCalibrationPoint, PivotAnalysis, GroundTruth } from './decision-trace';
export { labScorer } from './lab-profiles';
export type { LabTargetProfile, LabVulnerability, LabScore } from './lab-profiles';
