import { EventEmitter } from 'events';
import { ExtractedIntelligence, IngestedObservation } from './observation-ingestion';

export interface MissionMemory {
  missionId: string;
  target: string;
  goal: string;
  startedAt: string;
  discoveredTechnologies: Map<string, unknown>;
  discoveredVulnerabilities: Map<string, unknown>;
  discoveredEndpoints: Map<string, unknown>;
  actionHistory: ActionRecord[];
  beliefs: Belief[];
  priorityQueue: PriorityTask[];
}

export interface ActionRecord {
  id: string;
  timestamp: string;
  tool: string;
  target: string;
  success: boolean;
  outcome: string;
  confidence: number;
}

export interface Belief {
  statement: string;
  confidence: number;
  evidence: string[];
  createdAt: string;
}

export interface PriorityTask {
  id: string;
  action: string;
  target: string;
  priority: number;
  reasoning: string;
  expectedPayoff: number;
}

export class ReasoningEngine extends EventEmitter {
  private missions: Map<string, MissionMemory> = new Map();

  initializeMission(missionId: string, target: string, goal: string): MissionMemory {
    const memory: MissionMemory = {
      missionId,
      target,
      goal,
      startedAt: new Date().toISOString(),
      discoveredTechnologies: new Map(),
      discoveredVulnerabilities: new Map(),
      discoveredEndpoints: new Map(),
      actionHistory: [],
      beliefs: [],
      priorityQueue: []
    };
    this.missions.set(missionId, memory);
    return memory;
  }

  getMissionMemory(missionId: string): MissionMemory | undefined {
    return this.missions.get(missionId);
  }

  updateMemory(missionId: string, ingested: IngestedObservation) {
    const memory = this.missions.get(missionId);
    if (!memory) return;

    const { intelligence } = ingested;

    intelligence.technologies.forEach(tech => {
      const key = `${tech.name}:${tech.version || 'unknown'}`;
      if (!memory.discoveredTechnologies.has(key)) {
        memory.discoveredTechnologies.set(key, tech);
        this.addBelief(memory, {
          statement: `Target uses ${tech.name}${tech.version ? ` v${tech.version}` : ''}`,
          confidence: tech.confidence,
          evidence: tech.evidence,
          createdAt: new Date().toISOString()
        });
      }
    });

    intelligence.vulnerabilities.forEach(vuln => {
      const key = `${vuln.type}:${vuln.location}`;
      const existing = memory.discoveredVulnerabilities.get(key) as typeof vuln | undefined;
      if (!existing || (existing.confidence ?? 0) < vuln.confidence) {
        memory.discoveredVulnerabilities.set(key, vuln);
      }
    });

    intelligence.endpoints.forEach(endpoint => {
      if (!memory.discoveredEndpoints.has(endpoint.url)) {
        memory.discoveredEndpoints.set(endpoint.url, endpoint);
      }
    });

    this.rebuildPriorityQueue(memory, intelligence);
    this.emit('memory:updated', { missionId, memory });
  }

  private addBelief(memory: MissionMemory, belief: Belief) {
    const existing = memory.beliefs.find(b => b.statement === belief.statement);
    if (!existing) {
      memory.beliefs.push(belief);
    } else if (belief.confidence > existing.confidence) {
      existing.confidence = belief.confidence;
      existing.evidence.push(...belief.evidence);
    }
  }

  private rebuildPriorityQueue(memory: MissionMemory, intelligence: ExtractedIntelligence) {
    memory.priorityQueue = [];

    const goalPriorities: Record<string, number> = {
      rce: 10, auth_bypass: 9, sqli: 9, ssrf: 8, idor: 7, xss: 7,
      'account takeover': 10, 'sql injection': 9, 'auth bypass': 9
    };
    const basePriority = goalPriorities[memory.goal.toLowerCase()] || 5;

    intelligence.endpoints.filter(e => e.riskLevel === 'high').forEach(endpoint => {
      memory.priorityQueue.push({
        id: `task-${Date.now()}-${Math.random()}`,
        action: 'test_endpoint',
        target: endpoint.url,
        priority: basePriority + 2,
        reasoning: `High-risk endpoint for ${memory.goal}`,
        expectedPayoff: basePriority * 1000
      });
    });

    intelligence.vulnerabilities.forEach(vuln => {
      if (vuln.confidence > 0.7) {
        memory.priorityQueue.push({
          id: `task-${Date.now()}-${Math.random()}`,
          action: 'validate_vulnerability',
          target: vuln.location,
          priority: vuln.severity === 'critical' ? 10 : vuln.severity === 'high' ? 9 : 7,
          reasoning: `Validate ${vuln.type} (${vuln.severity})`,
          expectedPayoff: vuln.cvss ? vuln.cvss * 1000 : 5000
        });
      }
    });

    memory.priorityQueue.sort((a, b) => b.priority - a.priority);
  }

  recordAction(missionId: string, action: ActionRecord) {
    const memory = this.missions.get(missionId);
    if (!memory) return;
    memory.actionHistory.push(action);
    if (!action.success) {
      this.emit('action:failed', { missionId, action });
    }
  }

  getTopPriority(missionId: string): PriorityTask | undefined {
    return this.missions.get(missionId)?.priorityQueue[0];
  }

  getAllPriorities(missionId: string): PriorityTask[] {
    return this.missions.get(missionId)?.priorityQueue || [];
  }

  getBeliefs(missionId: string): Belief[] {
    return this.missions.get(missionId)?.beliefs || [];
  }
}

export const reasoningEngine = new ReasoningEngine();
