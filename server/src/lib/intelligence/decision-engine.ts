import { EventEmitter } from 'events';
import { reasoningEngine, PriorityTask, MissionMemory } from './reasoning-engine';

export interface Decision {
  id: string;
  missionId: string;
  timestamp: string;
  chosenAction: ProposedAction;
  alternatives: ProposedAction[];
  confidence: number;
  reasoning: string[];
}

export interface ProposedAction {
  tool: string;
  target: string;
  parameters: Record<string, unknown>;
  expectedOutcome: string;
  confidence: number;
  estimatedTime: number;
  riskLevel: 'low' | 'medium' | 'high';
}

export class DecisionEngine extends EventEmitter {
  async makeDecision(missionId: string): Promise<Decision> {
    const memory = reasoningEngine.getMissionMemory(missionId);
    if (!memory) throw new Error('Mission not found');

    const priorities = reasoningEngine.getAllPriorities(missionId).slice(0, 5);
    const proposals = this.generateProposals(memory.goal, priorities);

    const scored = proposals
      .map(p => ({ ...p, confidence: this.calculateConfidence(p, memory) }))
      .sort((a, b) => b.confidence - a.confidence);

    const decision: Decision = {
      id: `decision-${Date.now()}`,
      missionId,
      timestamp: new Date().toISOString(),
      chosenAction: scored[0],
      alternatives: scored.slice(1, 3),
      confidence: scored[0]?.confidence ?? 0,
      reasoning: scored[0] ? this.generateReasoning(scored[0], memory) : []
    };

    this.emit('decision:made', decision);
    return decision;
  }

  private generateProposals(goal: string, priorities: PriorityTask[]): ProposedAction[] {
    const proposals: ProposedAction[] = [];

    const goalTools: Record<string, string[]> = {
      rce: ['nuclei', 'nikto'],
      sqli: ['sqlmap', 'nuclei'],
      'sql injection': ['sqlmap', 'nuclei'],
      xss: ['nuclei'],
      ssrf: ['nuclei', 'ffuf'],
      idor: ['ffuf'],
      'auth bypass': ['nuclei'],
      'account takeover': ['nuclei', 'ffuf']
    };

    const tools = goalTools[goal.toLowerCase()] || ['nuclei'];

    for (const priority of priorities) {
      for (const tool of tools) {
        proposals.push({
          tool,
          target: priority.target,
          parameters: this.getToolParams(tool, goal),
          expectedOutcome: priority.reasoning,
          confidence: 0.7,
          estimatedTime: this.estimateTime(tool),
          riskLevel: this.assessRisk(tool)
        });
      }
    }

    return proposals;
  }

  private getToolParams(tool: string, goal: string): Record<string, unknown> {
    const params: Record<string, Record<string, unknown>> = {
      sqlmap: { flags: '--batch --risk=1' },
      nuclei: { templates: goal.toLowerCase().replace(/\s+/g, '') },
      nikto: { flags: '-Tuning 1' },
      ffuf: { wordlist: '/usr/share/wordlists/common.txt' }
    };
    return params[tool] || {};
  }

  private estimateTime(tool: string): number {
    const times: Record<string, number> = {
      sqlmap: 300, nuclei: 180, nikto: 240, ffuf: 60
    };
    return times[tool] || 120;
  }

  private assessRisk(tool: string): 'low' | 'medium' | 'high' {
    const risks: Record<string, 'low' | 'medium' | 'high'> = {
      sqlmap: 'high', hydra: 'high', nuclei: 'medium', nikto: 'medium', ffuf: 'low'
    };
    return risks[tool] || 'medium';
  }

  private calculateConfidence(action: ProposedAction, memory: MissionMemory): number {
    let confidence = 0.7;
    if (memory.discoveredTechnologies.size > 0) confidence += 0.1;
    if (action.riskLevel === 'high') confidence -= 0.1;
    return Math.min(1, Math.max(0, confidence));
  }

  private generateReasoning(action: ProposedAction, memory: MissionMemory): string[] {
    return [
      `Testing ${action.target} for ${memory.goal}`,
      `Using ${action.tool} based on discovered intelligence`,
      `Expected outcome: ${action.expectedOutcome}`,
      `Confidence: ${(action.confidence * 100).toFixed(0)}%`
    ];
  }
}

export const decisionEngine = new DecisionEngine();
