import { EventEmitter } from 'events';
import { reasoningEngine, PriorityTask, MissionMemory } from './reasoning-engine';
import { circuitBreaker } from './circuit-breaker';

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
  parameters: any;
  expectedOutcome: string;
  confidence: number;
  estimatedTime: number;
  riskLevel: 'low' | 'medium' | 'high';
}

export class DecisionEngine extends EventEmitter {
  private decisionHistory: Decision[] = [];

  async makeDecision(missionId: string): Promise<Decision> {
    const memory = reasoningEngine.getMissionMemory(missionId);
    if (!memory) {
      throw new Error('Mission not found in reasoning engine');
    }

    const priorities = reasoningEngine.getAllPriorities(missionId).slice(0, 5);
    const proposals = this.generateProposals(memory.goal, priorities);

    const scored = proposals.map(p => ({
      ...p,
      confidence: this.calculateConfidence(p, memory)
    }));

    scored.sort((a, b) => b.confidence - a.confidence);

    if (scored.length === 0) {
      // Default scan when nothing was proposed — but don't default onto a tool
      // whose circuit is open (that's how the hunt got stuck re-picking nuclei).
      const defaultTool = ['nuclei', 'nmap', 'ffuf', 'nikto'].find(t => circuitBreaker.isAvailable(t)) || 'nuclei';
      scored.push({
        tool: defaultTool,
        target: memory.target,
        parameters: this.getToolParams(defaultTool, memory.goal),
        expectedOutcome: 'General vulnerability scan',
        confidence: 0.5,
        estimatedTime: this.estimateTime(defaultTool),
        riskLevel: this.assessRisk(defaultTool)
      });
    }

    // Circuit-breaker awareness: drop tools whose circuit is OPEN from the
    // candidate set BEFORE choosing. The breaker is the execution layer's guard;
    // making it an INPUT to the decision stops the Brain from re-selecting a dead
    // tool every cycle and relying on a post-hoc fallback swap (the nuclei loop:
    // [Brain] Decision: nuclei → ... immediately after its circuit opened). If
    // every candidate is open we keep the original ranking and let the execution
    // layer's canExecute() fallback handle it, rather than deadlock with no action.
    const available = scored.filter(p => circuitBreaker.isAvailable(p.tool));
    const usable = available.length > 0 ? available : scored;

    const decision: Decision = {
      id: `decision-${Date.now()}-${Math.random().toString(36).substr(2, 6)}`,
      missionId,
      timestamp: new Date().toISOString(),
      chosenAction: usable[0],
      alternatives: usable.slice(1, 3),
      confidence: usable[0].confidence,
      reasoning: this.generateReasoning(usable[0], memory)
    };

    this.decisionHistory.push(decision);
    if (this.decisionHistory.length > 500) {
      this.decisionHistory = this.decisionHistory.slice(-250);
    }

    this.emit('decision:made', decision);

    return decision;
  }

  private generateProposals(goal: string, priorities: PriorityTask[]): ProposedAction[] {
    const proposals: ProposedAction[] = [];

    const goalTools: Record<string, string[]> = {
      'RCE': ['nuclei', 'nikto', 'nmap'],
      'SQL Injection': ['sqlmap', 'nuclei', 'ffuf'],
      'XSS': ['nuclei', 'ffuf', 'nikto'],
      'SSRF': ['nuclei', 'ffuf', 'nmap'],
      'IDOR': ['ffuf', 'nuclei'],
      'Auth Bypass': ['hydra', 'nuclei', 'ffuf'],
      'Account Takeover': ['hydra', 'nuclei', 'ffuf'],
      'API Security': ['nuclei', 'ffuf', 'nmap']
    };

    const tools = goalTools[goal] || ['nuclei', 'nmap'];

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

    if (proposals.length === 0) {
      for (const tool of tools) {
        proposals.push({
          tool,
          target: 'target',
          parameters: this.getToolParams(tool, goal),
          expectedOutcome: `General ${goal} scan`,
          confidence: 0.5,
          estimatedTime: this.estimateTime(tool),
          riskLevel: this.assessRisk(tool)
        });
      }
    }

    return proposals;
  }

  private getToolParams(tool: string, goal: string): any {
    const params: Record<string, any> = {
      'sqlmap': { flags: '--batch --risk=1' },
      'nuclei': { templates: goal.toLowerCase().replace(/ /g, '') },
      'nikto': { flags: '-Tuning 1' },
      'ffuf': { wordlist: '/usr/share/wordlists/common.txt' },
      'hydra': { flags: '-V -f' },
      'nmap': { flags: '-sV -sC' }
    };
    return params[tool] || {};
  }

  private estimateTime(tool: string): number {
    const times: Record<string, number> = {
      'sqlmap': 300,
      'nuclei': 180,
      'nikto': 240,
      'ffuf': 60,
      'hydra': 120,
      'nmap': 90
    };
    return times[tool] || 120;
  }

  private assessRisk(tool: string): 'low' | 'medium' | 'high' {
    const risks: Record<string, 'low' | 'medium' | 'high'> = {
      'sqlmap': 'high',
      'hydra': 'high',
      'nuclei': 'medium',
      'nikto': 'medium',
      'ffuf': 'low',
      'nmap': 'low'
    };
    return risks[tool] || 'medium';
  }

  private calculateConfidence(action: ProposedAction, memory: MissionMemory): number {
    let confidence = 0.7;

    if (memory.discoveredTechnologies.size > 0) {
      confidence += 0.1;
    }

    if (memory.discoveredEndpoints.size > 3) {
      confidence += 0.05;
    }

    if (memory.discoveredVulnerabilities.size > 0) {
      confidence += 0.1;
    }

    if (action.riskLevel === 'high') {
      confidence -= 0.1;
    }

    const failedWithSameTool = memory.actionHistory.filter(
      a => a.tool === action.tool && !a.success
    ).length;
    confidence -= failedWithSameTool * 0.15;

    return Math.min(1, Math.max(0, confidence));
  }

  private generateReasoning(action: ProposedAction, memory: MissionMemory): string[] {
    const reasons: string[] = [];

    reasons.push(`Testing ${action.target} for ${memory.goal}`);
    reasons.push(`Using ${action.tool} based on discovered intelligence`);

    if (memory.discoveredTechnologies.size > 0) {
      const techs = Array.from(memory.discoveredTechnologies.keys()).slice(0, 3);
      reasons.push(`Known technologies: ${techs.join(', ')}`);
    }

    if (memory.discoveredVulnerabilities.size > 0) {
      reasons.push(`${memory.discoveredVulnerabilities.size} potential vulnerabilities identified`);
    }

    reasons.push(`Expected outcome: ${action.expectedOutcome}`);
    reasons.push(`Confidence: ${(action.confidence * 100).toFixed(0)}%`);
    reasons.push(`Estimated time: ${action.estimatedTime}s`);

    return reasons;
  }

  getDecisionHistory(missionId?: string): Decision[] {
    if (missionId) {
      return this.decisionHistory.filter(d => d.missionId === missionId);
    }
    return this.decisionHistory;
  }

  getStats(): {
    totalDecisions: number;
    averageConfidence: number;
    toolDistribution: Record<string, number>;
  } {
    const totalDecisions = this.decisionHistory.length;
    const averageConfidence = totalDecisions > 0
      ? this.decisionHistory.reduce((sum, d) => sum + d.confidence, 0) / totalDecisions
      : 0;

    const toolDistribution: Record<string, number> = {};
    this.decisionHistory.forEach(d => {
      toolDistribution[d.chosenAction.tool] = (toolDistribution[d.chosenAction.tool] || 0) + 1;
    });

    return { totalDecisions, averageConfidence, toolDistribution };
  }
}

export const decisionEngine = new DecisionEngine();
