import { Agent, AgentType } from './types';

export class AgentRegistry {
  private agents: Map<string, Agent> = new Map();

  register(agent: Agent): void {
    this.agents.set(agent.id, agent);
  }

  get(agentId: string): Agent | null {
    return this.agents.get(agentId) || null;
  }

  getByHunt(huntId: string): Agent[] {
    return Array.from(this.agents.values()).filter(a => a.huntId === huntId);
  }

  getByType(huntId: string, type: AgentType): Agent[] {
    return Array.from(this.agents.values()).filter(
      a => a.huntId === huntId && a.type === type
    );
  }

  updateStatus(agentId: string, status: Agent['status']): void {
    const agent = this.agents.get(agentId);
    if (agent) {
      agent.status = status;
      agent.lastActivity = new Date();
    }
  }

  recordInvocation(agentId: string, success: boolean): void {
    const agent = this.agents.get(agentId);
    if (!agent) return;

    agent.invocations++;
    if (success) {
      agent.successCount++;
    } else {
      agent.errorCount++;
    }
    agent.lastActivity = new Date();
  }

  updateClaims(agentId: string, targets: string[]): void {
    const agent = this.agents.get(agentId);
    if (agent) {
      agent.claimedTargets = targets;
      agent.lastActivity = new Date();
    }
  }

  allIdle(huntId: string): boolean {
    const agents = this.getByHunt(huntId);
    return agents.every(a => a.status === 'idle' || a.status === 'stopped');
  }

  stopAll(huntId: string): void {
    const agents = this.getByHunt(huntId);
    agents.forEach(a => {
      a.status = 'stopped';
      a.lastActivity = new Date();
    });
  }

  remove(agentId: string): void {
    this.agents.delete(agentId);
  }

  getStats(huntId: string): {
    total: number;
    byType: Record<string, number>;
    byStatus: Record<string, number>;
    totalInvocations: number;
    successRate: number;
  } {
    const agents = this.getByHunt(huntId);

    const byType: Record<string, number> = {};
    const byStatus: Record<string, number> = {};
    let totalInvocations = 0;
    let totalSuccess = 0;

    agents.forEach(a => {
      byType[a.type] = (byType[a.type] || 0) + 1;
      byStatus[a.status] = (byStatus[a.status] || 0) + 1;
      totalInvocations += a.invocations;
      totalSuccess += a.successCount;
    });

    return {
      total: agents.length,
      byType,
      byStatus,
      totalInvocations,
      successRate: totalInvocations > 0 ? totalSuccess / totalInvocations : 0
    };
  }
}

export const agentRegistry = new AgentRegistry();
