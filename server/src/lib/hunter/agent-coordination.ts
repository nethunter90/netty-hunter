/**
 * AgentCoordinationTracker — lib/hunter singleton
 *
 * Tracks the coordination state of the multi-agent system per session,
 * including agent roles, task states, and coordinator decision log.
 */
import type { AgentRole, AgentState, CoordinationDecision, CoordinationState } from './types';

const ALL_ROLES: AgentRole[] = [
  'coordinator',
  'hypothesis_agent',
  'probe_agent',
  'verify_agent',
  'report_agent',
];

class AgentCoordinationTrackerImpl {
  private states:    Map<string, CoordinationState>    = new Map();

  private buildInitialState(sessionId: string): CoordinationState {
    const now = Date.now();
    const agents: Record<AgentRole, AgentState> = {} as Record<AgentRole, AgentState>;
    for (const role of ALL_ROLES) {
      agents[role] = { role, status: 'idle', taskCount: 0, lastActiveAt: now };
    }
    return { sessionId, agents, decisions: [], phase: 'initializing', blockers: [] };
  }

  private ensure(sessionId: string): CoordinationState {
    if (!this.states.has(sessionId)) {
      this.states.set(sessionId, this.buildInitialState(sessionId));
    }
    return this.states.get(sessionId)!;
  }

  getCoordinationState(sessionId: string): CoordinationState | null {
    return this.states.get(sessionId) ?? null;
  }

  getCoordinatorDecisionLog(sessionId: string): CoordinationDecision[] {
    return this.states.get(sessionId)?.decisions ?? [];
  }

  // Called from hunter-engine event system
  updateAgentState(sessionId: string, role: AgentRole, update: Partial<AgentState>): void {
    const state = this.ensure(sessionId);
    Object.assign(state.agents[role], { ...update, lastActiveAt: Date.now() });
    if (update.status) state.agents[role].taskCount += 1;
  }

  recordDecision(sessionId: string, decision: Omit<CoordinationDecision, 'at'>): void {
    const state = this.ensure(sessionId);
    state.decisions.push({ ...decision, at: Date.now() });
    // Keep last 100 decisions
    if (state.decisions.length > 100) state.decisions.shift();
  }

  updatePhase(sessionId: string, phase: string): void {
    const state = this.ensure(sessionId);
    state.phase = phase;

    this.recordDecision(sessionId, {
      coordinatorAction: 'phase_transition',
      reason:            `Advancing to phase: ${phase}`,
      affectedAgents:    ALL_ROLES,
    });
  }

  addBlocker(sessionId: string, blocker: string): void {
    const state = this.ensure(sessionId);
    if (!state.blockers.includes(blocker)) state.blockers.push(blocker);
  }

  clearBlocker(sessionId: string, blocker: string): void {
    const state = this.ensure(sessionId);
    state.blockers = state.blockers.filter(b => b !== blocker);
  }

  // Simulate coordination state from a reasoning event (used by tests/manual triggers)
  simulateFromReasoningEvent(sessionId: string, eventType: string, data: unknown): void {
    const state = this.ensure(sessionId);

    if (eventType === 'hypothesis_generated') {
      state.agents['hypothesis_agent'].status      = 'busy';
      state.agents['hypothesis_agent'].currentTask  = 'Generating hypotheses';
      state.agents['hypothesis_agent'].taskCount   += 1;
      state.agents['hypothesis_agent'].lastActiveAt = Date.now();
      this.recordDecision(sessionId, {
        coordinatorAction: 'assign_hypothesis',
        reason:            'New hypothesis generation event received',
        affectedAgents:    ['hypothesis_agent'],
      });
    } else if (eventType === 'probe_started') {
      state.agents['probe_agent'].status      = 'busy';
      state.agents['probe_agent'].currentTask  = typeof data === 'object' && data !== null && 'endpoint' in data
        ? `Probing ${(data as { endpoint: string }).endpoint}` : 'Probing endpoint';
      state.agents['probe_agent'].taskCount   += 1;
      state.agents['probe_agent'].lastActiveAt = Date.now();
    } else if (eventType === 'finding_confirmed') {
      state.agents['verify_agent'].status      = 'busy';
      state.agents['verify_agent'].currentTask  = 'Verifying finding';
      state.agents['verify_agent'].taskCount   += 1;
      state.agents['verify_agent'].lastActiveAt = Date.now();
    } else if (eventType === 'report_started') {
      state.agents['report_agent'].status      = 'busy';
      state.agents['report_agent'].currentTask  = 'Generating report';
      state.agents['report_agent'].lastActiveAt = Date.now();
    } else if (eventType === 'phase_complete') {
      for (const role of ALL_ROLES) state.agents[role].status = 'idle';
    }
  }

  initializeSession(sessionId: string): void {
    this.states.set(sessionId, this.buildInitialState(sessionId));
    this.updatePhase(sessionId, 'recon');
  }
}

export const agentCoordinationTracker = new AgentCoordinationTrackerImpl();
