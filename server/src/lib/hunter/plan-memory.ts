/**
 * PlanMemoryStore — lib/hunter singleton
 *
 * External plan storage outside the context window.
 * Stores multi-phase hunting plans and tracks phase advancement.
 */
import type { PlanPhase, PlanSummary } from './types';

const DEFAULT_PHASES: Omit<PlanPhase, 'outcomes' | 'startedAt' | 'completedAt'>[] = [
  { name: 'recon',       objective: 'Enumerate endpoints, technologies, and attack surface', status: 'pending' },
  { name: 'hypothesis',  objective: 'Generate ranked vulnerability hypotheses from recon data', status: 'pending' },
  { name: 'probe',       objective: 'Probe top-priority hypotheses with targeted tools', status: 'pending' },
  { name: 'exploit',     objective: 'Attempt exploitation of confirmed vulnerabilities', status: 'pending' },
  { name: 'verify',      objective: 'Run 4-layer verification pipeline on all findings', status: 'pending' },
  { name: 'report',      objective: 'Generate complete bug bounty reports', status: 'pending' },
];

class PlanMemoryStoreImpl {
  private plans: Map<string, PlanSummary> = new Map();

  private buildPlan(sessionId: string): PlanSummary {
    const phases: PlanPhase[] = DEFAULT_PHASES.map(p => ({ ...p, outcomes: [] }));
    const plan: PlanSummary = {
      sessionId,
      currentPhase:    null,
      phases,
      totalPhases:     phases.length,
      completedPhases: 0,
      startedAt:       Date.now(),
    };
    this.plans.set(sessionId, plan);
    return plan;
  }

  getPlanSummary(sessionId: string): PlanSummary | null {
    return this.plans.get(sessionId) ?? null;
  }

  ensurePlan(sessionId: string): PlanSummary {
    return this.plans.get(sessionId) ?? this.buildPlan(sessionId);
  }

  advancePhase(sessionId: string, outcomes: string[]): PlanPhase | null {
    const plan = this.ensurePlan(sessionId);

    // Complete current phase
    if (plan.currentPhase) {
      plan.currentPhase.status      = 'done';
      plan.currentPhase.outcomes    = outcomes;
      plan.currentPhase.completedAt = Date.now();
      plan.completedPhases         += 1;
    }

    // Find next pending phase
    const next = plan.phases.find(p => p.status === 'pending');
    if (!next) {
      plan.currentPhase = null;
      return null;
    }

    next.status    = 'active';
    next.startedAt = Date.now();
    plan.currentPhase = next;
    return next;
  }

  startPlan(sessionId: string): PlanPhase | null {
    const plan = this.ensurePlan(sessionId);
    return this.advancePhase(sessionId, []);
  }
}

export const planMemoryStore = new PlanMemoryStoreImpl();
