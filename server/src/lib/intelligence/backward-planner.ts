import {
  ATTACK_PATHS,
  GOAL_PAYOUT_DATA,
  HUNT_GOAL_PATHS,
  PIVOT_PLAYBOOKS,
  AttackPath,
  PivotStrategy,
  GoalPayoutData,
} from './seed-knowledge';
import { decisionTraceLogger } from './decision-trace';

export interface HuntPlan {
  huntId: string;
  goal: string;
  rankedPaths: RankedAttackPath[];
  currentPathIndex: number;
  phases: { name: string; actions: string[] }[];
  currentPhaseIndex: number;
  startedAt: number;
  pivotHistory: { from: string; to: string; reason: string; timestamp: number }[];
  status: 'planning' | 'executing' | 'pivoting' | 'completed' | 'aborted';
}

export interface RankedAttackPath {
  path: AttackPath;
  expectedValue: number;
  adjustedLikelihood: number;
  rank: number;
}

export interface ProgramContext {
  programId: string;
  programAge: number;
  reportCount: number;
  scopeChangeDays?: number;
  noveltyFloor: number;
}

const VULN_COMMONALITY: Record<string, number> = {
  'xss': 0.95,
  'cross-site scripting': 0.95,
  'sqli': 0.85,
  'sql injection': 0.85,
  'csrf': 0.80,
  'idor': 0.70,
  'open-redirect': 0.75,
  'ssrf': 0.40,
  'ssti': 0.25,
  'xxe': 0.30,
  'rce': 0.15,
  'remote code execution': 0.15,
  'lfi': 0.50,
  'rfi': 0.35,
  'auth-bypass': 0.55,
  'authentication bypass': 0.55,
  'cmdi': 0.20,
  'command injection': 0.20,
};

export class BackwardPlanner {
  private plans: Map<string, HuntPlan> = new Map();

  private computeDuplicateProbability(vulnType: string, programContext: ProgramContext): number {
    const ageFactor = Math.min(1 - Math.exp(-programContext.programAge / 90), 0.95);
    const normalizedVuln = vulnType.toLowerCase().replace(/\s+/g, ' ');
    let vulnCommonality = 0.50;
    for (const [key, value] of Object.entries(VULN_COMMONALITY)) {
      if (normalizedVuln.includes(key)) {
        vulnCommonality = Math.max(vulnCommonality, value);
      }
    }
    const reportVolumeFactor = Math.min(programContext.reportCount / 500, 1.0);
    return ageFactor * 0.3 + vulnCommonality * 0.4 + reportVolumeFactor * 0.3;
  }

  planHunt(
    huntId: string,
    goal: string,
    targetProfile?: { complexity: number; wafDetected: boolean; cloudHosted: boolean; authRequired: boolean },
    programContext?: ProgramContext
  ): HuntPlan {
    const rankedPaths = this.getOptimalPath(goal, targetProfile, programContext);

    const goalKey = goal.toLowerCase().replace(/\s+/g, '_');
    const goalPath = HUNT_GOAL_PATHS.find(
      (p) => p.goal === goalKey || p.goal.toLowerCase() === goal.toLowerCase()
    );
    const phases = goalPath
      ? goalPath.phases.map((p) => ({ name: p.name, actions: [...p.actions] }))
      : [{ name: 'reconnaissance', actions: ['enumerate target', 'identify attack surface'] }];

    const plan: HuntPlan = {
      huntId,
      goal,
      rankedPaths,
      currentPathIndex: 0,
      phases,
      currentPhaseIndex: 0,
      startedAt: Date.now(),
      pivotHistory: [],
      status: 'executing',
    };

    this.plans.set(huntId, plan);
    decisionTraceLogger.recordEvent({
      huntId,
      eventType: 'planner_ranking',
      sourceSystem: 'backward-planner',
      data: { goal, rankedPaths: rankedPaths.map(r => ({ pathId: r.path.id, vulnerability: r.path.vulnerability, ev: r.expectedValue, rank: r.rank })), totalPaths: rankedPaths.length },
      confidenceAtEvent: rankedPaths.length > 0 ? rankedPaths[0].adjustedLikelihood : 0,
      reasoning: `Backward planner ranked ${rankedPaths.length} paths for goal '${goal}'. Top path: ${rankedPaths[0]?.path.vulnerability || 'none'} (EV: $${rankedPaths[0]?.expectedValue || 0})`,
    }).catch(() => {});
    return plan;
  }

  getOptimalPath(
    goal: string,
    targetProfile?: { complexity: number; wafDetected: boolean; cloudHosted: boolean; authRequired: boolean },
    programContext?: ProgramContext
  ): RankedAttackPath[] {
    const paths = ATTACK_PATHS.filter(
      (p) => p.goal.toLowerCase() === goal.toLowerCase()
    );

    const ranked: RankedAttackPath[] = [];

    for (const path of paths) {
      let adjustedLikelihood = path.likelihood;

      if (targetProfile) {
        if (targetProfile.wafDetected) {
          const injectionTypes = ['sql injection', 'xss', 'injection', 'ssti'];
          if (injectionTypes.some((t) => path.vulnerability.toLowerCase().includes(t))) {
            adjustedLikelihood *= 0.5;
          }
        }

        if (targetProfile.cloudHosted) {
          const cloudBoosted = ['ssrf', 'cloud', 'metadata'];
          if (cloudBoosted.some((t) => path.vulnerability.toLowerCase().includes(t))) {
            adjustedLikelihood *= 1.3;
          }
        }

        if (targetProfile.authRequired) {
          const authRelated = ['auth', 'session', 'oauth', '2fa', 'password'];
          if (authRelated.some((t) => path.vulnerability.toLowerCase().includes(t))) {
            adjustedLikelihood *= 1.2;
          }
        }

        if (targetProfile.complexity > 0.7) {
          adjustedLikelihood *= 0.8;
        } else if (targetProfile.complexity < 0.3) {
          adjustedLikelihood *= 1.2;
        }

        adjustedLikelihood = Math.min(1, Math.max(0, adjustedLikelihood));
      }

      let expectedValue = adjustedLikelihood * path.avgPayout;

      if (programContext) {
        const dupeProb = this.computeDuplicateProbability(path.vulnerability, programContext);
        const discoveryProbability = 1 - dupeProb;
        if (discoveryProbability < programContext.noveltyFloor) {
          continue;
        }
        expectedValue = expectedValue * discoveryProbability;
      }

      ranked.push({
        path,
        expectedValue,
        adjustedLikelihood,
        rank: 0,
      });
    }

    ranked.sort((a, b) => b.expectedValue - a.expectedValue);
    ranked.forEach((r, i) => {
      r.rank = i + 1;
    });

    return ranked;
  }

  getCurrentPhase(huntId: string): { name: string; actions: string[] } | null {
    const plan = this.plans.get(huntId);
    if (!plan || plan.currentPhaseIndex >= plan.phases.length) {
      return null;
    }
    return plan.phases[plan.currentPhaseIndex];
  }

  advancePhase(huntId: string): { name: string; actions: string[] } | null {
    const plan = this.plans.get(huntId);
    if (!plan) return null;

    plan.currentPhaseIndex++;
    if (plan.currentPhaseIndex >= plan.phases.length) {
      plan.status = 'completed';
      return null;
    }

    return plan.phases[plan.currentPhaseIndex];
  }

  suggestPivot(huntId: string, deadEndCondition: string): PivotStrategy[] | null {
    const plan = this.plans.get(huntId);
    if (!plan) return null;

    const playbook = PIVOT_PLAYBOOKS.find(
      (p) => p.condition === deadEndCondition
    );
    if (!playbook) return null;

    const sortedPivots = [...playbook.pivots].sort((a, b) => b.weight - a.weight);

    const currentPath = plan.rankedPaths[plan.currentPathIndex];
    const fromName = currentPath ? currentPath.path.vulnerability : plan.goal;

    plan.pivotHistory.push({
      from: fromName,
      to: sortedPivots[0]?.strategy || deadEndCondition,
      reason: deadEndCondition,
      timestamp: Date.now(),
    });

    plan.status = 'pivoting';

    decisionTraceLogger.recordEvent({
      huntId,
      eventType: 'phase_advance',
      sourceSystem: 'backward-planner',
      data: { deadEndCondition, topPivot: sortedPivots[0]?.strategy, pivotCount: sortedPivots.length },
      confidenceAtEvent: 0.5,
      reasoning: `Backward planner pivot: dead-end '${deadEndCondition}', suggesting '${sortedPivots[0]?.strategy}'`,
    }).catch(() => {});

    return sortedPivots;
  }

  getExpectedValue(goal: string): { goal: string; avgPayout: number; topPath: string; topPathEV: number; totalPaths: number } {
    const goalData = GOAL_PAYOUT_DATA.find(
      (g) => g.goal.toLowerCase() === goal.toLowerCase()
    );
    const avgPayout = goalData ? goalData.avgPayout : 0;

    const ranked = this.getOptimalPath(goal);
    const topPath = ranked.length > 0 ? ranked[0].path.vulnerability : 'none';
    const topPathEV = ranked.length > 0 ? ranked[0].expectedValue : 0;

    return {
      goal,
      avgPayout,
      topPath,
      topPathEV,
      totalPaths: ranked.length,
    };
  }

  getAllGoalEVs(): { goal: string; avgPayout: number; topPathEV: number }[] {
    const results = GOAL_PAYOUT_DATA.map((goalData) => {
      const ranked = this.getOptimalPath(goalData.goal);
      const topPathEV = ranked.length > 0 ? ranked[0].expectedValue : 0;

      return {
        goal: goalData.goal,
        avgPayout: goalData.avgPayout,
        topPathEV,
      };
    });

    results.sort((a, b) => b.topPathEV - a.topPathEV);
    return results;
  }

  getPlan(huntId: string): HuntPlan | null {
    return this.plans.get(huntId) || null;
  }

  completePlan(huntId: string): void {
    const plan = this.plans.get(huntId);
    if (plan) {
      plan.status = 'completed';
    }
  }

  abortPlan(huntId: string, reason: string): void {
    const plan = this.plans.get(huntId);
    if (plan) {
      plan.status = 'aborted';
      plan.pivotHistory.push({
        from: plan.rankedPaths[plan.currentPathIndex]?.path.vulnerability || plan.goal,
        to: 'aborted',
        reason,
        timestamp: Date.now(),
      });
    }
  }

  getStats(): { activePlans: number; completedPlans: number; totalPivots: number } {
    let activePlans = 0;
    let completedPlans = 0;
    let totalPivots = 0;

    const plans = Array.from(this.plans.values());
    for (const plan of plans) {
      if (plan.status === 'executing' || plan.status === 'pivoting' || plan.status === 'planning') {
        activePlans++;
      } else if (plan.status === 'completed') {
        completedPlans++;
      }
      totalPivots += plan.pivotHistory.length;
    }

    return { activePlans, completedPlans, totalPivots };
  }
}

export const backwardPlanner = new BackwardPlanner();
