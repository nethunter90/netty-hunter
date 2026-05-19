import { huntOrchestrator } from '../orchestration/layer1-hunt-orchestrator';
import { metaReasoner } from './meta-reasoning';
import { backwardPlanner } from './backward-planner';
import { decisionTraceLogger, huntMetricsCollector } from './decision-trace';
import { labScorer } from './lab-profiles';
import { huntCortex } from './hunt-cortex';
import { adaptiveThresholdTuner } from './adaptive-threshold-tuner';

export interface LabHuntResult {
  huntId: string;
  profileId: string;
  goal: string;
  startedAt: number;
  completedAt?: number;
  status: 'running' | 'completed' | 'timeout' | 'error';
  metrics?: any;
  trace?: any[];
  error?: string;
}

export interface LabBatchResult {
  profileId: string;
  runs: LabHuntResult[];
  summary: {
    avgCoverage: number;
    avgPivotEfficiency: number;
    totalFindings: number;
    huntCount: number;
  };
}

export interface DeterminismResult {
  profileId: string;
  goal: string;
  iterations: number;
  top3Stability: number;
  rankDistribution: Map<string, number[]>;
  isDeterministic: boolean;
  varianceDetails: { pathId: string; ranks: number[]; stddev: number }[];
}

export interface PivotRegretAnalysis {
  pivotIndex: number;
  timestamp: number;
  fromStrategy: string;
  toStrategy: string;
  confidenceAtPivot: number;
  counterfactualFindings: number;
  actualFindings: number;
  regretScore: number;
  classification: 'correct_time_correct_vector' | 'correct_time_wrong_vector' | 'wrong_time_correct_vector' | 'wrong_time_wrong_vector';
  insight: string;
}

export class HuntLabRunner {
  async runHunt(profileId: string, goalOverride?: string, options?: { stealthMode?: string; resourceClass?: string }): Promise<LabHuntResult> {
    const profile = labScorer.getProfile(profileId);
    if (!profile) {
      return {
        huntId: '',
        profileId,
        goal: goalOverride || '',
        startedAt: Date.now(),
        status: 'error',
        error: `Profile not found: ${profileId}`,
      };
    }

    let goal = goalOverride;
    if (!goal) {
      const sorted = [...profile.expectedGoalRankings].sort((a, b) => a.expectedRank - b.expectedRank);
      goal = sorted.length > 0 ? sorted[0].goal : 'reconnaissance';
    }

    const stealthMode = (options?.stealthMode || 'balanced') as any;
    const resourceClass = (options?.resourceClass || (profile.targetCharacteristics.complexity < 0.4 ? 'lightweight' : 'standard')) as any;

    const hunt = await huntOrchestrator.createHunt({
      target: profile.targetUrl,
      goal,
      scope: { inScope: [profile.targetUrl], outOfScope: [] },
      autoAdvance: true,
      stealthMode,
      resourceClass,
    });

    const huntId = hunt.id;

    metaReasoner.initializeHuntState(huntId);

    await decisionTraceLogger.recordEvent({
      huntId,
      eventType: 'hunt_start',
      sourceSystem: 'hunt-lab-runner',
      data: {
        profileId,
        profileName: profile.name,
        targetUrl: profile.targetUrl,
        targetCharacteristics: profile.targetCharacteristics,
        goal,
        totalChallenges: profile.totalChallenges,
      },
      confidenceAtEvent: 1.0,
      reasoning: `Lab hunt started against ${profile.name} (${profile.targetUrl}) with goal '${goal}'`,
    });

    backwardPlanner.planHunt(huntId, goal, profile.targetCharacteristics);

    await this.waitForTarget(profile.targetUrl, 30000);

    await huntOrchestrator.startHunt(huntId);

    metaReasoner.startMonitoring(huntId);

    return {
      huntId,
      profileId,
      goal,
      startedAt: Date.now(),
      status: 'running',
    };
  }

  async awaitHuntCompletion(huntId: string, timeoutMs?: number): Promise<LabHuntResult> {
    const timeout = timeoutMs || 30 * 60 * 1000;
    const pollInterval = 5000;
    const startTime = Date.now();

    return new Promise<LabHuntResult>((resolve) => {
      const check = () => {
        const hunt = huntOrchestrator.getHunt(huntId);

        if (!hunt) {
          metaReasoner.stopMonitoring(huntId);
          resolve({
            huntId,
            profileId: '',
            goal: '',
            startedAt: startTime,
            status: 'error',
            error: `Hunt not found: ${huntId}`,
          });
          return;
        }

        if (hunt.status === 'completed') {
          metaReasoner.stopMonitoring(huntId);
          const trace = decisionTraceLogger.getTrace(huntId);
          const metrics = huntMetricsCollector.computeMetrics(huntId);
          resolve({
            huntId,
            profileId: '',
            goal: hunt.goal,
            startedAt: hunt.startedAt.getTime(),
            completedAt: Date.now(),
            status: 'completed',
            metrics,
            trace,
          });
          return;
        }

        if (Date.now() - startTime >= timeout) {
          metaReasoner.stopMonitoring(huntId);
          const trace = decisionTraceLogger.getTrace(huntId);
          const metrics = huntMetricsCollector.computeMetrics(huntId);
          resolve({
            huntId,
            profileId: '',
            goal: hunt.goal,
            startedAt: hunt.startedAt.getTime(),
            completedAt: Date.now(),
            status: 'timeout',
            metrics,
            trace,
          });
          return;
        }

        setTimeout(check, pollInterval);
      };

      check();
    });
  }

  private async waitForTarget(url: string, timeoutMs: number): Promise<void> {
    const start = Date.now();
    const pollInterval = 1000;

    while (Date.now() - start < timeoutMs) {
      try {
        const response = await fetch(url, { signal: AbortSignal.timeout(3000) });
        if (response.ok || response.status < 500) {
          console.log(`[HuntLabRunner] Target ${url} is reachable (${response.status})`);
          return;
        }
      } catch {
      }
      await new Promise(resolve => setTimeout(resolve, pollInterval));
    }

    console.warn(`[HuntLabRunner] Target ${url} not reachable after ${timeoutMs}ms, proceeding anyway`);
  }

  resetState(huntId: string): void {
  }

  async runBatch(profileId: string, count: number, goals?: string[]): Promise<LabBatchResult> {
    const profile = labScorer.getProfile(profileId);
    const runs: LabHuntResult[] = [];

    let goalList: string[] = [];
    if (goals && goals.length > 0) {
      goalList = goals;
    } else if (profile) {
      goalList = [...profile.expectedGoalRankings]
        .sort((a, b) => a.expectedRank - b.expectedRank)
        .map((g) => g.goal);
    }

    for (let i = 0; i < count; i++) {
      const goal = goalList.length > 0 ? goalList[i % goalList.length] : undefined;
      const result = await this.runHunt(profileId, goal);

      if (result.status === 'error') {
        runs.push(result);
        continue;
      }

      const completed = await this.awaitHuntCompletion(result.huntId);
      completed.profileId = profileId;
      runs.push(completed);

      this.resetState(result.huntId);
    }

    let totalCoverage = 0;
    let totalPivotEfficiency = 0;
    let totalFindings = 0;
    let metricsCount = 0;

    for (const run of runs) {
      if (run.metrics) {
        totalCoverage += run.metrics.coverageRatio || 0;
        totalPivotEfficiency += run.metrics.pivotEfficiencyRatio || 0;
        totalFindings += (run.trace || []).filter((e: any) => e.eventType === 'finding_confirmed').length;
        metricsCount++;
      }
    }

    return {
      profileId,
      runs,
      summary: {
        avgCoverage: metricsCount > 0 ? totalCoverage / metricsCount : 0,
        avgPivotEfficiency: metricsCount > 0 ? totalPivotEfficiency / metricsCount : 0,
        totalFindings,
        huntCount: runs.length,
      },
    };
  }

  checkDeterminism(profileId: string, iterations?: number): DeterminismResult {
    const n = iterations || 10;
    const profile = labScorer.getProfile(profileId);

    if (!profile) {
      return {
        profileId,
        goal: '',
        iterations: n,
        top3Stability: 0,
        rankDistribution: new Map(),
        isDeterministic: false,
        varianceDetails: [],
      };
    }

    const sorted = [...profile.expectedGoalRankings].sort((a, b) => a.expectedRank - b.expectedRank);
    const goal = sorted.length > 0 ? sorted[0].goal : '';

    const allRuns: string[][] = [];
    const rankDistribution: Map<string, number[]> = new Map();

    for (let i = 0; i < n; i++) {
      const paths = backwardPlanner.getOptimalPath(goal, profile.targetCharacteristics);
      const pathIds = paths.map((p) => p.path.id);
      allRuns.push(pathIds);

      for (let rank = 0; rank < pathIds.length; rank++) {
        const pathId = pathIds[rank];
        if (!rankDistribution.has(pathId)) {
          rankDistribution.set(pathId, []);
        }
        rankDistribution.get(pathId)!.push(rank + 1);
      }
    }

    let stableCount = 0;
    if (allRuns.length > 0) {
      const referenceTop3 = allRuns[0].slice(0, 3);
      for (const run of allRuns) {
        const runTop3 = run.slice(0, 3);
        const same = referenceTop3.every((id) => runTop3.includes(id)) && runTop3.every((id) => referenceTop3.includes(id));
        if (same) stableCount++;
      }
    }
    const top3Stability = allRuns.length > 0 ? stableCount / allRuns.length : 0;

    const varianceDetails: { pathId: string; ranks: number[]; stddev: number }[] = [];
    const entries = Array.from(rankDistribution.entries());
    for (const entry of entries) {
      const pathId = entry[0];
      const ranks = entry[1];
      const mean = ranks.reduce((s: number, r: number) => s + r, 0) / ranks.length;
      const variance = ranks.reduce((s: number, r: number) => s + (r - mean) ** 2, 0) / ranks.length;
      const stddev = Math.sqrt(variance);
      varianceDetails.push({ pathId, ranks, stddev });
    }

    return {
      profileId,
      goal,
      iterations: n,
      top3Stability,
      rankDistribution,
      isDeterministic: top3Stability >= 0.9,
      varianceDetails,
    };
  }

  computePivotRegret(huntId: string, profileId: string): PivotRegretAnalysis[] {
    const trace = decisionTraceLogger.getTrace(huntId);
    const pivots = trace.filter((e) => e.eventType === 'meta_pivot');
    const findings = trace.filter((e) => e.eventType === 'finding_confirmed');
    const results: PivotRegretAnalysis[] = [];

    for (let i = 0; i < pivots.length; i++) {
      const pivot = pivots[i];
      const pivotTimestamp = pivot.timestamp;
      const nextPivotTimestamp = i + 1 < pivots.length ? pivots[i + 1].timestamp : Infinity;

      const fromStrategy = pivot.data.fromStrategy || pivot.data.from || 'unknown';
      const toStrategy = pivot.data.toStrategy || pivot.data.to || 'unknown';
      const confidenceAtPivot = pivot.confidenceAtEvent;

      const actualFindings = findings.filter(
        (f) => f.timestamp > pivotTimestamp && f.timestamp < nextPivotTimestamp
      ).length;

      let counterfactualFindings = 0;
      if (i > 0) {
        const prevPivotTimestamp = pivots[i - 1].timestamp;
        const windowLength = pivotTimestamp - prevPivotTimestamp;
        const prevWindowFindings = findings.filter(
          (f) => f.timestamp > prevPivotTimestamp && f.timestamp <= pivotTimestamp
        ).length;
        counterfactualFindings = prevWindowFindings;
      } else {
        const huntStart = trace.find((e) => e.eventType === 'hunt_start');
        const startTs = huntStart ? huntStart.timestamp : 0;
        counterfactualFindings = findings.filter(
          (f) => f.timestamp > startTs && f.timestamp <= pivotTimestamp
        ).length;
      }

      const regretScore = (counterfactualFindings - actualFindings) / Math.max(1, counterfactualFindings + actualFindings);

      let classification: PivotRegretAnalysis['classification'];
      let insight: string;

      if (actualFindings > 0 && regretScore <= 0) {
        classification = 'correct_time_correct_vector';
        insight = `Pivot from '${fromStrategy}' to '${toStrategy}' was well-timed and productive. Found ${actualFindings} finding(s) after pivot, outperforming the previous strategy.`;
      } else if (actualFindings > 0 && regretScore > 0) {
        classification = 'wrong_time_correct_vector';
        insight = `Pivot to '${toStrategy}' found ${actualFindings} finding(s), but the previous strategy '${fromStrategy}' was still producing results. Consider delaying this pivot in future runs.`;
      } else if (actualFindings === 0 && counterfactualFindings > 0) {
        classification = 'correct_time_wrong_vector';
        insight = `Pivoting away from '${fromStrategy}' was justified (it had ${counterfactualFindings} prior finding(s)), but '${toStrategy}' yielded nothing. Consider alternative pivot targets.`;
      } else {
        classification = 'wrong_time_wrong_vector';
        insight = `Pivot from '${fromStrategy}' to '${toStrategy}' was unproductive on both sides. Neither strategy produced findings in this window. Re-evaluate pivot trigger conditions.`;
      }

      results.push({
        pivotIndex: i,
        timestamp: pivotTimestamp,
        fromStrategy,
        toStrategy,
        confidenceAtPivot,
        counterfactualFindings,
        actualFindings,
        regretScore,
        classification,
        insight,
      });
    }

    return results;
  }
}

export const huntLabRunner = new HuntLabRunner();
