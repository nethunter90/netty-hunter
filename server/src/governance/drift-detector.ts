import { v4 as uuidv4 } from 'uuid';
import type { Pool } from 'pg';
import {
  GovernanceSnapshot,
  DriftAnalysis,
  GovernancePillar,
  GovernanceVerdict,
  RiskLevel
} from './types';
import { GOVERNANCE_PILLARS } from './pillars';

export class DriftDetector {
  private snapshots: GovernanceSnapshot[] = [];
  private configChanges: Array<{ timestamp: Date; change: string; severity: 'low' | 'medium' | 'high' | 'critical' }> = [];
  private snapshotInterval: ReturnType<typeof setInterval> | null = null;
  private snapshotProvider: (() => GovernanceSnapshot) | null = null;
  private postSnapshotCallback?: (snap: GovernanceSnapshot) => void;

  constructor() {}

  setSnapshotProvider(provider: () => GovernanceSnapshot): void {
    this.snapshotProvider = provider;
  }

  startAutoSnapshot(intervalMs: number = 300000): void {
    if (this.snapshotInterval) clearInterval(this.snapshotInterval);
    this.snapshotInterval = setInterval(() => {
      this.takeSnapshot();
    }, intervalMs);
  }

  stopAutoSnapshot(): void {
    if (this.snapshotInterval) {
      clearInterval(this.snapshotInterval);
      this.snapshotInterval = null;
    }
  }

  setPostSnapshotCallback(cb: (snap: GovernanceSnapshot) => void): void {
    this.postSnapshotCallback = cb;
  }

  async loadSnapshotsFromDB(dbPool: Pool): Promise<void> {
    try {
      const cutoff = new Date(Date.now() - 86_400_000).toISOString();
      const { rows } = await dbPool.query(
        `SELECT snapshot FROM governance_snapshots
         WHERE created_at > $1 ORDER BY created_at ASC`,
        [cutoff]
      );
      for (const row of rows) {
        this.snapshots.push(row.snapshot as GovernanceSnapshot);
      }
      if (this.snapshots.length > 1000) {
        this.snapshots = this.snapshots.slice(-500);
      }
    } catch {
      // DB may not be ready yet — non-critical
    }
  }

  takeSnapshot(): GovernanceSnapshot {
    if (this.snapshotProvider) {
      const snapshot = this.snapshotProvider();
      this.snapshots.push(snapshot);
      if (this.snapshots.length > 1000) {
        this.snapshots = this.snapshots.slice(-500);
      }
      this.postSnapshotCallback?.(snapshot);
      return snapshot;
    }

    const snapshot: GovernanceSnapshot = {
      id: uuidv4(),
      timestamp: new Date(),
      config: {
        realToolsMode: process.env.REAL_TOOLS === 'true',
        scopeEnforcement: true,
        autoStealth: true,
        pillarSensitivities: {} as Record<GovernancePillar, number>,
        agentPermissions: {}
      },
      verdicts: { approved: 0, modified: 0, blocked: 0, total: 0 },
      pillarActivity: {} as Record<GovernancePillar, number>,
      agentActivity: {},
      riskDistribution: { low: 0, medium: 0, high: 0, critical: 0 }
    };

    for (const [name, def] of Object.entries(GOVERNANCE_PILLARS)) {
      snapshot.config.pillarSensitivities[name as GovernancePillar] = def.sensitivity;
      snapshot.pillarActivity[name as GovernancePillar] = 0;
    }

    this.snapshots.push(snapshot);
    this.postSnapshotCallback?.(snapshot);
    return snapshot;
  }

  recordConfigChange(change: string, severity: 'low' | 'medium' | 'high' | 'critical'): void {
    this.configChanges.push({
      timestamp: new Date(),
      change,
      severity
    });
  }

  analyze(recentWindowMs: number = 3600000, baselineWindowMs: number = 86400000): DriftAnalysis {
    const now = new Date();
    const recentStart = new Date(now.getTime() - recentWindowMs);
    const baselineStart = new Date(now.getTime() - baselineWindowMs);

    const recentSnapshots = this.snapshots.filter(
      s => new Date(s.timestamp).getTime() >= recentStart.getTime()
    );
    const baselineSnapshots = this.snapshots.filter(
      s => new Date(s.timestamp).getTime() >= baselineStart.getTime() &&
           new Date(s.timestamp).getTime() < recentStart.getTime()
    );

    const recentVerdicts = this.aggregateVerdicts(recentSnapshots);
    const baselineVerdicts = this.aggregateVerdicts(baselineSnapshots);

    const blockRateChange = this.calculateRateChange(
      baselineVerdicts.blocked, baselineVerdicts.total,
      recentVerdicts.blocked, recentVerdicts.total
    );
    const modifyRateChange = this.calculateRateChange(
      baselineVerdicts.modified, baselineVerdicts.total,
      recentVerdicts.modified, recentVerdicts.total
    );
    const approveRateChange = this.calculateRateChange(
      baselineVerdicts.approved, baselineVerdicts.total,
      recentVerdicts.approved, recentVerdicts.total
    );

    const verdictDriftFlagged = Math.abs(blockRateChange) > 20 || Math.abs(approveRateChange) > 20;

    const pillarDrift: DriftAnalysis['pillarDrift'] = [];
    for (const pillarName of Object.keys(GOVERNANCE_PILLARS) as GovernancePillar[]) {
      const recentActivity = this.aggregatePillarActivity(recentSnapshots, pillarName);
      const baselineActivity = this.aggregatePillarActivity(baselineSnapshots, pillarName);
      const change = this.calculateRateChange(baselineActivity, 1, recentActivity, 1);
      pillarDrift.push({
        pillar: pillarName,
        activityChange: change,
        flagged: Math.abs(change) > 50
      });
    }

    const recentConfigChanges = this.configChanges.filter(
      c => c.timestamp.getTime() >= baselineStart.getTime()
    );

    const anomalies: string[] = [];
    if (blockRateChange < -30) {
      anomalies.push('Significant decrease in block rate - governance may be loosening');
    }
    if (approveRateChange > 30) {
      anomalies.push('Significant increase in approval rate - review pillar sensitivities');
    }
    if (recentConfigChanges.some(c => c.severity === 'critical')) {
      anomalies.push('Critical configuration changes detected in analysis window');
    }
    if (recentSnapshots.length === 0 && baselineSnapshots.length > 0) {
      anomalies.push('No recent governance activity - possible monitoring gap');
    }

    const driftFlagged = pillarDrift.filter(p => p.flagged);
    if (driftFlagged.length > 2) {
      anomalies.push(`${driftFlagged.length} pillars show significant activity drift`);
    }

    return {
      timestamp: now,
      recentPeriod: {
        start: recentStart,
        end: now,
        snapshots: recentSnapshots.length
      },
      baselinePeriod: {
        start: baselineStart,
        end: recentStart,
        snapshots: baselineSnapshots.length
      },
      verdictDrift: {
        blockRateChange,
        modifyRateChange,
        approveRateChange,
        flagged: verdictDriftFlagged
      },
      pillarDrift,
      configChanges: recentConfigChanges,
      anomalies
    };
  }

  private aggregateVerdicts(snapshots: GovernanceSnapshot[]): {
    approved: number; modified: number; blocked: number; total: number;
  } {
    const result = { approved: 0, modified: 0, blocked: 0, total: 0 };
    for (const s of snapshots) {
      result.approved += s.verdicts.approved;
      result.modified += s.verdicts.modified;
      result.blocked += s.verdicts.blocked;
      result.total += s.verdicts.total;
    }
    return result;
  }

  private aggregatePillarActivity(snapshots: GovernanceSnapshot[], pillar: GovernancePillar): number {
    let total = 0;
    for (const s of snapshots) {
      total += s.pillarActivity[pillar] || 0;
    }
    return total;
  }

  private calculateRateChange(
    baselineCount: number, baselineTotal: number,
    recentCount: number, recentTotal: number
  ): number {
    const baselineRate = baselineTotal > 0 ? (baselineCount / baselineTotal) * 100 : 0;
    const recentRate = recentTotal > 0 ? (recentCount / recentTotal) * 100 : 0;
    return recentRate - baselineRate;
  }

  getSnapshots(limit?: number): GovernanceSnapshot[] {
    const results = [...this.snapshots].reverse();
    return limit ? results.slice(0, limit) : results;
  }

  getStats(): {
    totalSnapshots: number;
    configChanges: number;
    autoSnapshotActive: boolean;
  } {
    return {
      totalSnapshots: this.snapshots.length,
      configChanges: this.configChanges.length,
      autoSnapshotActive: this.snapshotInterval !== null
    };
  }
}
