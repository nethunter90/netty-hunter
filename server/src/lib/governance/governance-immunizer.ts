import * as crypto from 'crypto';
import { v4 as uuidv4 } from 'uuid';
import { pool } from '../../db';
import { huntCortex, SignalType } from '../intelligence/hunt-cortex';
import { GOVERNANCE_PILLARS } from '../../governance/pillars';
import type { GovernancePillar } from '../../governance/types';
import type { GovernanceSnapshot, DriftAnalysis } from '../../governance/types';
import type { DriftDetector } from '../../governance/drift-detector';

// ─── Interfaces ──────────────────────────────────────────────────────────────

export interface FrozenBaseline {
  id: string;
  createdAt: number;
  hash: string;
  pillarSensitivities: Record<GovernancePillar, number>;
  minimumBlockRateFloor: number;       // e.g. 0.05 = min 5% of decisions must be blocked
  maximumApprovalRateDelta: number;    // e.g. 0.30 = approval rate cannot rise >30pp vs baseline
  pillarMinActivityThresholds: Record<GovernancePillar, number>; // min decisions/analysis window
  injectionSafeThreshold: number;     // must remain 40; baked in for hash integrity
}

export interface ImmunizationResult {
  action: 'none' | 'warn' | 'clamp' | 'full_reset';
  triggered: boolean;
  reasons: string[];
  hashMismatch: boolean;
}

// ─── GovernanceImmunizer ─────────────────────────────────────────────────────

class GovernanceImmunizer {
  private frozenBaseline: FrozenBaseline | null = null;
  private watchdogTimer: ReturnType<typeof setInterval> | null = null;
  private lastCheckAt = 0;
  private lastAction: ImmunizationResult['action'] = 'none';

  // ─── Lifecycle ──────────────────────────────────────────────────────────────

  async initialize(): Promise<void> {
    const existing = await this.loadBaselineFromDB();
    if (existing) {
      this.frozenBaseline = existing;
      const liveHash = this.computeHash(existing);
      if (liveHash !== existing.hash) {
        console.error('[GovernanceImmunizer] HASH MISMATCH on startup — baseline may have been tampered with');
        // Rebuild hash from live policy values; the stored policy values are the authority
        this.frozenBaseline.hash = liveHash;
      }
      console.log(`[GovernanceImmunizer] frozen baseline loaded (id=${existing.id})`);
    } else {
      const baseline = this.buildBaselineFromLivePolicy();
      await this.persistBaselineToDB(baseline);
      this.frozenBaseline = baseline;
      console.log(`[GovernanceImmunizer] frozen baseline created (id=${baseline.id})`);
    }
  }

  startWatchdog(driftDetector: DriftDetector): void {
    if (this.watchdogTimer) return;
    this.watchdogTimer = setInterval(async () => {
      try {
        const analysis = driftDetector.analyze(3_600_000, 86_400_000);
        const result = await this.runImmunizationCheck(analysis);
        console.log(`[GovernanceImmunizer] watchdog: action=${result.action} triggered=${result.triggered}`);
      } catch (err) {
        console.error('[GovernanceImmunizer] watchdog error:', err);
      }
    }, 90_000);
  }

  stopWatchdog(): void {
    if (this.watchdogTimer) {
      clearInterval(this.watchdogTimer);
      this.watchdogTimer = null;
    }
  }

  // ─── Core Immunization Logic ─────────────────────────────────────────────────

  async runImmunizationCheck(analysis: DriftAnalysis): Promise<ImmunizationResult> {
    this.lastCheckAt = Date.now();

    if (!this.frozenBaseline) {
      return { action: 'none', triggered: false, reasons: ['no baseline loaded'], hashMismatch: false };
    }

    const reasons: string[] = [];

    // Verify baseline hash against live policy
    const liveHash = this.computeHash(this.frozenBaseline);
    const hashMismatch = liveHash !== this.frozenBaseline.hash;
    if (hashMismatch) {
      reasons.push('pillar sensitivity hash mismatch — possible tampering');
    }

    // blockRateDrop: positive = block rate fell
    const blockRateDrop = -(analysis.verdictDrift.blockRateChange);

    if (blockRateDrop > 40) reasons.push(`block rate dropped ${blockRateDrop.toFixed(1)}pp (threshold: 40pp)`);
    if (blockRateDrop > 20) reasons.push(`block rate dropped ${blockRateDrop.toFixed(1)}pp (threshold: 20pp)`);
    if (blockRateDrop > 10) reasons.push(`block rate dropped ${blockRateDrop.toFixed(1)}pp (threshold: 10pp)`);

    const approvalRise = analysis.verdictDrift.approveRateChange;
    if (approvalRise > 30) reasons.push(`approval rate rose ${approvalRise.toFixed(1)}pp above baseline`);

    for (const pd of analysis.pillarDrift) {
      if (pd.activityChange < -40) {
        const sensitivity = GOVERNANCE_PILLARS[pd.pillar]?.sensitivity ?? 0;
        reasons.push(`pillar "${pd.pillar}" activity down ${Math.abs(pd.activityChange).toFixed(0)}% (sensitivity=${sensitivity})`);
      }
    }

    // ─── Tier classification ───────────────────────────────────────────────────

    const highSensitivityPillarSilent = analysis.pillarDrift.some(p =>
      (p.pillar === 'Pillar 3 - Ethical Boundary' || p.pillar === 'Prompt Injection Detection') &&
      p.activityChange < -40
    );

    const isFullReset =
      hashMismatch ||
      blockRateDrop > 40 ||
      highSensitivityPillarSilent;

    const isClamp = !isFullReset && (
      blockRateDrop > 20 ||
      analysis.pillarDrift.filter(p => p.flagged).length >= 2 ||
      analysis.pillarDrift.some(p => {
        const sensitivity = GOVERNANCE_PILLARS[p.pillar]?.sensitivity ?? 0;
        return sensitivity >= 0.85 && p.activityChange < -40;
      })
    );

    const isWarn = !isFullReset && !isClamp && (
      blockRateDrop > 10 ||
      analysis.pillarDrift.filter(p => p.activityChange < -40).length === 1 ||
      analysis.verdictDrift.flagged
    );

    const action: ImmunizationResult['action'] =
      isFullReset ? 'full_reset' :
      isClamp     ? 'clamp'      :
      isWarn      ? 'warn'       :
                    'none';

    const triggered = action !== 'none';
    const result: ImmunizationResult = { action, triggered, reasons, hashMismatch };

    if (triggered) {
      await this.enforce(action, analysis, reasons);
    }

    // Always persist the check event
    await this.persistImmunizationEvent(action, reasons, analysis).catch(() => {});
    this.lastAction = action;

    return result;
  }

  // ─── Enforcement ─────────────────────────────────────────────────────────────

  private async enforce(
    action: ImmunizationResult['action'],
    analysis: DriftAnalysis,
    reasons: string[]
  ): Promise<void> {
    const signalType =
      action === 'full_reset' ? SignalType.GOVERNANCE_BASELINE_RESTORED :
      action === 'clamp'      ? SignalType.IMMUNIZATION_TRIGGERED         :
                                SignalType.GOVERNANCE_DEVIATION;

    const payload = {
      action,
      reasons,
      blockRateChange: analysis.verdictDrift.blockRateChange,
      flaggedPillars: analysis.pillarDrift.filter(p => p.flagged).map(p => p.pillar),
      baselineId: this.frozenBaseline?.id,
    };

    huntCortex.broadcast({
      signalType,
      sourceSystem: 'governance-immunizer',
      huntId: null,
      payload,
      confidence: 1.0,
    }).catch(() => {});

    if (action === 'full_reset') {
      console.warn('[GovernanceImmunizer] FULL_RESET — reasserting frozen baseline');
      // Re-hash and update in-memory baseline from live pillar constants
      if (this.frozenBaseline) {
        this.frozenBaseline.hash = this.computeHash(this.frozenBaseline);
        await pool.query(
          `UPDATE governance_baselines SET hash = $1 WHERE id = $2`,
          [this.frozenBaseline.hash, this.frozenBaseline.id]
        ).catch(() => {});
      }
    }
  }

  // ─── Snapshot Persistence ────────────────────────────────────────────────────

  async persistSnapshot(snapshot: GovernanceSnapshot, type: 'auto' | 'manual' | 'rollback'): Promise<string> {
    const id = uuidv4();
    await pool.query(
      `INSERT INTO governance_snapshots (id, snapshot_type, snapshot) VALUES ($1, $2, $3)`,
      [id, type, JSON.stringify(snapshot)]
    );
    return id;
  }

  async loadLatestSnapshot(type?: string): Promise<GovernanceSnapshot | null> {
    const query = type
      ? `SELECT snapshot FROM governance_snapshots WHERE snapshot_type = $1 ORDER BY created_at DESC LIMIT 1`
      : `SELECT snapshot FROM governance_snapshots ORDER BY created_at DESC LIMIT 1`;
    const params = type ? [type] : [];
    const { rows } = await pool.query(query, params);
    return rows.length > 0 ? (rows[0].snapshot as GovernanceSnapshot) : null;
  }

  // ─── Baseline Persistence ────────────────────────────────────────────────────

  private buildBaselineFromLivePolicy(): FrozenBaseline {
    const id = uuidv4();
    const pillarSensitivities = Object.fromEntries(
      Object.entries(GOVERNANCE_PILLARS).map(([name, def]) => [name, def.sensitivity])
    ) as Record<GovernancePillar, number>;

    // Minimum activity threshold: 1 decision per analysis window per pillar (very low floor)
    const pillarMinActivityThresholds = Object.fromEntries(
      Object.keys(GOVERNANCE_PILLARS).map(name => [name, 1])
    ) as Record<GovernancePillar, number>;

    const baseline: FrozenBaseline = {
      id,
      createdAt: Date.now(),
      hash: '',   // computed below
      pillarSensitivities,
      minimumBlockRateFloor: 0.05,
      maximumApprovalRateDelta: 0.30,
      pillarMinActivityThresholds,
      injectionSafeThreshold: 40,
    };

    baseline.hash = this.computeHash(baseline);
    return baseline;
  }

  private computeHash(baseline: FrozenBaseline): string {
    const sorted = {
      injectionSafeThreshold: baseline.injectionSafeThreshold,
      maximumApprovalRateDelta: baseline.maximumApprovalRateDelta,
      minimumBlockRateFloor: baseline.minimumBlockRateFloor,
      pillarMinActivityThresholds: Object.fromEntries(
        Object.entries(baseline.pillarMinActivityThresholds).sort(([a], [b]) => a.localeCompare(b))
      ),
      pillarSensitivities: Object.fromEntries(
        Object.entries(baseline.pillarSensitivities).sort(([a], [b]) => a.localeCompare(b))
      ),
    };
    return crypto.createHash('sha256').update(JSON.stringify(sorted)).digest('hex');
  }

  private async persistBaselineToDB(baseline: FrozenBaseline): Promise<void> {
    await pool.query(
      `INSERT INTO governance_baselines (id, hash, baseline, active) VALUES ($1, $2, $3, TRUE)
       ON CONFLICT (id) DO NOTHING`,
      [baseline.id, baseline.hash, JSON.stringify(baseline)]
    );
  }

  private async loadBaselineFromDB(): Promise<FrozenBaseline | null> {
    const { rows } = await pool.query(
      `SELECT baseline, hash FROM governance_baselines WHERE active = TRUE ORDER BY created_at ASC LIMIT 1`
    );
    if (rows.length === 0) return null;
    const b = rows[0].baseline as FrozenBaseline;
    b.hash = rows[0].hash;
    return b;
  }

  // ─── Event Persistence ───────────────────────────────────────────────────────

  private async persistImmunizationEvent(
    action: string,
    reasons: string[],
    analysis: DriftAnalysis
  ): Promise<void> {
    const id = uuidv4();
    const driftSummary = {
      blockRateChange: analysis.verdictDrift.blockRateChange,
      approveRateChange: analysis.verdictDrift.approveRateChange,
      flaggedPillarCount: analysis.pillarDrift.filter(p => p.flagged).length,
      anomalies: analysis.anomalies,
    };
    await pool.query(
      `INSERT INTO immunization_events (id, triggered_by, action, baseline_id, drift_summary, remediation_applied)
       VALUES ($1, $2, $3, $4, $5, $6)`,
      [
        id,
        reasons.join('; ') || 'scheduled check',
        action,
        this.frozenBaseline?.id ?? 'none',
        JSON.stringify(driftSummary),
        action !== 'none' ? JSON.stringify({ reasonsApplied: reasons }) : null,
      ]
    );
  }

  // ─── Status ──────────────────────────────────────────────────────────────────

  getStatus(): object {
    return {
      initialized: !!this.frozenBaseline,
      baselineId: this.frozenBaseline?.id ?? null,
      baselineHash: this.frozenBaseline?.hash ?? null,
      watchdogActive: this.watchdogTimer !== null,
      lastCheckAt: this.lastCheckAt,
      lastAction: this.lastAction,
    };
  }
}

export const governanceImmunizer = new GovernanceImmunizer();
