import { pool } from '../../db';

export interface ThresholdSet {
  noveltyFloor: number;
  healthFloor: number;
  maxDegraded: number;
  maxMissedEvents: number;
  stalenessTtlBase: number;
  eventDecayHalflife: number;
}

const DEFAULT_THRESHOLDS: ThresholdSet = {
  noveltyFloor: 0.1,
  healthFloor: 0.3,
  maxDegraded: 3,
  maxMissedEvents: 2,
  stalenessTtlBase: 600,
  eventDecayHalflife: 900,
};

class AdaptiveThresholdTuner {
  async getThresholds(targetType: string): Promise<ThresholdSet> {
    try {
      const result = await pool.query(
        `SELECT thresholds FROM threshold_history WHERE target_type = $1 LIMIT 1`,
        [targetType]
      );

      if (result.rows.length > 0) {
        return result.rows[0].thresholds as ThresholdSet;
      }

      return { ...DEFAULT_THRESHOLDS };
    } catch (_err) {
      return { ...DEFAULT_THRESHOLDS };
    }
  }

  async learnFromHunt(huntId: string, targetType: string, finalScore: number): Promise<void> {
    try {
      const pivotResult = await pool.query(
        `SELECT outcome_score, cycle_number
         FROM decision_journal
         WHERE hunt_id = $1 AND action = 'pivot'
         ORDER BY created_at ASC`,
        [huntId]
      );

      const thresholds = await this.getThresholds(targetType);

      for (const row of pivotResult.rows) {
        const outcomeScore = row.outcome_score;
        const cycleNumber = row.cycle_number;

        if (outcomeScore !== null && outcomeScore < 0.4) {
          thresholds.noveltyFloor *= 0.85;
          thresholds.healthFloor *= 0.9;
        }

        if (outcomeScore !== null && outcomeScore > 0.8 && cycleNumber > 10) {
          thresholds.noveltyFloor *= 1.1;
        }
      }

      thresholds.noveltyFloor = Math.min(0.3, Math.max(0.02, thresholds.noveltyFloor));
      thresholds.healthFloor = Math.min(0.6, Math.max(0.1, thresholds.healthFloor));

      await pool.query(
        `INSERT INTO threshold_history (target_type, thresholds, hunt_count, updated_at)
         VALUES ($1, $2, 1, now())
         ON CONFLICT (target_type) DO UPDATE
         SET thresholds = $2, hunt_count = threshold_history.hunt_count + 1, updated_at = now()`,
        [targetType, JSON.stringify(thresholds)]
      );
    } catch (_err) {}
  }

  async getTargetStats(): Promise<Array<{
    targetType: string;
    thresholds: ThresholdSet;
    huntCount: number;
    updatedAt: number;
  }>> {
    try {
      const result = await pool.query(
        `SELECT target_type, thresholds, hunt_count, updated_at FROM threshold_history`
      );

      return result.rows.map((row: any) => ({
        targetType: row.target_type,
        thresholds: row.thresholds as ThresholdSet,
        huntCount: row.hunt_count,
        updatedAt: new Date(row.updated_at).getTime(),
      }));
    } catch (_err) {
      return [];
    }
  }

  async resetThresholds(targetType: string): Promise<void> {
    try {
      await pool.query(
        `DELETE FROM threshold_history WHERE target_type = $1`,
        [targetType]
      );
    } catch (_err) {}
  }
}

export const adaptiveThresholdTuner = new AdaptiveThresholdTuner();
