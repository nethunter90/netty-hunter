import { pool } from '../../db';
import logger from '../../utils/logger';

const LEARNING_RATE = 0.1;
const DOMAIN = 'strategy_transitions';
const MIN_WEIGHT = 0.05;
const MAX_WEIGHT = 5.0;

class StrategyWeightLearner {
  async learn(): Promise<void> {
    try {
      const result = await pool.query(
        `SELECT strategy_before, strategy_after,
                AVG(outcome_score) AS avg_outcome,
                COUNT(*)::int      AS sample_count
         FROM decision_journal
         WHERE strategy_before IS NOT NULL
           AND strategy_after  IS NOT NULL
           AND outcome_score   IS NOT NULL
         GROUP BY strategy_before, strategy_after`
      );

      for (const row of result.rows) {
        const key = `${row.strategy_before}->${row.strategy_after}`;
        const avgOutcome: number = parseFloat(row.avg_outcome);
        const sampleCount: number = row.sample_count;

        const existing = await pool.query(
          `SELECT weight FROM reinforcement_store WHERE domain = $1 AND key = $2`,
          [DOMAIN, key]
        );

        const currentWeight = existing.rows.length > 0
          ? (existing.rows[0].weight as number)
          : 1.0;

        // Bayesian-style update: nudge current weight toward observed success rate
        const adjusted = currentWeight + avgOutcome * LEARNING_RATE * currentWeight;
        const clamped = Math.min(MAX_WEIGHT, Math.max(MIN_WEIGHT, adjusted));

        await pool.query(
          `INSERT INTO reinforcement_store
             (domain, key, value, success_count, total_count, weight, last_updated)
           VALUES ($1, $2, $3, $4, $5, $6, now())
           ON CONFLICT (domain, key) DO UPDATE
             SET value        = $3,
                 total_count  = reinforcement_store.total_count + $5,
                 weight       = $6,
                 last_updated = now()`,
          [
            DOMAIN,
            key,
            JSON.stringify({ avgOutcome, sampleCount }),
            Math.round(avgOutcome * sampleCount),
            sampleCount,
            clamped,
          ]
        );
      }
    } catch (err) {
      logger.warn("[StrategyWeightLearner] learn() failed — strategy weights not updated", { err });
    }
  }

  async loadWeights(): Promise<Map<string, number>> {
    const weights = new Map<string, number>();
    try {
      const result = await pool.query(
        `SELECT key, weight FROM reinforcement_store WHERE domain = $1`,
        [DOMAIN]
      );
      for (const row of result.rows) {
        weights.set(row.key as string, row.weight as number);
      }
    } catch (err) {
      logger.warn("[StrategyWeightLearner] loadWeights() failed — using hardcoded graph weights", { err });
    }
    return weights;
  }
}

export const strategyWeightLearner = new StrategyWeightLearner();
