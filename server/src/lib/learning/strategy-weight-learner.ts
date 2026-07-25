/**
 * PROVENANCE (2026-07-23 readiness handoff): decision_journal has no
 * programId of its own — huntId (text) is the hunt's sessionUuid, which
 * joins through hunt_sessions -> campaigns -> programs to reach platform.
 * Previously learn() aggregated across every hunt ever run with zero
 * program filter, and loadWeights() read the resulting global weights back
 * with none either — a second, undocumented contamination surface next to
 * the one closed in UnifiedReinforcementStore/ROIModel. Grouping now
 * includes platform per (strategy_before, strategy_after) pair; provenance
 * is derived from that platform via isCrossCampaignEligible() (the same
 * discriminator every other RL consumer uses, not a reimplementation) and
 * used as the same real::/lab::/unknown:: key prefix as everywhere else.
 * A row whose hunt_id doesn't join to any program (deleted session, bad
 * data) gets platform=null -> provenance "unknown", never silently "real".
 */
import { pool } from '../../db';
import logger from '../../utils/logger';
import { isCrossCampaignEligible } from '../hunter/custom-target-program';
import type { Provenance } from '../../intelligence/ReinforcementStore';

const LEARNING_RATE = 0.1;
const DOMAIN = 'strategy_transitions';
const MIN_WEIGHT = 0.05;
const MAX_WEIGHT = 5.0;

function resolveProvenanceFromPlatform(platform: string | null): Provenance {
  if (platform === null) return "unknown";
  return isCrossCampaignEligible({ platform }) ? "real" : "lab";
}

function prefixedKey(provenance: Provenance, key: string): string {
  return `${provenance}::${key}`;
}

class StrategyWeightLearner {
  async learn(): Promise<void> {
    try {
      const result = await pool.query(
        `SELECT dj.strategy_before, dj.strategy_after,
                p.platform         AS platform,
                AVG(dj.outcome_score) AS avg_outcome,
                COUNT(*)::int      AS sample_count
         FROM decision_journal dj
         LEFT JOIN hunt_sessions hs ON hs.session_uuid = dj.hunt_id
         LEFT JOIN campaigns     c  ON c.id = hs.campaign_id
         LEFT JOIN programs      p  ON p.id = c.program_id
         WHERE dj.strategy_before IS NOT NULL
           AND dj.strategy_after  IS NOT NULL
           AND dj.outcome_score   IS NOT NULL
         GROUP BY dj.strategy_before, dj.strategy_after, p.platform`
      );

      for (const row of result.rows) {
        const provenance = resolveProvenanceFromPlatform(row.platform ?? null);
        const rawKey = `${row.strategy_before}->${row.strategy_after}`;
        const key = prefixedKey(provenance, rawKey);
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
            JSON.stringify({ avgOutcome, sampleCount, provenance }),
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

  /** Provenance-gated read — a "real" hunt only ever loads real::-prefixed
   *  weights, exactly like every other RL read site. Falls back to the
   *  caller's hardcoded graph weights (empty map) on any resolution failure
   *  or absence of data, same as before this change. */
  async loadWeights(provenance: Provenance): Promise<Map<string, number>> {
    const weights = new Map<string, number>();
    try {
      const prefix = `${provenance}::`;
      const result = await pool.query(
        `SELECT key, weight FROM reinforcement_store WHERE domain = $1 AND key LIKE $2`,
        [DOMAIN, `${prefix}%`]
      );
      for (const row of result.rows) {
        const key = (row.key as string).slice(prefix.length);
        weights.set(key, row.weight as number);
      }
    } catch (err) {
      logger.warn("[StrategyWeightLearner] loadWeights() failed — using hardcoded graph weights", { err });
    }
    return weights;
  }
}

export const strategyWeightLearner = new StrategyWeightLearner();
