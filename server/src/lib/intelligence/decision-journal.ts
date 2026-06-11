import { pool } from '../../db';
import logger from '../../utils/logger';

export interface JournalEntry {
  id: string;
  huntId: string;
  strategyBefore: string;
  strategyAfter: string | null;
  action: string;
  rationale: string;
  healthSnapshot: Record<string, any>;
  contextVector: number[];
  findingsCount: number;
  cycleNumber: number;
  outcomeScore: number | null;
  createdAt: number;
}

class DecisionJournal {
  async log(entry: Omit<JournalEntry, 'id' | 'createdAt'>): Promise<void> {
    try {
      await pool.query(
        `INSERT INTO decision_journal (hunt_id, strategy_before, strategy_after, action, rationale, health_snapshot, context_vector, findings_count, cycle_number, outcome_score)
         VALUES ($1, $2, $3, $4, $5, $6, $7::real[], $8, $9, $10)`,
        [
          entry.huntId,
          entry.strategyBefore,
          entry.strategyAfter,
          entry.action,
          entry.rationale,
          JSON.stringify(entry.healthSnapshot),
          entry.contextVector,
          entry.findingsCount,
          entry.cycleNumber,
          entry.outcomeScore,
        ]
      );
    } catch (err) {
      logger.warn("[DecisionJournal] log() failed — journal entry lost", { err });
    }
  }

  async findSimilar(
    healthSnapshot: Record<string, any>,
    targetProfile: { complexityScore: number; volatilityScore: number; attackSurfaceBreadth: number },
    threshold: number = 0.80
  ): Promise<JournalEntry | null> {
    const queryVector = this.contextToVector(healthSnapshot, targetProfile);

    try {
      const result = await pool.query(
        `SELECT id, hunt_id, strategy_before, strategy_after, action, rationale, health_snapshot, context_vector, findings_count, cycle_number, outcome_score, created_at
         FROM decision_journal
         WHERE outcome_score >= 0.6
         ORDER BY outcome_score DESC
         LIMIT 50`
      );

      let bestEntry: JournalEntry | null = null;
      let bestSimilarity = -1;

      for (const row of result.rows) {
        const entryVector: number[] = row.context_vector || [];
        const similarity = this.cosineSimilarity(queryVector, entryVector);

        if (similarity > bestSimilarity && similarity >= threshold) {
          bestSimilarity = similarity;
          bestEntry = {
            id: row.id,
            huntId: row.hunt_id,
            strategyBefore: row.strategy_before,
            strategyAfter: row.strategy_after,
            action: row.action,
            rationale: row.rationale,
            healthSnapshot: row.health_snapshot || {},
            contextVector: entryVector,
            findingsCount: row.findings_count,
            cycleNumber: row.cycle_number,
            outcomeScore: row.outcome_score,
            createdAt: new Date(row.created_at).getTime(),
          };
        }
      }

      return bestEntry;
    } catch (err) {
      logger.debug("[DecisionJournal] findSimilar() failed", { err });
      return null;
    }
  }

  async backfillOutcomes(huntId: string, finalScore: number): Promise<void> {
    try {
      const result = await pool.query(
        `SELECT id, action, findings_count, cycle_number
         FROM decision_journal
         WHERE hunt_id = $1
         ORDER BY created_at ASC`,
        [huntId]
      );

      const entries = result.rows;

      for (let i = 0; i < entries.length; i++) {
        const entry = entries[i];
        let score: number;

        if (entry.action === 'pivot') {
          const findingsBefore = entry.findings_count;
          const findingsAfter = i + 1 < entries.length ? entries[i + 1].findings_count : findingsBefore;
          const gain = findingsAfter - findingsBefore;
          score = Math.min(1.0, finalScore * (0.5 + gain * 0.1));
        } else {
          score = finalScore * 0.8;
        }

        await pool.query(
          `UPDATE decision_journal SET outcome_score = $1 WHERE id = $2`,
          [score, entry.id]
        );
      }
    } catch (err) {
      logger.warn("[DecisionJournal] backfillOutcomes() failed — outcome scores not written", { huntId, err });
    }
  }

  contextToVector(
    health: Record<string, any>,
    profile?: { complexityScore: number; volatilityScore: number; attackSurfaceBreadth: number }
  ): number[] {
    return [
      health.avg_novelty_score || 0,
      (health.negative_evidence_count || 0) / 20,
      (health.degraded_verifications || 0) / 10,
      (health.missed_events || 0) / 5,
      health.health || 0.5,
      profile?.complexityScore || 0.5,
      profile?.volatilityScore || 0.5,
      profile?.attackSurfaceBreadth || 0.5,
    ];
  }

  cosineSimilarity(a: number[], b: number[]): number {
    if (a.length !== b.length) return 0;

    let dot = 0;
    let normA = 0;
    let normB = 0;

    for (let i = 0; i < a.length; i++) {
      dot += a[i] * b[i];
      normA += a[i] * a[i];
      normB += b[i] * b[i];
    }

    const denominator = Math.sqrt(normA) * Math.sqrt(normB);
    if (denominator === 0) return 0;

    return dot / denominator;
  }

  async getRecentEntries(huntId?: string, limit: number = 50): Promise<JournalEntry[]> {
    try {
      let query: string;
      let params: any[];

      if (huntId) {
        query = `SELECT id, hunt_id, strategy_before, strategy_after, action, rationale, health_snapshot, context_vector, findings_count, cycle_number, outcome_score, created_at
                 FROM decision_journal
                 WHERE hunt_id = $1
                 ORDER BY created_at DESC
                 LIMIT $2`;
        params = [huntId, limit];
      } else {
        query = `SELECT id, hunt_id, strategy_before, strategy_after, action, rationale, health_snapshot, context_vector, findings_count, cycle_number, outcome_score, created_at
                 FROM decision_journal
                 ORDER BY created_at DESC
                 LIMIT $1`;
        params = [limit];
      }

      const result = await pool.query(query, params);

      return result.rows.map((row: any) => ({
        id: row.id,
        huntId: row.hunt_id,
        strategyBefore: row.strategy_before,
        strategyAfter: row.strategy_after,
        action: row.action,
        rationale: row.rationale,
        healthSnapshot: row.health_snapshot || {},
        contextVector: row.context_vector || [],
        findingsCount: row.findings_count,
        cycleNumber: row.cycle_number,
        outcomeScore: row.outcome_score,
        createdAt: new Date(row.created_at).getTime(),
      }));
    } catch (err) {
      logger.debug("[DecisionJournal] getRecentEntries() failed", { err });
      return [];
    }
  }

  async getStats(): Promise<{
    totalEntries: number;
    scoredEntries: number;
    averageOutcome: number;
    pivotCount: number;
    huntCount: number;
  }> {
    try {
      const result = await pool.query(`
        SELECT
          COUNT(*)::int AS total_entries,
          COUNT(outcome_score)::int AS scored_entries,
          COALESCE(AVG(outcome_score), 0)::real AS average_outcome,
          COUNT(*) FILTER (WHERE action = 'pivot')::int AS pivot_count,
          COUNT(DISTINCT hunt_id)::int AS hunt_count
        FROM decision_journal
      `);

      const row = result.rows[0];
      return {
        totalEntries: row.total_entries,
        scoredEntries: row.scored_entries,
        averageOutcome: row.average_outcome,
        pivotCount: row.pivot_count,
        huntCount: row.hunt_count,
      };
    } catch (err) {
      logger.debug("[DecisionJournal] getStats() failed", { err });
      return {
        totalEntries: 0,
        scoredEntries: 0,
        averageOutcome: 0,
        pivotCount: 0,
        huntCount: 0,
      };
    }
  }
}

export const decisionJournal = new DecisionJournal();
