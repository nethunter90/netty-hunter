/**
 * Learning schema bootstrap.
 *
 * The cross-hunt learning subsystems (decision journal, adaptive threshold
 * tuner, strategy weight learner, hunt cortex) read and write three tables via
 * raw SQL. They were never added to the Drizzle schema, so every query silently
 * hit a missing relation and the learning loop stayed write-blocked.
 *
 * This creates the three tables with CREATE TABLE IF NOT EXISTS at startup,
 * mirroring the self-initializing pattern used by decision-trace.ts. Idempotent
 * and safe to call on every boot.
 */
import { pool } from '../../db';
import logger from '../../utils/logger';

let initialized = false;

export async function initLearningSchema(): Promise<void> {
  if (initialized) return;
  try {
    // Strategy-transition memory + counterfactual recall.
    await pool.query(`
      CREATE TABLE IF NOT EXISTS "decision_journal" (
        "id"              BIGSERIAL PRIMARY KEY,
        "hunt_id"         text NOT NULL,
        "strategy_before" text,
        "strategy_after"  text,
        "action"          text NOT NULL,
        "rationale"       text,
        "health_snapshot" jsonb NOT NULL DEFAULT '{}',
        "context_vector"  real[] NOT NULL DEFAULT '{}',
        "findings_count"  integer NOT NULL DEFAULT 0,
        "cycle_number"    integer NOT NULL DEFAULT 0,
        "outcome_score"   real,
        "created_at"      timestamp DEFAULT now()
      )
    `);
    await pool.query(`CREATE INDEX IF NOT EXISTS "decision_journal_hunt_idx" ON "decision_journal" ("hunt_id")`);
    await pool.query(`CREATE INDEX IF NOT EXISTS "decision_journal_outcome_idx" ON "decision_journal" ("outcome_score")`);

    // Per-target-type learned thresholds (novelty floor, health floor).
    await pool.query(`
      CREATE TABLE IF NOT EXISTS "threshold_history" (
        "target_type" text PRIMARY KEY,
        "thresholds"  jsonb NOT NULL DEFAULT '{}',
        "hunt_count"  integer NOT NULL DEFAULT 0,
        "updated_at"  timestamp DEFAULT now()
      )
    `);

    // Hunt cortex signal persistence (survives restart for windowed recall).
    await pool.query(`
      CREATE TABLE IF NOT EXISTS "cortex_signals" (
        "id"            varchar PRIMARY KEY,
        "signal_type"   text NOT NULL,
        "source_system" text NOT NULL,
        "hunt_id"       text,
        "payload"       jsonb NOT NULL DEFAULT '{}',
        "confidence"    real NOT NULL DEFAULT 0,
        "created_at"    timestamp DEFAULT now()
      )
    `);
    await pool.query(`CREATE INDEX IF NOT EXISTS "cortex_signals_created_idx" ON "cortex_signals" ("created_at")`);

    initialized = true;
    logger.info('[LearningSchema] decision_journal, threshold_history, cortex_signals ready');
  } catch (err) {
    // Non-fatal: learning degrades gracefully if the DB rejects DDL, but log it
    // loudly so the operator knows the flywheel is not persisting.
    logger.error('[LearningSchema] Failed to initialize learning tables — cross-hunt learning disabled', { err: String(err) });
    initialized = true;
  }
}
