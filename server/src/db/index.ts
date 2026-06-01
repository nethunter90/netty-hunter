import { drizzle } from "drizzle-orm/node-postgres";
import { Pool } from "pg";
import * as schema from "./schema";

const pool = new Pool({
  connectionString: process.env.DATABASE_URL || "postgresql://postgres:password@localhost:5432/netty_hunter",
  max: 20,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 2000,
});

// Idempotent DDL for tables added after initial schema creation.
// Runs once on startup; safe to run multiple times.
pool.connect().then(client => {
  client.query(`
    CREATE TABLE IF NOT EXISTS mission_memory_snapshots (
      id SERIAL PRIMARY KEY,
      hunt_id VARCHAR(128) NOT NULL UNIQUE,
      snapshot JSONB NOT NULL DEFAULT '{}',
      updated_at TIMESTAMP NOT NULL DEFAULT NOW()
    );
    CREATE UNIQUE INDEX IF NOT EXISTS mission_memory_hunt_id_idx
      ON mission_memory_snapshots (hunt_id);
    ALTER TABLE programs ADD COLUMN IF NOT EXISTS schedule_interval INTEGER NOT NULL DEFAULT 0;
    CREATE TABLE IF NOT EXISTS governance_baselines (
      id VARCHAR(64) PRIMARY KEY,
      created_at TIMESTAMP NOT NULL DEFAULT NOW(),
      hash TEXT NOT NULL,
      baseline JSONB NOT NULL,
      active BOOLEAN NOT NULL DEFAULT TRUE
    );
    CREATE TABLE IF NOT EXISTS governance_snapshots (
      id VARCHAR(64) PRIMARY KEY,
      created_at TIMESTAMP NOT NULL DEFAULT NOW(),
      snapshot_type VARCHAR(20) NOT NULL,
      snapshot JSONB NOT NULL
    );
    CREATE INDEX IF NOT EXISTS gov_snapshots_created_at_idx ON governance_snapshots (created_at);
    CREATE TABLE IF NOT EXISTS immunization_events (
      id VARCHAR(64) PRIMARY KEY,
      timestamp TIMESTAMP NOT NULL DEFAULT NOW(),
      triggered_by TEXT NOT NULL,
      action VARCHAR(20) NOT NULL,
      baseline_id VARCHAR(64) NOT NULL,
      drift_summary JSONB NOT NULL,
      remediation_applied JSONB
    );
    CREATE TABLE IF NOT EXISTS egress_route_metrics (
      id VARCHAR(64) PRIMARY KEY,
      proxy_id VARCHAR(64) NOT NULL,
      target TEXT NOT NULL,
      success_count INTEGER NOT NULL DEFAULT 0,
      failure_count INTEGER NOT NULL DEFAULT 0,
      avg_latency_ms REAL NOT NULL DEFAULT 0,
      last_used_at TIMESTAMP,
      burned BOOLEAN NOT NULL DEFAULT FALSE,
      banned_until TIMESTAMP,
      CONSTRAINT egress_proxy_target_uniq UNIQUE (proxy_id, target)
    );
  `).catch(() => { /* non-critical: table may already exist */ })
    .finally(() => client.release());
}).catch(() => { /* DB not yet available; pool will retry on first real query */ });

export const db = drizzle(pool, { schema });
export { pool };
export * from "./schema";
