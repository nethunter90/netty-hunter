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
  `).catch(() => { /* non-critical: table may already exist */ })
    .finally(() => client.release());
}).catch(() => { /* DB not yet available; pool will retry on first real query */ });

export const db = drizzle(pool, { schema });
export { pool };
export * from "./schema";
