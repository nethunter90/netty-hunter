/**
 * reset-learning.ts — wipe stored hunts + reset learning/calibration baselines.
 *
 * Usage:
 *   npm run reset:learning -- --confirm                  (keeps findings)
 *   npm run reset:learning -- --confirm --include-findings
 *
 * Destructive. Requires --confirm. Prints a plan first, then per-table row counts.
 *
 * What it wipes:
 *   Always — past hunts + their derived rows, and accumulated learning stats:
 *     hunt_sessions, solver_results, exploit_chains, mission_memory_snapshots,
 *     reinforcement_store (RL + ROI share this), autonomy_metrics
 *     (Brier / reinforcement-noise / autonomy), and the learning-schema raw tables
 *     decision_journal, threshold_history, cortex_signals (if present).
 *   Only with --include-findings — also: findings.
 *
 * Rationale: learning data is contaminated across engine configs (e.g. vision was
 * removed), and lab/test runs should not bleed into a clean baseline between batches.
 */
import { pool } from "../src/db";

const args = process.argv.slice(2);
const CONFIRM = args.includes("--confirm");
const INCLUDE_FINDINGS = args.includes("--include-findings");

// Order matters: child rows before parents to respect FK constraints.
const ALWAYS_TABLES = [
  "solver_results",
  "exploit_chains",
  "mission_memory_snapshots",
  "reinforcement_store",
  "autonomy_metrics",
  "decision_journal",
  "threshold_history",
  "cortex_signals",
];

async function tableExists(name: string): Promise<boolean> {
  const r = await pool.query("SELECT to_regclass($1) AS reg", [`public.${name}`]);
  return r.rows[0]?.reg !== null;
}

async function wipe(name: string): Promise<number | null> {
  if (!(await tableExists(name))) return null;
  const r = await pool.query(`DELETE FROM "${name}"`);
  return r.rowCount ?? 0;
}

async function main() {
  const targets = [...(INCLUDE_FINDINGS ? ["findings"] : []), ...ALWAYS_TABLES, "hunt_sessions"];

  console.log("\nreset-learning — will DELETE ALL ROWS from:");
  for (const t of targets) console.log(`  • ${t}`);
  console.log(`\nfindings: ${INCLUDE_FINDINGS ? "DELETED (--include-findings)" : "PRESERVED"}`);

  if (!CONFIRM) {
    console.log("\nDry run. Re-run with --confirm to execute.\n");
    await pool.end();
    process.exit(0);
  }

  console.log("\nExecuting...\n");
  const summary: Array<{ table: string; deleted: number | string }> = [];

  if (INCLUDE_FINDINGS) {
    // findings references hunt_sessions — delete it before the sessions.
    summary.push({ table: "findings", deleted: (await wipe("findings")) ?? "—(absent)" });
  } else {
    // Keeping findings: sever the hunt_session FK so deleting hunt_sessions can't
    // violate the constraint. Findings retain program_id (their source tag) and
    // campaign_id; only the now-defunct session link is nulled.
    const r = await pool.query(`UPDATE findings SET hunt_session_id = NULL WHERE hunt_session_id IS NOT NULL`);
    console.log(`  (kept findings; detached ${r.rowCount ?? 0} from wiped sessions)\n`);
  }

  for (const t of ALWAYS_TABLES) summary.push({ table: t, deleted: (await wipe(t)) ?? "—(absent)" });
  summary.push({ table: "hunt_sessions", deleted: (await wipe("hunt_sessions")) ?? "—(absent)" });

  console.log("Wiped:");
  for (const s of summary) console.log(`  ${s.table.padEnd(26)} ${s.deleted}`);
  console.log("\nDone. Learning/calibration baseline reset.\n");

  await pool.end();
}

main().catch(async (err) => {
  console.error("reset-learning failed:", err.message);
  await pool.end().catch(() => {});
  process.exit(1);
});
