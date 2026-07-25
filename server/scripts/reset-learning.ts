import "dotenv/config";
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
 *     autonomy_metrics (Brier / reinforcement-noise / autonomy), and the
 *     learning-schema raw tables decision_journal, threshold_history,
 *     cortex_signals (if present). From reinforcement_store, only the RL/ROI
 *     domains (see RL_DOMAINS below) — NOT the whole table.
 *   Only with --include-findings — also: findings.
 *
 * Rationale: learning data is contaminated across engine configs (e.g. vision was
 * removed), and lab/test runs should not bleed into a clean baseline between batches.
 *
 * 2026-07-23 readiness handoff fix: reinforcement_store also holds a
 * completely unrelated `settings` domain (live API tokens/usernames written
 * by routes/settings.ts — HACKERONE_TOKEN, etc.) and a `strategy_transitions`
 * domain that shares the table but is written by strategy-weight-learner.ts,
 * not UnifiedReinforcementStore. The old version of this script ran an
 * unconditional `DELETE FROM reinforcement_store`, which would have silently
 * destroyed those credentials alongside the RL wipe — verified live (8
 * `settings`-domain rows exist in this DB right now). This version deletes
 * an explicit RL_DOMAINS allowlist via `WHERE domain = ANY($1)` instead of
 * the whole table, so `settings` (and any future non-RL domain) survives by
 * construction, not by a maintainer remembering a `!=` exclusion.
 */
import { pool } from "../src/db";

const args = process.argv.slice(2);
const CONFIRM = args.includes("--confirm");
const INCLUDE_FINDINGS = args.includes("--include-findings");

// Order matters: child rows before parents to respect FK constraints.
const CHILD_TABLES = [
  "solver_results",
  "exploit_chains",
  "mission_memory_snapshots",
  "autonomy_metrics",
  "decision_journal",
  "threshold_history",
  "cortex_signals",
];

// Every RL/ROI domain living in reinforcement_store, per
// intelligence/ReinforcementStore.ts's RLDomain type plus
// strategy-weight-learner.ts's out-of-band "strategy_transitions" domain.
// Deliberately explicit and reviewable — do NOT replace with "everything
// except settings"; a new non-RL domain added later must be opted IN here,
// not opted out of a blocklist.
const RL_DOMAINS = [
  "tool_success",
  "framework_vuln",
  "program_type",
  "confidence_calibration",
  "exploration",
  "model_selection",
  "waf_evasion_technique",
  "payload_mutation_technique",
  "strategy_transitions",
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

async function wipeRlDomains(): Promise<number | null> {
  if (!(await tableExists("reinforcement_store"))) return null;
  const r = await pool.query(
    `DELETE FROM "reinforcement_store" WHERE domain = ANY($1::text[])`,
    [RL_DOMAINS],
  );
  return r.rowCount ?? 0;
}

async function main() {
  const targets = [
    ...(INCLUDE_FINDINGS ? ["findings"] : []),
    ...CHILD_TABLES,
    `reinforcement_store (domains: ${RL_DOMAINS.join(", ")} — "settings" and any other non-RL domain preserved)`,
    "hunt_sessions",
  ];

  console.log("\nreset-learning — will DELETE:");
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

  for (const t of CHILD_TABLES) summary.push({ table: t, deleted: (await wipe(t)) ?? "—(absent)" });
  summary.push({ table: "reinforcement_store (RL domains only)", deleted: (await wipeRlDomains()) ?? "—(absent)" });
  summary.push({ table: "hunt_sessions", deleted: (await wipe("hunt_sessions")) ?? "—(absent)" });

  console.log("Wiped:");
  for (const s of summary) console.log(`  ${s.table.padEnd(40)} ${s.deleted}`);
  console.log("\nDone. Learning/calibration baseline reset. settings-domain rows in reinforcement_store were left untouched.\n");

  await pool.end();
}

main().catch(async (err) => {
  console.error("reset-learning failed:", err.message);
  await pool.end().catch(() => {});
  process.exit(1);
});
