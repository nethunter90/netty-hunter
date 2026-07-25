/**
 * CI import-guard for the RL provenance-segregation chokepoint.
 *
 * Every read/write of the `reinforcement_store` table's RL domains must go
 * through UnifiedReinforcementStore (server/src/intelligence/ReinforcementStore.ts),
 * whose private upsert()/get()/queryDomain() helpers are the only place a key
 * is prefixed with its lab/real/unknown provenance before touching the DB. A
 * raw Drizzle import of the `reinforcementStore` table, or a raw SQL string
 * naming `reinforcement_store`, used anywhere else silently reintroduces the
 * unsegregated-RL-pool bug this project spent real effort closing (see the
 * 2026-07-23 RL segregation handoff) — a chokepoint with a known bypass is
 * not a chokepoint.
 *
 * This script is NOT a general-purpose lint rule: it knows about a small,
 * explicit allowlist of files that legitimately touch reinforcement_store
 * outside the chokepoint class, each with a stated reason. Anything else
 * fails the build.
 *
 * Run: npx tsx scripts/check-rl-bypass.ts
 * Wired as a `pretest` hook so `npm test` always runs it first.
 */
import { readFileSync, readdirSync, statSync } from "fs";
import { join, relative } from "path";

const SRC_ROOT = join(__dirname, "..", "src");

// Files allowed to touch reinforcement_store directly. Adding to this list
// is a deliberate, reviewable decision — each entry states WHY it's safe.
const ALLOWLIST: Record<string, string> = {
  "intelligence/ReinforcementStore.ts":
    "the chokepoint itself — the only place the table is read/written directly, " +
    "and the only place a key is provenance-prefixed",
  "db/schema.ts":
    "declares the table; does not read or write it",
  "routes/settings.ts":
    "writes/reads the UNRELATED `settings` domain sharing this table (live API " +
    "tokens/usernames — HACKERONE_TOKEN, etc.), never the RL domains; " +
    "see scripts/reset-learning.ts's RL_DOMAINS allowlist for the same distinction",
  "lib/learning/strategy-weight-learner.ts":
    "confirmed read live during a hunt (MetaReasoner.loadLearnedWeights() at " +
    "boot and completeHunt() per-hunt, both in lib/intelligence/meta-reasoning.ts) " +
    "— fixed in the 2026-07-23 RL segregation handoff to join " +
    "decision_journal -> hunt_sessions -> campaigns -> programs and provenance-" +
    "prefix its own keys the same way UnifiedReinforcementStore does. Raw SQL is " +
    "used here (not the Drizzle-based UnifiedReinforcementStore API) because this " +
    "needs a 3-table JOIN that API doesn't expose — a reviewed, disclosed " +
    "exception, not a silent skip.",
  "scripts/reset-learning.ts":
    "the RL wipe utility itself — deletes by domain (RL_DOMAINS allowlist, " +
    "preserving `settings`), doesn't read/write individual RL entries",
};

const EXCLUDED_DIRS = new Set(["__tests__", "fixtures", "workspace", "node_modules"]);

// Drizzle import of the raw table binding, under either its schema.ts name
// (reinforcementStore) or a local alias (e.g. `as rlTable`, `as reinforcementTable`).
const SCHEMA_IMPORT_PATTERN = /import\s*\{[^}]*\breinforcementStore\b[^}]*\}\s*from\s*["'].*db\/schema["']/;

// Raw SQL string naming the table — covers both `pool.query(...)` (node-pg,
// no Drizzle types) and any hand-written SQL template mentioning the table.
const RAW_SQL_PATTERN = /reinforcement_store/;

function walk(dir: string, files: string[] = []): string[] {
  for (const entry of readdirSync(dir)) {
    if (EXCLUDED_DIRS.has(entry)) continue;
    const full = join(dir, entry);
    const stat = statSync(full);
    if (stat.isDirectory()) {
      walk(full, files);
    } else if (entry.endsWith(".ts") && !entry.endsWith(".d.ts")) {
      files.push(full);
    }
  }
  return files;
}

function main(): void {
  const violations: Array<{ file: string; reason: string }> = [];

  for (const absPath of walk(SRC_ROOT)) {
    const relPath = relative(SRC_ROOT, absPath).replace(/\\/g, "/");
    if (relPath in ALLOWLIST) continue;

    const content = readFileSync(absPath, "utf-8");

    if (SCHEMA_IMPORT_PATTERN.test(content)) {
      violations.push({ file: relPath, reason: "imports the raw reinforcementStore table from db/schema — use UnifiedReinforcementStore instead" });
      continue; // don't double-report the same file via the SQL-string check below
    }
    if (RAW_SQL_PATTERN.test(content)) {
      violations.push({ file: relPath, reason: "references the literal table name \"reinforcement_store\" (raw SQL?) — use UnifiedReinforcementStore instead" });
    }
  }

  if (violations.length > 0) {
    console.error("\n[check-rl-bypass] FAILED — raw reinforcement_store access found outside the RL provenance chokepoint:\n");
    for (const v of violations) {
      console.error(`  src/${v.file}\n    ${v.reason}`);
    }
    console.error(
      "\nEvery RL domain read/write must go through UnifiedReinforcementStore " +
      "(server/src/intelligence/ReinforcementStore.ts), which provenance-prefixes " +
      "every key before it touches the DB. If this file genuinely never reads/writes " +
      "an RL domain (e.g. it's a config table sharing the physical table under a " +
      "different domain), add it to the ALLOWLIST in scripts/check-rl-bypass.ts with " +
      "a one-line justification — do not silently ignore this.\n"
    );
    process.exit(1);
  }

  console.log(`[check-rl-bypass] OK — no raw reinforcement_store access outside the allowlist (${Object.keys(ALLOWLIST).length} files allowlisted).`);
}

main();
