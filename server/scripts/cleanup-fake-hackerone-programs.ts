/**
 * cleanup-fake-hackerone-programs.ts — remove HackerOne programs that were
 * inserted with fabricated (not real) scope/rules by the sync-hackerone
 * fetch bug: every failed fetch (auth/handle/rate-limit) silently fell
 * through to generateFallbackScope()/generateFallbackRules(), producing
 * hundreds of rows identical except for the name (same 7 in-scope / 4
 * out-of-scope assets, same $10k/$100 bounty range, same 72h response time).
 *
 * fetchHackerOne() has since been fixed to log every failure instead of
 * swallowing it, and sync-hackerone now skips inserting a program rather
 * than storing fake data — but this does not retroactively clean up rows
 * a prior run already inserted. This script finds and (only with --confirm)
 * deletes those specific rows.
 *
 * Identification (all five must match). This narrows false positives hard,
 * but it is still a values match, not a cryptographic marker — a real
 * program could in principle happen to satisfy all five. Review the printed
 * list before passing --confirm.
 *   - platform = 'hackerone'
 *   - max_payout = 10000              (generateFallbackRules' fixed HackerOne value)
 *   - scope has exactly 7 entries     (generateFallbackScope's fixed in-scope count)
 *   - out_of_scope has exactly 4 entries, containing the literal
 *     "Third-party services"          (generateFallbackScope's fixed out-of-scope list)
 *   - last_hunted IS NULL             (safety guard: never touch a program
 *     that's actually been used, even if it happens to match the above)
 *
 * As a second safety guard, any matching program with campaigns OR targets
 * rows referencing it is skipped and reported rather than deleted, regardless
 * of last_hunted — both are real usage signals a coincidental match shouldn't
 * override, and (for targets) a required FK the batched DELETE would violate.
 *
 * Usage:
 *   npm run cleanup:fake-hackerone            (dry run — lists matches only)
 *   npm run cleanup:fake-hackerone -- --confirm   (deletes the safe matches)
 */
import "dotenv/config";
import { pool } from "../src/db";

const CONFIRM = process.argv.slice(2).includes("--confirm");

async function main() {
  const { rows: matches } = await pool.query(`
    SELECT id, name, program_handle, max_payout, out_of_scope, last_hunted
    FROM programs
    WHERE platform = 'hackerone'
      AND max_payout = 10000
      AND jsonb_array_length(scope) = 7
      AND jsonb_array_length(out_of_scope) = 4
      AND out_of_scope @> '["Third-party services"]'::jsonb
      AND last_hunted IS NULL
    ORDER BY id
  `);

  if (matches.length === 0) {
    console.log("\nNo fabricated HackerOne programs found matching the fallback signature. Nothing to do.\n");
    await pool.end();
    return;
  }

  console.log(`\nFound ${matches.length} program(s) matching the synthetic-fallback signature (platform=hackerone, max_payout=10000, 7 in-scope/4 out-of-scope entries including "Third-party services", never hunted).`);
  console.log("Review this list carefully before confirming — this is a strong heuristic, not a guaranteed-unique marker:\n");
  for (const m of matches) {
    console.log(`  #${m.id}  ${m.name}${m.program_handle ? ` (${m.program_handle})` : ""}`);
  }

  const ids = matches.map(m => m.id);
  const [{ rows: withCampaigns }, { rows: withTargets }] = await Promise.all([
    pool.query(`SELECT DISTINCT program_id FROM campaigns WHERE program_id = ANY($1::int[])`, [ids]),
    pool.query(`SELECT DISTINCT program_id FROM targets WHERE program_id = ANY($1::int[])`, [ids]),
  ]);
  const blockedIds = new Set([...withCampaigns, ...withTargets].map(r => r.program_id));
  const byId = new Map(matches.map(m => [m.id, m]));
  const deletable = matches.filter(m => !blockedIds.has(m.id));

  if (blockedIds.size > 0) {
    console.log(`\n${blockedIds.size} of the above have campaigns and/or targets attached despite last_hunted being NULL — skipping these as a safety measure:`);
    for (const id of blockedIds) {
      const m = byId.get(id)!;
      console.log(`  #${m.id}  ${m.name} — has campaign(s)/target(s), not deleting`);
    }
  }

  if (!CONFIRM) {
    console.log(`\nDry run. ${deletable.length} program(s) would be deleted. Re-run with --confirm to execute.\n`);
    await pool.end();
    return;
  }

  if (deletable.length === 0) {
    console.log("\nNothing safe to delete after guards.\n");
    await pool.end();
    return;
  }

  const deleteIds = deletable.map(m => m.id);
  const result = await pool.query(`DELETE FROM programs WHERE id = ANY($1::int[])`, [deleteIds]);
  console.log(`\nDeleted ${result.rowCount ?? 0} fabricated HackerOne program row(s). Re-run sync-hackerone to re-fetch them with real data once the underlying fetch issue is resolved.\n`);

  await pool.end();
}

main().catch(async (err) => {
  console.error("cleanup-fake-hackerone-programs failed:", err.message);
  await pool.end().catch(() => {});
  process.exit(1);
});
