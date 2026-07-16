/**
 * backfill-scope-assets.ts — populate metadata.scopeAssets for programs that
 * already have real per-program scope in the flat scope/out_of_scope columns
 * (e.g. imported before the metadata.scopeAssets structure existed) but have
 * nothing in metadata for TargetSelectionIntelligence's asset-testability/
 * bounty-eligibility/severity-ceiling scoring to read — so these programs are
 * silently scored with neutral 0.5 defaults today despite having real scope.
 *
 * This is a heuristic inference from bare identifier strings (a flat
 * domain/URL list carries no asset-type/severity-ceiling/eligibility
 * metadata of its own), so it errs conservative:
 *   - type: '*.' prefix -> wildcard; http(s) URL -> url (or api/android/ios
 *     for recognizable patterns); anything else -> domain
 *   - maxSeverity: left unset (uncapped) — there is no real signal to infer
 *     a severity ceiling from a bare string, and guessing one could
 *     wrongly suppress a program's severityCeilingScore
 *   - eligible: true for in-scope entries, false for out-of-scope — matches
 *     how a real HackerOne sync populates these fields
 *
 * Only touches programs where metadata has no scopeAssets key at all, so it
 * never overwrites real per-asset data from an actual sync (or a previous
 * run of this script).
 *
 * Usage:
 *   npm run backfill:scope-assets              (dry run — reports counts)
 *   npm run backfill:scope-assets -- --confirm    (writes metadata.scopeAssets)
 */
import "dotenv/config";
import { pool } from "../src/db";
import type { ScopeAsset } from "../src/lib/bounty-intelligence/program-fetcher";

const CONFIRM = process.argv.slice(2).includes("--confirm");

function inferAssetType(identifier: string): ScopeAsset["type"] {
  if (identifier.startsWith("*.")) return "wildcard";
  if (/^https?:\/\//i.test(identifier)) {
    if (/play\.google\.com/i.test(identifier)) return "android";
    if (/apps\.apple\.com|itunes\.apple\.com/i.test(identifier)) return "ios";
    if (/\/api(\/|$)/i.test(identifier)) return "api";
    return "url";
  }
  return "domain";
}

function toScopeAssets(identifiers: unknown, eligible: boolean): ScopeAsset[] {
  if (!Array.isArray(identifiers)) return [];
  return identifiers
    .filter((id): id is string => typeof id === "string" && id.length > 0)
    .map(identifier => ({ type: inferAssetType(identifier), identifier, eligible }));
}

async function main() {
  const { rows } = await pool.query(`
    SELECT id, name, platform, scope, out_of_scope, metadata
    FROM programs
    WHERE NOT (metadata ? 'scopeAssets')
      AND jsonb_array_length(scope) > 0
    ORDER BY id
  `);

  if (rows.length === 0) {
    console.log("\nNo programs need a scopeAssets backfill. Nothing to do.\n");
    await pool.end();
    return;
  }

  console.log(`\nFound ${rows.length} program(s) with real scope but no metadata.scopeAssets:\n`);
  for (const r of rows) {
    const outCount = Array.isArray(r.out_of_scope) ? r.out_of_scope.length : 0;
    console.log(`  #${r.id}  ${r.name} [${r.platform}] — ${r.scope.length} in-scope, ${outCount} out-of-scope`);
  }

  if (!CONFIRM) {
    console.log(`\nDry run. ${rows.length} program(s) would be updated. Re-run with --confirm to execute.\n`);
    await pool.end();
    return;
  }

  let updated = 0;
  for (const r of rows) {
    const inScope = toScopeAssets(r.scope, true);
    const outOfScope = toScopeAssets(r.out_of_scope, false);
    const metadata = { ...(r.metadata || {}), scopeAssets: { inScope, outOfScope } };
    await pool.query(`UPDATE programs SET metadata = $1::jsonb WHERE id = $2`, [JSON.stringify(metadata), r.id]);
    updated++;
  }

  console.log(`\nBackfilled metadata.scopeAssets for ${updated} program(s). The recommendation engine will use real asset-testability/bounty-eligibility scoring for them on the next rank.\n`);
  await pool.end();
}

main().catch(async (err) => {
  console.error("backfill-scope-assets failed:", err.message);
  await pool.end().catch(() => {});
  process.exit(1);
});
