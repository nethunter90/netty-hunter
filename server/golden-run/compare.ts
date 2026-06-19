/**
 * Golden-run diff helper.
 *
 * Queries the most recent completed hunt session (or a specific session ID
 * passed as argv[2]) and diffs its findings against the golden spec.
 *
 * Usage:
 *   npm run golden:compare                    # compare most recent completed session
 *   npm run golden:compare -- <session-id>   # compare a specific session
 *
 * Output: PASS/FAIL for each assertion category, plus a delta list showing
 * what's new or missing vs. the baseline confirmed set. Exit 0 if all
 * hard-floor assertions pass, exit 1 if any fail.
 */

import { readFileSync } from "fs";
import { join } from "path";
import { Pool } from "pg";

// ─── Types ────────────────────────────────────────────────────────────────────

interface SpecFinding {
  vulnClass: string;
  endpointPath: string;
  discoveryTool?: string;
  minConfidence?: number;
  allowedStatuses?: string[];
  technique?: string;
  _comment?: string;
}

interface GoldenSpec {
  meta: Record<string, unknown>;
  inputs: Record<string, unknown>;
  hardFloor: SpecFinding[];
  confirmedSet: SpecFinding[];
  mustNotConfirm: (SpecFinding & { allowedStatuses: string[] })[];
  counts: { totalFindings: { min: number; max?: number }; confirmed: { min: number; max?: number }; deduplicated: { min: number }; _notes: string[] };
  governance: { maxActionableInterventions: number; _check: string; _source: string };
  rateLimiting: { max429sFromTarget: number; _check: string; _note: string };
}

interface DbFinding {
  id: number;
  vuln_type: string;
  affected_url: string;
  confidence: number;
  verification_status: string;
  evidence: unknown;
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

function endpointPath(url: string): string {
  try {
    return new URL(url).pathname;
  } catch {
    return url;
  }
}

function matchesFinding(f: DbFinding, spec: SpecFinding): boolean {
  return (
    f.vuln_type === spec.vulnClass &&
    endpointPath(f.affected_url) === spec.endpointPath
  );
}

function discoveryToolOf(f: DbFinding): string | undefined {
  const ev = f.evidence as any;
  if (!ev) return undefined;
  const arr = Array.isArray(ev) ? ev : Object.values(ev);
  for (const e of arr) {
    if (e?.tool) return String(e.tool);
  }
  return undefined;
}

// ─── Reporting ────────────────────────────────────────────────────────────────

type Status = "PASS" | "FAIL" | "WARN" | "INFO";

function line(status: Status, label: string, detail = "") {
  const sym = status === "PASS" ? "✓" : status === "FAIL" ? "✗" : status === "WARN" ? "!" : "·";
  const pad = label.padEnd(52);
  console.log(`  ${sym}  ${pad}${detail}`);
}

function section(title: string) {
  console.log(`\n── ${title} ${"─".repeat(Math.max(0, 60 - title.length - 4))}`);
}

// ─── Main ─────────────────────────────────────────────────────────────────────

async function main() {
  const specPath = join(__dirname, "spec.json");
  const spec: GoldenSpec = JSON.parse(readFileSync(specPath, "utf8"));

  const pool = new Pool({ connectionString: process.env.DATABASE_URL });

  // ── Resolve session ────────────────────────────────────────────────────────
  const sessionArg = process.argv[2];
  let sessionId: number;
  let sessionRow: Record<string, unknown>;

  if (sessionArg && /^\d+$/.test(sessionArg)) {
    sessionId = Number(sessionArg);
    const r = await pool.query(
      `SELECT hs.id, t.url, hs.status, hs.started_at, hs.completed_at
       FROM hunt_sessions hs JOIN targets t ON t.id = hs.target_id
       WHERE hs.id = $1`,
      [sessionId]
    );
    if (r.rows.length === 0) {
      console.error(`Session ${sessionId} not found.`);
      process.exit(1);
    }
    sessionRow = r.rows[0];
  } else {
    const r = await pool.query(
      `SELECT hs.id, t.url, hs.status, hs.started_at, hs.completed_at
       FROM hunt_sessions hs JOIN targets t ON t.id = hs.target_id
       WHERE hs.status = 'completed'
       ORDER BY hs.id DESC LIMIT 1`
    );
    if (r.rows.length === 0) {
      console.error("No completed hunt sessions found.");
      process.exit(1);
    }
    sessionRow = r.rows[0];
    sessionId = sessionRow.id as number;
  }

  // ── Fetch findings ─────────────────────────────────────────────────────────
  const findingsResult = await pool.query<DbFinding>(
    `SELECT id, vuln_type, affected_url, confidence, verification_status, evidence
     FROM findings WHERE hunt_session_id = $1 ORDER BY id`,
    [sessionId]
  );
  const findings = findingsResult.rows;
  await pool.end();

  // ── Header ─────────────────────────────────────────────────────────────────
  console.log("\n╔══════════════════════════════════════════════════════════════╗");
  console.log("║         Netty Hunter — Golden-Run Diff Report                ║");
  console.log("╚══════════════════════════════════════════════════════════════╝");
  console.log(`\n  Session:  #${sessionId} (${sessionRow.url})`);
  console.log(`  Status:   ${sessionRow.status}`);
  console.log(`  Started:  ${sessionRow.started_at}`);
  console.log(`  Baseline: spec.json from ${spec.meta.date} (session ${spec.meta.huntSessionId})`);

  const confirmed = findings.filter(f => f.verification_status === "confirmed");
  const rejected  = findings.filter(f => f.verification_status === "rejected");
  const deduped   = findings.filter(f => f.verification_status === "deduplicated");
  const inconclusive = findings.filter(f => f.verification_status === "inconclusive");

  let hardFail = 0;

  // ── SECTION 1: Hard floor ──────────────────────────────────────────────────
  section("HARD FLOOR (must hold every run)");

  for (const floor of spec.hardFloor) {
    const match = confirmed.find(f => matchesFinding(f, floor));
    if (match) {
      const confOk = floor.minConfidence === undefined || match.confidence >= floor.minConfidence;
      const toolOk = !floor.discoveryTool || discoveryToolOf(match) === floor.discoveryTool;
      if (confOk && toolOk) {
        line("PASS", `${floor.vulnClass} @ ${floor.endpointPath}`, `confidence=${match.confidence.toFixed(3)}`);
      } else {
        hardFail++;
        if (!confOk) line("FAIL", `${floor.vulnClass} @ ${floor.endpointPath}`, `confidence=${match.confidence.toFixed(3)} < floor ${floor.minConfidence}`);
        if (!toolOk) line("FAIL", `${floor.vulnClass} @ ${floor.endpointPath}`, `discoveryTool=${discoveryToolOf(match)} ≠ ${floor.discoveryTool}`);
      }
    } else {
      hardFail++;
      line("FAIL", `${floor.vulnClass} @ ${floor.endpointPath}`, "NOT confirmed — investigate pipeline");
    }
  }

  // ── SECTION 2: Confirmed-set delta ────────────────────────────────────────
  section("CONFIRMED SET DELTA");

  const missing: SpecFinding[] = [];
  const matched: SpecFinding[] = [];

  for (const expected of spec.confirmedSet) {
    if (confirmed.find(f => matchesFinding(f, expected))) {
      matched.push(expected);
    } else {
      missing.push(expected);
    }
  }

  const baseline = new Set(spec.confirmedSet.map(s => `${s.vulnClass}:${s.endpointPath}`));
  const extra = confirmed.filter(f => !baseline.has(`${f.vuln_type}:${endpointPath(f.affected_url)}`));

  for (const m of matched) {
    const f = confirmed.find(f => matchesFinding(f, m))!;
    line("PASS", `${m.vulnClass} @ ${m.endpointPath}`, `id=${f.id} conf=${f.confidence.toFixed(3)}`);
  }
  for (const m of missing) {
    line("WARN", `MISSING ${m.vulnClass} @ ${m.endpointPath}`, "was in baseline — LLM variance or regression?");
  }
  for (const e of extra) {
    line("INFO", `NEW ${e.vuln_type} @ ${endpointPath(e.affected_url)}`, `id=${e.id} conf=${e.confidence.toFixed(3)} — update spec if valid`);
  }

  // ── SECTION 3: Must-not-confirm ────────────────────────────────────────────
  section("MUST-NOT-CONFIRM (browser gate + class contracts)");

  for (const forbidden of spec.mustNotConfirm) {
    const match = findings.find(f => matchesFinding(f, forbidden));
    if (!match) {
      line("INFO", `${forbidden.vulnClass} @ ${forbidden.endpointPath}`, "not found this run");
      continue;
    }
    if (forbidden.allowedStatuses.includes(match.verification_status)) {
      line("PASS", `${forbidden.vulnClass} @ ${forbidden.endpointPath}`, `status=${match.verification_status} (allowed)`);
    } else {
      hardFail++;
      line("FAIL", `${forbidden.vulnClass} @ ${forbidden.endpointPath}`, `status=${match.verification_status} — should not be confirmed`);
    }
  }

  // ── SECTION 4: Counts ─────────────────────────────────────────────────────
  section("COUNTS (soft — LLM variance expected)");

  const totalOk = findings.length >= spec.counts.totalFindings.min &&
    (spec.counts.totalFindings.max === undefined || findings.length <= spec.counts.totalFindings.max);
  const confirmedOk = confirmed.length >= spec.counts.confirmed.min &&
    (spec.counts.confirmed.max === undefined || confirmed.length <= spec.counts.confirmed.max);
  const dedupOk = deduped.length >= spec.counts.deduplicated.min;

  line(totalOk ? "PASS" : "WARN",
    `Total findings: ${findings.length}`,
    `expected ${spec.counts.totalFindings.min}–${spec.counts.totalFindings.max ?? "∞"}`);
  line(confirmedOk ? "PASS" : "WARN",
    `Confirmed: ${confirmed.length}`,
    `expected ${spec.counts.confirmed.min}–${spec.counts.confirmed.max ?? "∞"}`);
  line(dedupOk ? "PASS" : "WARN",
    `Deduplicated: ${deduped.length}`,
    `expected ≥ ${spec.counts.deduplicated.min}`);
  line("INFO", `Rejected: ${rejected.length} | Inconclusive: ${inconclusive.length}`, "");

  // ── SECTION 5: All confirmed findings ─────────────────────────────────────
  section("ALL CONFIRMED FINDINGS (this run)");
  if (confirmed.length === 0) {
    line("WARN", "No confirmed findings", "");
  }
  for (const f of confirmed) {
    const tool = discoveryToolOf(f) ?? "—";
    line("INFO",
      `#${f.id} ${f.vuln_type} @ ${endpointPath(f.affected_url)}`,
      `conf=${f.confidence.toFixed(3)} tool=${tool}`);
  }

  // ── SECTION 6: Manual checks reminder ─────────────────────────────────────
  section("MANUAL CHECKS (cannot be automated — check before marking run valid)");
  console.log(`\n  !  Governance: no actionable interventions expected.`);
  console.log(`     → ${spec.governance._source}`);
  console.log(`\n  !  429s from target: expect 0.`);
  console.log(`     → ${spec.rateLimiting._check}`);
  console.log(`     → ${spec.rateLimiting._note}`);

  // ── Summary ────────────────────────────────────────────────────────────────
  console.log("\n" + "─".repeat(65));
  if (hardFail === 0) {
    console.log(`\n  RESULT: PASS — all hard-floor assertions hold.`);
    if (missing.length > 0) {
      console.log(`  NOTE: ${missing.length} baseline finding(s) missing — check if LLM variance or regression.`);
    }
    if (extra.length > 0) {
      console.log(`  NOTE: ${extra.length} new confirmed finding(s) vs. baseline — update spec.json if valid.`);
    }
    console.log();
    process.exit(0);
  } else {
    console.log(`\n  RESULT: FAIL — ${hardFail} hard-floor assertion(s) failed.`);
    console.log(`  Investigate the stateful pipeline before declaring the run valid.\n`);
    process.exit(1);
  }
}

main().catch(err => {
  console.error("compare.ts error:", err);
  process.exit(2);
});
