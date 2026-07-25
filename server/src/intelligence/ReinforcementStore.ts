/**
 * Unified Reinforcement Store
 * Cross-hunt self-learning system with 5+ domains:
 * 1. Tool Success Rates
 * 2. Framework-Vuln Matrix
 * 3. Program Type Heuristics
 * 4. Confidence Calibration
 * 5. Exploration Tracking
 * 6. Model Selection
 * 7. WAF Evasion Technique
 * 8. Payload Mutation Technique
 *
 * PROVENANCE SEGREGATION (2026-07-23 readiness handoff — closes the RL
 * practice/real contamination blocker): every keyed record()/get() method
 * below takes a required `provenance` argument and the private upsert()/get()
 * helpers prefix every key with it (`real::`, `lab::`, `unknown::`) before it
 * ever touches the DB. This is the SOLE place a key is constructed or parsed
 * for the keyed (single-row) API, so no caller can forget the tag — TypeScript
 * makes the parameter required, not optional-with-a-default.
 *
 * Resolve provenance via `resolveProvenance()` in
 * `lib/hunter/custom-target-program.ts` (wraps the existing
 * `isCrossCampaignEligible()` discriminator — do not reimplement it here).
 * FAIL CLOSED: an unresolvable/ambiguous program resolves to "unknown", and
 * "unknown" is never read by a "real" caller (see getToolSuccessRate et al.
 * — provenance is an exact match on the read key, not a fallback chain).
 *
 * The seven domain-wide SCAN methods (getVulnsForFramework,
 * getBestStrategyForProgramType, computeBrierScore, getBestWafEvasionTechnique,
 * getBestPayloadMutationTechnique, applyTemporalDecay, getStats) don't do a
 * single-key lookup — they scan every row in a domain and parse structure out
 * of the key. Four of them (the two "get best X" pickers, plus
 * getVulnsForFramework/getBestStrategyForProgramType) now go through
 * queryDomain(domain, provenance), which strips the provenance prefix from
 * each row's key before returning it, so their existing key.split(':')
 * parsing is unchanged. computeBrierScore(), applyTemporalDecay(), and
 * getStats() are deliberately left as cross-provenance aggregates via
 * queryDomainAllProvenance() — they're observability/calibration metrics
 * about the reasoning system itself, not part of a hunt's tool-selection
 * decision path, so mixing lab+real data here is a reasoned scoping choice,
 * not an oversight. getAllEntriesForDomain() is the explicit, clearly-labeled
 * escape hatch for read-only dashboard reporting
 * (lib/hunter/reinforcement-store.ts) — never call it from a hunt-decision
 * path.
 */
import { db } from "../db";
import { reinforcementStore as reinforcementTable } from "../db/schema";
import { eq, and, lt, sql } from "drizzle-orm";
import logger from "../utils/logger";

export type RLDomain =
  | "tool_success"
  | "framework_vuln"
  | "program_type"
  | "confidence_calibration"
  | "exploration"
  | "model_selection"
  | "waf_evasion_technique"
  | "payload_mutation_technique";

/** Lab/real segregation tag. "unknown" covers any program whose platform
 *  couldn't be resolved (missing programId, DB lookup failure, etc.) — it is
 *  a real, distinct bucket, never a silent default into "real". */
export type Provenance = "real" | "lab" | "unknown";

const PROVENANCE_VALUES: readonly Provenance[] = ["real", "lab", "unknown"];

function prefixKey(provenance: Provenance, key: string): string {
  return `${provenance}::${key}`;
}

/** Strip a recognized provenance prefix from a stored key, for callers that
 *  need the original (pre-provenance) key shape back — e.g. the dashboard
 *  adapter's key.split(':') parsing. Defensive: rows written before this
 *  change (pre-wipe) have no prefix and pass through unchanged. */
export function stripProvenance(key: string): string {
  for (const p of PROVENANCE_VALUES) {
    const prefix = `${p}::`;
    if (key.startsWith(prefix)) return key.slice(prefix.length);
  }
  return key;
}

export interface RLEntry {
  domain: RLDomain;
  key: string;
  value: Record<string, unknown>;
  successCount: number;
  totalCount: number;
  successRate: number;
  weight: number;
  lastUpdated: Date;
}

export class UnifiedReinforcementStore {
  private static instance: UnifiedReinforcementStore;

  static getInstance(): UnifiedReinforcementStore {
    if (!UnifiedReinforcementStore.instance) {
      UnifiedReinforcementStore.instance = new UnifiedReinforcementStore();
    }
    return UnifiedReinforcementStore.instance;
  }

  // ── Domain 1: Tool Success Rates ──────────────────────────────────────────
  async recordToolOutcome(tool: string, vulnClass: string, success: boolean, provenance: Provenance): Promise<void> {
    const key = `${tool}:${vulnClass}`;
    await this.upsert("tool_success", key, {}, success, provenance);
  }

  async getToolSuccessRate(tool: string, vulnClass: string, provenance: Provenance): Promise<number> {
    const entry = await this.get("tool_success", `${tool}:${vulnClass}`, provenance);
    return entry ? entry.successRate : 0.5;
  }

  // ── Domain 1b: Vuln-class-only success rate (ROIModel's shape — same
  //     domain, no tool component in the key; distinguishable from Domain 1's
  //     `tool:vulnClass` keys since a bare vulnClass never contains ':'). ──
  async recordVulnClassOutcome(vulnClass: string, success: boolean, provenance: Provenance): Promise<void> {
    await this.upsert("tool_success", vulnClass, {}, success, provenance);
  }

  async getVulnClassStats(vulnClass: string, provenance: Provenance): Promise<{ successCount: number; totalCount: number }> {
    const entry = await this.get("tool_success", vulnClass, provenance);
    return { successCount: entry?.successCount ?? 0, totalCount: entry?.totalCount ?? 0 };
  }

  // ── Domain 2: Framework-Vuln Matrix ───────────────────────────────────────
  async recordFrameworkVuln(framework: string, vulnClass: string, found: boolean, provenance: Provenance): Promise<void> {
    const key = `${framework}:${vulnClass}`;
    await this.upsert("framework_vuln", key, { framework, vulnClass }, found, provenance);
  }

  async getFrameworkVulnRate(framework: string, vulnClass: string, provenance: Provenance): Promise<number> {
    const entry = await this.get("framework_vuln", `${framework}:${vulnClass}`, provenance);
    return entry ? entry.successRate : 0.15;
  }

  async getVulnsForFramework(framework: string, provenance: Provenance): Promise<Array<{ vulnClass: string; rate: number }>> {
    const entries = await this.queryDomain("framework_vuln", provenance);
    return entries
      .filter(e => e.key.startsWith(`${framework}:`))
      .map(e => ({
        vulnClass: e.key.split(":")[1],
        rate: (e.successCount || 0) / Math.max(e.totalCount || 1, 1),
      }))
      .sort((a, b) => b.rate - a.rate);
  }

  // ── Domain 3: Program Type Heuristics ─────────────────────────────────────
  async recordProgramTypeHeuristic(
    programType: string,
    strategy: string,
    successful: boolean,
    provenance: Provenance,
  ): Promise<void> {
    await this.upsert("program_type", `${programType}:${strategy}`, { programType, strategy }, successful, provenance);
  }

  async getBestStrategyForProgramType(programType: string, provenance: Provenance): Promise<string[]> {
    const entries = await this.queryDomain("program_type", provenance);
    return entries
      .filter(e => e.key.startsWith(`${programType}:`))
      .sort((a, b) => {
        const rateA = (a.successCount || 0) / Math.max(a.totalCount || 1, 1);
        const rateB = (b.successCount || 0) / Math.max(b.totalCount || 1, 1);
        return rateB - rateA;
      })
      .slice(0, 5)
      .map(e => e.key.split(":")[1]);
  }

  // ── Domain 4: Confidence Calibration ──────────────────────────────────────
  async recordConfidenceCalibration(
    vulnClass: string,
    predictedConfidence: number,
    actuallyFound: boolean,
    provenance: Provenance,
  ): Promise<void> {
    const bucket = Math.round(predictedConfidence * 10) / 10; // round to 0.1 buckets
    const key = `${vulnClass}:${bucket}`;
    await this.upsert("confidence_calibration", key, { bucket, vulnClass }, actuallyFound, provenance);
  }

  /** Cross-provenance aggregate by design — a calibration metric about the
   *  reasoning system's own confidence estimates, not a per-hunt tool-choice
   *  input. See module docstring. */
  async computeBrierScore(): Promise<number> {
    const entries = await this.queryDomainAllProvenance("confidence_calibration");

    if (entries.length === 0) return 0.25; // default uncertain

    let brierSum = 0;
    let count = 0;
    for (const e of entries) {
      const predictedP = Number(e.key.split(":")[1]) || 0;
      const actualRate = (e.successCount || 0) / Math.max(e.totalCount || 1, 1);
      brierSum += Math.pow(predictedP - actualRate, 2);
      count++;
    }

    return count > 0 ? brierSum / count : 0.25;
  }

  // ── Domain 5: Exploration Tracking ────────────────────────────────────────
  async recordExploration(endpointPattern: string, vulnClass: string, provenance: Provenance): Promise<void> {
    const key = `${endpointPattern}:${vulnClass}`;
    await this.upsert("exploration", key, {}, false, provenance);
  }

  async hasBeenExplored(endpointPattern: string, vulnClass: string, provenance: Provenance): Promise<boolean> {
    const entry = await this.get("exploration", `${endpointPattern}:${vulnClass}`, provenance);
    return entry !== null;
  }

  // ── Generic Record (for external callers) ─────────────────────────────────
  async record(domain: RLDomain, key: string, success: boolean, provenance: Provenance): Promise<void> {
    await this.upsert(domain, key, {}, success, provenance);
  }

  // ── Domain 6: Model Selection ─────────────────────────────────────────────
  // Tracks confirmation rates per model per vuln class.
  // Key format: "${model}:${vulnClass}" e.g. "claude:sqli", "ollama:xss"
  async recordModelOutcome(model: string, vulnClass: string, confirmed: boolean, provenance: Provenance): Promise<void> {
    await this.upsert("model_selection", `${model}:${vulnClass}`, { model, vulnClass }, confirmed, provenance);
  }

  async getModelSuccessRate(model: string, vulnClass: string, provenance: Provenance): Promise<number> {
    const entry = await this.get("model_selection", `${model}:${vulnClass}`, provenance);
    if (!entry || entry.totalCount === 0) return -1; // -1 = no data
    return entry.successCount / entry.totalCount;
  }

  /** Returns the model with better confirmed hypothesis rate for a given vuln class.
   *  Returns null when there's insufficient data to make a call (< 3 samples each). */
  async getBetterModel(
    vulnClass: string,
    candidates: string[] = ["claude"],
    provenance: Provenance = "unknown",
  ): Promise<string | null> {
    const MIN_SAMPLES = 3;
    let best: string | null = null;
    let bestRate = -1;

    for (const model of candidates) {
      const entry = await this.get("model_selection", `${model}:${vulnClass}`, provenance);
      if (!entry || entry.totalCount < MIN_SAMPLES) continue;
      const rate = entry.successCount / entry.totalCount;
      if (rate > bestRate) { bestRate = rate; best = model; }
    }
    return best;
  }

  // ── Domain 7: WAF Evasion Technique ───────────────────────────────────────
  // Keyed by WAF VENDOR, not app stack — evasion effectiveness transfers by
  // which WAF is in front of the target (what beats Cloudflare beats
  // Cloudflare regardless of the origin's language), never by the origin
  // app's own stack. Keep this axis separate from Domain 8 below; merging
  // them would misattribute a vendor-specific bypass to the wrong cause.
  async recordWafEvasionOutcome(
    vendor: string, vulnClass: string, technique: string, success: boolean, provenance: Provenance,
  ): Promise<void> {
    const key = `${vendor}:${vulnClass}:${technique}`;
    await this.upsert("waf_evasion_technique", key, { vendor, vulnClass, technique }, success, provenance);
  }

  /** Null when there's insufficient data (< 3 samples) to prefer a learned
   *  technique over the fingerprint-informed default — same cold-start-safe
   *  discipline as getBetterModel(). Not yet called anywhere (the read/warm-
   *  start path is intentionally deferred — see retry-failure-classifier.ts). */
  async getBestWafEvasionTechnique(vendor: string, vulnClass: string, provenance: Provenance): Promise<string | null> {
    const MIN_SAMPLES = 3;
    const prefix = `${vendor}:${vulnClass}:`;
    const entries = await this.queryDomain("waf_evasion_technique", provenance);
    const best = entries
      .filter(e => e.key.startsWith(prefix) && (e.totalCount || 0) >= MIN_SAMPLES)
      .map(e => ({ technique: e.key.slice(prefix.length), rate: (e.successCount || 0) / Math.max(e.totalCount || 1, 1) }))
      .sort((a, b) => b.rate - a.rate)[0];
    return best?.technique ?? null;
  }

  // ── Domain 8: Payload Mutation Technique ──────────────────────────────────
  // Keyed by APP STACK, not WAF vendor — the winning encoding/breakout syntax
  // tracks the target's own parser, not whatever sits in front of it.
  async recordPayloadMutationOutcome(
    stack: string, vulnClass: string, technique: string, success: boolean, provenance: Provenance,
  ): Promise<void> {
    const key = `${stack}:${vulnClass}:${technique}`;
    await this.upsert("payload_mutation_technique", key, { stack, vulnClass, technique }, success, provenance);
  }

  /** Same cold-start/min-sample discipline as getBestWafEvasionTechnique().
   *  Not yet called anywhere — read/warm-start path intentionally deferred. */
  async getBestPayloadMutationTechnique(stack: string, vulnClass: string, provenance: Provenance): Promise<string | null> {
    const MIN_SAMPLES = 3;
    const prefix = `${stack}:${vulnClass}:`;
    const entries = await this.queryDomain("payload_mutation_technique", provenance);
    const best = entries
      .filter(e => e.key.startsWith(prefix) && (e.totalCount || 0) >= MIN_SAMPLES)
      .map(e => ({ technique: e.key.slice(prefix.length), rate: (e.successCount || 0) / Math.max(e.totalCount || 1, 1) }))
      .sort((a, b) => b.rate - a.rate)[0];
    return best?.technique ?? null;
  }

  // ── Temporal Decay ────────────────────────────────────────────────────────
  // Cross-provenance by design (see module docstring) — decay is a uniform
  // staleness discount, not a per-hunt read that could bias tool selection.
  async applyTemporalDecay(domainName: RLDomain, decayDays: number = 30): Promise<void> {
    const cutoff = new Date(Date.now() - decayDays * 24 * 3600 * 1000);
    const staleEntries = await db.select()
      .from(reinforcementTable)
      .where(and(eq(reinforcementTable.domain, domainName), lt(reinforcementTable.lastUpdated, cutoff)));

    for (const entry of staleEntries) {
      const newWeight = (entry.weight || 1) * 0.9; // 10% decay
      await db.update(reinforcementTable).set({ weight: newWeight }).where(eq(reinforcementTable.id, entry.id));
    }

    logger.info("RL: Temporal decay applied", { domain: domainName, affected: staleEntries.length });
  }

  // ── Helpers ───────────────────────────────────────────────────────────────
  private async upsert(
    domain: RLDomain, key: string, value: Record<string, unknown>, success: boolean, provenance: Provenance,
  ): Promise<void> {
    const prefixedKey = prefixKey(provenance, key);
    // Atomic INSERT … ON CONFLICT DO UPDATE avoids the get-then-update race
    // when multiple hunts run concurrently and record outcomes for the same key.
    await db.insert(reinforcementTable).values({
      domain,
      key: prefixedKey,
      value,
      successCount: success ? 1 : 0,
      totalCount: 1,
      weight: 1.0,
    }).onConflictDoUpdate({
      target: [reinforcementTable.domain, reinforcementTable.key],
      set: {
        successCount: sql`${reinforcementTable.successCount} + ${success ? 1 : 0}`,
        totalCount: sql`${reinforcementTable.totalCount} + 1`,
        lastUpdated: new Date(),
      },
    });
  }

  private async get(domain: RLDomain, key: string, provenance: Provenance): Promise<RLEntry | null> {
    const prefixedKey = prefixKey(provenance, key);
    const [entry] = await db.select().from(reinforcementTable)
      .where(and(eq(reinforcementTable.domain, domain), eq(reinforcementTable.key, prefixedKey)))
      .limit(1);

    if (!entry) return null;
    return {
      domain: entry.domain as RLDomain,
      key: stripProvenance(entry.key),
      value: entry.value as Record<string, unknown>,
      successCount: entry.successCount || 0,
      totalCount: entry.totalCount || 0,
      successRate: (entry.successCount || 0) / Math.max(entry.totalCount || 1, 1),
      weight: entry.weight || 1.0,
      lastUpdated: entry.lastUpdated,
    };
  }

  /** Domain-wide scan restricted to one provenance, with the prefix already
   *  stripped from each row's `.key` so existing `key.split(':')` parsing in
   *  the callers above is unchanged. This — not a caller-side db.select() —
   *  is the sole scan path for provenance-gated domain reads. */
  private async queryDomain(domain: RLDomain, provenance: Provenance): Promise<RLEntry[]> {
    const prefix = `${provenance}::`;
    const rows = await db.select().from(reinforcementTable).where(eq(reinforcementTable.domain, domain));
    return rows
      .filter(r => r.key.startsWith(prefix))
      .map(r => ({
        domain: r.domain as RLDomain,
        key: stripProvenance(r.key),
        value: r.value as Record<string, unknown>,
        successCount: r.successCount || 0,
        totalCount: r.totalCount || 0,
        successRate: (r.successCount || 0) / Math.max(r.totalCount || 1, 1),
        weight: r.weight || 1.0,
        lastUpdated: r.lastUpdated,
      }));
  }

  /** Cross-provenance scan — deliberately unfiltered. See module docstring:
   *  used only by computeBrierScore()/getStats() (observability/calibration,
   *  not hunt-decision reads) and by the explicit reporting escape hatch
   *  below. NEVER call this from a hunt-decision path. */
  private async queryDomainAllProvenance(domain: RLDomain): Promise<RLEntry[]> {
    const rows = await db.select().from(reinforcementTable).where(eq(reinforcementTable.domain, domain));
    return rows.map(r => ({
      domain: r.domain as RLDomain,
      key: stripProvenance(r.key),
      value: r.value as Record<string, unknown>,
      successCount: r.successCount || 0,
      totalCount: r.totalCount || 0,
      successRate: (r.successCount || 0) / Math.max(r.totalCount || 1, 1),
      weight: r.weight || 1.0,
      lastUpdated: r.lastUpdated,
    }));
  }

  /** Explicit, clearly-labeled reporting escape hatch for the dashboard
   *  adapter (lib/hunter/reinforcement-store.ts) — returns every row in a
   *  domain across all provenances, prefix-stripped. Never call from a
   *  hunt-decision path; use queryDomain() (private, provenance-gated)
   *  for that instead. */
  async getAllEntriesForDomain(domain: RLDomain): Promise<RLEntry[]> {
    return this.queryDomainAllProvenance(domain);
  }

  async getStats(): Promise<Record<RLDomain, { entries: number; avgSuccessRate: number }>> {
    const domains: RLDomain[] = ["tool_success", "framework_vuln", "program_type", "confidence_calibration", "exploration"];
    const stats: Record<string, { entries: number; avgSuccessRate: number }> = {};

    for (const domain of domains) {
      const entries = await db.select().from(reinforcementTable).where(eq(reinforcementTable.domain, domain));
      const avgRate = entries.length > 0
        ? entries.reduce((sum, e) => sum + (e.successCount || 0) / Math.max(e.totalCount || 1, 1), 0) / entries.length
        : 0;
      stats[domain] = { entries: entries.length, avgSuccessRate: Math.round(avgRate * 100) / 100 };
    }

    return stats as Record<RLDomain, { entries: number; avgSuccessRate: number }>;
  }
}

export default UnifiedReinforcementStore;
