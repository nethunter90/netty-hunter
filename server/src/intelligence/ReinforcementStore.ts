/**
 * Unified Reinforcement Store
 * Cross-hunt self-learning system with 5 domains:
 * 1. Tool Success Rates
 * 2. Framework-Vuln Matrix
 * 3. Program Type Heuristics
 * 4. Confidence Calibration
 * 5. Exploration Tracking
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
  async recordToolOutcome(tool: string, vulnClass: string, success: boolean): Promise<void> {
    const key = `${tool}:${vulnClass}`;
    await this.upsert("tool_success", key, {}, success);
  }

  async getToolSuccessRate(tool: string, vulnClass: string): Promise<number> {
    const entry = await this.get("tool_success", `${tool}:${vulnClass}`);
    return entry ? entry.successRate : 0.5;
  }

  // ── Domain 2: Framework-Vuln Matrix ───────────────────────────────────────
  async recordFrameworkVuln(framework: string, vulnClass: string, found: boolean): Promise<void> {
    const key = `${framework}:${vulnClass}`;
    await this.upsert("framework_vuln", key, { framework, vulnClass }, found);
  }

  async getFrameworkVulnRate(framework: string, vulnClass: string): Promise<number> {
    const entry = await this.get("framework_vuln", `${framework}:${vulnClass}`);
    return entry ? entry.successRate : 0.15;
  }

  async getVulnsForFramework(framework: string): Promise<Array<{ vulnClass: string; rate: number }>> {
    const entries = await db.select()
      .from(reinforcementTable)
      .where(
        and(
          eq(reinforcementTable.domain, "framework_vuln"),
          // key starts with framework
        )
      );
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
    successful: boolean
  ): Promise<void> {
    await this.upsert("program_type", `${programType}:${strategy}`, { programType, strategy }, successful);
  }

  async getBestStrategyForProgramType(programType: string): Promise<string[]> {
    const entries = await db.select().from(reinforcementTable)
      .where(eq(reinforcementTable.domain, "program_type"));

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
    actuallyFound: boolean
  ): Promise<void> {
    const bucket = Math.round(predictedConfidence * 10) / 10; // round to 0.1 buckets
    const key = `${vulnClass}:${bucket}`;
    await this.upsert("confidence_calibration", key, { bucket, vulnClass }, actuallyFound);
  }

  async computeBrierScore(): Promise<number> {
    const entries = await db.select().from(reinforcementTable)
      .where(eq(reinforcementTable.domain, "confidence_calibration"));

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
  async recordExploration(endpointPattern: string, vulnClass: string): Promise<void> {
    const key = `${endpointPattern}:${vulnClass}`;
    await this.upsert("exploration", key, {}, false);
  }

  async hasBeenExplored(endpointPattern: string, vulnClass: string): Promise<boolean> {
    const entry = await this.get("exploration", `${endpointPattern}:${vulnClass}`);
    return entry !== null;
  }

  // ── Generic Record (for external callers) ─────────────────────────────────
  async record(domain: RLDomain, key: string, success: boolean): Promise<void> {
    await this.upsert(domain, key, {}, success);
  }

  // ── Domain 6: Model Selection ─────────────────────────────────────────────
  // Tracks confirmation rates per model per vuln class.
  // Key format: "${model}:${vulnClass}" e.g. "claude:sqli", "ollama:xss"
  async recordModelOutcome(model: string, vulnClass: string, confirmed: boolean): Promise<void> {
    await this.upsert("model_selection", `${model}:${vulnClass}`, { model, vulnClass }, confirmed);
  }

  async getModelSuccessRate(model: string, vulnClass: string): Promise<number> {
    const entry = await this.get("model_selection", `${model}:${vulnClass}`);
    if (!entry || entry.totalCount === 0) return -1; // -1 = no data
    return entry.successCount / entry.totalCount;
  }

  /** Returns the model with better confirmed hypothesis rate for a given vuln class.
   *  Returns null when there's insufficient data to make a call (< 3 samples each). */
  async getBetterModel(
    vulnClass: string,
    candidates: string[] = ["claude"]
  ): Promise<string | null> {
    const MIN_SAMPLES = 3;
    let best: string | null = null;
    let bestRate = -1;

    for (const model of candidates) {
      const entry = await this.get("model_selection", `${model}:${vulnClass}`);
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
  async recordWafEvasionOutcome(vendor: string, vulnClass: string, technique: string, success: boolean): Promise<void> {
    const key = `${vendor}:${vulnClass}:${technique}`;
    await this.upsert("waf_evasion_technique", key, { vendor, vulnClass, technique }, success);
  }

  /** Null when there's insufficient data (< 3 samples) to prefer a learned
   *  technique over the fingerprint-informed default — same cold-start-safe
   *  discipline as getBetterModel(). Not yet called anywhere (the read/warm-
   *  start path is intentionally deferred — see retry-failure-classifier.ts). */
  async getBestWafEvasionTechnique(vendor: string, vulnClass: string): Promise<string | null> {
    const MIN_SAMPLES = 3;
    const prefix = `${vendor}:${vulnClass}:`;
    const entries = await db.select().from(reinforcementTable)
      .where(eq(reinforcementTable.domain, "waf_evasion_technique"));
    const best = entries
      .filter(e => e.key.startsWith(prefix) && (e.totalCount || 0) >= MIN_SAMPLES)
      .map(e => ({ technique: e.key.slice(prefix.length), rate: (e.successCount || 0) / Math.max(e.totalCount || 1, 1) }))
      .sort((a, b) => b.rate - a.rate)[0];
    return best?.technique ?? null;
  }

  // ── Domain 8: Payload Mutation Technique ──────────────────────────────────
  // Keyed by APP STACK, not WAF vendor — the winning encoding/breakout syntax
  // tracks the target's own parser, not whatever sits in front of it.
  async recordPayloadMutationOutcome(stack: string, vulnClass: string, technique: string, success: boolean): Promise<void> {
    const key = `${stack}:${vulnClass}:${technique}`;
    await this.upsert("payload_mutation_technique", key, { stack, vulnClass, technique }, success);
  }

  /** Same cold-start/min-sample discipline as getBestWafEvasionTechnique().
   *  Not yet called anywhere — read/warm-start path intentionally deferred. */
  async getBestPayloadMutationTechnique(stack: string, vulnClass: string): Promise<string | null> {
    const MIN_SAMPLES = 3;
    const prefix = `${stack}:${vulnClass}:`;
    const entries = await db.select().from(reinforcementTable)
      .where(eq(reinforcementTable.domain, "payload_mutation_technique"));
    const best = entries
      .filter(e => e.key.startsWith(prefix) && (e.totalCount || 0) >= MIN_SAMPLES)
      .map(e => ({ technique: e.key.slice(prefix.length), rate: (e.successCount || 0) / Math.max(e.totalCount || 1, 1) }))
      .sort((a, b) => b.rate - a.rate)[0];
    return best?.technique ?? null;
  }

  // ── Temporal Decay ────────────────────────────────────────────────────────
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
  private async upsert(domain: RLDomain, key: string, value: Record<string, unknown>, success: boolean): Promise<void> {
    // Atomic INSERT … ON CONFLICT DO UPDATE avoids the get-then-update race
    // when multiple hunts run concurrently and record outcomes for the same key.
    await db.insert(reinforcementTable).values({
      domain,
      key,
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

  private async get(domain: RLDomain, key: string): Promise<RLEntry | null> {
    const [entry] = await db.select().from(reinforcementTable)
      .where(and(eq(reinforcementTable.domain, domain), eq(reinforcementTable.key, key)))
      .limit(1);

    if (!entry) return null;
    return {
      domain: entry.domain as RLDomain,
      key: entry.key,
      value: entry.value as Record<string, unknown>,
      successCount: entry.successCount || 0,
      totalCount: entry.totalCount || 0,
      successRate: (entry.successCount || 0) / Math.max(entry.totalCount || 1, 1),
      weight: entry.weight || 1.0,
      lastUpdated: entry.lastUpdated,
    };
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
