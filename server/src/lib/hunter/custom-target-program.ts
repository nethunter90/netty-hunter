/**
 * Resolves the synthetic program used for programId===-1 ("custom target" /
 * ad-hoc pentest, no formal bug-bounty program) launches.
 *
 * Previously this looked up a single shared "Custom / Local Lab" program with
 * scope: ["*"] and reused it forever, for every -1 launch regardless of what
 * targetUrl was passed. Since ScopeGuard's isInScope() check always passes
 * against a "*" pattern, that meant EVERY custom-target hunt was effectively
 * unscoped -- a real target typo'd or deliberately pointed at an unauthorized
 * domain would sail through every scope gate with no boundary at all.
 *
 * Now each distinct custom target gets its own program, named and scoped to
 * what was actually specified -- "*.<hostname>" by default (covers the target
 * host and its subdomains, so recon/subdomain-expansion still works exactly as
 * before), or an explicit customScope list when the caller supplies one (for a
 * real customer engagement whose authorized scope is broader than one host).
 * This preserves the "just paste a target and go" workflow for ad-hoc/customer
 * pentests -- nothing requires pre-registering a formal Program -- while
 * making the scope that gets enforced actually reflect what was declared for
 * that engagement, rather than a standing wildcard.
 */
import { db } from "../../db";
import { programs, huntSessions, campaigns } from "../../db/schema";
import { eq, and } from "drizzle-orm";
import { ScopeGuard } from "../../middleware/scopeGuard";
import type { Provenance } from "../../intelligence/ReinforcementStore";

export async function resolveCustomTargetProgram(targetUrl: string, customScope?: string[]): Promise<number> {
  const hostname = new URL(targetUrl).hostname;
  const scope = customScope && customScope.length > 0 ? customScope : [`*.${hostname}`];
  const label = `Custom: ${hostname}`;

  const [existing] = await db.select().from(programs)
    .where(and(eq(programs.platform, "local"), eq(programs.name, label)))
    .limit(1);

  if (existing) {
    // An explicit scope this time (e.g. the engagement's authorized scope grew)
    // updates the program so future launches against this host see it too.
    if (customScope && customScope.length > 0) {
      await db.update(programs).set({ scope }).where(eq(programs.id, existing.id));
      ScopeGuard.getInstance().invalidateCache(existing.id);
    }
    return existing.id;
  }

  const [created] = await db.insert(programs).values({
    name: label,
    platform: "local",
    scope,
    outOfScope: [],
  }).returning();
  return created.id;
}

/**
 * Whether a program's data (findings, tool-selection outcomes) should count
 * toward cross-campaign priors — recommendation floors, RL reinforcement, or
 * anything else that aggregates across hunts. Practice/lab targets (this
 * module's synthetic "local" programs, plus "custom"/"other") overrepresent
 * priors relative to real programs if left in: same eligibility question for
 * every consumer, so it lives here once rather than being re-inlined at each
 * call site (was previously duplicated ad hoc, e.g. bounty.ts's
 * platform-based filter).
 */
export function isCrossCampaignEligible(program: { platform: string }): boolean {
  return !["local", "custom", "other"].includes(program.platform);
}

/**
 * RL provenance segregation (2026-07-23 readiness handoff).
 *
 * Wraps isCrossCampaignEligible() above — the SAME discriminator, not a
 * reimplementation — into the three-way tag the reinforcement store's
 * key-prefix chokepoint (ReinforcementStore.ts) requires. FAIL CLOSED: a
 * missing/unresolvable program (lookup failure, deleted program, bad id)
 * resolves to "unknown", never silently to "real". "unknown" entries are
 * written to their own namespace and are never read back by a "real"-context
 * caller (see ReinforcementStore.ts's queryDomain/get — provenance is an
 * exact key match, not a fallback chain).
 */
export async function resolveProvenance(programId: number | null | undefined): Promise<Provenance> {
  if (typeof programId !== "number" || !Number.isFinite(programId)) return "unknown";
  try {
    const [program] = await db.select({ platform: programs.platform })
      .from(programs).where(eq(programs.id, programId)).limit(1);
    if (!program) return "unknown";
    return isCrossCampaignEligible(program) ? "real" : "lab";
  } catch {
    return "unknown";
  }
}

/**
 * Same as resolveProvenance() but starting from a hunt's sessionUuid instead
 * of a programId directly — for callers that only have hunt/session
 * identity in scope (e.g. MetaReasoner.completeHunt(huntId, ...) and
 * strategy-weight-learner's decision_journal aggregation use the same join
 * shape inline via raw SQL for a bulk query; this is the single-row version
 * for callers making one resolution at a time). Joins
 * hunt_sessions -> campaigns -> programs; any missing link resolves to
 * "unknown", never a silent "real".
 */
export async function resolveProvenanceFromHuntId(huntId: string): Promise<Provenance> {
  try {
    const [row] = await db.select({ programId: campaigns.programId })
      .from(huntSessions)
      .innerJoin(campaigns, eq(campaigns.id, huntSessions.campaignId))
      .where(eq(huntSessions.sessionUuid, huntId))
      .limit(1);
    if (!row) return "unknown";
    return resolveProvenance(row.programId);
  } catch {
    return "unknown";
  }
}
