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
import { programs } from "../../db/schema";
import { eq, and } from "drizzle-orm";
import { ScopeGuard } from "../../middleware/scopeGuard";

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
