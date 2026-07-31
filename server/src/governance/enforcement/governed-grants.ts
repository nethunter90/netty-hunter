import { and, eq, isNull } from 'drizzle-orm';
import { db, governedGrants } from '../../db';
import logger from '../../utils/logger';

const INJECTION_OVERRIDE_GRANT_TYPE = 'prompt_injection_override';
const HUNT_SESSION_SCOPE = 'hunt_session';

/**
 * Prompt-injection chokepoint BUILD, R1 — modeled directly on
 * ScopeGuard.getScope()'s cache (middleware/scopeGuard.ts:256-427: a 30s TTL
 * Map plus an explicit invalidateCache()), NOT on HunterEngine.checkScopeDrift()'s
 * once-per-loop-iteration cadence. checkScopeDrift() is a drift ALARM checked
 * once per runLoop() iteration; it is not the live enforcement point for
 * scope (ScopeGuard.isInScope(), checked per HTTP request, is). createMessage()
 * is called far more often per iteration than runLoop() itself (LogicExploitAgent's
 * tool-use loop alone can fire ~16 calls in one iteration) — an override check
 * on checkScopeDrift()'s cadence would leave a revoked grant live for however
 * long the current iteration takes, which is worse than no session-grain at all.
 *
 * THIS CACHE CARRIES THE LIVE-REVOCATION GUARANTEE THE WHOLE DESIGN DEPENDS
 * ON. Do not widen CACHE_TTL beyond a "still effectively live" window, and do
 * not replace this with a value captured once at hunt start — that would
 * silently reproduce the exact staleness failure this design was built to
 * avoid. If this needs to change, re-read the 3c grain-decision writeup first.
 */
const CACHE_TTL_MS = 30 * 1000;

const overrideCache = new Map<string, { active: boolean; cachedAt: number }>();

export async function hasActiveInjectionOverride(huntSessionId: string): Promise<boolean> {
  const cached = overrideCache.get(huntSessionId);
  if (cached && Date.now() - cached.cachedAt < CACHE_TTL_MS) {
    return cached.active;
  }

  let active = false;
  try {
    const rows = await db.select().from(governedGrants).where(and(
      eq(governedGrants.grantType, INJECTION_OVERRIDE_GRANT_TYPE),
      eq(governedGrants.scope, HUNT_SESSION_SCOPE),
      eq(governedGrants.scopeId, huntSessionId),
      isNull(governedGrants.revokedAt),
    )).limit(1);
    active = rows.length > 0;
  } catch (err) {
    // Fail closed — same posture as checkScopeDrift()'s catch block. A DB
    // hiccup must never be silently read as "override active".
    logger.error('[governed-grants] Override lookup failed — failing closed (treating as not overridden)', {
      huntSessionId, err: String(err),
    });
    active = false;
  }

  overrideCache.set(huntSessionId, { active, cachedAt: Date.now() });
  return active;
}

export function invalidateInjectionOverrideCache(huntSessionId: string): void {
  overrideCache.delete(huntSessionId);
}

export async function grantInjectionOverride(
  huntSessionId: string,
  grantedBy: string,
  reason: string,
): Promise<void> {
  const alreadyActive = await hasActiveInjectionOverride(huntSessionId);
  if (alreadyActive) return;

  await db.insert(governedGrants).values({
    grantType: INJECTION_OVERRIDE_GRANT_TYPE,
    scope: HUNT_SESSION_SCOPE,
    scopeId: huntSessionId,
    grantedBy,
    reason,
  });
  invalidateInjectionOverrideCache(huntSessionId);
  logger.warn('[governed-grants] Prompt-injection override GRANTED', { huntSessionId, grantedBy, reason });
}

export async function revokeInjectionOverride(huntSessionId: string, revokedBy: string): Promise<void> {
  await db.update(governedGrants)
    .set({ revokedAt: new Date(), revokedBy })
    .where(and(
      eq(governedGrants.grantType, INJECTION_OVERRIDE_GRANT_TYPE),
      eq(governedGrants.scope, HUNT_SESSION_SCOPE),
      eq(governedGrants.scopeId, huntSessionId),
      isNull(governedGrants.revokedAt),
    ));
  invalidateInjectionOverrideCache(huntSessionId);
  logger.warn('[governed-grants] Prompt-injection override REVOKED', { huntSessionId, revokedBy });
}
