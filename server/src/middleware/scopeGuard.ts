/**
 * ScopeGuard Security Gate
 * Hard scope validation at every tool invocation – fail-closed design.
 * Prevents hunting outside declared program scope.
 */
import { Request, Response, NextFunction } from "express";
import { db } from "../db";
import { programs, targets } from "../db/schema";
import { eq } from "drizzle-orm";
import logger from "../utils/logger";

export interface ScopeTarget {
  url: string;
  programId: number;
}

export class ScopeGuard {
  private static instance: ScopeGuard;
  private scopeCache = new Map<number, { inScope: string[]; outOfScope: string[]; cachedAt: number }>();
  private readonly CACHE_TTL = 5 * 60 * 1000; // 5 minutes

  static getInstance(): ScopeGuard {
    if (!ScopeGuard.instance) ScopeGuard.instance = new ScopeGuard();
    return ScopeGuard.instance;
  }

  async isInScope(url: string, programId: number): Promise<{ allowed: boolean; reason: string }> {
    try {
      const scope = await this.getScope(programId);
      const hostname = this.extractHostname(url);

      // Check out-of-scope first (fail-closed)
      for (const pattern of scope.outOfScope) {
        if (this.matchesPattern(hostname, pattern)) {
          return { allowed: false, reason: `URL matches out-of-scope pattern: ${pattern}` };
        }
      }

      // Check in-scope
      for (const pattern of scope.inScope) {
        if (this.matchesPattern(hostname, pattern)) {
          return { allowed: true, reason: "URL is in scope" };
        }
      }

      return { allowed: false, reason: "URL not found in any in-scope patterns" };
    } catch (err) {
      logger.error("ScopeGuard error", { err, url, programId });
      return { allowed: false, reason: "Scope validation error – failing closed" };
    }
  }

  private async getScope(programId: number): Promise<{ inScope: string[]; outOfScope: string[] }> {
    const cached = this.scopeCache.get(programId);
    if (cached && Date.now() - cached.cachedAt < this.CACHE_TTL) {
      return { inScope: cached.inScope, outOfScope: cached.outOfScope };
    }

    const [program] = await db.select().from(programs).where(eq(programs.id, programId)).limit(1);
    if (!program) throw new Error(`Program ${programId} not found`);

    const inScope = (program.scope as string[]) || [];
    const outOfScope = (program.outOfScope as string[]) || [];

    this.scopeCache.set(programId, { inScope, outOfScope, cachedAt: Date.now() });
    return { inScope, outOfScope };
  }

  invalidateCache(programId: number): void {
    this.scopeCache.delete(programId);
  }

  private extractHostname(url: string): string {
    try {
      return new URL(url).hostname;
    } catch {
      return url;
    }
  }

  private matchesPattern(hostname: string, pattern: string): boolean {
    // Support wildcards: *.example.com
    const normalized = pattern.replace(/^\*\./, "");
    return hostname === normalized || hostname.endsWith(`.${normalized}`);
  }
}

// Express middleware factory
export function scopeGuardMiddleware(programIdExtractor: (req: Request) => number | null) {
  const guard = ScopeGuard.getInstance();

  return async (req: Request, res: Response, next: NextFunction) => {
    const programId = programIdExtractor(req);
    if (!programId) return next(); // no program context – skip check

    const url = req.body?.url || req.query?.url as string;
    if (!url) return next();

    const { allowed, reason } = await guard.isInScope(url, programId);
    if (!allowed) {
      logger.warn("ScopeGuard blocked request", { url, programId, reason });
      return res.status(403).json({ error: "Out of scope", reason });
    }
    next();
  };
}
