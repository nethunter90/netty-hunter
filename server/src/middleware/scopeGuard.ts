/**
 * ScopeGuard Security Gate
 * Hard scope validation at every tool invocation – fail-closed design.
 * Prevents hunting outside declared program scope.
 * DNS rebinding protection: resolves hostname to IP on every check and blocks
 * RFC1918/loopback/link-local addresses to prevent TOCTOU scope bypass.
 */
import dns from "dns";
import { promisify } from "util";
import { Request, Response, NextFunction } from "express";
import { db } from "../db";
import { programs, targets } from "../db/schema";
import { eq } from "drizzle-orm";
import logger from "../utils/logger";

const dnsLookupAsync = promisify(dns.lookup);

function isPrivateIP(ip: string): boolean {
  const p = ip.split(".").map(Number);
  if (p.length === 4) {
    if (p[0] === 10) return true;
    if (p[0] === 172 && p[1] >= 16 && p[1] <= 31) return true;
    if (p[0] === 192 && p[1] === 168) return true;
    if (p[0] === 127) return true;
    if (p[0] === 169 && p[1] === 254) return true;
    if (p[0] === 0) return true;
  }
  if (ip === "::1" || ip === "0:0:0:0:0:0:0:1") return true;
  if (/^(fc|fd)/i.test(ip)) return true; // IPv6 ULA
  return false;
}

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

      // DNS rebinding protection: resolve to IP and block private/internal ranges.
      // Done on every call (never cached) so a TOCTOU rebind can't slip through.
      try {
        const { address } = await dnsLookupAsync(hostname);
        if (isPrivateIP(address)) {
          logger.warn("ScopeGuard: DNS rebinding blocked", { hostname, address });
          return { allowed: false, reason: `DNS rebinding protection: ${hostname} resolved to private IP ${address}` };
        }
      } catch {
        // DNS resolution failure is non-fatal for scope pattern check but we log it.
        logger.debug("ScopeGuard: DNS lookup failed (non-fatal)", { hostname });
      }

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
