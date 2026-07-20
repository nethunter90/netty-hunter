/**
 * ScopeGuard Security Gate
 * Hard scope validation at every tool invocation – fail-closed design.
 * Prevents hunting outside declared program scope.
 *
 * DNS protection: follows the full CNAME chain and checks every A record
 * on the terminal hostname so DNS rebinding and shared-infra pivots are
 * both caught before Layer 2 fires any payload.
 *
 * programId policy (three-way, see classifyProgramPolicy):
 *   - "real"    (programId > 0)  — full protection: private/loopback IP
 *                                  resolution is blocked (rebinding/SSRF),
 *                                  and IP/CIDR exclusions are enforced with
 *                                  a fail-closed DNS-failure posture.
 *   - "lab"     (programId === -1) — the explicit local-lab sentinel. Scope
 *                                  + exclusions (including IP/CIDR excludes)
 *                                  are enforced exactly as for "real"; ONLY
 *                                  the private/loopback-IP block is relaxed,
 *                                  because every current hunt target lives
 *                                  on loopback/RFC-1918 by design.
 *   - "invalid" (missing/0/other) — fail closed before any DB/DNS work. A
 *                                  real hunt launched without a valid
 *                                  programId must never silently run
 *                                  unguarded, and must never be treated as lab.
 */
import dns from "dns";
import { Request, Response, NextFunction } from "express";
import { db } from "../db";
import { programs, targets } from "../db/schema";
import { eq } from "drizzle-orm";
import logger from "../utils/logger";

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

/** Three-way programId policy — see module docstring for the semantics of each. */
export type ScopePolicy = "real" | "lab" | "invalid";

export function classifyProgramPolicy(programId: number | null | undefined): ScopePolicy {
  if (programId === -1) return "lab";
  if (typeof programId === "number" && Number.isFinite(programId) && programId > 0) return "real";
  return "invalid";
}

/** IPv4-only CIDR/exact-IP matcher for user-declared IP/CIDR exclusions —
 *  distinct from the automatic RFC-1918 rebinding block above, which fires
 *  regardless of what the scope explicitly lists. */
function ipv4ToInt(ip: string): number | null {
  const p = ip.split(".").map(Number);
  if (p.length !== 4 || p.some(n => !Number.isInteger(n) || n < 0 || n > 255)) return null;
  return ((p[0] << 24) | (p[1] << 16) | (p[2] << 8) | p[3]) >>> 0;
}

/** True if `pattern` is shaped like an IPv4 address or CIDR block (as opposed
 *  to a hostname pattern). IPv6 IP/CIDR exclusions are not recognized here —
 *  a documented gap (matches the existing IPv4-only rebinding check), not a
 *  silent bypass: such a pattern simply falls through to hostMatches() and
 *  never matches as a hostname either, so it's inert rather than dangerous. */
export function isIpOrCidrPattern(pattern: string): boolean {
  return /^\d{1,3}(\.\d{1,3}){3}(\/\d{1,2})?$/.test(pattern.trim());
}

export function ipMatchesPattern(ip: string, pattern: string): boolean {
  const [base, bits] = pattern.trim().split("/");
  const ipInt = ipv4ToInt(ip);
  const baseInt = ipv4ToInt(base);
  if (ipInt === null || baseInt === null) return false;
  if (bits === undefined) return ipInt === baseInt;
  const prefix = Number(bits);
  if (!Number.isInteger(prefix) || prefix < 0 || prefix > 32) return false;
  const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
  return (ipInt & mask) === (baseInt & mask);
}

// Definitive multi-tenant SaaS platforms — payloads here hit shared infrastructure.
const SHARED_INFRA_BLOCK = [
  /(?:^|\.)salesforce\.com$/i,
  /(?:^|\.)force\.com$/i,
  /(?:^|\.)shopify\.com$/i,
  /(?:^|\.)myshopify\.com$/i,
  /(?:^|\.)zendesk\.com$/i,
  /(?:^|\.)hubspot\.com$/i,
  /(?:^|\.)hubspotpages\.com$/i,
  /(?:^|\.)freshdesk\.com$/i,
  /(?:^|\.)intercom\.io$/i,
  /(?:^|\.)helpscout\.net$/i,
  /(?:^|\.)atlassian\.net$/i,
  /(?:^|\.)jira\.com$/i,
  /(?:^|\.)stripe\.com$/i,
  /(?:^|\.)squarespace\.com$/i,
  /(?:^|\.)wix\.com$/i,
  /(?:^|\.)wordpress\.com$/i,
];

// CDN providers — the target legitimately chose them; allow but emit a Cortex warning
// so the strategy layer knows aggressive payloads are hitting a shared edge node.
const SHARED_INFRA_WARN = [
  /(?:^|\.)cloudfront\.net$/i,
  /(?:^|\.)akamaiedge\.net$/i,
  /(?:^|\.)akamai\.net$/i,
  /(?:^|\.)edgesuite\.net$/i,
  /(?:^|\.)edgekey\.net$/i,
  /(?:^|\.)fastly\.net$/i,
  /(?:^|\.)cdn77\.com$/i,
  /(?:^|\.)azureedge\.net$/i,
];

/** Follow the CNAME chain from hostname up to maxDepth hops.
 *  Returns the full chain: [entry, hop1, …, terminal].
 *  Stops on loop detection, resolution failure, or depth limit. */
async function followCNAMEChain(hostname: string, maxDepth = 10): Promise<string[]> {
  const chain: string[] = [hostname];
  const seen = new Set<string>([hostname]);
  let current = hostname;

  for (let i = 0; i < maxDepth; i++) {
    let cnames: string[];
    try {
      cnames = await dns.promises.resolve(current, "CNAME");
    } catch {
      break; // No CNAME record — current is the terminal
    }
    if (!cnames.length) break;
    const next = cnames[0].replace(/\.$/, ""); // strip trailing dot
    if (seen.has(next)) break;                 // loop guard
    seen.add(next);
    chain.push(next);
    current = next;
  }

  return chain;
}

/** Classify the terminal CNAME hostname.
 *  'block'  — definitive shared-tenant SaaS, refuse the request.
 *  'warn'   — CDN edge node, allow but signal the Cortex.
 *  'ok'     — no known shared-infra pattern detected. */
function classifyTerminal(hostname: string): "block" | "warn" | "ok" {
  if (SHARED_INFRA_BLOCK.some(re => re.test(hostname))) return "block";
  if (SHARED_INFRA_WARN.some(re => re.test(hostname))) return "warn";
  return "ok";
}

// ── Path-aware scope matching (pure, exported for unit testing) ────────────────
// A scope pattern is host-only ("example.com", "*.example.com", "*") or host+path
// ("localhost:5000/api/Addresss"). Host-only admits any path (backward-compatible);
// host+path restricts to that path subtree. Adding path enforcement can only NARROW
// the allowed set — it never widens what host-level scope already permitted.

/** Strip a `:port` suffix from a host, leaving IPv6 literals intact.
 *  Handles bracketed IPv6 ("[::1]:5000" → "::1"); only strips host:port when there
 *  is a single colon (IPv4/hostname) so bare IPv6 ("::1") is untouched. */
function stripPort(host: string): string {
  if (host.startsWith("[")) {
    const m = host.match(/^\[(.+?)\](?::\d+)?$/);
    if (m) return m[1];
  }
  if ((host.match(/:/g) || []).length === 1) return host.replace(/:\d+$/, "");
  return host;
}

/** True for intentionally-local targets (loopback / RFC-1918 / link-local literals).
 *  DNS-rebinding protection only matters when a PUBLIC host resolves to a private IP;
 *  a target whose hostname is already local has nothing to rebind. */
export function isLocalHostname(hostname: string): boolean {
  const h = stripPort(hostname.toLowerCase());
  if (h === "localhost" || h.endsWith(".localhost")) return true;
  if (h === "::1" || h === "0:0:0:0:0:0:0:1") return true;
  if (h.includes(":") && /^(fc|fd)/i.test(h)) return true; // IPv6 ULA
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(h)) return isPrivateIP(h);
  return false;
}

/** Split a scope pattern into a host part and an optional normalized path prefix. */
export function parsePattern(pattern: string): { hostPart: string; pathPrefix: string | null } {
  const p = pattern.trim().replace(/^https?:\/\//i, ""); // strip scheme
  const slash = p.indexOf("/");
  if (slash === -1) return { hostPart: p, pathPrefix: null };
  const hostPart = p.slice(0, slash);
  let path = p.slice(slash);                 // includes leading '/'
  if (path.length > 1) path = path.replace(/\/+$/, ""); // drop trailing slash(es)
  return { hostPart, pathPrefix: path || "/" };
}

/** Host comparison. Strips port and wildcard prefix; '*' matches any host.
 *  Case-insensitive. (Port is not part of host identity — consistent with how
 *  bug-bounty host scope works, and required for localhost:PORT scoping.) */
export function hostMatches(hostname: string, hostPart: string): boolean {
  if (hostPart === "*") return true;
  const n = stripPort(hostPart).replace(/^\*\./, "").toLowerCase();
  const h = stripPort(hostname).toLowerCase();
  return h === n || h.endsWith(`.${n}`);
}

/** Boundary-safe path-prefix match. A null/root prefix admits any path. */
export function pathMatches(pathname: string, pathPrefix: string | null): boolean {
  if (pathPrefix === null || pathPrefix === "" || pathPrefix === "/") return true;
  const prefix = pathPrefix.replace(/\/+$/, "");
  return pathname === prefix || pathname.startsWith(`${prefix}/`);
}

/** Pure host+path scope decision (no DNS/CNAME). Out-of-scope takes precedence;
 *  in-scope requires a pattern matching BOTH host and path. */
export function evaluateScopeDecision(
  hostname: string,
  pathname: string,
  inScope: string[],
  outOfScope: string[],
): { allowed: boolean; reason: string } {
  for (const pat of outOfScope) {
    const { hostPart, pathPrefix } = parsePattern(pat);
    if (hostMatches(hostname, hostPart) && pathMatches(pathname, pathPrefix)) {
      return { allowed: false, reason: `URL matches out-of-scope pattern: ${pat}` };
    }
  }
  let hostInScope = false;
  for (const pat of inScope) {
    const { hostPart, pathPrefix } = parsePattern(pat);
    if (hostMatches(hostname, hostPart)) {
      hostInScope = true;
      if (pathMatches(pathname, pathPrefix)) return { allowed: true, reason: "URL is in scope" };
    }
  }
  if (!hostInScope) return { allowed: false, reason: "URL not found in any in-scope patterns" };
  return { allowed: false, reason: `host in scope but path '${pathname}' is outside the in-scope path prefix(es)` };
}

export interface ScopeTarget {
  url: string;
  programId: number;
}

export class ScopeGuard {
  private static instance: ScopeGuard;
  private scopeCache = new Map<number, { inScope: string[]; outOfScope: string[]; cachedAt: number }>();
  private readonly CACHE_TTL = 30 * 1000; // 30 seconds — short TTL so scope changes take effect quickly

  static getInstance(): ScopeGuard {
    if (!ScopeGuard.instance) ScopeGuard.instance = new ScopeGuard();
    return ScopeGuard.instance;
  }

  // Telemetry only — counts every scope decision (hunt-phase AND manual UI checks)
  // since all callers funnel through isInScope(). Does NOT affect enforcement.
  private stats = { totalChecks: 0, allowed: 0, blocked: 0 };

  getStats(): { totalChecks: number; allowed: number; blocked: number; blockRate: number } {
    const { totalChecks, allowed, blocked } = this.stats;
    return { totalChecks, allowed, blocked, blockRate: totalChecks > 0 ? blocked / totalChecks : 0 };
  }

  /** Public entry point — tallies the decision then returns the unchanged verdict. */
  async isInScope(url: string, programId: number | null | undefined): Promise<{
    allowed: boolean;
    reason: string;
    sharedInfraWarning?: string;
  }> {
    const result = await this.evaluateScope(url, programId);
    this.stats.totalChecks++;
    if (result.allowed) this.stats.allowed++; else this.stats.blocked++;
    return result;
  }

  // Enforcement logic — isInScope() wraps this to add telemetry.
  private async evaluateScope(url: string, programId: number | null | undefined): Promise<{
    allowed: boolean;
    reason: string;
    sharedInfraWarning?: string;
  }> {
    // Fat-finger guard: classify BEFORE any DB/DNS work. A missing/zero/other
    // programId is never treated as lab-mode — it fails closed immediately.
    const policy = classifyProgramPolicy(programId);
    if (policy === "invalid") {
      logger.warn("ScopeGuard: invalid programId — failing closed", { url, programId });
      return { allowed: false, reason: `Invalid programId (${String(programId)}) — failing closed` };
    }

    try {
      const scope = await this.getScope(programId as number);
      const hostname = this.extractHostname(url);
      let pathname = "/";
      try { pathname = new URL(url).pathname || "/"; } catch { /* non-URL input → root */ }

      // Host + path scope gate (out-of-scope precedence; in-scope needs host AND path).
      // Host-only patterns admit any path, so existing host-level scopes are unchanged;
      // path-bearing patterns (e.g. "localhost:5000/api/Addresss") restrict to the subtree.
      const decision = evaluateScopeDecision(hostname, pathname, scope.inScope, scope.outOfScope);
      if (!decision.allowed) {
        return { allowed: false, reason: decision.reason };
      }

      // Follow the CNAME chain; fall back to [hostname] if DNS is unavailable.
      let chain: string[];
      try {
        chain = await followCNAMEChain(hostname);
      } catch {
        chain = [hostname];
      }

      // Sweep every hop after the entry against the out-of-scope HOSTS (path is
      // irrelevant to a CNAME hop — match on the host part only).
      for (const hop of chain.slice(1)) {
        for (const pattern of scope.outOfScope) {
          if (hostMatches(hop, parsePattern(pattern).hostPart)) {
            logger.warn("ScopeGuard: CNAME chain hop matches out-of-scope", { hop, pattern });
            return { allowed: false, reason: `CNAME chain passes through out-of-scope pattern: ${pattern} (via ${hop})` };
          }
        }
      }

      // Classify the terminal hostname for shared-infrastructure detection.
      const terminal = chain[chain.length - 1];
      const termClass = classifyTerminal(terminal);
      if (termClass === "block") {
        logger.warn("ScopeGuard: CNAME chain terminates at shared-tenant SaaS", { terminal, chain });
        return { allowed: false, reason: `CNAME chain resolves to shared-tenant platform: ${terminal}` };
      }

      // Resolve the terminal's A records once — feeds both the rebinding block
      // (policy-gated below) and the IP/CIDR exclusion check (always active).
      const ipCidrExclusions = scope.outOfScope.filter(isIpOrCidrPattern);
      let resolvedIps: string[] | null = null;
      let resolveFailed = false;
      try {
        resolvedIps = await dns.promises.resolve4(terminal);
      } catch {
        resolveFailed = true;
      }

      // IP/CIDR exclusions — enforced identically for "real" and "lab" (these are
      // explicit user-declared excludes, not the automatic private-range block).
      if (ipCidrExclusions.length > 0) {
        if (resolvedIps) {
          for (const ip of resolvedIps) {
            for (const pattern of ipCidrExclusions) {
              if (ipMatchesPattern(ip, pattern)) {
                logger.warn("ScopeGuard: resolved IP matches IP/CIDR exclusion", { terminal, ip, pattern });
                return { allowed: false, reason: `Resolved IP ${ip} matches out-of-scope pattern: ${pattern}` };
              }
            }
          }
        } else if (policy === "real") {
          // Can't verify where a "real" program's host resolves — don't send.
          logger.warn("ScopeGuard: DNS resolution failed for IP/CIDR exclusion check — failing closed (real program)", { terminal });
          return { allowed: false, reason: `Could not resolve ${terminal} to verify IP/CIDR exclusions — failing closed` };
        }
        // policy === "lab" + resolve failure: non-fatal, mirrors the rebinding
        // soft-fail below — lab targets (localhost) always resolve in practice.
      }

      // Automatic private/loopback-IP rebinding block — policy-gated.
      // "real": always active. "lab": relaxed, since every current hunt target
      // lives on loopback/RFC-1918 by design (see module docstring).
      const skipRebindingBlock = policy === "lab" || isLocalHostname(hostname);
      if (!skipRebindingBlock) {
        if (resolvedIps) {
          for (const ip of resolvedIps) {
            if (isPrivateIP(ip)) {
              logger.warn("ScopeGuard: DNS rebinding blocked", { terminal, ip });
              return { allowed: false, reason: `DNS rebinding protection: ${terminal} resolved to private IP ${ip}` };
            }
          }
        } else if (resolveFailed) {
          // Resolution failure is non-fatal for the rebinding check specifically —
          // hostname may lack A records (IPv6-only, etc.). Documented, deliberate
          // exception to the outer fail-closed guarantee; narrower than it looks
          // because the IP/CIDR check above already fails closed for "real" when
          // exclusions are declared. Left as-is per amendment 3.
          logger.debug("ScopeGuard: resolve4 failed for terminal (non-fatal)", { terminal });
        }
      }

      const sharedInfraWarning = termClass === "warn"
        ? `CNAME chain routes through CDN edge node: ${terminal}`
        : undefined;

      return { allowed: true, reason: "URL is in scope", sharedInfraWarning };
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
}

// Express middleware factory — NOT currently wired to any route (verified: no
// caller anywhere imports scopeGuardMiddleware). Left as dead code, out of scope
// for the transport-layer chokepoint handoff since it's not on the egress path.
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
