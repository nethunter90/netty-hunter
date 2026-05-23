import { v4 as uuidv4 } from 'uuid';
import { AgentContract, NetworkRequest, GovernancePillar } from '../types';
import { CoreGovernance } from '../core-governance';

/** TTL for scope-verification cache entries (ms). Keeps the 8-pillar check off
 *  the hot path for repeated requests to already-verified endpoints. */
const SCOPE_CACHE_TTL_MS = 5 * 60 * 1000; // 5 minutes

interface ScopeCacheEntry {
  inScope: boolean;
  reason: string;
  expiresAt: number;
}

class ScopeVerifyCache {
  private cache = new Map<string, ScopeCacheEntry>();

  get(hostname: string, huntId?: string): ScopeCacheEntry | null {
    const key = `${hostname}:${huntId ?? ''}`;
    const entry = this.cache.get(key);
    if (!entry) return null;
    if (Date.now() > entry.expiresAt) { this.cache.delete(key); return null; }
    return entry;
  }

  set(hostname: string, huntId: string | undefined, inScope: boolean, reason: string, ttlMs = SCOPE_CACHE_TTL_MS): void {
    const key = `${hostname}:${huntId ?? ''}`;
    this.cache.set(key, { inScope, reason, expiresAt: Date.now() + ttlMs });
    // Evict stale entries lazily to bound memory growth
    if (this.cache.size > 2000) {
      const now = Date.now();
      for (const [k, v] of this.cache) {
        if (v.expiresAt < now) this.cache.delete(k);
      }
    }
  }
}

const BLOCKED_DOMAINS = [
  'localhost', '127.0.0.1', '0.0.0.0',
  '169.254.169.254', 'metadata.google.internal',
  '10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16'
];

const ALWAYS_ALLOWED_DOMAINS = [
  'nvd.nist.gov', 'cve.mitre.org', 'exploit-db.com',
  'cvedetails.com', 'github.com', 'raw.githubusercontent.com',
  'api.github.com', 'crt.sh', 'dns.google',
  'shodan.io', 'api.shodan.io',
  'virustotal.com', 'www.virustotal.com',
  'urlscan.io', 'otx.alienvault.com'
];

export class GovernanceProxy {
  private governance: CoreGovernance;
  private contracts: Map<string, AgentContract> = new Map();
  private requestLog: NetworkRequest[] = [];
  private rateLimitCounters: Map<string, { count: number; windowStart: number }> = new Map();
  private stealthEnabled: boolean = true;
  private scopeCache = new ScopeVerifyCache();

  constructor(governance: CoreGovernance) {
    this.governance = governance;
  }

  registerAgent(contract: AgentContract): void {
    this.contracts.set(contract.agentId, contract);
    this.governance.audit({
      category: 'agent',
      severity: 'info',
      message: `Agent contract registered: ${contract.agentId} (${contract.restrictionLevel})`,
      metadata: {
        agentId: contract.agentId,
        allowedDomains: contract.allowedDomains.length,
        rateLimit: contract.rateLimit,
        restrictionLevel: contract.restrictionLevel
      },
      agentId: contract.agentId
    });
  }

  async validateRequest(
    agentId: string,
    url: string,
    method: string,
    huntId?: string
  ): Promise<{
    allowed: boolean;
    reason: string;
    stealthDelay: number;
    request: NetworkRequest;
  }> {
    const request: NetworkRequest = {
      id: uuidv4(),
      timestamp: new Date(),
      agentId,
      url,
      method,
      status: 'allowed',
      stealth: { delayApplied: 0, jitter: 0 }
    };

    let hostname: string;
    try {
      hostname = new URL(url).hostname;
    } catch {
      request.status = 'blocked';
      request.blockReason = 'Invalid URL';
      this.logRequest(request);
      return { allowed: false, reason: 'Invalid URL', stealthDelay: 0, request };
    }

    if (this.isBlockedDomain(hostname)) {
      request.status = 'blocked';
      request.blockReason = `Blocked domain: ${hostname}`;
      this.logRequest(request);

      this.governance.recordDecision({
        agentId,
        agentName: `Agent ${agentId}`,
        action: `Network request: ${method} ${url}`,
        actionType: 'network',
        verdict: 'blocked',
        pillar: 'Pillar 3 - Ethical Boundary',
        confidence: 1.0,
        reason: `Domain "${hostname}" is blocked (internal/cloud metadata)`,
        coachMessage: `Network access to ${hostname} is blocked to prevent SSRF and internal network access.`,
        huntId
      });

      return { allowed: false, reason: `Blocked domain: ${hostname}`, stealthDelay: 0, request };
    }

    const contract = this.contracts.get(agentId);
    if (contract) {
      if (contract.restrictionLevel === 'strict') {
        const domainAllowed = contract.allowedDomains.some(d =>
          hostname === d || hostname.endsWith('.' + d)
        ) || ALWAYS_ALLOWED_DOMAINS.some(d => hostname === d || hostname.endsWith('.' + d));

        if (!domainAllowed) {
          request.status = 'blocked';
          request.blockReason = 'Domain not in agent contract';
          this.logRequest(request);

          this.governance.recordDecision({
            agentId,
            agentName: `Agent ${agentId}`,
            action: `Network request: ${method} ${url}`,
            actionType: 'network',
            verdict: 'blocked',
            pillar: 'Safety Controls',
            confidence: 0.9,
            reason: `Domain "${hostname}" not in agent's allowed domains`,
            coachMessage: `This agent is restricted to specific domains. ${hostname} is not on the list.`,
            huntId
          });

          return { allowed: false, reason: 'Domain not in agent contract', stealthDelay: 0, request };
        }
      }

      if (!this.checkRateLimit(agentId, contract.rateLimit)) {
        request.status = 'blocked';
        request.blockReason = 'Rate limit exceeded';
        this.logRequest(request);

        this.governance.recordDecision({
          agentId,
          agentName: `Agent ${agentId}`,
          action: `Network request: ${method} ${url}`,
          actionType: 'network',
          verdict: 'blocked',
          pillar: 'Safety Controls',
          confidence: 1.0,
          reason: `Rate limit exceeded (${contract.rateLimit}/min)`,
          coachMessage: `Agent has exceeded its rate limit of ${contract.rateLimit} requests per minute. Please slow down.`,
          huntId
        });

        return { allowed: false, reason: 'Rate limit exceeded', stealthDelay: 0, request };
      }
    }

    // Fast path: always-allowed domains bypass scope verification entirely
    const isAlwaysAllowed = ALWAYS_ALLOWED_DOMAINS.some(d => hostname === d || hostname.endsWith('.' + d));
    const cached = isAlwaysAllowed ? null : this.scopeCache.get(hostname, huntId);
    const scopeCheck = cached ?? await this.governance.verifyScope(hostname, huntId);
    if (!cached && !isAlwaysAllowed) {
      // Cache the result so subsequent requests to this host skip the 8-pillar check
      this.scopeCache.set(hostname, huntId, scopeCheck.inScope, scopeCheck.reason ?? '');
    }
    if (!scopeCheck.inScope) {
      request.status = 'blocked';
      request.blockReason = 'Out of scope';
      this.logRequest(request);
      return { allowed: false, reason: `Out of scope: ${scopeCheck.reason}`, stealthDelay: 0, request };
    }

    let stealthDelay = 0;
    if (this.stealthEnabled) {
      const baseDelay = 500 + Math.random() * 2000;
      const jitter = Math.random() * 500;
      stealthDelay = Math.round(baseDelay + jitter);
      request.stealth = { delayApplied: Math.round(baseDelay), jitter: Math.round(jitter) };
    }

    request.status = 'allowed';
    this.logRequest(request);

    this.governance.recordDecision({
      agentId,
      agentName: `Agent ${agentId}`,
      action: `Network request: ${method} ${url}`,
      actionType: 'network',
      verdict: 'approved',
      pillar: 'Blue Team Oversight',
      confidence: 0.85,
      reason: `Request to ${hostname} approved`,
      coachMessage: `Network request approved. Stealth delay: ${stealthDelay}ms`,
      huntId
    });

    return { allowed: true, reason: 'Approved', stealthDelay, request };
  }

  private isBlockedDomain(hostname: string): boolean {
    for (const blocked of BLOCKED_DOMAINS) {
      if (blocked.includes('/')) continue;
      if (hostname === blocked) return true;
    }

    const parts = hostname.split('.').map(Number);
    if (parts.length === 4 && parts.every(p => !isNaN(p))) {
      const ip = parts;
      if (ip[0] === 10) return true;
      if (ip[0] === 172 && ip[1] >= 16 && ip[1] <= 31) return true;
      if (ip[0] === 192 && ip[1] === 168) return true;
      if (ip[0] === 169 && ip[1] === 254) return true;
    }

    return false;
  }

  private checkRateLimit(agentId: string, limit: number): boolean {
    const now = Date.now();
    const counter = this.rateLimitCounters.get(agentId);

    if (!counter || now - counter.windowStart > 60000) {
      this.rateLimitCounters.set(agentId, { count: 1, windowStart: now });
      return true;
    }

    counter.count++;
    return counter.count <= limit;
  }

  private logRequest(request: NetworkRequest): void {
    this.requestLog.push(request);
    if (this.requestLog.length > 10000) {
      this.requestLog = this.requestLog.slice(-5000);
    }
  }

  setStealthMode(enabled: boolean): void {
    this.stealthEnabled = enabled;
  }

  getRequestLog(filters?: {
    agentId?: string;
    status?: 'allowed' | 'blocked';
    limit?: number;
  }): NetworkRequest[] {
    let results = [...this.requestLog];

    if (filters?.agentId) results = results.filter(r => r.agentId === filters.agentId);
    if (filters?.status) results = results.filter(r => r.status === filters.status);

    results.sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime());

    if (filters?.limit) results = results.slice(0, filters.limit);

    return results;
  }

  getAgentContracts(): AgentContract[] {
    const result: AgentContract[] = [];
    this.contracts.forEach(v => result.push(v));
    return result;
  }

  getStats(): {
    totalRequests: number;
    allowed: number;
    blocked: number;
    blockRate: number;
    stealthEnabled: boolean;
    registeredAgents: number;
  } {
    const allowed = this.requestLog.filter(r => r.status === 'allowed').length;
    const blocked = this.requestLog.filter(r => r.status === 'blocked').length;
    const total = this.requestLog.length;

    return {
      totalRequests: total,
      allowed,
      blocked,
      blockRate: total > 0 ? Math.round((blocked / total) * 100) : 0,
      stealthEnabled: this.stealthEnabled,
      registeredAgents: this.contracts.size
    };
  }
}
