import { pool } from '../../db';
import { huntCortex, SignalType } from '../intelligence/hunt-cortex';
import { dynamicRateLimiter } from './dynamic-rate-limiter';
import type { AxiosProxyConfig } from 'axios';

export interface ProxyRoute {
  id: string;
  type: 'http' | 'socks5' | 'tor' | 'direct';
  url: string;       // "http://host:port", "socks5://host:port", or "" for direct
  host: string;
  port: number;
  priority: number;  // lower = higher preference; 0 = highest
  geo?: string;
}

interface RouteHealth {
  proxyId: string;
  target: string;
  successCount: number;
  failureCount: number;
  totalLatencyMs: number;
  avgLatencyMs: number;
  burned: boolean;
  burnedUntil: number;
  dirty: boolean;    // needs flush to DB
}

export interface AllocatedRoute {
  proxyId: string;
  isDirect: boolean;
  proxyUrl: string | null;
  // null for socks5/tor — those route via proxychains on CLI tools only
  // TODO: add socks-proxy-agent for in-process SOCKS5 support
  axiosProxy: AxiosProxyConfig | null;
  rationale: string;
}

const FLUSH_INTERVAL_MS = 30_000;

class EgressRouteAllocator {
  private routes: ProxyRoute[] = [];
  private health: Map<string /* proxyId:target */, RouteHealth> = new Map();
  private currentAssignments: Map<string /* target */, string /* proxyId */> = new Map();
  private flushTimer: ReturnType<typeof setInterval> | null = null;
  private socketEmitter: ((event: string, data: unknown) => void) | null = null;

  constructor() {
    this.parseEnvPool();
    this.ensureDirectRoute();
    this.startFlushTimer();
    // Burn the currently-assigned route when the rate limiter detects a hard ban
    dynamicRateLimiter.onHardBan((target, durationMs) => {
      const hostname = this.extractHostname(target);
      const proxyId = this.currentAssignments.get(hostname) ?? 'direct';
      this.burnRoute(proxyId, target, durationMs);
    });
  }

  // ─── Pool Management ────────────────────────────────────────────────────────

  setSocketEmitter(emit: (event: string, data: unknown) => void): void {
    this.socketEmitter = emit;
  }

  getCurrentAssignment(target: string): string | undefined {
    return this.currentAssignments.get(this.extractHostname(target));
  }

  register(route: ProxyRoute): void {
    if (!this.routes.find(r => r.id === route.id)) {
      this.routes.push(route);
    }
  }

  private parseEnvPool(): void {
    const raw = process.env.PROXY_POOL || '';
    if (!raw.trim()) return;
    raw.split(',').forEach((entry, idx) => {
      const url = entry.trim();
      if (!url) return;
      try {
        const parsed = new URL(url);
        const type = parsed.protocol === 'socks5:' ? 'socks5'
          : parsed.protocol === 'tor:' ? 'tor'
          : 'http';
        this.register({
          id: `pool_${idx}`,
          type,
          url,
          host: parsed.hostname,
          port: parseInt(parsed.port || '8080', 10),
          priority: idx,
        });
      } catch {
        console.warn(`[EgressAllocator] invalid proxy URL: ${url}`);
      }
    });
  }

  private ensureDirectRoute(): void {
    if (!this.routes.find(r => r.id === 'direct')) {
      this.routes.push({ id: 'direct', type: 'direct', url: '', host: '', port: 0, priority: 99 });
    }
  }

  // ─── Route Allocation ───────────────────────────────────────────────────────

  allocate(target: string, tool: string, huntId: string): AllocatedRoute {
    const hostname = this.extractHostname(target);
    const now = Date.now();

    const eligible = this.routes.filter(r => {
      const h = this.getHealth(r.id, hostname);
      return !(h.burned && h.burnedUntil > now);
    });

    if (eligible.length === 0) {
      // All routes burned — emit exhausted signal and use least-recently-burned
      huntCortex.broadcast({
        signalType: SignalType.EGRESS_ROUTE_EXHAUSTED,
        sourceSystem: 'egress-route-allocator',
        huntId,
        payload: { target: hostname, tool, routeCount: this.routes.length },
        confidence: 1.0,
      }).catch(() => {});

      const fallback = [...this.routes].sort((a, b) => {
        const ha = this.getHealth(a.id, hostname);
        const hb = this.getHealth(b.id, hostname);
        return ha.burnedUntil - hb.burnedUntil;
      })[0] ?? this.routes[this.routes.length - 1];

      return this.buildAllocation(fallback, 'all-routes-burned-fallback');
    }

    // Score eligible routes
    const scored = eligible.map(r => ({
      route: r,
      score: this.scoreRoute(r, hostname),
    })).sort((a, b) => b.score - a.score);

    const best = scored[0].route;
    const prevId = this.currentAssignments.get(hostname);

    if (prevId && prevId !== best.id) {
      const changePayload = { target: hostname, tool, from: prevId, to: best.id, huntId };
      huntCortex.broadcast({
        signalType: SignalType.EGRESS_ROUTE_CHANGED,
        sourceSystem: 'egress-route-allocator',
        huntId,
        payload: changePayload,
        confidence: 0.9,
      }).catch(() => {});
      this.socketEmitter?.('egress:route_changed', changePayload);
    }

    this.currentAssignments.set(hostname, best.id);
    return this.buildAllocation(best, `score=${scored[0].score.toFixed(3)}`);
  }

  private scoreRoute(route: ProxyRoute, target: string): number {
    const h = this.getHealth(route.id, target);
    const total = h.successCount + h.failureCount;
    const successRate = total > 0 ? h.successCount / total : 0.75; // optimistic prior
    const latencyScore = 1 - Math.min(h.avgLatencyMs, 10_000) / 10_000;
    const priorityScore = 1 - route.priority / 100;
    return successRate * 0.5 + latencyScore * 0.3 + priorityScore * 0.2;
  }

  private buildAllocation(route: ProxyRoute, rationale: string): AllocatedRoute {
    const isDirect = route.type === 'direct';
    const proxyUrl = isDirect ? null : route.url;
    const axiosProxy: AxiosProxyConfig | null =
      route.type === 'http' && !isDirect
        ? { host: route.host, port: route.port, protocol: 'http' }
        : null;

    return { proxyId: route.id, isDirect, proxyUrl, axiosProxy, rationale };
  }

  // ─── Outcome Recording ──────────────────────────────────────────────────────

  recordOutcome(proxyId: string, target: string, statusCode: number, latencyMs: number): void {
    const hostname = this.extractHostname(target);
    const h = this.getHealth(proxyId, hostname);
    if (statusCode >= 200 && statusCode < 500) {
      h.successCount++;
    } else {
      h.failureCount++;
    }
    const total = h.successCount + h.failureCount;
    h.avgLatencyMs = h.totalLatencyMs / total;
    h.totalLatencyMs += latencyMs;
    h.dirty = true;
  }

  burnRoute(proxyId: string, target: string, durationMs: number): void {
    const hostname = this.extractHostname(target);
    const h = this.getHealth(proxyId, hostname);
    h.burned = true;
    h.burnedUntil = Date.now() + durationMs;
    h.dirty = true;
    console.log(`[EgressAllocator] route ${proxyId} burned for ${hostname} (${Math.round(durationMs / 60_000)}min)`);
  }

  // ─── Health Map Helpers ─────────────────────────────────────────────────────

  private getHealth(proxyId: string, target: string): RouteHealth {
    const key = `${proxyId}:${target}`;
    if (!this.health.has(key)) {
      this.health.set(key, {
        proxyId, target,
        successCount: 0, failureCount: 0,
        totalLatencyMs: 0, avgLatencyMs: 0,
        burned: false, burnedUntil: 0,
        dirty: false,
      });
    }
    return this.health.get(key)!;
  }

  private extractHostname(target: string): string {
    try {
      return new URL(target.startsWith('http') ? target : `http://${target}`).hostname;
    } catch {
      return target;
    }
  }

  // ─── DB Persistence ─────────────────────────────────────────────────────────

  async loadMetricsFromDB(): Promise<void> {
    try {
      const { rows } = await pool.query(
        `SELECT proxy_id, target, success_count, failure_count, avg_latency_ms,
                burned, banned_until
         FROM egress_route_metrics`
      );
      for (const row of rows) {
        const h = this.getHealth(row.proxy_id, row.target);
        h.successCount = row.success_count;
        h.failureCount = row.failure_count;
        h.avgLatencyMs = row.avg_latency_ms;
        h.burned = row.burned;
        h.burnedUntil = row.banned_until ? new Date(row.banned_until).getTime() : 0;
        h.dirty = false;
      }
    } catch (err) {
      console.warn('[EgressAllocator] could not load metrics from DB:', err);
    }
  }

  private startFlushTimer(): void {
    this.flushTimer = setInterval(() => this.flushDirtyMetrics(), FLUSH_INTERVAL_MS);
  }

  private async flushDirtyMetrics(): Promise<void> {
    const dirty = [...this.health.values()].filter(h => h.dirty);
    if (dirty.length === 0) return;

    for (const h of dirty) {
      try {
        const id = `${h.proxyId}:${h.target}`;
        const bannedUntil = h.burnedUntil > 0 ? new Date(h.burnedUntil).toISOString() : null;
        await pool.query(
          `INSERT INTO egress_route_metrics
             (id, proxy_id, target, success_count, failure_count, avg_latency_ms,
              last_used_at, burned, banned_until)
           VALUES ($1,$2,$3,$4,$5,$6,NOW(),$7,$8)
           ON CONFLICT (proxy_id, target) DO UPDATE SET
             success_count = $4,
             failure_count = $5,
             avg_latency_ms = $6,
             last_used_at = NOW(),
             burned = $7,
             banned_until = $8`,
          [id, h.proxyId, h.target, h.successCount, h.failureCount,
           h.avgLatencyMs, h.burned, bannedUntil]
        );
        h.dirty = false;
      } catch {
        // non-critical — will retry on next flush
      }
    }
  }

  // ─── Public Inspection ──────────────────────────────────────────────────────

  getPoolStatus(): Array<{ route: ProxyRoute; health: RouteHealth[] }> {
    return this.routes.map(r => ({
      route: r,
      health: [...this.health.values()].filter(h => h.proxyId === r.id),
    }));
  }
}

export const egressAllocator = new EgressRouteAllocator();

// Load persisted burn state from DB at startup (fire-and-forget)
egressAllocator.loadMetricsFromDB().catch(() => {});
