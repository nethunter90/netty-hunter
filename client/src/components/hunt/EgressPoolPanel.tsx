import { useState, useEffect, useCallback } from "react";
import { ChevronDown, ChevronRight, Network } from "lucide-react";
import type { Socket } from "socket.io-client";

interface RouteHealth {
  proxyId: string;
  target: string;
  successCount: number;
  failureCount: number;
  avgLatencyMs: number;
  burned: boolean;
  burnedUntil: number;
}

interface ProxyRoute {
  id: string;
  type: "http" | "socks5" | "tor" | "direct";
  url: string;
  host: string;
  port: number;
  priority: number;
  geo?: string;
}

interface PoolEntry {
  route: ProxyRoute;
  health: RouteHealth[];
}

interface RouteChangedPayload {
  target: string;
  tool: string;
  from?: string;
  to: string;
  huntId: string;
}

const POLL_INTERVAL_MS = 15_000;
const FLASH_DURATION_MS = 2_000;

function successRate(health: RouteHealth[]): number {
  const total = health.reduce((s, h) => s + h.successCount + h.failureCount, 0);
  const success = health.reduce((s, h) => s + h.successCount, 0);
  return total > 0 ? success / total : 0;
}

function totalRequests(health: RouteHealth[]): number {
  return health.reduce((s, h) => s + h.successCount + h.failureCount, 0);
}

function isBurned(health: RouteHealth[]): boolean {
  const now = Date.now();
  return health.some(h => h.burned && h.burnedUntil > now);
}

function burnCountdown(health: RouteHealth[]): number {
  const now = Date.now();
  const latest = health.reduce((max, h) => (h.burned && h.burnedUntil > max ? h.burnedUntil : max), 0);
  return latest > now ? Math.ceil((latest - now) / 1000) : 0;
}

function RateBar({ rate }: { rate: number }) {
  const pct = Math.round(rate * 100);
  const color = rate >= 0.8 ? "bg-emerald-500" : rate >= 0.5 ? "bg-amber-400" : "bg-red-500";
  return (
    <div className="flex items-center gap-1.5">
      <div className="w-14 h-1.5 bg-zinc-800 rounded-full overflow-hidden">
        <div className={`h-full rounded-full ${color}`} style={{ width: `${pct}%` }} />
      </div>
      <span className="text-[9px] text-hack-dim w-7">{pct}%</span>
    </div>
  );
}

function TypeChip({ type }: { type: ProxyRoute["type"] }) {
  const colors: Record<string, string> = {
    http:    "text-hack-blue border-hack-blue/30",
    socks5:  "text-hack-purple border-hack-purple/30",
    tor:     "text-hack-orange border-hack-orange/30",
    direct:  "text-zinc-500 border-zinc-700",
  };
  return (
    <span className={`text-[9px] font-mono px-1 py-px rounded border ${colors[type] ?? colors.direct}`}>
      {type}
    </span>
  );
}

interface Props {
  socket: ReturnType<typeof import("../../lib/socket").getSocket>;
}

export function EgressPoolPanel({ socket }: Props) {
  const [collapsed, setCollapsed] = useState(false);
  const [pool, setPool] = useState<PoolEntry[]>([]);
  const [flashedRoutes, setFlashedRoutes] = useState<Set<string>>(new Set());
  const [lastChange, setLastChange] = useState<RouteChangedPayload | null>(null);

  const fetchPool = useCallback(async () => {
    try {
      const res = await fetch("/api/governance/egress/status");
      if (!res.ok) return;
      const data: PoolEntry[] = await res.json();
      setPool(data);
    } catch {
      // non-critical
    }
  }, []);

  useEffect(() => {
    fetchPool();
    const timer = setInterval(fetchPool, POLL_INTERVAL_MS);
    return () => clearInterval(timer);
  }, [fetchPool]);

  useEffect(() => {
    const handler = (data: RouteChangedPayload) => {
      setLastChange(data);
      setFlashedRoutes(prev => new Set([...prev, data.to]));
      setTimeout(() => {
        setFlashedRoutes(prev => {
          const next = new Set(prev);
          next.delete(data.to);
          return next;
        });
      }, FLASH_DURATION_MS);
      fetchPool();
    };
    socket.on("egress:route_changed", handler);
    return () => { socket.off("egress:route_changed", handler); };
  }, [socket, fetchPool]);

  return (
    <div className="border-t border-hack-border flex-shrink-0">
      <button
        onClick={() => setCollapsed(x => !x)}
        className="flex items-center justify-between w-full px-3 py-2 text-[10px] font-mono text-hack-dim hover:text-hack-text transition-colors"
      >
        <div className="flex items-center gap-1.5">
          <Network className="w-3 h-3" />
          <span className="uppercase">Proxy Pool</span>
          <span className="text-zinc-600">({pool.length})</span>
        </div>
        {collapsed
          ? <ChevronRight className="w-3 h-3" />
          : <ChevronDown className="w-3 h-3" />}
      </button>

      {!collapsed && (
        <div className="px-3 pb-3 space-y-1.5">
          {pool.length === 0 && (
            <div className="text-[9px] text-hack-dim font-mono text-center py-2">no routes</div>
          )}
          {pool.map(({ route, health }) => {
            const rate = successRate(health);
            const reqs = totalRequests(health);
            const burned = isBurned(health);
            const countdown = burned ? burnCountdown(health) : 0;
            const flashing = flashedRoutes.has(route.id);
            return (
              <div
                key={route.id}
                className={`rounded p-1.5 transition-colors duration-500 ${
                  flashing ? "bg-amber-400/10 border border-amber-400/20" : "bg-hack-muted border border-transparent"
                }`}
              >
                <div className="flex items-center gap-1.5 flex-wrap">
                  <span className={`text-[10px] font-mono font-bold ${burned ? "text-amber-400" : "text-hack-text"}`}>
                    {route.id}
                  </span>
                  <TypeChip type={route.type} />
                  {burned && (
                    <span className="text-[9px] text-amber-400 font-mono">
                      burned {countdown > 0 ? `${countdown}s` : ""}
                    </span>
                  )}
                  {!burned && reqs === 0 && (
                    <span className="text-[9px] text-zinc-600 font-mono">idle</span>
                  )}
                  {!burned && reqs > 0 && (
                    <span className="text-[9px] text-emerald-400 font-mono">healthy</span>
                  )}
                  <span className="text-[9px] text-zinc-600 font-mono ml-auto">{reqs} req</span>
                </div>
                {route.type !== "direct" && (
                  <div className="mt-1">
                    <RateBar rate={burned ? 0 : rate} />
                  </div>
                )}
                {route.type !== "direct" && route.url && (
                  <div className="text-[9px] text-zinc-600 font-mono truncate mt-0.5">{route.url}</div>
                )}
              </div>
            );
          })}
          {lastChange && (
            <div className="text-[9px] text-hack-dim font-mono pt-1 border-t border-hack-border/50">
              last change: {lastChange.from ?? "—"} → {lastChange.to}
              {lastChange.target && <span className="text-zinc-600"> ({lastChange.target})</span>}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
