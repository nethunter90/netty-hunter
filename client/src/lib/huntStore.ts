/**
 * Module-level hunt state store (observable).
 *
 * Holds all live hunt progress — activity events, sessions, hypothesis stats —
 * in a singleton that survives React unmount/remount. The socket subscription
 * that feeds it lives ABOVE the panel routing (see huntEventBridge.ts), so the
 * store keeps receiving events no matter which panel is mounted. The Hunt panel
 * is a pure reader via the useHuntStore() hook.
 *
 * State is held immutably: every mutator replaces `_state` with a new object and
 * notifies subscribers, so useSyncExternalStore gets a stable, change-only
 * snapshot.
 */
import { useSyncExternalStore } from 'react';
import type { ActivityEvent } from '../components/LiveActivityFeed';

export interface StoredSession {
  sessionUuid: string;
  targetUrl: string;
  status: 'running' | 'stopping' | 'complete' | 'error';
  phase: string;
  iteration: number;
  findings: number;
}

export interface ExternalHunt {
  id: string;
  kind: string;
  targetUrl: string;
}

export interface HuntStoreState {
  activeSessions: StoredSession[];
  activityEvents: ActivityEvent[];
  hypStats: { pending: number; probing: number; confirmed: number; rejected: number };
  proxyEnabled: boolean;
  wafBypassEnabled: boolean;
  externalHunt: ExternalHunt | null;
}

const EMPTY: HuntStoreState = {
  activeSessions: [],
  activityEvents: [],
  hypStats: { pending: 0, probing: 0, confirmed: 0, rejected: 0 },
  proxyEnabled: false,
  wafBypassEnabled: false,
  externalHunt: null,
};

let _state: HuntStoreState = { ...EMPTY };

const listeners = new Set<() => void>();
function notify(): void {
  for (const l of listeners) l();
}

export const huntStore = {
  get activeSessions(): StoredSession[] { return _state.activeSessions; },
  get activityEvents(): ActivityEvent[] { return _state.activityEvents; },
  get hypStats() { return _state.hypStats; },
  get proxyEnabled(): boolean { return _state.proxyEnabled; },
  get wafBypassEnabled(): boolean { return _state.wafBypassEnabled; },
  get externalHunt(): ExternalHunt | null { return _state.externalHunt; },

  // ── Observable plumbing (for useSyncExternalStore) ──
  subscribe(listener: () => void): () => void {
    listeners.add(listener);
    return () => listeners.delete(listener);
  },
  getSnapshot(): HuntStoreState {
    return _state;
  },

  // ── Mutators (each replaces _state immutably, then notifies) ──
  setSessions(sessions: StoredSession[]): void {
    _state = { ..._state, activeSessions: sessions };
    notify();
  },

  updateSessions(fn: (prev: StoredSession[]) => StoredSession[]): void {
    _state = { ..._state, activeSessions: fn(_state.activeSessions) };
    notify();
  },

  pushEvent(event: ActivityEvent): void {
    // Cap retained events (~300) so long hunts don't grow state unbounded.
    _state = { ..._state, activityEvents: [..._state.activityEvents.slice(-299), event] };
    notify();
  },

  setHypStats(stats: HuntStoreState['hypStats']): void {
    _state = { ..._state, hypStats: stats };
    notify();
  },

  updateHypStats(fn: (prev: HuntStoreState['hypStats']) => HuntStoreState['hypStats']): void {
    _state = { ..._state, hypStats: fn(_state.hypStats) };
    notify();
  },

  setProxyEnabled(val: boolean): void {
    _state = { ..._state, proxyEnabled: val };
    notify();
  },

  setWafBypassEnabled(val: boolean): void {
    _state = { ..._state, wafBypassEnabled: val };
    notify();
  },

  setExternalHunt(hunt: ExternalHunt | null): void {
    _state = { ..._state, externalHunt: hunt };
    notify();
  },

  hasActiveSessions(): boolean {
    return _state.activeSessions.some(s => s.status === 'running' || s.status === 'stopping');
  },

  /** Called at the start of a new hunt — clears events and hyp stats but leaves
   *  proxy/externalHunt as the caller manages them. */
  clearForNewHunt(): void {
    _state = {
      ..._state,
      activityEvents: [],
      hypStats: { pending: 0, probing: 0, confirmed: 0, rejected: 0 },
      activeSessions: [],
    };
    notify();
  },
};

/** React 18 hook — re-renders the caller whenever the store changes. */
export function useHuntStore(): HuntStoreState {
  return useSyncExternalStore(huntStore.subscribe, huntStore.getSnapshot);
}
