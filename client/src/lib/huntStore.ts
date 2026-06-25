/**
 * Module-level hunt state store.
 *
 * Survives React component unmount/remount (panel navigation). HuntConsole
 * reads from this on mount and writes to it on every state change, so
 * switching panels and coming back restores the live hunt UI instantly.
 *
 * Not a global React context — just a module singleton. No deps required.
 */
import type { ActivityEvent } from '../components/LiveActivityFeed';

export interface StoredSession {
  sessionUuid: string;
  targetUrl: string;
  status: 'running' | 'stopping' | 'complete' | 'error';
  phase: string;
  iteration: number;
  findings: number;
}

interface HuntStoreState {
  activeSessions: StoredSession[];
  activityEvents: ActivityEvent[];
  hypStats: { pending: number; probing: number; confirmed: number; rejected: number };
  proxyEnabled: boolean;
}

const EMPTY: HuntStoreState = {
  activeSessions: [],
  activityEvents: [],
  hypStats: { pending: 0, probing: 0, confirmed: 0, rejected: 0 },
  proxyEnabled: false,
};

let _state: HuntStoreState = { ...EMPTY, activityEvents: [] };

export const huntStore = {
  get activeSessions(): StoredSession[] { return _state.activeSessions; },
  get activityEvents(): ActivityEvent[] { return _state.activityEvents; },
  get hypStats() { return _state.hypStats; },
  get proxyEnabled(): boolean { return _state.proxyEnabled; },

  setSessions(sessions: StoredSession[]): void {
    _state.activeSessions = sessions;
  },

  pushEvent(event: ActivityEvent): void {
    _state.activityEvents = [..._state.activityEvents.slice(-299), event];
  },

  setHypStats(stats: HuntStoreState['hypStats']): void {
    _state.hypStats = stats;
  },

  setProxyEnabled(val: boolean): void {
    _state.proxyEnabled = val;
  },

  hasActiveSessions(): boolean {
    return _state.activeSessions.some(s => s.status === 'running' || s.status === 'stopping');
  },

  /** Called at the start of a new hunt — clears events and hyp stats but leaves
   *  the session list untouched until the new session is added. */
  clearForNewHunt(): void {
    _state.activityEvents = [];
    _state.hypStats = { pending: 0, probing: 0, confirmed: 0, rejected: 0 };
    _state.activeSessions = [];
  },
};
