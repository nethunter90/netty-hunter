/**
 * Module-level orchestration state store (observable).
 *
 * Holds the live 6-layer orchestration progress — layer statuses, phase, counts,
 * and the execution-stream activity events — in a singleton that survives React
 * unmount/remount. The socket subscription that feeds it lives ABOVE the panel
 * routing (orchestrationEventBridge.ts), so leaving the Orchestration panel and
 * coming back restores the full prior stream instead of showing an empty feed.
 *
 * Same pattern as huntStore: immutable _state replaced on every mutation +
 * notify(), read via useOrchestrationStore() (useSyncExternalStore).
 */
import { useSyncExternalStore } from 'react';
import type { ActivityEvent } from '../components/LiveActivityFeed';

export interface LayerStatus {
  layer: number;
  name: string;
  phase: 'pending' | 'running' | 'passed' | 'failed' | 'skipped';
  startedAt?: number;
  completedAt?: number;
  durationMs?: number;
  error?: string;
}

export interface ExternalHunt { id: string; kind: string; targetUrl: string; }

export interface OrchestrationState {
  orchestrationId: string | null;
  layers: LayerStatus[];
  phase: string;
  findings: number;
  verified: number;
  loading: boolean;
  launching: boolean;
  stopping: boolean;
  externalHunt: ExternalHunt | null;
  activityEvents: ActivityEvent[];
}

const LAYER_NAMES = [
  'GOVERNANCE GATE', 'TARGET INTELLIGENCE', 'STRATEGY PLANNING',
  'EXECUTION ENGINE', 'VERIFICATION GATE', 'INTELLIGENCE HARVEST',
];

export function freshLayers(): LayerStatus[] {
  return Array.from({ length: 6 }, (_, i) => ({ layer: i + 1, name: LAYER_NAMES[i], phase: 'pending' as const }));
}

const EMPTY: OrchestrationState = {
  orchestrationId: null,
  layers: freshLayers(),
  phase: 'idle',
  findings: 0,
  verified: 0,
  loading: false,
  launching: false,
  stopping: false,
  externalHunt: null,
  activityEvents: [],
};

let _state: OrchestrationState = { ...EMPTY };

const listeners = new Set<() => void>();
function notify(): void { for (const l of listeners) l(); }
function set(patch: Partial<OrchestrationState>): void { _state = { ..._state, ...patch }; notify(); }

export const orchestrationStore = {
  subscribe(listener: () => void): () => void {
    listeners.add(listener);
    return () => listeners.delete(listener);
  },
  getSnapshot(): OrchestrationState { return _state; },

  setOrchestrationId(id: string | null): void { set({ orchestrationId: id }); },
  setPhase(phase: string): void { set({ phase }); },
  setLoading(v: boolean): void { set({ loading: v }); },
  setLaunching(v: boolean): void { set({ launching: v }); },
  setStopping(v: boolean): void { set({ stopping: v }); },
  setExternalHunt(h: ExternalHunt | null): void { set({ externalHunt: h }); },
  setFindings(n: number): void { set({ findings: n }); },
  setVerified(n: number): void { set({ verified: n }); },
  incFindings(): void { set({ findings: _state.findings + 1 }); },
  incVerified(): void { set({ verified: _state.verified + 1 }); },

  updateLayers(fn: (prev: LayerStatus[]) => LayerStatus[]): void { set({ layers: fn(_state.layers) }); },

  pushEvent(ev: ActivityEvent): void {
    // Cap retained events (~300) so long orchestrations don't grow state unbounded.
    set({ activityEvents: [..._state.activityEvents.slice(-299), ev] });
  },

  /** Reset live state for a fresh run (keeps nothing from the prior orchestration). */
  clearForNewRun(): void {
    _state = {
      ..._state,
      orchestrationId: null,
      layers: freshLayers(),
      phase: 'idle',
      findings: 0,
      verified: 0,
      externalHunt: null,
      activityEvents: [],
    };
    notify();
  },

  /** Hydrate from a server reconnect (fresh page load) without wiping the event
   *  stream the bridge may already hold. */
  hydrate(patch: Partial<OrchestrationState>): void { set(patch); },
};

/** React 18 hook — re-renders the caller whenever the store changes. */
export function useOrchestrationStore(): OrchestrationState {
  return useSyncExternalStore(orchestrationStore.subscribe, orchestrationStore.getSnapshot);
}
