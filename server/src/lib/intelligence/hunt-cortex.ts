import { EventEmitter } from 'events';
import { pool } from '../../db';
import { decisionTraceLogger } from './decision-trace';

export enum SignalType {
  TOOL_NOVELTY = 'TOOL_NOVELTY',
  TOOL_NEGATIVE_EVIDENCE = 'TOOL_NEGATIVE_EVIDENCE',
  TOOL_PARSE_ERROR = 'TOOL_PARSE_ERROR',
  VERIFICATION_DEGRADED = 'VERIFICATION_DEGRADED',
  VERIFICATION_FAILED = 'VERIFICATION_FAILED',
  EVENT_EXPIRED = 'EVENT_EXPIRED',
  EVENT_PREEMPTED = 'EVENT_PREEMPTED',
  FALLBACK_USED = 'FALLBACK_USED',
  PIVOT_EXECUTED = 'PIVOT_EXECUTED',
  FINDING_CONFIRMED = 'FINDING_CONFIRMED',
  FINDING_INVALIDATED = 'FINDING_INVALIDATED',
  SHARED_INFRA_DETECTED = 'SHARED_INFRA_DETECTED',
  TARGET_FRAGILITY_HIGH = 'TARGET_FRAGILITY_HIGH',
  TARGET_FRAGILITY_CLEARED = 'TARGET_FRAGILITY_CLEARED',
  GOVERNANCE_DEVIATION = 'GOVERNANCE_DEVIATION',
  IMMUNIZATION_TRIGGERED = 'IMMUNIZATION_TRIGGERED',
  GOVERNANCE_BASELINE_RESTORED = 'GOVERNANCE_BASELINE_RESTORED',
  EGRESS_ROUTE_CHANGED = 'EGRESS_ROUTE_CHANGED',
  EGRESS_ROUTE_EXHAUSTED = 'EGRESS_ROUTE_EXHAUSTED',
}

export interface CortexSignal {
  id?: string;
  signalType: SignalType;
  sourceSystem: string;
  timestamp?: number;
  payload: Record<string, any>;
  huntId: string | null;
  confidence: number;
}

const MAX_BUFFER_SIZE = 10000;

class HuntCortex extends EventEmitter {
  private signalBuffer: CortexSignal[] = [];
  private subscribers: Map<string, Array<(signal: CortexSignal) => void>> = new Map();
  private windowSeconds: number = 300;
  private recentFingerprints: Map<string, number> = new Map();
  private readonly DEDUP_WINDOW_MS = 1000;

  constructor() {
    super();
    this.setMaxListeners(100);
  }

  private isDuplicate(signal: CortexSignal): boolean {
    const fp = `${signal.signalType}:${signal.huntId}:${signal.sourceSystem}`;
    const now = Date.now();
    const last = this.recentFingerprints.get(fp);
    if (last !== undefined && now - last < this.DEDUP_WINDOW_MS) return true;
    this.recentFingerprints.set(fp, now);
    if (this.recentFingerprints.size > 500) {
      for (const [k, t] of this.recentFingerprints) {
        if (now - t > this.DEDUP_WINDOW_MS * 2) this.recentFingerprints.delete(k);
      }
    }
    return false;
  }

  async broadcast(signal: CortexSignal): Promise<void> {
    if (this.isDuplicate(signal)) return;
    if (!signal.id) {
      signal.id = `sig-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
    }
    if (!signal.timestamp) {
      signal.timestamp = Date.now();
    }
    if (signal.confidence === undefined || signal.confidence === null) {
      signal.confidence = 1.0;
    }

    this.signalBuffer.push(signal);
    if (this.signalBuffer.length > MAX_BUFFER_SIZE) {
      this.signalBuffer = this.signalBuffer.slice(this.signalBuffer.length - MAX_BUFFER_SIZE);
    }

    try {
      await pool.query(
        `INSERT INTO cortex_signals (id, signal_type, source_system, hunt_id, payload, confidence)
         VALUES ($1, $2, $3, $4, $5, $6)`,
        [
          signal.id,
          signal.signalType,
          signal.sourceSystem,
          signal.huntId,
          JSON.stringify(signal.payload),
          signal.confidence,
        ]
      );
    } catch (_err) {}

    decisionTraceLogger.recordEvent({
      huntId: signal.huntId || 'global',
      eventType: 'cortex_signal',
      sourceSystem: signal.sourceSystem,
      data: { signalType: signal.signalType, payload: signal.payload },
      confidenceAtEvent: signal.confidence,
      reasoning: `Cortex signal: ${signal.signalType} from ${signal.sourceSystem}`,
    }).catch(() => {});

    const typeCallbacks = this.subscribers.get(signal.signalType) || [];
    for (const cb of typeCallbacks) {
      try { cb(signal); } catch (_e) {}
    }

    const wildcardCallbacks = this.subscribers.get('*') || [];
    for (const cb of wildcardCallbacks) {
      try { cb(signal); } catch (_e) {}
    }

    this.emit('signal', signal);
  }

  subscribe(signalType: string, callback: (signal: CortexSignal) => void): void {
    if (!this.subscribers.has(signalType)) {
      this.subscribers.set(signalType, []);
    }
    this.subscribers.get(signalType)!.push(callback);
  }

  unsubscribe(signalType: string, callback: (signal: CortexSignal) => void): void {
    const callbacks = this.subscribers.get(signalType);
    if (!callbacks) return;
    const idx = callbacks.indexOf(callback);
    if (idx !== -1) {
      callbacks.splice(idx, 1);
    }
  }

  recentSignals(filters?: { signalTypes?: SignalType[]; huntId?: string; since?: number }): CortexSignal[] {
    const since = filters?.since || (Date.now() - this.windowSeconds * 1000);
    return this.signalBuffer.filter(s => {
      if ((s.timestamp || 0) < since) return false;
      if (filters?.signalTypes && !filters.signalTypes.includes(s.signalType)) return false;
      if (filters?.huntId && s.huntId !== filters.huntId) return false;
      return true;
    });
  }

  computeHuntHealth(huntId: string): Record<string, number> {
    const signals = this.recentSignals({ huntId });

    const noveltySignals = signals.filter(s => s.signalType === SignalType.TOOL_NOVELTY);
    const avg_novelty_score = noveltySignals.length > 0
      ? noveltySignals.reduce((sum, s) => sum + (s.payload.noveltyScore || 0), 0) / noveltySignals.length
      : 0;

    const negative_evidence_count = signals.filter(s => s.signalType === SignalType.TOOL_NEGATIVE_EVIDENCE).length;
    const degraded_verifications = signals.filter(s => s.signalType === SignalType.VERIFICATION_DEGRADED).length;
    const missed_events = signals.filter(s => s.signalType === SignalType.EVENT_EXPIRED).length;
    const fallback_actions = signals.filter(s => s.signalType === SignalType.FALLBACK_USED).length;
    const signal_count = signals.length;

    let health = 1.0;
    health -= Math.max(0, 0.5 - avg_novelty_score);
    health -= negative_evidence_count * 0.05;
    health -= degraded_verifications * 0.08;
    health -= missed_events * 0.15;
    health -= fallback_actions * 0.1;
    health = Math.min(1, Math.max(0, health));

    return {
      avg_novelty_score,
      negative_evidence_count,
      degraded_verifications,
      missed_events,
      fallback_actions,
      signal_count,
      health,
    };
  }

  async loadRecentFromDb(windowSeconds?: number): Promise<void> {
    const window = windowSeconds || this.windowSeconds;
    try {
      const result = await pool.query(
        `SELECT id, signal_type, source_system, hunt_id, payload, confidence, created_at
         FROM cortex_signals
         WHERE created_at > now() - interval '${window} seconds'
         ORDER BY created_at ASC`
      );

      for (const row of result.rows) {
        this.signalBuffer.push({
          id: row.id,
          signalType: row.signal_type as SignalType,
          sourceSystem: row.source_system,
          timestamp: new Date(row.created_at).getTime(),
          payload: row.payload || {},
          huntId: row.hunt_id,
          confidence: row.confidence,
        });
      }

      if (this.signalBuffer.length > MAX_BUFFER_SIZE) {
        this.signalBuffer = this.signalBuffer.slice(this.signalBuffer.length - MAX_BUFFER_SIZE);
      }
    } catch (_err) {}
  }

  getStats(): { bufferSize: number; subscriberCount: number; signalTypeCounts: Record<string, number> } {
    let subscriberCount = 0;
    for (const callbacks of Array.from(this.subscribers.values())) {
      subscriberCount += callbacks.length;
    }

    const signalTypeCounts: Record<string, number> = {};
    for (const signal of this.signalBuffer) {
      signalTypeCounts[signal.signalType] = (signalTypeCounts[signal.signalType] || 0) + 1;
    }

    return {
      bufferSize: this.signalBuffer.length,
      subscriberCount,
      signalTypeCounts,
    };
  }
}

export const huntCortex = new HuntCortex();
