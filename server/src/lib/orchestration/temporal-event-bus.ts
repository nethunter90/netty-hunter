import { EventEmitter } from 'events';
import { AgentEvent, AgentType } from './types';
import { eventBus } from './layer3-event-bus';
import { v4 as uuidv4 } from 'uuid';
import { huntCortex, SignalType } from '../intelligence/hunt-cortex';

export interface TemporalEvent extends AgentEvent {
  urgency: number;
  urgencyDecayFn: 'linear' | 'exponential' | 'step';
  halfLife: number;
  correlationGroup?: string;
  preemptive: boolean;
}

interface UrgencyDefaults {
  urgency: number;
  urgencyDecayFn: 'linear' | 'exponential' | 'step';
  halfLife: number;
  preemptive: boolean;
}

const EVENT_URGENCY_DEFAULTS: Record<string, UrgencyDefaults | ((data: Record<string, any>) => UrgencyDefaults)> = {
  'vulnerability_found': (data: Record<string, any>) => {
    const severity = data?.vulnerability?.severity || data?.severity || 'medium';
    if (severity === 'critical' || severity === 'high') {
      return { urgency: 0.9, urgencyDecayFn: 'exponential', halfLife: 300, preemptive: true };
    }
    return { urgency: 0.5, urgencyDecayFn: 'linear', halfLife: 600, preemptive: false };
  },
  'endpoint_characterized': { urgency: 0.3, urgencyDecayFn: 'linear', halfLife: 1800, preemptive: false },
  'defense_detected': { urgency: 0.7, urgencyDecayFn: 'exponential', halfLife: 120, preemptive: true },
  'scan_complete': { urgency: 0.4, urgencyDecayFn: 'linear', halfLife: 900, preemptive: false },
  'claim_released': { urgency: 0.2, urgencyDecayFn: 'linear', halfLife: 600, preemptive: false },
};

export class TemporalEventBus extends EventEmitter {
  private temporalEvents: Map<string, TemporalEvent> = new Map();
  private pendingEvents: Map<AgentType, TemporalEvent[]> = new Map();
  private recentEvents: TemporalEvent[] = [];
  deadLetterQueue: TemporalEvent[] = [];
  private correlatedCount: number = 0;
  private deadLetterTimer: ReturnType<typeof setInterval> | null = null;
  private cleanupTimer: ReturnType<typeof setInterval> | null = null;

  constructor() {
    super();
    this.setMaxListeners(100);

    this.deadLetterTimer = setInterval(() => {
      this.processDeadLetters();
    }, 30_000);

    this.cleanupTimer = setInterval(() => {
      const cutoff = Date.now() - 60_000;
      this.recentEvents = this.recentEvents.filter(e => e.timestamp.getTime() > cutoff);
    }, 15_000);
  }

  private getUrgencyDefaults(type: string, data: Record<string, any>): UrgencyDefaults {
    const config = EVENT_URGENCY_DEFAULTS[type];
    if (!config) {
      return { urgency: 0.3, urgencyDecayFn: 'linear', halfLife: 600, preemptive: false };
    }
    if (typeof config === 'function') {
      return config(data);
    }
    return config;
  }

  getCurrentUrgency(event: TemporalEvent): number {
    const now = Date.now();
    const ageSeconds = (now - event.timestamp.getTime()) / 1000;
    const maxAge = event.halfLife * 2;

    switch (event.urgencyDecayFn) {
      case 'linear':
        return Math.max(0, event.urgency * (1 - ageSeconds / maxAge));
      case 'exponential':
        return event.urgency * Math.pow(0.5, ageSeconds / event.halfLife);
      case 'step':
        return ageSeconds < event.halfLife ? event.urgency : 0;
      default:
        return event.urgency;
    }
  }

  correlateEvents(newEvent: TemporalEvent): TemporalEvent {
    const correlationWindow = 10_000;
    const now = Date.now();
    const newTarget = newEvent.data?.target || newEvent.data?.endpoint || newEvent.data?.vulnerability?.endpoint;

    const candidates = this.recentEvents.filter(existing => {
      const age = now - existing.timestamp.getTime();
      if (age > correlationWindow) return false;
      if (existing.id === newEvent.id) return false;

      const existingTarget = existing.data?.target || existing.data?.endpoint || existing.data?.vulnerability?.endpoint;
      if (newTarget && existingTarget && newTarget === existingTarget) return true;
      if (existing.huntId === newEvent.huntId && existing.type === newEvent.type) return true;

      return false;
    });

    if (candidates.length === 0) {
      this.recentEvents.push(newEvent);
      return newEvent;
    }

    const groupId = newEvent.correlationGroup || `corr-${uuidv4().slice(0, 8)}`;
    const mergedData: Record<string, any> = { ...newEvent.data, correlatedEvents: [] as string[] };
    let maxUrgency = newEvent.urgency;

    for (const candidate of candidates) {
      mergedData.correlatedEvents.push(candidate.id);
      for (const [key, value] of Object.entries(candidate.data)) {
        if (!(key in mergedData)) {
          mergedData[key] = value;
        } else if (Array.isArray(mergedData[key]) && Array.isArray(value)) {
          mergedData[key] = Array.from(new Set([...mergedData[key], ...value]));
        }
      }
      maxUrgency = Math.max(maxUrgency, candidate.urgency);

      this.temporalEvents.delete(candidate.id);
      Array.from(this.pendingEvents.entries()).forEach(([agentType, events]) => {
        this.pendingEvents.set(agentType, events.filter(e => e.id !== candidate.id));
      });
    }

    const enriched: TemporalEvent = {
      ...newEvent,
      data: mergedData,
      urgency: maxUrgency,
      correlationGroup: groupId,
    };

    this.correlatedCount++;
    this.recentEvents.push(enriched);
    return enriched;
  }

  publishTemporal(
    type: string,
    agentId: string,
    huntId: string,
    data: Record<string, any>,
    subscribers: AgentType[] = [],
    urgencyOverride?: Partial<Pick<TemporalEvent, 'urgency' | 'urgencyDecayFn' | 'halfLife' | 'preemptive'>>
  ): string {
    const defaults = this.getUrgencyDefaults(type, data);

    const event: TemporalEvent = {
      id: uuidv4(),
      type,
      agentId,
      huntId,
      timestamp: new Date(),
      data,
      processed: false,
      subscribers,
      urgency: urgencyOverride?.urgency ?? defaults.urgency,
      urgencyDecayFn: urgencyOverride?.urgencyDecayFn ?? defaults.urgencyDecayFn,
      halfLife: urgencyOverride?.halfLife ?? defaults.halfLife,
      preemptive: urgencyOverride?.preemptive ?? defaults.preemptive,
    };

    const correlated = this.correlateEvents(event);
    this.temporalEvents.set(correlated.id, correlated);

    eventBus.publish(type, agentId, huntId, correlated.data, subscribers);

    if (subscribers.length > 0) {
      for (const subType of subscribers) {
        if (!this.pendingEvents.has(subType)) {
          this.pendingEvents.set(subType, []);
        }
        this.pendingEvents.get(subType)!.push(correlated);
      }
    }

    this.emit(type, correlated);
    this.emit('*', correlated);

    if (correlated.preemptive && correlated.urgency > 0.8) {
      this.emit('event:preempt', correlated);
    }

    return correlated.id;
  }

  getPending(agentType: AgentType, huntId: string): TemporalEvent[] {
    const pending = this.pendingEvents.get(agentType) || [];
    return pending
      .filter(e => e.huntId === huntId && !e.processed)
      .map(e => ({ ...e, urgency: this.getCurrentUrgency(e) }))
      .filter(e => e.urgency > 0)
      .sort((a, b) => b.urgency - a.urgency);
  }

  markProcessed(eventId: string): void {
    const event = this.temporalEvents.get(eventId);
    if (event) {
      event.processed = true;
    }
    eventBus.markProcessed(eventId);
  }

  subscribe(agentType: AgentType, eventTypes: string[], handler: (event: TemporalEvent) => void): void {
    for (const type of eventTypes) {
      this.on(type, handler);
    }
  }

  private processDeadLetters(): void {
    const now = Date.now();
    const toRemove: string[] = [];

    Array.from(this.temporalEvents.entries()).forEach(([id, event]) => {
      if (event.processed) return;
      const currentUrgency = this.getCurrentUrgency(event);
      if (currentUrgency <= 0.001) {
        event.processed = true;
        this.deadLetterQueue.push(event);
        toRemove.push(id);
        this.emit('event:dead_letter', event);
        huntCortex.broadcast({
          signalType: SignalType.EVENT_EXPIRED,
          sourceSystem: 'event_bus',
          huntId: event.huntId || null,
          payload: {
            eventType: event.type,
            originalUrgency: event.urgency,
            ageSeconds: (Date.now() - event.timestamp.getTime()) / 1000,
          },
          confidence: 0,
        });
      }
    });

    for (const id of toRemove) {
      Array.from(this.pendingEvents.entries()).forEach(([agentType, events]) => {
        this.pendingEvents.set(agentType, events.filter(e => e.id !== id));
      });
    }

    if (this.deadLetterQueue.length > 1000) {
      this.deadLetterQueue = this.deadLetterQueue.slice(-500);
    }
  }

  getDeadLetters(huntId?: string): TemporalEvent[] {
    if (huntId) {
      return this.deadLetterQueue.filter(e => e.huntId === huntId);
    }
    return [...this.deadLetterQueue];
  }

  getTemporalStats(huntId?: string): {
    activeEvents: number;
    deadLetters: number;
    avgUrgency: number;
    correlatedCount: number;
  } {
    let events = Array.from(this.temporalEvents.values());
    let deadLetters = this.deadLetterQueue;

    if (huntId) {
      events = events.filter(e => e.huntId === huntId);
      deadLetters = deadLetters.filter(e => e.huntId === huntId);
    }

    const active = events.filter(e => !e.processed);
    const avgUrgency = active.length > 0
      ? active.reduce((sum, e) => sum + this.getCurrentUrgency(e), 0) / active.length
      : 0;

    return {
      activeEvents: active.length,
      deadLetters: deadLetters.length,
      avgUrgency,
      correlatedCount: this.correlatedCount,
    };
  }

  getHistory(huntId: string, limit: number = 100): TemporalEvent[] {
    return Array.from(this.temporalEvents.values())
      .filter(e => e.huntId === huntId)
      .sort((a, b) => b.timestamp.getTime() - a.timestamp.getTime())
      .slice(0, limit);
  }

  clear(huntId: string): void {
    const entries = Array.from(this.temporalEvents.entries());
    for (const [id, event] of entries) {
      if (event.huntId === huntId) {
        this.temporalEvents.delete(id);
      }
    }

    Array.from(this.pendingEvents.entries()).forEach(([type, events]) => {
      this.pendingEvents.set(type, events.filter(e => e.huntId !== huntId));
    });

    this.deadLetterQueue = this.deadLetterQueue.filter(e => e.huntId !== huntId);

    eventBus.clear(huntId);
  }

  destroy(): void {
    if (this.deadLetterTimer) {
      clearInterval(this.deadLetterTimer);
      this.deadLetterTimer = null;
    }
    if (this.cleanupTimer) {
      clearInterval(this.cleanupTimer);
      this.cleanupTimer = null;
    }
  }
}

export const temporalEventBus = new TemporalEventBus();
