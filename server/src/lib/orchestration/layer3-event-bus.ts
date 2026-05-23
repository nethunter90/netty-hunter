import { EventEmitter } from 'events';
import { AgentEvent, AgentType } from './types';
import { v4 as uuidv4 } from 'uuid';

export class AgentEventBus extends EventEmitter {
  private events: Map<string, AgentEvent> = new Map();
  private pendingEvents: Map<AgentType, AgentEvent[]> = new Map();

  constructor() {
    super();
    this.setMaxListeners(100);
  }

  publish(
    type: string,
    agentId: string,
    huntId: string,
    data: Record<string, any>,
    subscribers: AgentType[] = []
  ): string {
    const event: AgentEvent = {
      id: uuidv4(),
      type,
      agentId,
      huntId,
      timestamp: new Date(),
      data,
      processed: false,
      subscribers
    };

    this.events.set(event.id, event);

    if (subscribers.length > 0) {
      subscribers.forEach(subType => {
        if (!this.pendingEvents.has(subType)) {
          this.pendingEvents.set(subType, []);
        }
        this.pendingEvents.get(subType)!.push(event);
      });
    }

    this.emit(type, event);
    this.emit('*', event);

    console.log(`[EventBus] Published: ${type} from ${agentId}`);

    return event.id;
  }

  getPending(agentType: AgentType, huntId: string): AgentEvent[] {
    const pending = this.pendingEvents.get(agentType) || [];
    return pending.filter(e => e.huntId === huntId && !e.processed);
  }

  markProcessed(eventId: string): void {
    const event = this.events.get(eventId);
    if (event) {
      event.processed = true;
    }
  }

  subscribe(agentType: AgentType, eventTypes: string[], handler: (event: AgentEvent) => void): void {
    eventTypes.forEach(type => {
      this.on(type, handler);
    });

    console.log(`[EventBus] ${agentType} subscribed to: ${eventTypes.join(', ')}`);
  }

  publishEndpointCharacterized(
    agentId: string,
    huntId: string,
    endpoint: { url: string; statusCode?: number; title?: string; technologies?: string[] }
  ): string {
    return this.publish(
      'endpoint_characterized',
      agentId,
      huntId,
      { endpoint },
      ['scanner']
    );
  }

  publishScanComplete(
    agentId: string,
    huntId: string,
    target: string,
    vulnerabilities: any[]
  ): string {
    return this.publish(
      'scan_complete',
      agentId,
      huntId,
      { target, vulnerabilities },
      ['exploit']
    );
  }

  publishVulnerabilityFound(
    agentId: string,
    huntId: string,
    vulnerability: {
      type: string;
      severity: string;
      endpoint: string;
      description: string;
      exploitable: boolean;
    }
  ): string {
    return this.publish(
      'vulnerability_found',
      agentId,
      huntId,
      { vulnerability },
      ['exploit', 'cognitive']
    );
  }

  publishClaimReleased(
    agentId: string,
    huntId: string,
    target: string
  ): string {
    return this.publish(
      'claim_released',
      agentId,
      huntId,
      { target },
      ['scanner', 'exploit']
    );
  }

  publishDefenseDetected(
    agentId: string,
    huntId: string,
    defense: {
      type: 'waf' | 'ids' | 'rate_limit' | 'bot_detection';
      endpoint: string;
      details: string;
    }
  ): string {
    return this.publish(
      'defense_detected',
      agentId,
      huntId,
      { defense },
      ['recon', 'scanner', 'exploit', 'support']
    );
  }

  publishPhaseComplete(
    agentId: string,
    huntId: string,
    phase: string
  ): string {
    return this.publish(
      'mission_phase_complete',
      agentId,
      huntId,
      { phase },
      ['cognitive']
    );
  }

  getHistory(huntId: string, limit: number = 100): AgentEvent[] {
    return Array.from(this.events.values())
      .filter(e => e.huntId === huntId)
      .sort((a, b) => b.timestamp.getTime() - a.timestamp.getTime())
      .slice(0, limit);
  }

  clear(huntId: string): void {
    const entries = Array.from(this.events.entries());
    for (const [id, event] of entries) {
      if (event.huntId === huntId) {
        this.events.delete(id);
      }
    }

    const pendingEntries = Array.from(this.pendingEvents.entries());
    for (const [type, events] of pendingEntries) {
      this.pendingEvents.set(
        type,
        events.filter(e => e.huntId !== huntId)
      );
    }
  }
}

export const eventBus = new AgentEventBus();
