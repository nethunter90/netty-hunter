import { EventEmitter } from 'events';

class ExtendedEventBus extends EventEmitter {
  publish(event: string, source: string, huntId: string, data: Record<string, unknown>, _channels?: string[]): void {
    this.emit(event, { source, huntId, ...data });
  }
}

export const eventBus = new ExtendedEventBus();
eventBus.setMaxListeners(100);
