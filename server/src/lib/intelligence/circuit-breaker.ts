import { EventEmitter } from 'events';
import logger from '../../utils/logger';

export interface CircuitState {
  tool: string;
  state: 'closed' | 'open' | 'half_open';
  failures: number;
  successes: number;
  lastFailure?: string;
  openedAt?: string;
}

export class CircuitBreaker extends EventEmitter {
  private circuits: Map<string, CircuitState> = new Map();
  private readonly failureThreshold = 3;
  private readonly cooldownMs = 60000;

  recordSuccess(tool: string) {
    const circuit = this.getCircuit(tool);
    circuit.successes++;
    if (circuit.state === 'half_open' && circuit.successes >= 2) {
      this.closeCircuit(tool);
    }
  }

  recordFailure(tool: string, error: string) {
    const circuit = this.getCircuit(tool);
    circuit.failures++;
    circuit.lastFailure = error;
    if (circuit.failures >= this.failureThreshold) {
      this.openCircuit(tool);
    }
  }

  canExecute(tool: string): { allowed: boolean; fallback?: string } {
    const circuit = this.getCircuit(tool);

    if (circuit.state === 'closed') return { allowed: true };

    if (circuit.state === 'open') {
      if (circuit.openedAt) {
        const elapsed = Date.now() - new Date(circuit.openedAt).getTime();
        if (elapsed > this.cooldownMs) {
          circuit.state = 'half_open';
          circuit.successes = 0;
          circuit.failures = 0;
          return { allowed: true };
        }
      }
      return { allowed: false, fallback: this.getFallback(tool) };
    }

    return { allowed: true };
  }

  private getFallback(tool: string): string | undefined {
    const fallbacks: Record<string, string> = {
      sqlmap: 'nuclei',
      nuclei: 'nikto',
      nmap: 'masscan'
    };
    return fallbacks[tool];
  }

  private openCircuit(tool: string) {
    const circuit = this.getCircuit(tool);
    circuit.state = 'open';
    circuit.openedAt = new Date().toISOString();
    this.emit('circuit:opened', { tool });
    logger.warn(`[Brain] Circuit breaker opened for ${tool}`);
  }

  private closeCircuit(tool: string) {
    const circuit = this.getCircuit(tool);
    circuit.state = 'closed';
    circuit.failures = 0;
    circuit.successes = 0;
    circuit.openedAt = undefined;
    this.emit('circuit:closed', { tool });
    logger.info(`[Brain] Circuit breaker closed for ${tool}`);
  }

  private getCircuit(tool: string): CircuitState {
    if (!this.circuits.has(tool)) {
      this.circuits.set(tool, { tool, state: 'closed', failures: 0, successes: 0 });
    }
    return this.circuits.get(tool)!;
  }

  getState(tool: string): CircuitState {
    return this.getCircuit(tool);
  }
}

export const circuitBreaker = new CircuitBreaker();
