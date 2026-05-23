import { EventEmitter } from 'events';

export interface CircuitState {
  tool: string;
  state: 'closed' | 'open' | 'half_open';
  failures: number;
  successes: number;
  lastFailure?: string;
  lastError?: string;
  openedAt?: string;
}

export class CircuitBreaker extends EventEmitter {
  private circuits: Map<string, CircuitState> = new Map();
  private failureThreshold = 3;
  private cooldownMs = 60000;

  private static FALLBACKS: Record<string, string> = {
    'sqlmap': 'nuclei',
    'nuclei': 'nikto',
    'nikto': 'nuclei',
    'nmap': 'masscan',
    'masscan': 'nmap',
    'gobuster': 'ffuf',
    'ffuf': 'gobuster',
    'hydra': 'nuclei',
    'amass': 'subfinder',
    'subfinder': 'amass'
  };

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
    circuit.lastFailure = new Date().toISOString();
    circuit.lastError = error;

    if (circuit.failures >= this.failureThreshold) {
      this.openCircuit(tool);
    }
  }

  canExecute(tool: string): { allowed: boolean; fallback?: string; reason?: string } {
    const circuit = this.getCircuit(tool);

    if (circuit.state === 'closed') {
      return { allowed: true };
    }

    if (circuit.state === 'open') {
      if (circuit.openedAt) {
        const elapsed = Date.now() - new Date(circuit.openedAt).getTime();
        if (elapsed > this.cooldownMs) {
          circuit.state = 'half_open';
          circuit.successes = 0;
          circuit.failures = 0;
          return { allowed: true, reason: 'Circuit half-open, testing recovery' };
        }
      }

      return {
        allowed: false,
        fallback: CircuitBreaker.FALLBACKS[tool],
        reason: `Circuit open: ${circuit.failures} failures, last error: ${circuit.lastError}`
      };
    }

    return { allowed: true, reason: 'Circuit half-open' };
  }

  private openCircuit(tool: string) {
    const circuit = this.getCircuit(tool);
    circuit.state = 'open';
    circuit.openedAt = new Date().toISOString();

    this.emit('circuit:opened', { tool, failures: circuit.failures, lastError: circuit.lastError });
    console.warn(`[Circuit Breaker] ${tool} circuit OPENED after ${circuit.failures} failures`);
  }

  private closeCircuit(tool: string) {
    const circuit = this.getCircuit(tool);
    circuit.state = 'closed';
    circuit.failures = 0;
    circuit.successes = 0;
    circuit.openedAt = undefined;

    this.emit('circuit:closed', { tool });
    console.log(`[Circuit Breaker] ${tool} circuit CLOSED (recovered)`);
  }

  private getCircuit(tool: string): CircuitState {
    if (!this.circuits.has(tool)) {
      this.circuits.set(tool, {
        tool,
        state: 'closed',
        failures: 0,
        successes: 0
      });
    }
    return this.circuits.get(tool)!;
  }

  getState(tool: string): CircuitState {
    return this.getCircuit(tool);
  }

  getAllStates(): CircuitState[] {
    return Array.from(this.circuits.values());
  }

  resetCircuit(tool: string) {
    this.circuits.delete(tool);
    this.emit('circuit:reset', { tool });
  }

  resetAll() {
    this.circuits.clear();
    this.emit('circuit:reset-all', {});
  }

  getStats(): {
    total: number;
    open: number;
    closed: number;
    halfOpen: number;
  } {
    const states = this.getAllStates();
    return {
      total: states.length,
      open: states.filter(s => s.state === 'open').length,
      closed: states.filter(s => s.state === 'closed').length,
      halfOpen: states.filter(s => s.state === 'half_open').length
    };
  }
}

export const circuitBreaker = new CircuitBreaker();
