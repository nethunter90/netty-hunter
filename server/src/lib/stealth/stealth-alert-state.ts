import { stealthLogger } from './stealth-logger';

export type AlertLevel = 'none' | 'low' | 'medium' | 'high' | 'critical';

export interface AlertSignal {
  type: string;
  name: string;
  confidence: number;
  details?: string;
}

export interface StealthAlertState {
  active: boolean;
  level: AlertLevel;
  reason: string;
  signals: AlertSignal[];
  updatedAt: number;
  expiresAt: number;
  target: string;
}

type StateListener = (state: StealthAlertState) => void;

const AUTO_CLEAR_MS = 5 * 60 * 1000;

function createDefaultState(): StealthAlertState {
  return {
    active: false,
    level: 'none',
    reason: '',
    signals: [],
    updatedAt: 0,
    expiresAt: 0,
    target: '',
  };
}

class StealthAlertStateManager {
  private state: StealthAlertState = createDefaultState();
  private listeners: Set<StateListener> = new Set();
  private autoClearTimer: ReturnType<typeof setTimeout> | null = null;

  update(level: AlertLevel, reason: string, signals: AlertSignal[], target: string): void {
    const now = Date.now();

    this.state = {
      active: true,
      level,
      reason,
      signals,
      updatedAt: now,
      expiresAt: now + AUTO_CLEAR_MS,
      target,
    };

    if (this.autoClearTimer) {
      clearTimeout(this.autoClearTimer);
    }

    this.autoClearTimer = setTimeout(() => {
      this.clear();
    }, AUTO_CLEAR_MS);

    stealthLogger.log('alert', {
      action: 'update',
      level,
      reason,
      signals,
      target,
      expiresAt: this.state.expiresAt,
    });

    this.notifyListeners();
  }

  clear(): void {
    if (this.autoClearTimer) {
      clearTimeout(this.autoClearTimer);
      this.autoClearTimer = null;
    }

    this.state = createDefaultState();
    this.state.updatedAt = Date.now();

    stealthLogger.log('alert', {
      action: 'clear',
    });

    this.notifyListeners();
  }

  getState(): StealthAlertState {
    return { ...this.state, signals: [...this.state.signals] };
  }

  isActive(): boolean {
    return this.state.active && Date.now() < this.state.expiresAt;
  }

  onUpdate(callback: StateListener): void {
    this.listeners.add(callback);
  }

  removeListener(callback: StateListener): void {
    this.listeners.delete(callback);
  }

  private notifyListeners(): void {
    const snapshot = this.getState();
    for (const listener of Array.from(this.listeners)) {
      try {
        listener(snapshot);
      } catch {}
    }
  }
}

export const stealthAlertState = new StealthAlertStateManager();
