import { stealthLogger } from './stealth-logger';

interface ModeLimits {
  maxWindows: number;
  popupDelay: number;
  minGap: number;
  idleTimeout: number;
}

const MODE_LIMITS: Record<string, ModeLimits> = {
  aggressive: { maxWindows: 10, popupDelay: 0, minGap: 0, idleTimeout: 0 },
  stealth: { maxWindows: 2, popupDelay: 3000, minGap: 2000, idleTimeout: 60000 },
  ultrastealth: { maxWindows: 1, popupDelay: 5000, minGap: 5000, idleTimeout: 30000 },
};

interface TrackedWindow {
  id: string;
  priority: 'critical' | 'normal';
  lastActivity: number;
}

interface QueuedWindow {
  id: string;
  priority: 'critical' | 'normal';
  mode: string;
}

interface OpenWindowResult {
  allowed: boolean;
  queued?: boolean;
  bumpedId?: string;
  delay?: number;
}

class WindowManager {
  private activeWindows: Map<string, TrackedWindow> = new Map();
  private queue: QueuedWindow[] = [];
  private lastOpenTime: number = 0;

  private getLimits(mode: string): ModeLimits {
    return MODE_LIMITS[mode] || MODE_LIMITS.aggressive;
  }

  openWindow(id: string, priority: 'critical' | 'normal', mode: string): OpenWindowResult {
    const limits = this.getLimits(mode);
    const now = Date.now();
    const gap = now - this.lastOpenTime;

    if (limits.minGap > 0 && gap < limits.minGap) {
      this.queue.push({ id, priority, mode });
      stealthLogger.log('window_block', { windowId: id, reason: 'min_gap', mode, gap, required: limits.minGap });
      return { allowed: false, queued: true, delay: limits.minGap - gap };
    }

    if (this.activeWindows.size < limits.maxWindows) {
      this.activeWindows.set(id, { id, priority, lastActivity: now });
      this.lastOpenTime = now;
      return { allowed: true, delay: limits.popupDelay };
    }

    if (priority === 'critical') {
      let bumpTarget: string | undefined;
      const entries = Array.from(this.activeWindows.entries());
      for (const [wid, win] of entries) {
        if (win.priority === 'normal') {
          bumpTarget = wid;
          break;
        }
      }

      if (bumpTarget) {
        this.activeWindows.delete(bumpTarget);
        this.activeWindows.set(id, { id, priority, lastActivity: now });
        this.lastOpenTime = now;
        stealthLogger.log('window_block', { windowId: bumpTarget, reason: 'bumped', bumpedBy: id, mode });
        return { allowed: true, bumpedId: bumpTarget, delay: limits.popupDelay };
      }
    }

    this.queue.push({ id, priority, mode });
    stealthLogger.log('window_block', { windowId: id, reason: 'max_windows', mode, active: this.activeWindows.size, max: limits.maxWindows });
    return { allowed: false, queued: true };
  }

  closeWindow(id: string): void {
    this.activeWindows.delete(id);

    if (this.queue.length > 0) {
      const next = this.queue.shift()!;
      const limits = this.getLimits(next.mode);
      this.activeWindows.set(next.id, { id: next.id, priority: next.priority, lastActivity: Date.now() });
      this.lastOpenTime = Date.now();
    }
  }

  recordActivity(id: string): void {
    const win = this.activeWindows.get(id);
    if (win) {
      win.lastActivity = Date.now();
    }
  }

  checkIdleWindows(): string[] {
    const now = Date.now();
    const toClose: string[] = [];

    const entries = Array.from(this.activeWindows.entries());
    for (const [id, win] of entries) {
      const limits = this.getLimits('stealth');
      if (limits.idleTimeout > 0 && (now - win.lastActivity) > limits.idleTimeout) {
        toClose.push(id);
      }
    }

    return toClose;
  }

  shouldShowAlert(priority: 'critical' | 'high' | 'medium' | 'low', mode: string): boolean {
    if (mode === 'aggressive') return true;
    if (mode === 'ultrastealth') return priority === 'critical';
    if (mode === 'stealth') return priority === 'critical' || priority === 'high';
    return true;
  }

  getAnimationLevel(mode: string): 'full' | 'reduced' | 'minimal' {
    if (mode === 'ultrastealth') return 'minimal';
    if (mode === 'stealth') return 'reduced';
    return 'full';
  }

  getStats(): {
    activeWindows: number;
    queuedWindows: number;
    windows: { id: string; priority: string; lastActivity: number }[];
    queue: { id: string; priority: string }[];
    modeLimits: Record<string, ModeLimits>;
  } {
    return {
      activeWindows: this.activeWindows.size,
      queuedWindows: this.queue.length,
      windows: Array.from(this.activeWindows.values()).map(w => ({
        id: w.id,
        priority: w.priority,
        lastActivity: w.lastActivity,
      })),
      queue: this.queue.map(q => ({ id: q.id, priority: q.priority })),
      modeLimits: { ...MODE_LIMITS },
    };
  }
}

export const windowManager = new WindowManager();
