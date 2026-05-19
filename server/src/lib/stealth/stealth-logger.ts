import * as fs from 'fs';
import * as path from 'path';
import * as crypto from 'crypto';

const STEALTH_EVENT_TYPES = [
  'mode_change',
  'alert',
  'tool_deferral',
  'tool_execution',
  'window_block',
  'vision_trigger',
  'timing_adjustment',
  'human_simulation',
  'auto_adjustment',
  'platform_rule',
] as const;

export type StealthEventType = typeof STEALTH_EVENT_TYPES[number];

export interface StealthLogEntry {
  id: string;
  timestamp: string;
  sessionId: string;
  eventType: StealthEventType;
  data: any;
  metadata?: Record<string, any>;
}

export interface StealthEventFilter {
  eventType?: StealthEventType;
  date?: string;
  sessionId?: string;
}

const LOGS_DIR = path.join(process.cwd(), 'logs', 'stealth');
const REPLAY_DIR = path.join(LOGS_DIR, 'replay');
const FLUSH_INTERVAL_MS = 5000;
const FLUSH_THRESHOLD = 50;

class StealthLogger {
  private buffer: StealthLogEntry[] = [];
  private sessionId: string;
  private flushTimer: ReturnType<typeof setInterval> | null = null;

  constructor() {
    this.ensureDirs();
    this.sessionId = crypto.randomUUID();
    this.flushTimer = setInterval(() => this.flush(), FLUSH_INTERVAL_MS);
  }

  private ensureDirs(): void {
    try {
      fs.mkdirSync(LOGS_DIR, { recursive: true });
      fs.mkdirSync(REPLAY_DIR, { recursive: true });
    } catch {}
  }

  private getDailyFile(date?: string): string {
    const d = date || new Date().toISOString().split('T')[0];
    return path.join(LOGS_DIR, `stealth-${d}.ndjson`);
  }

  private getReplayFile(sessionId: string): string {
    return path.join(REPLAY_DIR, `${sessionId}.ndjson`);
  }

  log(eventType: StealthEventType, data: any, metadata?: Record<string, any>): void {
    const entry: StealthLogEntry = {
      id: crypto.randomUUID(),
      timestamp: new Date().toISOString(),
      sessionId: this.sessionId,
      eventType,
      data,
      ...(metadata !== undefined && { metadata }),
    };

    this.buffer.push(entry);

    if (this.buffer.length >= FLUSH_THRESHOLD) {
      this.flush();
    }
  }

  flush(): void {
    if (this.buffer.length === 0) return;

    const entries = [...this.buffer];
    this.buffer = [];

    this.ensureDirs();

    const byDate = new Map<string, StealthLogEntry[]>();
    const bySession = new Map<string, StealthLogEntry[]>();

    for (const entry of entries) {
      const date = entry.timestamp.split('T')[0];
      if (!byDate.has(date)) byDate.set(date, []);
      byDate.get(date)!.push(entry);

      if (!bySession.has(entry.sessionId)) bySession.set(entry.sessionId, []);
      bySession.get(entry.sessionId)!.push(entry);
    }

    Array.from(byDate.entries()).forEach(([date, dateEntries]) => {
      const lines = dateEntries.map(e => JSON.stringify(e)).join('\n') + '\n';
      try {
        fs.appendFileSync(this.getDailyFile(date), lines);
      } catch (err) {
        console.error('[StealthLogger] Daily write error:', err);
      }
    });

    Array.from(bySession.entries()).forEach(([sid, sessionEntries]) => {
      const lines = sessionEntries.map(e => JSON.stringify(e)).join('\n') + '\n';
      try {
        fs.appendFileSync(this.getReplayFile(sid), lines);
      } catch (err) {
        console.error('[StealthLogger] Replay write error:', err);
      }
    });
  }

  getSessionId(): string {
    return this.sessionId;
  }

  rotateSession(): string {
    this.flush();
    this.sessionId = crypto.randomUUID();
    return this.sessionId;
  }

  getEvents(filter?: StealthEventFilter): StealthLogEntry[] {
    const date = filter?.date || new Date().toISOString().split('T')[0];
    const file = this.getDailyFile(date);

    if (!fs.existsSync(file)) return [];

    try {
      const content = fs.readFileSync(file, 'utf-8');
      let entries = content
        .split('\n')
        .filter(line => line.trim())
        .map(line => {
          try {
            return JSON.parse(line) as StealthLogEntry;
          } catch {
            return null;
          }
        })
        .filter((e): e is StealthLogEntry => e !== null);

      if (filter?.eventType) {
        entries = entries.filter(e => e.eventType === filter.eventType);
      }
      if (filter?.sessionId) {
        entries = entries.filter(e => e.sessionId === filter.sessionId);
      }

      return entries;
    } catch {
      return [];
    }
  }

  getReplayLog(sessionId: string): StealthLogEntry[] {
    const file = this.getReplayFile(sessionId);

    if (!fs.existsSync(file)) return [];

    try {
      const content = fs.readFileSync(file, 'utf-8');
      return content
        .split('\n')
        .filter(line => line.trim())
        .map(line => {
          try {
            return JSON.parse(line) as StealthLogEntry;
          } catch {
            return null;
          }
        })
        .filter((e): e is StealthLogEntry => e !== null);
    } catch {
      return [];
    }
  }

  getStats(): {
    counts: Record<StealthEventType, number>;
    totalEntries: number;
    buffered: number;
    currentSessionId: string;
  } {
    const counts = {} as Record<StealthEventType, number>;
    for (const t of STEALTH_EVENT_TYPES) {
      counts[t] = 0;
    }

    const date = new Date().toISOString().split('T')[0];
    const events = this.getEvents({ date });

    for (const e of events) {
      if (e.eventType in counts) {
        counts[e.eventType]++;
      }
    }

    for (const e of this.buffer) {
      if (e.eventType in counts) {
        counts[e.eventType]++;
      }
    }

    return {
      counts,
      totalEntries: events.length + this.buffer.length,
      buffered: this.buffer.length,
      currentSessionId: this.sessionId,
    };
  }

  shutdown(): void {
    this.flush();
    if (this.flushTimer) {
      clearInterval(this.flushTimer);
      this.flushTimer = null;
    }
  }
}

export const stealthLogger = new StealthLogger();
