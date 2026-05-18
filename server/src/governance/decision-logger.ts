import { v4 as uuidv4 } from 'uuid';
import * as fs from 'fs';
import * as path from 'path';
import { GovernanceDecision } from './types';

const DECISIONS_DIR = path.join(process.cwd(), 'logs', 'governance-decisions');

export class DecisionLogger {
  private buffer: GovernanceDecision[] = [];
  private flushInterval: ReturnType<typeof setInterval> | null = null;
  private currentFile: string = '';

  constructor() {
    this.ensureDir();
    this.rotateFile();
    this.flushInterval = setInterval(() => this.flush(), 5000);
  }

  private ensureDir(): void {
    try {
      fs.mkdirSync(DECISIONS_DIR, { recursive: true });
    } catch {}
  }

  private rotateFile(): void {
    const date = new Date().toISOString().split('T')[0];
    this.currentFile = path.join(DECISIONS_DIR, `decisions-${date}.ndjson`);
  }

  log(decision: GovernanceDecision): void {
    this.buffer.push(decision);
    if (this.buffer.length >= 50) {
      this.flush();
    }
  }

  flush(): void {
    if (this.buffer.length === 0) return;

    this.rotateFile();

    const lines = this.buffer.map(d => JSON.stringify({
      ...d,
      timestamp: d.timestamp instanceof Date ? d.timestamp.toISOString() : d.timestamp
    })).join('\n') + '\n';

    try {
      fs.appendFileSync(this.currentFile, lines);
    } catch (err) {
      console.error('[DecisionLogger] Write error:', err);
    }

    this.buffer = [];
  }

  readDecisions(options?: {
    date?: string;
    limit?: number;
    verdict?: string;
    pillar?: string;
  }): GovernanceDecision[] {
    const date = options?.date || new Date().toISOString().split('T')[0];
    const file = path.join(DECISIONS_DIR, `decisions-${date}.ndjson`);

    if (!fs.existsSync(file)) return [];

    try {
      const content = fs.readFileSync(file, 'utf-8');
      let decisions = content
        .split('\n')
        .filter(line => line.trim())
        .map(line => {
          try {
            return JSON.parse(line) as GovernanceDecision;
          } catch {
            return null;
          }
        })
        .filter((d): d is GovernanceDecision => d !== null);

      if (options?.verdict) {
        decisions = decisions.filter(d => d.verdict === options.verdict);
      }
      if (options?.pillar) {
        decisions = decisions.filter(d => d.pillar === options.pillar);
      }
      if (options?.limit) {
        decisions = decisions.slice(-options.limit);
      }

      return decisions;
    } catch {
      return [];
    }
  }

  getAvailableDates(): string[] {
    try {
      return fs.readdirSync(DECISIONS_DIR)
        .filter(f => f.startsWith('decisions-') && f.endsWith('.ndjson'))
        .map(f => f.replace('decisions-', '').replace('.ndjson', ''))
        .sort()
        .reverse();
    } catch {
      return [];
    }
  }

  getDecisionById(id: string): GovernanceDecision | null {
    const dates = this.getAvailableDates();
    for (const date of dates) {
      const decisions = this.readDecisions({ date });
      const found = decisions.find(d => d.id === id);
      if (found) return found;
    }

    const buffered = this.buffer.find(d => d.id === id);
    return buffered || null;
  }

  getReplayData(decisionId: string): GovernanceDecision['replay'] | null {
    const decision = this.getDecisionById(decisionId);
    return decision?.replay || null;
  }

  getStats(): {
    totalLogged: number;
    buffered: number;
    availableDates: string[];
    currentFile: string;
  } {
    return {
      totalLogged: this.readDecisions().length + this.buffer.length,
      buffered: this.buffer.length,
      availableDates: this.getAvailableDates(),
      currentFile: this.currentFile
    };
  }

  shutdown(): void {
    this.flush();
    if (this.flushInterval) {
      clearInterval(this.flushInterval);
      this.flushInterval = null;
    }
  }
}
