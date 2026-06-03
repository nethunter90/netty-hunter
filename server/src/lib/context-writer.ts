/**
 * ContextWriter — streams live hunt state to context/ files.
 *
 * Claude Code reads these files automatically (via CLAUDE.md instructions)
 * so it always has full situational awareness about what the hunt is doing,
 * what it found, and what errors occurred — without the user having to explain
 * anything when they open the terminal.
 *
 * Files written:
 *   context/hunt-live.json      — current hunt state (overwritten each update)
 *   context/hunt-findings.json  — all confirmed findings so far
 *   context/errors.jsonl        — append-only error log
 */
import { promises as fs } from "fs";
import path from "path";

const CONTEXT_DIR = path.join(process.cwd(), "context");

async function write(filename: string, data: unknown): Promise<void> {
  await fs.mkdir(CONTEXT_DIR, { recursive: true });
  await fs.writeFile(
    path.join(CONTEXT_DIR, filename),
    JSON.stringify(data, null, 2)
  );
}

async function append(filename: string, data: unknown): Promise<void> {
  await fs.mkdir(CONTEXT_DIR, { recursive: true });
  await fs.appendFile(
    path.join(CONTEXT_DIR, filename),
    JSON.stringify(data) + "\n"
  );
}

export interface HuntLiveState {
  sessionId: string;
  targetUrl: string;
  phase: string;
  iteration: number;
  hypothesesCount: number;
  findingsCount: number;
  lastActivity: string;
  activeModel: string;
  usingClaudeBridge: boolean;
  errors: { ts: string; message: string }[];
}

export interface FindingRecord {
  id: string;
  vulnClass: string;
  severity: string;
  confidence: number;
  endpoint?: string;
  payload?: string;
  description: string;
  confirmedAt: string;
}

class ContextWriter {
  private state: HuntLiveState | null = null;
  private findings: FindingRecord[] = [];
  private recentErrors: { ts: string; message: string }[] = [];
  private flushTimer: ReturnType<typeof setTimeout> | null = null;

  updateState(patch: Partial<HuntLiveState>): void {
    if (!this.state && !patch.sessionId) return;
    this.state = { ...(this.state ?? ({} as HuntLiveState)), ...patch };
    this.state.lastActivity = new Date().toISOString();
    this.state.errors = this.recentErrors.slice(-10);
    this.scheduleFlush();
  }

  addFinding(finding: FindingRecord): void {
    this.findings.push(finding);
    this.scheduleFlush();
  }

  recordError(message: string): void {
    const entry = { ts: new Date().toISOString(), message: message.slice(0, 500) };
    this.recentErrors.push(entry);
    if (this.recentErrors.length > 50) this.recentErrors.shift();
    // Write errors immediately — don't wait for debounce
    append("errors.jsonl", entry).catch(() => {});
    if (this.state) {
      this.state.errors = this.recentErrors.slice(-10);
      this.scheduleFlush();
    }
  }

  /** Reset for a new hunt session. */
  reset(sessionId: string, targetUrl: string, activeModel: string): void {
    this.findings = [];
    this.recentErrors = [];
    this.state = {
      sessionId,
      targetUrl,
      phase: "observe",
      iteration: 0,
      hypothesesCount: 0,
      findingsCount: 0,
      lastActivity: new Date().toISOString(),
      activeModel,
      usingClaudeBridge: false,
      errors: [],
    };
    this.flush();
  }

  private scheduleFlush(): void {
    if (this.flushTimer) return;
    this.flushTimer = setTimeout(() => {
      this.flushTimer = null;
      this.flush();
    }, 500);
  }

  private flush(): void {
    if (this.state) {
      write("hunt-live.json", this.state).catch(() => {});
    }
    if (this.findings.length > 0) {
      write("hunt-findings.json", this.findings).catch(() => {});
    }
  }
}

export const contextWriter = new ContextWriter();
