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
 *   context/hunt-digest.txt     — single-line compact status (token-efficient)
 *   context/alerts.jsonl        — key events only: findings, errors, phase changes
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
  // The `findings` table's integer PK, set once persistFinding() resolves.
  // Lets a later Layer 5 verification verdict (keyed by that same DB id)
  // find and retract this entry — see retractFinding().
  dbId?: number;
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

  /**
   * Layer 5's 4-layer verification runs *after* the engine's own fast-path
   * confidence threshold already pushed a finding here — so a later
   * "rejected"/"inconclusive" verdict was previously silent: the finding
   * stayed visible in hunt-findings.json as "confirmed" forever, with no
   * trace of the more rigorous pipeline overturning it. Called from
   * CampaignOrchestrator's Layer 5 gate once verification completes.
   */
  retractFinding(dbId: number): void {
    const before = this.findings.length;
    this.findings = this.findings.filter((f) => f.dbId !== dbId);
    if (this.findings.length !== before) this.scheduleFlush();
  }

  /** Reconcile confidence once Layer 5 confirms — the fast-path value was provisional. */
  updateFindingConfidence(dbId: number, confidence: number): void {
    const finding = this.findings.find((f) => f.dbId === dbId);
    if (finding) {
      finding.confidence = confidence;
      this.scheduleFlush();
    }
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

  /** Emit a notable event to alerts.jsonl (findings, phase changes, critical errors). */
  alert(type: string, detail: Record<string, unknown>): void {
    append("alerts.jsonl", { ts: new Date().toISOString(), type, ...detail }).catch(() => {});
  }

  private flush(): void {
    if (this.state) {
      write("hunt-live.json", this.state).catch(() => {});
      this.writeDigest();
    }
    // Always write, even when this.findings is now empty. The `> 0` guard this
    // replaced meant a full retraction (every finding on this hunt turning out
    // non-confirmed after verification) could never be reflected on disk: once
    // the array emptied, flush() silently kept the LAST non-empty snapshot —
    // stale, pre-verification "confirmed" data — forever. Confirmed live via a
    // direct-launch hunt (2026-07-24 readiness fix, blocker D Phase 2): three
    // findings all ended up rejected/deduplicated, and hunt-findings.json kept
    // showing two of them at their original heuristic confidence indefinitely.
    write("hunt-findings.json", this.findings).catch(() => {});
  }

  private writeDigest(): void {
    if (!this.state) return;
    const s = this.state;
    const ts = new Date().toISOString().slice(11, 19); // HH:MM:SS
    const errFlag = this.recentErrors.length > 0 ? ` ERR=${this.recentErrors.length}` : "";
    const line =
      `[${ts}] ${s.phase.toUpperCase().padEnd(9)} | iter=${String(s.iteration).padStart(2)} | ` +
      `hyps=${s.hypothesesCount} found=${s.findingsCount}${errFlag} | ` +
      `model=${s.activeModel} | ${s.targetUrl}\n`;
    fs.mkdir(CONTEXT_DIR, { recursive: true })
      .then(() => fs.writeFile(path.join(CONTEXT_DIR, "hunt-digest.txt"), line))
      .catch(() => {});
  }
}

export const contextWriter = new ContextWriter();
