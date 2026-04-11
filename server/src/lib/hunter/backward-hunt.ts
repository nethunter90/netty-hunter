/**
 * BackwardHuntEngine — lib/hunter singleton
 *
 * Session-aware goal-first hunting that works backward from objectives
 * using pre-built attack trees.
 */
import { v4 as uuidv4 } from 'uuid';

export interface BackwardHuntState {
  sessionId:   string;
  huntId:      string;
  objective:   string;
  currentGoal: string;
  steps:       BackwardStep[];
  hypotheses:  BackwardHypothesis[];
  status:      'active' | 'paused' | 'complete' | 'failed';
  startedAt:   number;
  updatedAt:   number;
}

export interface BackwardStep {
  id:          string;
  description: string;
  vulnClass:   string;
  succeeded:   boolean;
  result:      unknown;
  recordedAt:  number;
}

export interface BackwardHypothesis {
  id:         string;
  vulnClass:  string;
  rationale:  string;
  priority:   number;
  tools:      string[];
}

export interface BackwardSummary {
  sessionId:     string;
  objective:     string;
  currentGoal:   string;
  status:        BackwardHuntState['status'];
  stepsCompleted: number;
  stepsSucceeded: number;
  hypotheses:    BackwardHypothesis[];
  startedAt:     number;
}

// ── Pre-built attack tree hypotheses ─────────────────────────────────────────

const OBJECTIVE_HYPOTHESES: Record<string, BackwardHypothesis[]> = {
  account_takeover: [
    { id: uuidv4(), vulnClass: 'xss',       rationale: 'XSS to steal session cookie',              priority: 0.8, tools: ['nuclei', 'manual'] },
    { id: uuidv4(), vulnClass: 'auth_bypass', rationale: 'Password reset flow vulnerability',       priority: 0.7, tools: ['manual', 'burp'] },
    { id: uuidv4(), vulnClass: 'open_redirect', rationale: 'Redirect for OAuth token theft',        priority: 0.6, tools: ['manual'] },
    { id: uuidv4(), vulnClass: 'sqli',       rationale: 'SQL injection in login form',              priority: 0.5, tools: ['sqlmap'] },
    { id: uuidv4(), vulnClass: 'csrf',       rationale: 'CSRF to change email/password',            priority: 0.4, tools: ['manual'] },
  ],
  data_exfiltration: [
    { id: uuidv4(), vulnClass: 'idor',       rationale: 'IDOR to access other users data',          priority: 0.9, tools: ['manual'] },
    { id: uuidv4(), vulnClass: 'sqli',       rationale: 'SQL injection for database dump',          priority: 0.8, tools: ['sqlmap'] },
    { id: uuidv4(), vulnClass: 'ssrf',       rationale: 'SSRF to access cloud metadata/S3',         priority: 0.7, tools: ['nuclei', 'manual'] },
    { id: uuidv4(), vulnClass: 'xxe',        rationale: 'XXE to read internal files',               priority: 0.6, tools: ['nuclei'] },
    { id: uuidv4(), vulnClass: 'info_disclosure', rationale: 'Sensitive data in API responses',     priority: 0.7, tools: ['curl_probe'] },
  ],
  rce: [
    { id: uuidv4(), vulnClass: 'rce',        rationale: 'Command injection in user-controlled input', priority: 0.9, tools: ['nuclei', 'manual'] },
    { id: uuidv4(), vulnClass: 'lfi',        rationale: 'LFI to RCE via log poisoning',             priority: 0.7, tools: ['nuclei', 'manual'] },
    { id: uuidv4(), vulnClass: 'ssrf',       rationale: 'SSRF to internal service RCE',             priority: 0.6, tools: ['manual'] },
    { id: uuidv4(), vulnClass: 'sqli',       rationale: 'SQLi to write web shell',                  priority: 0.5, tools: ['sqlmap'] },
  ],
};

function matchObjective(objective: string): string {
  const o = objective.toLowerCase();
  if (o.includes('account') || o.includes('takeover') || o.includes('login') || o.includes('auth')) return 'account_takeover';
  if (o.includes('data') || o.includes('exfil') || o.includes('pii') || o.includes('leak')) return 'data_exfiltration';
  if (o.includes('rce') || o.includes('execute') || o.includes('shell') || o.includes('command')) return 'rce';
  return 'data_exfiltration';
}

// ── Singleton ─────────────────────────────────────────────────────────────────

class BackwardHuntEngineStore {
  private hunts: Map<string, BackwardHuntState> = new Map();

  createBackwardHunt(sessionId: string, objective: string): BackwardHuntState {
    const treeKey    = matchObjective(objective);
    const hypotheses = (OBJECTIVE_HYPOTHESES[treeKey] ?? OBJECTIVE_HYPOTHESES.data_exfiltration)
      .map(h => ({ ...h, id: uuidv4() }));    // fresh IDs per session

    const hunt: BackwardHuntState = {
      sessionId,
      huntId:      uuidv4(),
      objective,
      currentGoal: objective,
      steps:       [],
      hypotheses,
      status:      'active',
      startedAt:   Date.now(),
      updatedAt:   Date.now(),
    };

    this.hunts.set(sessionId, hunt);
    return hunt;
  }

  getSummary(sessionId: string): BackwardSummary | null {
    const hunt = this.hunts.get(sessionId);
    if (!hunt) return null;

    return {
      sessionId:      hunt.sessionId,
      objective:      hunt.objective,
      currentGoal:    hunt.currentGoal,
      status:         hunt.status,
      stepsCompleted: hunt.steps.length,
      stepsSucceeded: hunt.steps.filter(s => s.succeeded).length,
      hypotheses:     hunt.hypotheses,
      startedAt:      hunt.startedAt,
    };
  }

  generateHypotheses(sessionId: string): BackwardHypothesis[] {
    const hunt = this.hunts.get(sessionId);
    if (!hunt) return [];
    return hunt.hypotheses.sort((a, b) => b.priority - a.priority);
  }

  recordStepResult(sessionId: string, stepDescription: string, succeeded: boolean, result: unknown): void {
    const hunt = this.hunts.get(sessionId);
    if (!hunt) return;

    hunt.steps.push({
      id:          uuidv4(),
      description: stepDescription,
      vulnClass:   'unknown',
      succeeded,
      result,
      recordedAt:  Date.now(),
    });
    hunt.updatedAt = Date.now();

    if (succeeded) {
      hunt.status = 'complete';
    }
  }
}

export const backwardHuntEngine = new BackwardHuntEngineStore();
