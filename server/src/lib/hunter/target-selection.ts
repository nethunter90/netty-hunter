/**
 * TargetSelectionEngine — lib/hunter singleton
 *
 * In-memory program store with ROI-based scoring, ranking, and outcome feedback.
 */
import { v4 as uuidv4 } from 'uuid';

export interface ProgramMetadata {
  programId: string;
  platform: string;
  name: string;
  maxPayout?: number;
  responseTime?: number;       // hours
  scope?: string[];
  outOfScope?: string[];
  techStack?: string[];
  successRate?: number;
}

export interface ProgramScore {
  programId: string;
  name: string;
  platform: string;
  roiScore: number;
  rank: number;
  factors: {
    payoutScore:       number;
    responseTimeScore: number;
    successRateScore:  number;
    scopeBreadthScore: number;
    noiseScore:        number;
    platformScore:     number;
  };
  competition: 'low' | 'medium' | 'high';
  recommendedFor: string[];
}

export interface OutcomeRecord {
  accepted:  boolean;
  payout:    number;
  vulnType:  string;
  recordedAt: number;
}

// ── Singleton ─────────────────────────────────────────────────────────────────

class TargetSelectionEngineStore {
  private programs:  Map<string, ProgramMetadata>        = new Map();
  private outcomes:  Map<string, OutcomeRecord[]>        = new Map();
  private huntCounts: Map<string, number>                = new Map();

  addProgram(metadata: ProgramMetadata): void {
    this.programs.set(metadata.programId, metadata);
    if (!this.huntCounts.has(metadata.programId)) this.huntCounts.set(metadata.programId, 0);
  }

  scoreProgram(programId: string): ProgramScore {
    const prog = this.programs.get(programId);
    if (!prog) throw new Error(`Program ${programId} not found`);

    const hunts  = this.huntCounts.get(programId) || 0;
    const outs   = this.outcomes.get(programId)   || [];
    const finds  = outs.filter(o => o.accepted).length;

    const PLATFORM_SCORE: Record<string, number> = {
      hackerone: 0.9, bugcrowd: 0.85, intigriti: 0.8,
      synack: 0.95, yeswehack: 0.75,
    };

    const factors = {
      payoutScore:       Math.min(1, (prog.maxPayout || 0) / 10000),
      responseTimeScore: Math.max(0, 1 - ((prog.responseTime || 168) / 168)),
      successRateScore:  prog.successRate ?? (hunts > 0 ? finds / hunts : 0.3),
      scopeBreadthScore: Math.min(1, ((prog.scope?.length || 1) / 10)),
      noiseScore:        hunts < 5 ? 0.8 : Math.max(0, 1 - (hunts / 50)),
      platformScore:     PLATFORM_SCORE[prog.platform] || 0.5,
    };

    const weights = { payoutScore: 0.3, responseTimeScore: 0.15, successRateScore: 0.25, scopeBreadthScore: 0.1, noiseScore: 0.1, platformScore: 0.1 };
    const roiScore = Object.entries(factors).reduce((s, [k, v]) => s + v * (weights[k as keyof typeof weights] || 0), 0);

    const competition: ProgramScore['competition'] = hunts > 20 ? 'high' : hunts > 5 ? 'medium' : 'low';

    const recommendedFor: string[] = [];
    if (factors.payoutScore > 0.7)  recommendedFor.push('high-value hunting');
    if (factors.noiseScore > 0.6)   recommendedFor.push('low-competition');
    if (factors.scopeBreadthScore > 0.5) recommendedFor.push('broad-scope recon');

    return {
      programId,
      name: prog.name,
      platform: prog.platform,
      roiScore: Math.round(roiScore * 100) / 100,
      rank: 0,
      factors,
      competition,
      recommendedFor,
    };
  }

  rankAll(): ProgramScore[] {
    const scores = Array.from(this.programs.keys()).map(id => {
      try { return this.scoreProgram(id); }
      catch { return null; }
    }).filter((s): s is ProgramScore => s !== null);

    scores.sort((a, b) => b.roiScore - a.roiScore);
    scores.forEach((s, i) => { s.rank = i + 1; });
    return scores;
  }

  getTargetQueue(limit?: number): ProgramScore[] {
    const ranked = this.rankAll();
    return limit ? ranked.slice(0, limit) : ranked;
  }

  updateFromOutcome(programId: string, outcome: { accepted: boolean; payout: number; vulnType: string }): void {
    const out: OutcomeRecord = { ...outcome, recordedAt: Date.now() };
    const existing = this.outcomes.get(programId) || [];
    existing.push(out);
    this.outcomes.set(programId, existing);
    this.huntCounts.set(programId, (this.huntCounts.get(programId) || 0) + 1);
  }
}

export const targetSelectionEngine = new TargetSelectionEngineStore();
