/**
 * ROIModel — lib/hunter singleton
 *
 * Tracks expected value, priority multipliers, and manual threshold overrides
 * for bug bounty program and vulnerability type decisions.
 */

export interface EVProfile {
  programId: string;
  expectedValue: number;
  confidence: number;
  historySize: number;
  breakdown: {
    avgPayout: number;
    successProbability: number;
    timeMultiplier: number;
    competitionPenalty: number;
  };
}

export interface Thresholds {
  minAcceptableEV:    number;
  maxTimeInvestment:  number;   // hours
  minConfidence:      number;
  vulnPriorityFloor:  Record<string, number>;
}

export interface ManualOverride {
  type:   string;
  values: Record<string, number>;
  reason: string;
  active: boolean;
}

export interface GlobalStats {
  totalPrograms:   number;
  avgEV:           number;
  topProgram:      string | null;
  totalPayouts:    number;
  successRate:     number;
}

// ── Singleton ─────────────────────────────────────────────────────────────────

const DEFAULT_THRESHOLDS: Thresholds = {
  minAcceptableEV:   100,
  maxTimeInvestment: 8,
  minConfidence:     0.4,
  vulnPriorityFloor: {
    rce: 0.9, sqli: 0.8, ssrf: 0.7, xss: 0.5, idor: 0.6,
    lfi: 0.6, xxe: 0.7, csrf: 0.4, cors: 0.3, info_disclosure: 0.3,
  },
};

const BASE_PAYOUTS: Record<string, number> = {
  rce: 5000, sqli: 3000, ssrf: 2000, xss: 1000, idor: 1500,
  lfi: 1500, xxe: 2000, csrf: 500, cors: 300, auth_bypass: 2000,
  open_redirect: 200, info_disclosure: 300, misconfig: 500,
  subdomain_takeover: 1500, rate_limit_bypass: 300, business_logic: 2500,
  security_headers: 150, exposed_admin: 1000,
};

class ROIModelStore {
  private evProfiles:     Map<string, EVProfile>                       = new Map();
  private overrides:      Map<string, ManualOverride>                  = new Map();
  private thresholds:     Thresholds                                   = { ...DEFAULT_THRESHOLDS };
  private payoutHistory:  Array<{ programId: string; payout: number; vulnType: string; at: number }> = [];

  // ── EV ─────────────────────────────────────────────────────────────────────

  calculateEVForProgram(programId: string): EVProfile {
    const cached = this.evProfiles.get(programId);

    const history = this.payoutHistory.filter(h => h.programId === programId);
    if (history.length === 0) {
      const profile: EVProfile = {
        programId,
        expectedValue:   0,
        confidence:      0,
        historySize:     0,
        breakdown: { avgPayout: 0, successProbability: 0, timeMultiplier: 1, competitionPenalty: 0 },
      };
      this.evProfiles.set(programId, profile);
      return profile;
    }

    const payouts = history.map(h => h.payout);
    const avgPayout = payouts.reduce((s, p) => s + p, 0) / payouts.length;
    const successProbability = Math.min(0.95, 0.1 + (history.length * 0.05));
    const competitionPenalty = Math.max(0, 1 - (history.length * 0.01));

    const ev = avgPayout * successProbability * competitionPenalty;

    const profile: EVProfile = {
      programId,
      expectedValue:   Math.round(ev),
      confidence:      Math.min(0.95, 0.3 + (history.length * 0.05)),
      historySize:     history.length,
      breakdown:       { avgPayout: Math.round(avgPayout), successProbability, timeMultiplier: 1, competitionPenalty },
    };
    this.evProfiles.set(programId, profile);
    return profile;
  }

  getGlobalStats(): GlobalStats {
    const programs = Array.from(this.evProfiles.keys());
    const evs      = programs.map(p => this.evProfiles.get(p)!.expectedValue);
    const avgEV    = evs.length > 0 ? evs.reduce((s, e) => s + e, 0) / evs.length : 0;
    const topEntry = programs.reduce<{ id: string; ev: number } | null>((max, p) => {
      const ev = this.evProfiles.get(p)!.expectedValue;
      return !max || ev > max.ev ? { id: p, ev } : max;
    }, null);

    const totalPayouts = this.payoutHistory.reduce((s, h) => s + h.payout, 0);
    const successCount = this.payoutHistory.filter(h => h.payout > 0).length;
    const successRate  = this.payoutHistory.length > 0 ? successCount / this.payoutHistory.length : 0;

    return {
      totalPrograms: programs.length,
      avgEV:         Math.round(avgEV),
      topProgram:    topEntry?.id ?? null,
      totalPayouts,
      successRate:   Math.round(successRate * 100) / 100,
    };
  }

  // ── Thresholds & Overrides ─────────────────────────────────────────────────

  getThresholds(): Thresholds {
    return { ...this.thresholds };
  }

  setManualOverride(scope: string, override: ManualOverride): void {
    const key = `${scope}:${override.type}`;
    this.overrides.set(key, override);

    if (override.type === 'vulnPriority' && override.values) {
      for (const [vuln, value] of Object.entries(override.values)) {
        this.thresholds.vulnPriorityFloor[vuln] = value;
      }
    }
    if (override.type === 'ev' && override.values.minAcceptableEV !== undefined) {
      this.thresholds.minAcceptableEV = override.values.minAcceptableEV;
    }
  }

  clearManualOverride(scope: string, type: string): void {
    const key = `${scope}:${type}`;
    this.overrides.delete(key);
    // Restore defaults for that type
    if (type === 'vulnPriority') {
      this.thresholds.vulnPriorityFloor = { ...DEFAULT_THRESHOLDS.vulnPriorityFloor };
    }
    if (type === 'ev') {
      this.thresholds.minAcceptableEV = DEFAULT_THRESHOLDS.minAcceptableEV;
    }
  }

  getPriorityMultiplier(vulnType: string, programId?: string): number {
    const floor = this.thresholds.vulnPriorityFloor[vulnType] ?? 0.3;
    const base  = BASE_PAYOUTS[vulnType] ?? 300;

    // Program-specific adjustment
    if (programId) {
      const profile = this.evProfiles.get(programId);
      if (profile && profile.expectedValue > 0) {
        return Math.round((floor + (profile.expectedValue / 10000) * 0.2) * 100) / 100;
      }
    }

    return Math.round(floor * 100) / 100;
  }

  // Called by hunter-engine when a payout is received
  recordPayout(programId: string, vulnType: string, payout: number): void {
    this.payoutHistory.push({ programId, vulnType, payout, at: Date.now() });
    // Invalidate cached EV
    this.evProfiles.delete(programId);
  }
}

export const roiModel = new ROIModelStore();
