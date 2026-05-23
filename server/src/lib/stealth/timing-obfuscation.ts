import { stealthLogger } from './stealth-logger';

type ActionType = 'recon' | 'exploit' | 'scan';

interface TimingProfile {
  recon: [number, number];
  exploit: [number, number];
  scan: [number, number];
  maxBurst: number;
  cooldown: number;
  jitter: number;
}

interface DelayBreakdown {
  baseDelay: number;
  jitter: number;
  burstPenalty: number;
  circadianMultiplier: number;
  riskMultiplier: number;
  totalDelay: number;
}

const TIMING_PROFILES: Record<string, TimingProfile> = {
  aggressive: { recon: [100, 500], exploit: [500, 2000], scan: [200, 1000], maxBurst: 50, cooldown: 1000, jitter: 0.20 },
  balanced: { recon: [1000, 3000], exploit: [3000, 10000], scan: [1000, 3000], maxBurst: 25, cooldown: 5000, jitter: 0.25 },
  stealth: { recon: [3000, 10000], exploit: [10000, 30000], scan: [5000, 15000], maxBurst: 3, cooldown: 15000, jitter: 0.50 },
  ultrastealth: { recon: [30000, 120000], exploit: [60000, 300000], scan: [30000, 90000], maxBurst: 1, cooldown: 120000, jitter: 0.70 },
};

const RISK_MULTIPLIERS: Record<string, number> = {
  low: 1.0,
  medium: 1.2,
  high: 1.8,
  critical: 3.0,
};

class TimingObfuscation {
  private burstCounters: Map<string, number> = new Map();

  private getProfile(profile: string): TimingProfile {
    return TIMING_PROFILES[profile] || TIMING_PROFILES.stealth;
  }

  private getCircadianMultiplier(): number {
    const hour = new Date().getUTCHours();
    if (hour >= 9 && hour < 17) return 0.8;
    if (hour >= 2 && hour < 6) return 1.5;
    return 1.0;
  }

  private randomInRange(min: number, max: number): number {
    return min + Math.random() * (max - min);
  }

  private applyJitter(value: number, jitterFraction: number): number {
    const variation = value * jitterFraction;
    return value + (Math.random() * 2 - 1) * variation;
  }

  calculateDelay(actionType: ActionType, profile: string, risk?: string, target?: string): DelayBreakdown {
    const p = this.getProfile(profile);
    const range = p[actionType];
    const baseDelay = this.randomInRange(range[0], range[1]);
    const jitter = this.applyJitter(baseDelay, p.jitter) - baseDelay;

    let burstPenalty = 0;
    if (target) {
      const consecutive = this.burstCounters.get(target) || 0;
      if (consecutive > p.maxBurst) {
        const overage = consecutive - p.maxBurst;
        burstPenalty = baseDelay * (1 + 0.5 * overage);
      }
    }

    const circadianMultiplier = this.getCircadianMultiplier();
    const riskMultiplier = RISK_MULTIPLIERS[risk || 'low'] || 1.0;

    const totalDelay = Math.max(0, (baseDelay + jitter + burstPenalty) * circadianMultiplier * riskMultiplier);

    stealthLogger.log('timing_adjustment', {
      actionType,
      profile,
      risk: risk || 'low',
      target: target || null,
      baseDelay: Math.round(baseDelay),
      jitter: Math.round(jitter),
      burstPenalty: Math.round(burstPenalty),
      circadianMultiplier,
      riskMultiplier,
      totalDelay: Math.round(totalDelay),
    });

    return {
      baseDelay: Math.round(baseDelay),
      jitter: Math.round(jitter),
      burstPenalty: Math.round(burstPenalty),
      circadianMultiplier,
      riskMultiplier,
      totalDelay: Math.round(totalDelay),
    };
  }

  getDelay(actionType: ActionType, profile: string, risk?: string, target?: string): number {
    return this.calculateDelay(actionType, profile, risk, target).totalDelay;
  }

  shuffleActions<T>(actions: T[], profile: string): T[] {
    if (profile === 'aggressive') return [...actions];

    const shuffled = [...actions];
    for (let i = shuffled.length - 1; i > 0; i--) {
      const j = Math.floor(Math.random() * (i + 1));
      [shuffled[i], shuffled[j]] = [shuffled[j], shuffled[i]];
    }
    return shuffled;
  }

  recordAction(target: string): void {
    const current = this.burstCounters.get(target) || 0;
    this.burstCounters.set(target, current + 1);
  }

  resetBurst(target: string): void {
    this.burstCounters.delete(target);
  }

  getStats(): {
    profiles: Record<string, { maxBurst: number; cooldown: number; jitter: number }>;
    burstCounts: Record<string, number>;
    currentCircadianMultiplier: number;
  } {
    const profiles: Record<string, { maxBurst: number; cooldown: number; jitter: number }> = {};
    for (const [name, p] of Object.entries(TIMING_PROFILES)) {
      profiles[name] = { maxBurst: p.maxBurst, cooldown: p.cooldown, jitter: p.jitter };
    }

    const burstCounts: Record<string, number> = {};
    for (const [target, count] of Array.from(this.burstCounters.entries())) {
      burstCounts[target] = count;
    }

    return {
      profiles,
      burstCounts,
      currentCircadianMultiplier: this.getCircadianMultiplier(),
    };
  }
}

export const timingObfuscation = new TimingObfuscation();
