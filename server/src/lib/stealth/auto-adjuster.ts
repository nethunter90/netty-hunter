import { stealthLogger } from './stealth-logger';

type StealthMode = 'aggressive' | 'stealth' | 'ultrastealth';

interface DetectionSignal {
  type: string;
  value: number;
}

interface PlatformRules {
  minMode: StealthMode;
  maxReqPerMin: number;
  proxyRequired: boolean;
  blockedTools: string[];
}

interface EvaluationResult {
  mode: StealthMode;
  risk: number;
  platformRules?: PlatformRules;
  adjustedAt: number;
}

interface AutoAdjusterStats {
  currentMode: StealthMode;
  detectionRisk: number;
  lastAdjustment: number;
  adjustmentCount: number;
  platformOverrides: number;
}

const SIGNAL_WEIGHTS: Record<string, number> = {
  honeypot: 40,
  ids: 35,
  captcha: 30,
  waf: 25,
  ratelimit: 20,
  behavioral: 15,
};

const MODE_ORDER: StealthMode[] = ['aggressive', 'stealth', 'ultrastealth'];

const PLATFORM_RULES: Record<string, PlatformRules> = {
  hackerone: { minMode: 'stealth', maxReqPerMin: 30, proxyRequired: false, blockedTools: [] },
  bugcrowd: { minMode: 'stealth', maxReqPerMin: 25, proxyRequired: false, blockedTools: [] },
  intigriti: { minMode: 'stealth', maxReqPerMin: 20, proxyRequired: false, blockedTools: ['sqlmap'] },
  synack: { minMode: 'ultrastealth', maxReqPerMin: 10, proxyRequired: true, blockedTools: ['masscan', 'nuclei'] },
  yeswehack: { minMode: 'stealth', maxReqPerMin: 25, proxyRequired: false, blockedTools: [] },
};

const COOLDOWN_MS = 10_000;
const DEFAULT_MAX_REQ_PER_MIN = 60;

class AutoAdjuster {
  private currentMode: StealthMode = 'aggressive';
  private detectionRisk: number = 0;
  private lastAdjustment: number = 0;
  private adjustmentCount: number = 0;
  private platformOverrides: number = 0;

  private modeIndex(mode: StealthMode): number {
    return MODE_ORDER.indexOf(mode);
  }

  private calculateRisk(signals: DetectionSignal[]): number {
    let totalWeight = 0;
    let weightedSum = 0;

    for (const signal of signals) {
      const weight = SIGNAL_WEIGHTS[signal.type];
      if (weight === undefined) continue;
      totalWeight += weight;
      weightedSum += weight * Math.max(0, Math.min(1, signal.value));
    }

    if (totalWeight === 0) return 0;
    return (weightedSum / totalWeight) * 100;
  }

  private riskToMode(risk: number): StealthMode {
    if (risk >= 70) return 'ultrastealth';
    if (risk >= 40) return 'stealth';
    return 'aggressive';
  }

  private enforceFloor(mode: StealthMode, minMode: StealthMode): StealthMode {
    return this.modeIndex(mode) >= this.modeIndex(minMode) ? mode : minMode;
  }

  evaluate(signals: DetectionSignal[], platform?: string): EvaluationResult {
    const now = Date.now();
    const risk = this.calculateRisk(signals);
    this.detectionRisk = risk;

    let newMode = this.riskToMode(risk);
    let rules: PlatformRules | undefined;

    if (platform) {
      rules = this.getPlatformRules(platform) ?? undefined;
      if (rules) {
        const before = newMode;
        newMode = this.enforceFloor(newMode, rules.minMode);
        if (before !== newMode) {
          this.platformOverrides++;
          stealthLogger.log('platform_rule', {
            platform,
            requestedMode: before,
            enforcedMode: newMode,
            rules,
          });
        }
      }
    }

    const cooldownElapsed = now - this.lastAdjustment >= COOLDOWN_MS;

    if (newMode !== this.currentMode && cooldownElapsed) {
      const previousMode = this.currentMode;
      this.currentMode = newMode;
      this.lastAdjustment = now;
      this.adjustmentCount++;

      stealthLogger.log('auto_adjustment', {
        previousMode,
        newMode,
        risk,
        signals,
        platform: platform || null,
      });
    }

    return {
      mode: this.currentMode,
      risk,
      ...(rules && { platformRules: rules }),
      adjustedAt: this.lastAdjustment,
    };
  }

  getCurrentMode(): StealthMode {
    return this.currentMode;
  }

  setMode(mode: StealthMode): void {
    const previousMode = this.currentMode;
    this.currentMode = mode;
    this.lastAdjustment = Date.now();
    this.adjustmentCount++;

    stealthLogger.log('auto_adjustment', {
      previousMode,
      newMode: mode,
      risk: this.detectionRisk,
      forced: true,
    });
  }

  getPlatformRules(platform: string): PlatformRules | null {
    return PLATFORM_RULES[platform.toLowerCase()] ?? null;
  }

  isToolBlocked(tool: string, platform?: string): boolean {
    if (!platform) return false;
    const rules = this.getPlatformRules(platform);
    if (!rules) return false;
    return rules.blockedTools.includes(tool.toLowerCase());
  }

  getMaxRequestsPerMinute(platform?: string): number {
    if (!platform) return DEFAULT_MAX_REQ_PER_MIN;
    const rules = this.getPlatformRules(platform);
    return rules ? rules.maxReqPerMin : DEFAULT_MAX_REQ_PER_MIN;
  }

  getStats(): AutoAdjusterStats {
    return {
      currentMode: this.currentMode,
      detectionRisk: this.detectionRisk,
      lastAdjustment: this.lastAdjustment,
      adjustmentCount: this.adjustmentCount,
      platformOverrides: this.platformOverrides,
    };
  }
}

export const autoAdjuster = new AutoAdjuster();
