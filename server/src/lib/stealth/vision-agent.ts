import { stealthLogger } from './stealth-logger';

interface ModeConfig {
  alwaysOn: boolean;
  throttleInterval: number;
  maxActivationsPerMinute: number;
  quality: 'high' | 'low';
  overlays: boolean;
}

const MODE_CONFIGS: Record<string, ModeConfig> = {
  normal: {
    alwaysOn: true,
    throttleInterval: 0,
    maxActivationsPerMinute: Infinity,
    quality: 'high',
    overlays: true,
  },
  stealth: {
    alwaysOn: false,
    throttleInterval: 10000,
    maxActivationsPerMinute: 6,
    quality: 'low',
    overlays: false,
  },
};

interface TriggerConfig {
  cooldown: number;
  critical: boolean;
}

const TRIGGER_CONFIGS: Record<string, TriggerConfig> = {
  modal: { cooldown: 5000, critical: false },
  alert: { cooldown: 5000, critical: false },
  error: { cooldown: 0, critical: true },
  captcha: { cooldown: 0, critical: true },
  login: { cooldown: 10000, critical: false },
  confirmation: { cooldown: 5000, critical: false },
};

interface ActivationRecord {
  trigger: string;
  timestamp: number;
}

interface ShouldActivateResult {
  allowed: boolean;
  reason?: string;
  quality: 'high' | 'low';
  overlays: boolean;
}

class VisionAgent {
  private activations: ActivationRecord[] = [];
  private lastTriggerTime: Map<string, number> = new Map();
  private lastGlobalActivation: number = 0;
  private blockedCount: number = 0;
  private triggerCounts: Map<string, number> = new Map();

  private getConfig(mode: string): ModeConfig {
    return MODE_CONFIGS[mode] || MODE_CONFIGS.normal;
  }

  private getTriggerConfig(trigger: string): TriggerConfig {
    return TRIGGER_CONFIGS[trigger] || { cooldown: 5000, critical: false };
  }

  private getActivationsInLastMinute(): number {
    const oneMinuteAgo = Date.now() - 60000;
    this.activations = this.activations.filter(a => a.timestamp > oneMinuteAgo);
    return this.activations.length;
  }

  shouldActivate(trigger: string, mode: string): ShouldActivateResult {
    const config = this.getConfig(mode);
    const triggerConfig = this.getTriggerConfig(trigger);
    const now = Date.now();

    if (mode === 'normal') {
      stealthLogger.log('vision_trigger', { trigger, mode, allowed: true });
      return { allowed: true, quality: config.quality, overlays: config.overlays };
    }

    const lastTrigger = this.lastTriggerTime.get(trigger) || 0;
    if (triggerConfig.cooldown > 0 && (now - lastTrigger) < triggerConfig.cooldown) {
      this.blockedCount++;
      const reason = `trigger_cooldown: ${triggerConfig.cooldown}ms not elapsed`;
      stealthLogger.log('vision_trigger', { trigger, mode, allowed: false, reason });
      return { allowed: false, reason, quality: config.quality, overlays: config.overlays };
    }

    const recentCount = this.getActivationsInLastMinute();
    if (recentCount >= config.maxActivationsPerMinute) {
      this.blockedCount++;
      const reason = `rate_limit: ${recentCount}/${config.maxActivationsPerMinute} per minute`;
      stealthLogger.log('vision_trigger', { trigger, mode, allowed: false, reason });
      return { allowed: false, reason, quality: config.quality, overlays: config.overlays };
    }

    if (!triggerConfig.critical && config.throttleInterval > 0) {
      const sinceLast = now - this.lastGlobalActivation;
      if (sinceLast < config.throttleInterval) {
        this.blockedCount++;
        const reason = `global_throttle: ${config.throttleInterval}ms interval, ${sinceLast}ms elapsed`;
        stealthLogger.log('vision_trigger', { trigger, mode, allowed: false, reason });
        return { allowed: false, reason, quality: config.quality, overlays: config.overlays };
      }
    }

    stealthLogger.log('vision_trigger', { trigger, mode, allowed: true });
    return { allowed: true, quality: config.quality, overlays: config.overlays };
  }

  recordActivation(trigger: string): void {
    const now = Date.now();
    this.activations.push({ trigger, timestamp: now });
    this.lastTriggerTime.set(trigger, now);
    this.lastGlobalActivation = now;
    this.triggerCounts.set(trigger, (this.triggerCounts.get(trigger) || 0) + 1);
  }

  getScreenshotQuality(mode: string): 'high' | 'low' {
    return this.getConfig(mode).quality;
  }

  isOverlayEnabled(mode: string): boolean {
    return this.getConfig(mode).overlays;
  }

  getStats(): {
    activationsPerTrigger: Record<string, number>;
    blockedCount: number;
    recentActivations: number;
    modeConfigs: Record<string, ModeConfig>;
    triggerConfigs: Record<string, TriggerConfig>;
  } {
    const activationsPerTrigger: Record<string, number> = {};
    const entries = Array.from(this.triggerCounts.entries());
    for (const [trigger, count] of entries) {
      activationsPerTrigger[trigger] = count;
    }

    return {
      activationsPerTrigger,
      blockedCount: this.blockedCount,
      recentActivations: this.getActivationsInLastMinute(),
      modeConfigs: { ...MODE_CONFIGS },
      triggerConfigs: { ...TRIGGER_CONFIGS },
    };
  }
}

export const visionAgent = new VisionAgent();
