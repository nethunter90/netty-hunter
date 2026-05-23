import { stealthLogger } from './stealth-logger';

interface ToolProfile {
  noiseScore: number;
  wafSensitivity: number;
  rateLimitSensitivity: number;
}

interface ThreatContext {
  wafDetected?: boolean;
  rateLimited?: boolean;
  recentBlocks?: number;
}

export interface ToolQueueEntry {
  tool: string;
  effectiveScore: number;
  deferralMinutes?: number;
  reason: string;
  alternatives?: string[];
}

interface PrioritizeResult {
  immediate: ToolQueueEntry[];
  deferred: ToolQueueEntry[];
  blocked: ToolQueueEntry[];
}

const TOOL_PROFILES: Record<string, ToolProfile> = {
  whois:      { noiseScore: 10, wafSensitivity: 0, rateLimitSensitivity: 0 },
  dig:        { noiseScore: 10, wafSensitivity: 0, rateLimitSensitivity: 0 },
  host:       { noiseScore: 10, wafSensitivity: 0, rateLimitSensitivity: 0 },
  nslookup:   { noiseScore: 10, wafSensitivity: 0, rateLimitSensitivity: 0 },
  curl:       { noiseScore: 15, wafSensitivity: 1, rateLimitSensitivity: 1 },
  wget:       { noiseScore: 15, wafSensitivity: 1, rateLimitSensitivity: 1 },
  httpx:      { noiseScore: 20, wafSensitivity: 1, rateLimitSensitivity: 2 },
  amass:      { noiseScore: 25, wafSensitivity: 0, rateLimitSensitivity: 1 },
  subfinder:  { noiseScore: 25, wafSensitivity: 0, rateLimitSensitivity: 1 },
  whatweb:    { noiseScore: 30, wafSensitivity: 1, rateLimitSensitivity: 1 },
  nmap:       { noiseScore: 50, wafSensitivity: 3, rateLimitSensitivity: 2 },
  wpscan:     { noiseScore: 55, wafSensitivity: 4, rateLimitSensitivity: 3 },
  dirb:       { noiseScore: 60, wafSensitivity: 4, rateLimitSensitivity: 4 },
  dirsearch:  { noiseScore: 60, wafSensitivity: 4, rateLimitSensitivity: 4 },
  gobuster:   { noiseScore: 65, wafSensitivity: 4, rateLimitSensitivity: 5 },
  ffuf:       { noiseScore: 65, wafSensitivity: 4, rateLimitSensitivity: 5 },
  wfuzz:      { noiseScore: 70, wafSensitivity: 4, rateLimitSensitivity: 4 },
  nikto:      { noiseScore: 75, wafSensitivity: 5, rateLimitSensitivity: 4 },
  nuclei:     { noiseScore: 75, wafSensitivity: 4, rateLimitSensitivity: 4 },
  masscan:    { noiseScore: 80, wafSensitivity: 3, rateLimitSensitivity: 5 },
  sqlmap:     { noiseScore: 85, wafSensitivity: 5, rateLimitSensitivity: 3 },
  hydra:      { noiseScore: 95, wafSensitivity: 5, rateLimitSensitivity: 5 },
};

const PASSIVE_TOOLS = new Set(['whois', 'dig', 'host', 'nslookup']);

const THREAT_FACTORS: Record<string, number> = {
  none: 1,
  low: 1.5,
  medium: 2,
  high: 2.5,
  critical: 3,
};

const ALTERNATIVES: Record<string, string[]> = {
  gobuster:  ['ffuf', 'dirb'],
  nmap:      ['nmap -sS -T2'],
  masscan:   ['nmap'],
  nikto:     ['whatweb'],
  sqlmap:    ['manual testing'],
  hydra:     ['manual testing'],
};

class ToolPriority {
  private totalPrioritizations = 0;
  private toolBlocks = 0;
  private deferrals = 0;
  private blockHistory: { tool: string; timestamp: number }[] = [];

  getToolProfile(tool: string): ToolProfile | null {
    return TOOL_PROFILES[tool] ?? null;
  }

  getEffectiveScore(tool: string, threatLevel: string, context: ThreatContext): number {
    const profile = TOOL_PROFILES[tool];
    if (!profile) return 0;

    const factor = THREAT_FACTORS[threatLevel] ?? 1;
    let score = profile.noiseScore * factor;

    if (context.wafDetected) {
      score += profile.wafSensitivity * 10;
    }

    if (context.rateLimited) {
      score += profile.rateLimitSensitivity * 8;
    }

    const blocks = context.recentBlocks ?? 0;
    score += blocks * 5;

    return score;
  }

  getAlternatives(tool: string): string[] {
    return ALTERNATIVES[tool] ?? [];
  }

  recordBlock(tool: string): void {
    this.blockHistory.push({ tool, timestamp: Date.now() });
    this.toolBlocks++;
  }

  prioritize(tools: string[], threatLevel: string, context: ThreatContext): PrioritizeResult {
    this.totalPrioritizations++;

    const result: PrioritizeResult = {
      immediate: [],
      deferred: [],
      blocked: [],
    };

    for (const tool of tools) {
      const profile = TOOL_PROFILES[tool];
      if (!profile) {
        result.immediate.push({
          tool,
          effectiveScore: 0,
          reason: 'Unknown tool — passed through',
        });
        continue;
      }

      const effectiveScore = this.getEffectiveScore(tool, threatLevel, context);
      const isPassive = PASSIVE_TOOLS.has(tool);
      const blocks = context.recentBlocks ?? 0;
      const alternatives = this.getAlternatives(tool);

      if (effectiveScore > 100) {
        const entry: ToolQueueEntry = {
          tool,
          effectiveScore,
          reason: `Blocked: effective score ${effectiveScore} exceeds threshold`,
        };
        if (alternatives.length > 0) entry.alternatives = alternatives;
        result.blocked.push(entry);
        this.toolBlocks++;

        stealthLogger.log('tool_deferral', {
          tool,
          action: 'blocked',
          effectiveScore,
          threatLevel,
          alternatives,
        });
        continue;
      }

      let deferralMinutes: number | undefined;
      let reason: string;

      if (threatLevel === 'critical' && !isPassive) {
        deferralMinutes = 5;
        reason = 'Critical threat level — non-passive tool deferred 5m';
      } else if (threatLevel === 'high' && profile.noiseScore > 60) {
        deferralMinutes = 3;
        reason = 'High threat level — noisy tool deferred 3m';
      } else if (effectiveScore >= 80) {
        deferralMinutes = 2;
        reason = `Effective score ${effectiveScore} >= 80 — deferred 2m`;
      } else if (blocks >= 3 && !isPassive) {
        deferralMinutes = 1;
        reason = `${blocks} recent blocks — non-passive tool deferred 1m`;
      } else {
        reason = 'Safe to run immediately';
      }

      const entry: ToolQueueEntry = {
        tool,
        effectiveScore,
        reason,
      };

      if (deferralMinutes !== undefined) {
        entry.deferralMinutes = deferralMinutes;
        if (alternatives.length > 0) entry.alternatives = alternatives;
        result.deferred.push(entry);
        this.deferrals++;

        stealthLogger.log('tool_deferral', {
          tool,
          action: 'deferred',
          deferralMinutes,
          effectiveScore,
          threatLevel,
          reason,
          alternatives,
        });
      } else {
        result.immediate.push(entry);
      }
    }

    return result;
  }

  getStats(): { totalPrioritizations: number; toolBlocks: number; deferrals: number } {
    return {
      totalPrioritizations: this.totalPrioritizations,
      toolBlocks: this.toolBlocks,
      deferrals: this.deferrals,
    };
  }
}

export const toolPriority = new ToolPriority();
