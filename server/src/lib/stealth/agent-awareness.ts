import { stealthLogger } from './stealth-logger';

interface PoCStrategy {
  maxPayloads: number;
  delayMs: number;
  obfuscation: boolean;
}

interface ModeConfig {
  delayActions: boolean;
  minimizeVisibility: boolean;
  stealthTools: boolean;
  riskMultiplier: number;
  pocStrategy: PoCStrategy;
}

interface ToolGuidance {
  preferred: string[];
  avoided: string[];
  blocked: string[];
}

interface AgentContext {
  mode: string;
  config: ModeConfig;
  toolGuidance: ToolGuidance;
  pocStrategy: PoCStrategy;
  riskMultiplier: number;
}

const MODE_CONFIGS: Record<string, ModeConfig> = {
  aggressive: {
    delayActions: false,
    minimizeVisibility: false,
    stealthTools: false,
    riskMultiplier: 1.0,
    pocStrategy: { maxPayloads: 100, delayMs: 50, obfuscation: false },
  },
  stealth: {
    delayActions: true,
    minimizeVisibility: true,
    stealthTools: true,
    riskMultiplier: 1.5,
    pocStrategy: { maxPayloads: 20, delayMs: 5000, obfuscation: true },
  },
  ultrastealth: {
    delayActions: true,
    minimizeVisibility: true,
    stealthTools: true,
    riskMultiplier: 3.0,
    pocStrategy: { maxPayloads: 5, delayMs: 30000, obfuscation: true },
  },
};

const TOOL_GUIDANCE: Record<string, ToolGuidance> = {
  aggressive: {
    preferred: [],
    avoided: [],
    blocked: [],
  },
  stealth: {
    preferred: ['httpx', 'amass', 'subfinder', 'nmap'],
    avoided: ['masscan', 'hydra'],
    blocked: [],
  },
  ultrastealth: {
    preferred: ['whois', 'dig', 'curl', 'httpx'],
    avoided: ['masscan', 'nuclei', 'sqlmap', 'gobuster'],
    blocked: [],
  },
};

class AgentAwareness {
  private queriesServed: number = 0;
  private modeDistribution: Record<string, number> = {
    aggressive: 0,
    stealth: 0,
    ultrastealth: 0,
  };

  private resolveMode(mode: string): string {
    const m = mode.toLowerCase();
    if (m in MODE_CONFIGS) return m;
    return 'stealth';
  }

  private trackQuery(mode: string): void {
    this.queriesServed++;
    const resolved = this.resolveMode(mode);
    this.modeDistribution[resolved] = (this.modeDistribution[resolved] || 0) + 1;
  }

  getContext(mode: string): AgentContext {
    this.trackQuery(mode);
    const resolved = this.resolveMode(mode);
    const config = MODE_CONFIGS[resolved];

    stealthLogger.log('mode_change', { mode: resolved, action: 'getContext' });

    return {
      mode: resolved,
      config,
      toolGuidance: this.getToolGuidance(resolved),
      pocStrategy: config.pocStrategy,
      riskMultiplier: config.riskMultiplier,
    };
  }

  getToolGuidance(mode: string): ToolGuidance {
    const resolved = this.resolveMode(mode);
    return { ...TOOL_GUIDANCE[resolved] };
  }

  getPoCStrategy(mode: string): PoCStrategy {
    const resolved = this.resolveMode(mode);
    return { ...MODE_CONFIGS[resolved].pocStrategy };
  }

  isActionAllowed(action: string, riskLevel: string, mode: string): { allowed: boolean; reason?: string } {
    const resolved = this.resolveMode(mode);
    const risk = riskLevel.toLowerCase();

    if (resolved === 'ultrastealth' && risk === 'critical') {
      stealthLogger.log('tool_deferral', {
        action,
        riskLevel: risk,
        mode: resolved,
        blocked: true,
      });
      return {
        allowed: false,
        reason: `Critical-risk actions are blocked in ultrastealth mode: ${action}`,
      };
    }

    const guidance = TOOL_GUIDANCE[resolved];
    if (guidance.blocked.includes(action)) {
      return {
        allowed: false,
        reason: `Action "${action}" is blocked in ${resolved} mode`,
      };
    }

    if (guidance.avoided.includes(action)) {
      return {
        allowed: true,
        reason: `Action "${action}" is flagged as noisy in ${resolved} mode — use with caution`,
      };
    }

    return { allowed: true };
  }

  getRiskMultiplier(mode: string): number {
    const resolved = this.resolveMode(mode);
    return MODE_CONFIGS[resolved].riskMultiplier;
  }

  getStats(): { queriesServed: number; modeDistribution: Record<string, number> } {
    return {
      queriesServed: this.queriesServed,
      modeDistribution: { ...this.modeDistribution },
    };
  }
}

export const agentAwareness = new AgentAwareness();
