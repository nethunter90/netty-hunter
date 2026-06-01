import { stealthLogger } from './stealth-logger';
import { egressAllocator } from './egress-route-allocator';

type RiskLevel = 'low' | 'medium' | 'high' | 'critical';

interface ToolConfig {
  flags: string;
  proxySupport: boolean;
}

interface ExecutionPlan {
  tool: string;
  command: string;
  stealthFlags: string;
  estimatedDelay: number;
  proxyRouting: boolean;
  passiveMode: boolean;
  warnings: string[];
  userAgent: string;
  dnsServer: string;
}

const TOOL_STEALTH_FLAGS: Record<string, ToolConfig> = {
  nmap: { flags: '-T2 --randomize-hosts --scan-delay 500ms --data-length 32', proxySupport: true },
  sqlmap: { flags: '--delay=2 --time-sec=10 --random-agent --safe-url-retries=3', proxySupport: true },
  gobuster: { flags: '--delay 500ms --threads 2 --timeout 30s', proxySupport: true },
  ffuf: { flags: '-rate 5 -t 2 -timeout 30', proxySupport: true },
  nikto: { flags: '-Pause 3 -timeout 30 -evasion 1', proxySupport: true },
  nuclei: { flags: '-rl 10 -c 2 -timeout 30 -retries 3', proxySupport: true },
  amass: { flags: '-passive -timeout 30', proxySupport: false },
  httpx: { flags: '-rl 10 -t 2 -timeout 30', proxySupport: true },
  hydra: { flags: '-t 2 -W 3 -c 5', proxySupport: true },
  wpscan: { flags: '--throttle 2000 --random-user-agent', proxySupport: true },
  masscan: { flags: '--rate 100 --randomize-hosts --banners', proxySupport: false },
  dirb: { flags: '-z 500 -t', proxySupport: true },
  wfuzz: { flags: '--delay 0.5 -t 2', proxySupport: true },
  wappalyzer: { flags: '--delay=3000 --max-depth=2', proxySupport: false },
  eyewitness: { flags: '--timeout 15 --threads 2 --delay 3', proxySupport: false },
};

const BALANCED_STEALTH_FLAGS: Record<string, ToolConfig> = {
  nmap: { flags: '-T3 --randomize-hosts --scan-delay 250ms', proxySupport: true },
  sqlmap: { flags: '--delay=1 --time-sec=5 --random-agent', proxySupport: true },
  gobuster: { flags: '--delay 250ms --threads 5 --timeout 20s', proxySupport: true },
  ffuf: { flags: '-rate 15 -t 5 -timeout 20', proxySupport: true },
  nikto: { flags: '-Pause 1 -timeout 20', proxySupport: true },
  nuclei: { flags: '-rl 30 -c 5 -timeout 20 -retries 2', proxySupport: true },
  amass: { flags: '-passive -timeout 20', proxySupport: false },
  httpx: { flags: '-rl 30 -t 5 -timeout 20', proxySupport: true },
  hydra: { flags: '-t 4 -W 2 -c 3', proxySupport: true },
  wpscan: { flags: '--throttle 1000 --random-user-agent', proxySupport: true },
  masscan: { flags: '--rate 500 --randomize-hosts --banners', proxySupport: false },
  dirb: { flags: '-z 250 -t', proxySupport: true },
  wfuzz: { flags: '--delay 0.25 -t 5', proxySupport: true },
  wappalyzer: { flags: '--delay=1500 --max-depth=3', proxySupport: false },
  eyewitness: { flags: '--timeout 10 --threads 3 --delay 1', proxySupport: false },
};

const USER_AGENTS = [
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
  'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
  'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15',
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0',
  'Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0',
];

const DNS_SERVERS = ['1.1.1.1', '8.8.8.8', '9.9.9.9', '208.67.222.222', '77.88.8.8'];

const RISK_CLASSIFICATIONS: Record<RiskLevel, string[]> = {
  low: ['whois', 'dig', 'host', 'nslookup'],
  medium: ['nmap', 'httpx', 'amass', 'whatweb', 'wappalyzer', 'eyewitness'],
  high: ['gobuster', 'ffuf', 'dirb', 'wfuzz', 'nikto', 'nuclei', 'wpscan', 'masscan'],
  critical: ['sqlmap', 'hydra'],
};

const DELAY_RANGES: Record<RiskLevel, [number, number]> = {
  low: [500, 2000],
  medium: [2000, 8000],
  high: [5000, 15000],
  critical: [15000, 60000],
};

class ToolRunner {
  private executions = 0;
  private plansGenerated = 0;
  private programProfiles: Map<string, { stealthProfile: string; maxScanRate: number }> = new Map();
  private activeProgramId: string | null = null;

  setProgram(programId: string, profile: { stealthProfile: string; maxScanRate: number }): void {
    this.programProfiles.set(programId, profile);
    this.activeProgramId = programId;
  }

  getActiveProfile(): string {
    if (this.activeProgramId) {
      const profile = this.programProfiles.get(this.activeProgramId);
      if (profile) return profile.stealthProfile;
    }
    return 'balanced';
  }

  getRandomUserAgent(): string {
    return USER_AGENTS[Math.floor(Math.random() * USER_AGENTS.length)];
  }

  getRandomDNS(): string {
    return DNS_SERVERS[Math.floor(Math.random() * DNS_SERVERS.length)];
  }

  getToolRisk(tool: string): RiskLevel {
    const normalized = tool.toLowerCase();
    for (const [risk, tools] of Object.entries(RISK_CLASSIFICATIONS)) {
      if (tools.includes(normalized)) {
        return risk as RiskLevel;
      }
    }
    return 'medium';
  }

  getToolConfig(tool: string): { flags: string; proxySupport: boolean; risk: RiskLevel } | null {
    const normalized = tool.toLowerCase();
    const config = TOOL_STEALTH_FLAGS[normalized];
    if (!config) return null;
    return {
      flags: config.flags,
      proxySupport: config.proxySupport,
      risk: this.getToolRisk(normalized),
    };
  }

  private getAdaptiveDelay(risk: RiskLevel): number {
    const [min, max] = DELAY_RANGES[risk];
    return Math.floor(Math.random() * (max - min + 1)) + min;
  }

  injectStealthFlags(tool: string, command: string, mode: string): string {
    const normalized = tool.toLowerCase();
    const config = TOOL_STEALTH_FLAGS[normalized];
    if (!config) return command;

    let modified = `${command} ${config.flags}`;

    if (mode === 'aggressive') {
      modified = command;
    }

    this.executions++;

    stealthLogger.log('tool_execution', {
      tool: normalized,
      mode,
      flagsInjected: mode !== 'aggressive',
      flags: config.flags,
    });

    return modified;
  }

  generatePlan(tool: string, target: string, mode: string, proxyUrlOrHuntId?: string): ExecutionPlan {
    // proxyUrlOrHuntId: if it looks like a URL, use it directly (backwards compat);
    // if it looks like a hunt/session ID, allocate a route via the egress allocator
    let proxyUrl: string | undefined;
    if (proxyUrlOrHuntId) {
      if (proxyUrlOrHuntId.startsWith('http') || proxyUrlOrHuntId.startsWith('socks')) {
        proxyUrl = proxyUrlOrHuntId;
      } else {
        const allocated = egressAllocator.allocate(target, tool, proxyUrlOrHuntId);
        proxyUrl = allocated.proxyUrl ?? undefined;
      }
    }
    const normalized = tool.toLowerCase();
    let effectiveMode = mode;
    if (effectiveMode === 'balanced' && this.activeProgramId) {
      const programProfile = this.programProfiles.get(this.activeProgramId);
      if (programProfile) {
        const stealthOrder = ['aggressive', 'balanced', 'stealth', 'ultrastealth'];
        const programIdx = stealthOrder.indexOf(programProfile.stealthProfile);
        const modeIdx = stealthOrder.indexOf(effectiveMode);
        if (programIdx > modeIdx) {
          effectiveMode = programProfile.stealthProfile;
        }
      }
    }

    const flagSet = effectiveMode === 'balanced' ? BALANCED_STEALTH_FLAGS : TOOL_STEALTH_FLAGS;
    const config = flagSet[normalized] || TOOL_STEALTH_FLAGS[normalized];
    const risk = this.getToolRisk(normalized);
    const userAgent = this.getRandomUserAgent();
    const dnsServer = this.getRandomDNS();
    const warnings: string[] = [];

    const stealthFlags = config ? config.flags : '';
    const proxyRouting = !!(proxyUrl && config?.proxySupport);
    const passiveMode = risk === 'low' || normalized === 'amass';
    const estimatedDelay = this.getAdaptiveDelay(risk);

    if (risk === 'critical') {
      warnings.push(`${normalized} is a critical-risk tool — use with extreme caution`);
    }
    if (risk === 'high') {
      warnings.push(`${normalized} is a high-risk tool — monitor for detection`);
    }
    if (proxyUrl && config && !config.proxySupport) {
      warnings.push(`${normalized} does not support proxy routing`);
    }
    if (!config) {
      warnings.push(`No stealth configuration found for ${normalized}`);
    }

    let command = `${normalized} ${target}`;
    if (effectiveMode !== 'aggressive' && stealthFlags) {
      command = `${normalized} ${stealthFlags} ${target}`;
    }
    if (proxyRouting && proxyUrl) {
      command += ` --proxy ${proxyUrl}`;
    }

    this.plansGenerated++;

    stealthLogger.log('tool_execution', {
      action: 'plan_generated',
      tool: normalized,
      target,
      mode: effectiveMode,
      risk,
      proxyRouting,
      estimatedDelay,
    });

    return {
      tool: normalized,
      command,
      stealthFlags,
      estimatedDelay,
      proxyRouting,
      passiveMode,
      warnings,
      userAgent,
      dnsServer,
    };
  }

  getStats(): { toolsConfigured: number; executions: number; plansGenerated: number } {
    return {
      toolsConfigured: Object.keys(TOOL_STEALTH_FLAGS).length,
      executions: this.executions,
      plansGenerated: this.plansGenerated,
    };
  }
}

export const toolRunner = new ToolRunner();
